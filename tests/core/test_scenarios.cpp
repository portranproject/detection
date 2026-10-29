// 시나리오 테스트 (4_ §4-2, 3_ §9): tests/data/의 .jsonl을 엔진에 넣고 나온 경보를 같은 이름 .expected.json과 비교한다.
// 시각은 ±tolerance_ms(1칸)를 허용한다. 엔진에는 실행 파일과 같이 1단계·2단계 룰을 모두 기본값으로 등록한다 —
// 2단계 룰은 hello에 ue_evt 표시가 있을 때만 돈다(2_ §6.5).
//  - scenarios/(합성)·captured/(실측 변환, 4_ §4.2): 1단계 시나리오 T1~T24
//  - stage2_green/: 2단계 데이터 (10/29 이슈 #33). 파일은 팀이 준비해 넣는다 — 비어 있으면 도는 시험이 없다
// 경보 시각 허용 오차(이슈 #40): 1단계 데이터만 기대 파일의 tolerance_ms(±1칸)를 쓴다 — Succ가 1~2칸 늦게 찍혀 성립 칸이
// 흔들리기 때문이다(3_ §3·§9, 5_ §11). 2단계부터는 '마감 시각 이상인 첫 kpm2'처럼 시각이 정확히 정해지므로 0으로
// 정확히 비교한다 — 경보가 한 칸 늦어지는 회귀도 잡게
#include "detect/engine.h"
#include "detect/rules/auth_stall.h"
#include "detect/rules/blind_dos.h"
#include "detect/rules/bts_variant.h"
#include "detect/rules/uplink_dos.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

using namespace detect;
namespace fs = std::filesystem;

namespace {

const std::string kSuffix = ".expected.json";

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() > suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// 하위 폴더(scenarios 기준 상대)들에서 .expected.json이 있는 데이터셋 이름
std::vector<std::string> dataset_names(std::initializer_list<const char*> subs) {
  std::vector<std::string> names;
  for (const char* sub : subs) {
    for (const auto& e : fs::directory_iterator(std::string(DETECT_SCENARIO_DIR) + "/" + sub)) {
      const std::string f = e.path().filename().string();
      if (ends_with(f, kSuffix)) names.push_back(std::string(sub) + f.substr(0, f.size() - kSuffix.size()));
    }
  }
  std::sort(names.begin(), names.end());
  return names;
}

const char* kind_name(AlertEventKind k) {
  switch (k) {
    case AlertEventKind::Raise: return "RAISE";
    case AlertEventKind::Clear: return "CLEAR";
    case AlertEventKind::End: return "END";
    case AlertEventKind::Update: return "UPDATE";
  }
  return "?";
}

// 실행 파일과 같은 룰 구성(기본값)으로 재생한다 (4_ §3)
std::vector<AlertEvent> replay(const std::string& path) {
  BtsVariantConfig cfg;
  SeriesConfig scfg;
  scfg.window_ms = cfg.window_ms;
  Engine engine(scfg);
  engine.add_rule(std::make_unique<BtsVariantRule>(cfg));
  engine.add_ue_rule(std::make_unique<BlindDosRule>());
  engine.add_ue_rule(std::make_unique<AuthStallRule>());
  engine.add_ue_rule(std::make_unique<UplinkDosRule>());
  std::ifstream in(path);
  std::string line;
  std::vector<AlertEvent> alerts;
  while (std::getline(in, line)) {
    auto out = engine.feed_line(line);
    alerts.insert(alerts.end(), out.alerts.begin(), out.alerts.end());
  }
  return alerts;
}

// 기대 파일과 비교: 경보마다 kind·rule(없으면 L3-01-V)·cell·t_rel_ms는 늘, mode(RAISE)·severity·branch·reason·alert_kind는
// 기대 파일에 있으면 본다. exact_time이면 기대 파일의 tolerance_ms를 쓰지 않고 시각을 정확히 비교한다(2단계부터)
void check_dataset(const std::string& name, bool exact_time) {
  const std::string base = std::string(DETECT_SCENARIO_DIR) + "/" + name;
  std::ifstream ef(base + kSuffix);
  ASSERT_TRUE(ef) << base;
  const auto expected = nlohmann::json::parse(ef);
  const int64_t t0 = expected.at("t0_ms").get<int64_t>();
  const int64_t tol = exact_time ? 0 : expected.at("tolerance_ms").get<int64_t>();

  const auto got = replay(base + ".jsonl");

  std::string got_text;
  for (const auto& a : got) got_text += "  " + format_log_line(a) + "  (t_rel=" + std::to_string(a.t - t0) + ")\n";

  const auto& want = expected.at("alerts");
  ASSERT_EQ(got.size(), want.size()) << name << " got:\n" << got_text;
  for (std::size_t i = 0; i < got.size(); ++i) {
    const auto& w = want[i];
    const auto& g = got[i];
    EXPECT_EQ(kind_name(g.kind), w.at("kind").get<std::string>()) << "#" << i << "\n" << got_text;
    EXPECT_EQ(g.rule, w.value("rule", std::string(BtsVariantRule::kId))) << "#" << i << "\n" << got_text;
    EXPECT_EQ(g.cell_id, w.at("cell").get<int64_t>()) << "#" << i << "\n" << got_text;
    EXPECT_NEAR(static_cast<double>(g.t - t0), w.at("t_rel_ms").get<double>(), static_cast<double>(tol))
        << "#" << i << " (tolerance " << tol << " ms)\n" << got_text;
    if (g.kind == AlertEventKind::Raise && w.contains("mode")) {
      EXPECT_EQ(g.mode == AlertMode::Normal ? "normal" : "dl_missing", w.at("mode").get<std::string>())
          << "#" << i;
    }
    if (w.contains("severity")) {
      EXPECT_EQ(g.severity == Severity::High ? "high" : "medium", w.at("severity").get<std::string>()) << "#" << i;
    }
    if (w.contains("branch")) {
      EXPECT_EQ(g.branch.value_or(""), w.at("branch").get<std::string>()) << "#" << i;
    }
    if (w.contains("reason")) {
      EXPECT_EQ(g.reason, w.at("reason").get<std::string>()) << "#" << i;
    }
    if (w.contains("alert_kind")) {  // attack | anomaly — 불확실 경보 (14_ §6.2, 이슈 #48)
      EXPECT_EQ(g.alert_kind, w.at("alert_kind").get<std::string>()) << "#" << i;
    }
  }
}

class Scenario : public ::testing::TestWithParam<std::string> {};
class Stage2Scenario : public ::testing::TestWithParam<std::string> {};

}  // namespace

TEST_P(Scenario, AlertsMatchExpected) { check_dataset(GetParam(), false); }

TEST_P(Stage2Scenario, AlertsMatchExpected) { check_dataset(GetParam(), true); }

// stage2_green/ 정리 상태: 폴더가 있고, .jsonl마다 같은 이름 .expected.json이 있다(그 반대도) — 데이터를 넣을 때 짝이
// 빠지면 시험에서 조용히 빠지지 않게 (4_ §4.2 파일명 규칙)
TEST(Stage2Data, EveryJsonlHasExpected) {
  const fs::path dir = fs::path(DETECT_SCENARIO_DIR) / ".." / "stage2_green";
  ASSERT_TRUE(fs::is_directory(dir)) << dir;
  for (const auto& e : fs::directory_iterator(dir)) {
    const std::string f = e.path().filename().string();
    if (ends_with(f, ".jsonl")) {
      EXPECT_TRUE(fs::exists(dir / (f.substr(0, f.size() - 6) + kSuffix))) << f;
    } else if (ends_with(f, kSuffix)) {
      EXPECT_TRUE(fs::exists(dir / (f.substr(0, f.size() - kSuffix.size()) + ".jsonl"))) << f;
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Data, Scenario, ::testing::ValuesIn(dataset_names({"", "../captured/"})),
                         [](const ::testing::TestParamInfo<std::string>& info) {
                           // gtest 이름은 영숫자·_만 — 시나리오 번호(T03 등)만 쓴다
                           std::string n = info.param;
                           const bool captured = n.rfind("../captured/", 0) == 0;
                           if (captured) n = n.substr(12);
                           std::string id = n.substr(0, n.find('_'));
                           if (captured) id = "captured_" + id + "_" + std::to_string(std::hash<std::string>{}(n) % 1000);
                           return id;
                         });

// 2단계 데이터는 아직 없을 수 있다 — 비어 있어도 시험 실행이 실패하지 않게 한다
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(Stage2Scenario);
INSTANTIATE_TEST_SUITE_P(Data, Stage2Scenario, ::testing::ValuesIn(dataset_names({"../stage2_green/"})),
                         [](const ::testing::TestParamInfo<std::string>& info) {
                           // gtest 이름은 영숫자·_만 — 파일 이름의 영숫자(룰 ID 등)에 이름 해시를 붙여 겹치지 않게
                           const std::string n = info.param.substr(16);  // "../stage2_green/" 뒤
                           std::string id;
                           for (const char c : n) {
                             if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) id += c;
                             else if (c == '-' || c == '_') id += '_';
                           }
                           return id + "_" + std::to_string(std::hash<std::string>{}(n) % 1000);
                         });
