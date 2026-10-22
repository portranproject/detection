// 시나리오 테스트 (4_ §4-2, 3_ §9): tests/data/scenarios/의 .jsonl을 엔진에 넣고
// 나온 경보를 같은 이름 .expected.json과 비교한다. 시각은 ±tolerance_ms(1칸)를 허용한다.
#include "detect/engine.h"
#include "detect/rules/bts_variant.h"

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

// 시나리오 폴더(합성)와 captured 폴더(실측 변환, 4_ §4.2)의 .expected.json이 있는 데이터셋 — 경로는 scenarios 기준 상대
std::vector<std::string> scenario_names() {
  std::vector<std::string> names;
  for (const char* sub : {"", "../captured/"}) {
  for (const auto& e : fs::directory_iterator(std::string(DETECT_SCENARIO_DIR) + "/" + sub)) {
    const std::string f = e.path().filename().string();
    const std::string suffix = ".expected.json";
    if (f.size() > suffix.size() && f.compare(f.size() - suffix.size(), suffix.size(), suffix) == 0)
      names.push_back(std::string(sub) + f.substr(0, f.size() - suffix.size()));
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

std::vector<AlertEvent> replay(const std::string& path) {
  BtsVariantConfig cfg;
  SeriesConfig scfg;
  scfg.window_ms = cfg.window_ms;
  Engine engine(scfg);
  engine.add_rule(std::make_unique<BtsVariantRule>(cfg));
  std::ifstream in(path);
  std::string line;
  std::vector<AlertEvent> alerts;
  while (std::getline(in, line)) {
    auto out = engine.feed_line(line);
    alerts.insert(alerts.end(), out.alerts.begin(), out.alerts.end());
  }
  return alerts;
}

class Scenario : public ::testing::TestWithParam<std::string> {};

}  // namespace

TEST_P(Scenario, AlertsMatchExpected) {
  const std::string base = std::string(DETECT_SCENARIO_DIR) + "/" + GetParam();
  std::ifstream ef(base + ".expected.json");
  ASSERT_TRUE(ef) << base;
  const auto expected = nlohmann::json::parse(ef);
  const int64_t t0 = expected.at("t0_ms").get<int64_t>();
  const int64_t tol = expected.at("tolerance_ms").get<int64_t>();

  const auto got = replay(base + ".jsonl");

  std::string got_text;
  for (const auto& a : got) got_text += "  " + format_log_line(a) + "  (t_rel=" + std::to_string(a.t - t0) + ")\n";

  const auto& want = expected.at("alerts");
  ASSERT_EQ(got.size(), want.size()) << GetParam() << " got:\n" << got_text;
  for (std::size_t i = 0; i < got.size(); ++i) {
    const auto& w = want[i];
    const auto& g = got[i];
    EXPECT_EQ(kind_name(g.kind), w.at("kind").get<std::string>()) << "#" << i << "\n" << got_text;
    EXPECT_EQ(g.cell_id, w.at("cell").get<int64_t>()) << "#" << i << "\n" << got_text;
    EXPECT_NEAR(static_cast<double>(g.t - t0), w.at("t_rel_ms").get<double>(), static_cast<double>(tol))
        << "#" << i << "\n" << got_text;
    if (g.kind == AlertEventKind::Raise) {
      EXPECT_EQ(g.mode == AlertMode::Normal ? "normal" : "dl_missing", w.at("mode").get<std::string>())
          << "#" << i;
    }
    if (w.contains("reason")) {
      EXPECT_EQ(g.reason, w.at("reason").get<std::string>()) << "#" << i;
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Data, Scenario, ::testing::ValuesIn(scenario_names()),
                         [](const ::testing::TestParamInfo<std::string>& info) {
                           // gtest 이름은 영숫자·_만 — 시나리오 번호(T03 등)만 쓴다
                           std::string n = info.param;
                           const bool captured = n.rfind("../captured/", 0) == 0;
                           if (captured) n = n.substr(12);
                           std::string id = n.substr(0, n.find('_'));
                           if (captured) id = "captured_" + id + "_" + std::to_string(std::hash<std::string>{}(n) % 1000);
                           return id;
                         });
