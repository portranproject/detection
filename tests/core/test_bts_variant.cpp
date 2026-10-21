// L3-01-V 룰 단위 테스트 (3_ §3·§4·§4.1·§5·§6.1 다·§7·§8). 시간 흐름 전체는 test_scenarios에서 본다
#include "detect/engine.h"
#include "detect/rules/bts_variant.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace detect;
using nlohmann::json;

namespace {

constexpr int64_t kT0 = 1792209000000;
constexpr int64_t kP = 100;

// 칸 하나의 입력. f가 nullopt면 FailCause를 null로(DL 미관측), att가 nullopt면 A·S를 null로
struct SlotIn {
  SlotIn(std::optional<int64_t> a = 0, int64_t s = 0, std::optional<int64_t> fr = 0,
         std::optional<int64_t> cx = std::nullopt)
      : att(a), succ(s), f(fr), uectx(cx) {}
  std::optional<int64_t> att;
  int64_t succ;
  std::optional<int64_t> f;
  std::optional<int64_t> uectx;
};

class Harness {
 public:
  explicit Harness(BtsVariantConfig cfg = {}, int64_t t_nr = 1000, json max_conn = nullptr) : rule_(nullptr) {
    SeriesConfig scfg;
    scfg.window_ms = cfg.window_ms;
    engine_ = std::make_unique<Engine>(scfg);
    auto r = std::make_unique<BtsVariantRule>(cfg);
    rule_ = r.get();
    engine_->add_rule(std::move(r));
    json h = {{"type", "hello"}, {"ver", 1}, {"session", "S"}, {"seq", seq_++},
              {"cells", json::array({{{"cell_id", 1}, {"max_conn", max_conn}}})},
              {"period_ms", kP}, {"noreply_timeout_ms", t_nr}, {"clock", "realtime"}};
    feed(h.dump());
  }

  EngineOutput feed(const std::string& line) {
    EngineOutput o = engine_->feed_line(line);
    alerts.insert(alerts.end(), o.alerts.begin(), o.alerts.end());
    diags.insert(diags.end(), o.diags.begin(), o.diags.end());
    return o;
  }

  // 다음 칸 하나
  EngineOutput slot(const SlotIn& in) {
    const int64_t ts = kT0 + n_ * kP;
    ++n_;
    json cc = json::object();
    cc["RRC.ConnEstabAtt"] = in.att ? json{{"total", *in.att}} : json(nullptr);
    cc["RRC.ConnEstabSucc"] = in.att ? json{{"total", in.succ}} : json(nullptr);
    cc["RRC.ConnEstabFailCause"] =
        in.f ? json{{"NetworkReject", 0}, {"NoReply", *in.f}, {"Other", 0}} : json(nullptr);
    json k = {{"type", "kpm2"}, {"ver", 1}, {"session", "S"}, {"seq", seq_++}, {"cell_id", 1},
              {"t_start_ms", ts}, {"t_end_ms", ts + kP}, {"cc", cc}};
    if (in.uectx) k["ext"] = {{"UeCtxMax", *in.uectx}};
    return feed(k.dump());
  }

  void slots(int n, const SlotIn& in) {
    for (int i = 0; i < n; ++i) slot(in);
  }

  int64_t t_rel(const AlertEvent& e) const { return e.t - kT0; }
  bool has_diag(DiagKind k) const {
    return std::any_of(diags.begin(), diags.end(), [&](const Diag& d) { return d.kind == k; });
  }

  BtsVariantRule* rule_;
  std::vector<AlertEvent> alerts;
  std::vector<Diag> diags;

 private:
  std::unique_ptr<Engine> engine_;
  int64_t seq_ = 1;
  int64_t n_ = 0;
};

}  // namespace

// 윈도우가 다 차기 전(W/P + D칸)은 보류 — 경보도 판정도 없다 (3_ §3·§8)
TEST(BtsVariant, HoldUntilWindowsFull) {
  Harness h;
  h.slots(19, {10, 0, 10});
  EXPECT_FALSE(h.rule_->mode(1));  // 아직 한 번도 판정하지 않음
  h.slot({10, 0, 10});             // 20칸째: A 윈도우 [0, 1000) 완성
  EXPECT_EQ(h.rule_->mode(1), AlertMode::Normal);
}

// A 윈도우는 T_nr(D칸)만큼 과거, F 윈도우는 현재 — 공격 시도 3/칸이 D칸 뒤 NoReply 3/칸 (3_ §3)
TEST(BtsVariant, RaiseWithShiftedWindowsAndLogValues) {
  Harness h;
  h.slots(10, {0, 0, 0});  // 칸 0..9 조용
  h.slots(10, {3, 0, 0});  // 칸 10..19 공격 시도
  h.slots(4, {3, 0, 3});   // 칸 20..23 NoReply 도착 (D = 10)
  // 칸 21·22·23에서 성립(A_w ≥ 5, ratio = 1) → M = 3 → 칸 23(t = 2400)에서 RAISE
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(h.t_rel(e), 2400);
  EXPECT_EQ(e.a_w, 12);  // A 윈도우 = 칸 4..13 → 시도 칸 10..13
  EXPECT_EQ(e.f_w, 12);  // F 윈도우 = 칸 14..23 → NoReply 칸 20..23
  EXPECT_EQ(e.mode, AlertMode::Normal);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.candidates, std::vector<std::string>{"L3-11"});
  EXPECT_EQ(e.alert_id, "S-L3-01-V-1-" + std::to_string(2 + 23));  // seq: hello 1, 칸 0 = 2
}

// T_nr = 500이면 D = 5칸 — 시차가 hello 값을 따른다 (3_ §3)
TEST(BtsVariant, ShiftFollowsHelloNoReplyTimeout) {
  Harness h({}, 500);
  h.slots(10, {0, 0, 0});
  h.slots(5, {6, 0, 0});
  h.slots(3, {6, 0, 6});  // 시도 5칸 뒤 NoReply
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.t_rel(h.alerts[0]), 1800);
}

// 정상 급증: S가 함께 늘면 ratio = 0 → C2 불성립 (3_ §6)
TEST(BtsVariant, NormalSurgeNoAlert) {
  Harness h;
  h.slots(60, {30, 30, 0});
  EXPECT_TRUE(h.alerts.empty());
}

// C4: hello max_conn이 있고 UeCtxMax ≥ 0.9 × max_conn이면 RAISE severity high (3_ §4·§7)
TEST(BtsVariant, C4FromHelloMaxConn) {
  Harness h({}, 1000, 96);
  h.slots(10, {0, 0, 0});
  h.slots(10, {3, 0, 0, 90});
  h.slots(4, {3, 0, 3, 90});
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].severity, Severity::High);
  EXPECT_EQ(h.alerts[0].uectx, 90);
  EXPECT_EQ(h.alerts[0].max_conn, 96);
  EXPECT_NE(format_log_line(h.alerts[0]).find("uectx=90/96 severity=high"), std::string::npos);
}

// C4가 경보 중에 참이 되면 UPDATE 1회 (결정 E2). max_conn은 설정 값 (hello가 null)
TEST(BtsVariant, C4LaterGivesSingleUpdate) {
  BtsVariantConfig cfg;
  cfg.max_conn = 96;
  Harness h(cfg);
  h.slots(10, {0, 0, 0});
  h.slots(10, {3, 0, 0, 50});
  h.slots(4, {3, 0, 3, 50});
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
  h.slots(5, {3, 0, 3, 95});
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].severity, Severity::High);
}

// C4: UeCtxMax가 없거나 max_conn 미정이면 끔 → medium
TEST(BtsVariant, C4OffWithoutInputs) {
  Harness h;  // max_conn 없음
  h.slots(10, {0, 0, 0});
  h.slots(10, {3, 0, 0, 96});
  h.slots(4, {3, 0, 3, 96});
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
  EXPECT_FALSE(h.alerts[0].uectx);
}

// A·S 누락이 10칸을 넘으면 룰 비활성 로그, 다시 들어오면 재개 로그 (3_ §8)
TEST(BtsVariant, MissingKeysInactiveAndResumed) {
  Harness h;
  h.slots(25, {1, 1, 0});
  h.slots(10, {std::nullopt});
  EXPECT_FALSE(h.has_diag(DiagKind::RuleInactive));
  h.slot({std::nullopt});
  EXPECT_TRUE(h.has_diag(DiagKind::RuleInactive));
  h.slot({1, 1, 0});
  EXPECT_TRUE(h.has_diag(DiagKind::RuleResumed));
}

// F가 null이 되면 DL 미관측 모드로, 모드가 바뀔 때 로그 (3_ §4.1·§8, 결정 E1)
TEST(BtsVariant, ModeSwitchToDlMissing) {
  Harness h;
  h.slots(25, {1, 1, 0});
  EXPECT_EQ(h.rule_->mode(1), AlertMode::Normal);
  h.slot({1, 1, std::nullopt});
  EXPECT_EQ(h.rule_->mode(1), AlertMode::DlMissing);  // 보류 없이 바로 전환
  EXPECT_TRUE(h.has_diag(DiagKind::ModeChanged));
}

// 웜업이 끝났을 때 k × base < A_min이면 1회 로그 (3_ §5, 결정 E6)
TEST(BtsVariant, BaselineLowLoggedAfterWarmup) {
  BtsVariantConfig cfg;
  cfg.warmup_ms = 3000;
  Harness h(cfg);
  h.slots(60, {0, 0, 0});
  EXPECT_EQ(std::count_if(h.diags.begin(), h.diags.end(),
                          [](const Diag& d) { return d.kind == DiagKind::BaselineLow; }),
            1);
}

// 의심 칸(ratio ≥ θ)은 기준선 갱신에서 빠진다 — 공격 칸이 base를 끌어올리지 않음 (3_ §5)
TEST(BtsVariant, SuspiciousSlotsExcludedFromBaseline) {
  BtsVariantConfig cfg;
  cfg.warmup_ms = 1000;
  cfg.baseline_tau_s = 1;  // α = 0.1 — 제외하지 않으면 base가 공격을 금방 따라간다
  cfg.m_raise = 1000;      // 경보가 나지 않게 해서 '의심 칸 제외'만 본다
  Harness h(cfg);
  h.slots(40, {2, 2, 0});  // 정상: A_w = 20
  const double before = *h.rule_->base(1);
  h.slots(10, {10, 0, 0});
  h.slots(20, {10, 0, 10});  // ratio ≈ 1인 칸
  EXPECT_NEAR(*h.rule_->base(1), before, 1.5);  // 제외가 없으면 ≈ 100
}
