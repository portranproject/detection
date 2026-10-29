// L3-01-V 룰 단위 테스트 (3_ §3·§4·§4.1·§5·§6.1 다·§7·§8, 입력 침묵 이슈 #50). 시간 흐름 전체는 test_scenarios에서 본다
#include "detect/engine.h"
#include "detect/rules/bts_variant.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
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

  // 입력 침묵 — 실행 파일이 벽시계로 알리는 것을 흉내 낸다 (3_ §8, 이슈 #50)
  EngineOutput silent(int64_t ms = 10000) {
    EngineOutput o = engine_->on_input_silent(ms);
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
  EXPECT_EQ(e.values.at("a_w"), 12);  // A 윈도우 = 칸 4..13 → 시도 칸 10..13
  EXPECT_EQ(e.values.at("f_w"), 12);  // F 윈도우 = 칸 14..23 → NoReply 칸 20..23
  EXPECT_EQ(e.mode, AlertMode::Normal);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.candidates, std::vector<std::string>{"L3-11"});
  EXPECT_EQ(e.alert_id, "S-L3-01-V-1-" + std::to_string(2 + 23));  // seq: hello 1, 칸 0 = 2
  // 공통 경보 형식 (14_ §8.5): 웜업 중이라 C3는 넣지 않음, F_w = 12 ≥ F_abs라 C2a도 성립 (결정 J2)
  EXPECT_EQ(e.stage, 1);
  EXPECT_EQ(e.unit, "cell");
  EXPECT_EQ(e.alert_kind, "attack");
  EXPECT_EQ(e.cond, (std::vector<std::string>{"C1", "C2", "C2a"}));
  // 로그 줄 전체 (3_ §7 순서): 룰이 log_fields로 넣는 근거 값 + 공통 꼬리 severity·mode·candidates (4_ §6.1 #5)
  char base[32];
  std::snprintf(base, sizeof(base), "%.1f", e.values.at("base").get<double>());
  EXPECT_EQ(format_log_line(e), "ALERT RAISE rule=L3-01-V cell=1 t=" + std::to_string(e.t) +
                                    " A_w=12 F_w=12 ratio=1.00 base=" + base +
                                    " k=3 theta=0.5 f_abs=10 severity=medium mode=normal candidates=L3-11");
  // alert 레코드의 자리 (14_ §8.5 옮김 표): k·theta는 실수, f_abs는 normal 모드만, refs는 A·F 윈도우 seq 범위
  EXPECT_EQ(e.params.dump(), R"({"k":3.0,"theta":0.5,"f_abs":10})");
  EXPECT_TRUE(e.refs.contains("a"));
  EXPECT_TRUE(e.refs.contains("f"));
}

// 입력 침묵 (3_ §8 — 10/29 Q-45 해결, 이슈 #50): 경보 중 실행 파일이 침묵을 알리면 END(reason=input_silent, t = 그 셀 마지막 칸)와
// 진단 1회. 버퍼·기준선·모드는 그대로라 칸을 이어 넣으면 다시 M칸 성립에서 새 RAISE(상태기계는 초기화됨). 경보가 없으면 진단만.
// hello 전에도 안전하다
TEST(BtsVariant, EndOnInputSilent) {
  Harness h;
  h.slots(10, {0, 0, 0});
  h.slots(10, {3, 0, 0});
  h.slots(4, {3, 0, 3});  // 칸 23(t = 2400)에서 RAISE
  ASSERT_EQ(h.alerts.size(), 1u);
  const std::optional<double> base = h.rule_->base(1);
  EngineOutput o = h.silent(10000);
  ASSERT_EQ(o.alerts.size(), 1u);
  EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
  EXPECT_EQ(o.alerts[0].reason, "input_silent");
  EXPECT_EQ(o.alerts[0].alert_id, h.alerts[0].alert_id);
  EXPECT_EQ(h.t_rel(o.alerts[0]), 2400);
  EXPECT_EQ(o.alerts[0].duration_ms, 0);
  EXPECT_EQ(format_log_line(o.alerts[0]),
            "ALERT END rule=L3-01-V cell=1 t=" + std::to_string(kT0 + 2400) + " duration_ms=0 reason=input_silent");
  ASSERT_EQ(o.diags.size(), 1u);
  EXPECT_EQ(o.diags[0].kind, DiagKind::InputSilent);
  EXPECT_EQ(o.outcome, FeedOutcome::Dropped);
  EXPECT_FALSE(h.rule_->alert_active(1));
  EXPECT_EQ(h.rule_->base(1), base);  // 기준선 유지
  EXPECT_EQ(h.rule_->mode(1), AlertMode::Normal);
  // 경보가 없으면 진단만 — 다시 kpm2가 올 때까지 1회로 막는 것은 실행 파일의 몫
  o = h.silent(10000);
  EXPECT_TRUE(o.alerts.empty());
  EXPECT_EQ(o.diags.size(), 1u);
  // 이어서 공격 칸: 버퍼가 그대로라 보류 없이 바로 판정, 상태기계는 초기화됐으니 M = 3칸 성립 뒤 칸 26(t = 2700)에서 새 RAISE
  h.slots(3, {3, 0, 3});
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.t_rel(h.alerts[2]), 2700);
  EXPECT_NE(h.alerts[2].alert_id, h.alerts[0].alert_id);

  Engine bare;  // hello 전 — 룰은 셀이 없어 진단만
  bare.add_rule(std::make_unique<BtsVariantRule>());
  EngineOutput b = bare.on_input_silent(10000);
  EXPECT_TRUE(b.alerts.empty());
  EXPECT_EQ(b.diags.size(), 1u);
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
  EXPECT_EQ(h.alerts[0].values.at("uectx"), 90);
  EXPECT_EQ(h.alerts[0].values.at("max_conn"), 96);
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
  EXPECT_FALSE(h.alerts[0].values.contains("uectx"));
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

// C2a (3_ §4, 10/27 Q-41): 정상 부하가 커서 ratio < θ여도 1초 NoReply가 F_abs(10) 이상이면 C1·C3 없이 RAISE.
// 정상 6/칸(60/s) + 공격 5/칸(50/s) → ratio ≤ 50/110 ≈ 0.45 < θ, F_w는 공격 NoReply 2칸부터 10 ≥ F_abs
TEST(BtsVariant, C2aRaisesUnderHighNormalLoad) {
  Harness h;
  h.slots(10, {6, 6, 0});
  h.slots(10, {11, 6, 0});
  h.slots(4, {11, 6, 5});  // 칸 20..23 NoReply 5/칸 → 칸 21부터 F_w ≥ 10 → M = 3 → 칸 23(t = 2400)에서 RAISE
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(h.t_rel(e), 2400);
  ASSERT_TRUE(e.values.contains("ratio"));
  EXPECT_LT(e.values.at("ratio").get<double>(), 0.5);  // 비율로는 못 잡는 경우
  EXPECT_EQ(e.params.at("f_abs"), 10);
  EXPECT_NE(format_log_line(e).find("theta=0.5 f_abs=10"), std::string::npos);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"C1", "C2a"}));  // C2 불성립 — C2a로 걸렸음이 보인다
}

// 같은 입력에서 F_abs를 아주 크게 두면 비율 조건만 남아 경보가 없다 — 위 RAISE가 C2a 때문임을 확인
TEST(BtsVariant, LargeFabsLeavesRatioOnly) {
  BtsVariantConfig cfg;
  cfg.f_abs = 1000000;
  Harness h(cfg);
  h.slots(10, {6, 6, 0});
  h.slots(10, {11, 6, 0});
  h.slots(20, {11, 6, 5});
  EXPECT_TRUE(h.alerts.empty());
}

// C2a 칸도 의심 칸 — ratio < θ지만 F_w ≥ F_abs면 기준선 갱신에서 빠진다 (3_ §5, 10/27 Q-41)
TEST(BtsVariant, C2aSlotsExcludedFromBaseline) {
  BtsVariantConfig cfg;
  cfg.warmup_ms = 1000;
  cfg.baseline_tau_s = 1;  // α = 0.1
  cfg.m_raise = 1000;      // 경보가 나지 않게
  Harness h(cfg);
  h.slots(40, {30, 30, 0});  // 정상 30/칸: base = 300
  const double before = *h.rule_->base(1);
  h.slots(10, {40, 30, 0});  // 공격 10/칸 섞임, NoReply는 아직 — A 윈도우는 아직 정상 구간
  h.slots(30, {40, 30, 10}); // 첫 NoReply 칸부터 F_w = 10 ≥ F_abs → 의심 칸. ratio = 100/400 = 0.25 < θ, U = 0.25 < θ
  EXPECT_NEAR(*h.rule_->base(1), before, 0.5);  // 제외가 없으면 400 쪽으로 올라간다
}

// DL 미관측 모드에는 C2a가 없다 — RAISE에 f_abs가 없고 로그에도 안 찍힘 (3_ §4.1·§7)
TEST(BtsVariant, DlMissingRaiseHasNoFabs) {
  Harness h;
  h.slots(10, {1, 1, std::nullopt});
  h.slots(10, {3, 0, std::nullopt});  // U가 θ를 넘어 시차 없이 RAISE
  ASSERT_FALSE(h.alerts.empty());
  EXPECT_EQ(h.alerts[0].mode, AlertMode::DlMissing);
  EXPECT_FALSE(h.alerts[0].params.contains("f_abs"));
  EXPECT_EQ(format_log_line(h.alerts[0]).find("f_abs="), std::string::npos);
  EXPECT_EQ(h.alerts[0].cond, std::vector<std::string>{"U"});  // 웜업 중 — C3 없음 (결정 J3)
}

// 웜업이 끝난 뒤 RAISE면 C3가 cond에 들어간다 (14_ §8.5, 결정 J2). F_abs를 크게 둬 C2a는 빠짐
TEST(BtsVariant, CondHasC3AfterWarmup) {
  BtsVariantConfig cfg;
  cfg.warmup_ms = 1000;
  cfg.f_abs = 1000;
  Harness h(cfg);
  h.slots(40, {0, 0, 0});
  h.slots(10, {3, 0, 0});
  h.slots(4, {3, 0, 3});
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].cond, (std::vector<std::string>{"C1", "C2", "C3"}));
}

// DL 미관측 모드도 웜업 뒤면 base′ 기준 C3를 함께 적는다 (결정 J3)
TEST(BtsVariant, DlMissingCondHasC3AfterWarmup) {
  BtsVariantConfig cfg;
  cfg.warmup_ms = 1000;
  Harness h(cfg);
  h.slots(40, {1, 1, std::nullopt});  // base′ ≈ 10 → k × base′ ≈ 30
  h.slots(10, {5, 0, std::nullopt});
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].mode, AlertMode::DlMissing);
  EXPECT_EQ(h.alerts[0].cond, (std::vector<std::string>{"U", "C3"}));
}
