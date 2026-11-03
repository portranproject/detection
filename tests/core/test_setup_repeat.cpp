// 4단계 룰 AN-07 같은 S-TMSI의 Setup 반복·Complete 없음 테스트 — 21_ §7.8 AN07-T1~T7 (설정 범위는 test_config.cpp) + 11/04 결정
// (망 거절은 '그 연결에서 RRCReject를 봤는지', 반복은 경보 values.extra, 지난 레코드도 판정 이유만 셈). 합성 ue_evt·kpm2 줄로 한다
// (같은 시나리오의 재생 데이터는 tests/data/stage4_yellow/SAN07_* — tools/gen_stage4.py). 시각은 kT0 기준 ms. 미완료 흐름 Q: 같은
// Part1로 RRCSetupRequest → RRCSetup → (Complete 없음) → 시작 + 2 s에 CU의 UEContextReleaseCommand/Complete, 10 s 간격.
// 닫힐 때 판정하고(21_ §1.3) RAISE는 닫힌 시각이 든 창의 kpm2에서 낸다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/setup_repeat.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace detect;

namespace {

constexpr int64_t kT0 = 1793005200000;
constexpr uint64_t kS = 0x0123456789ab;
constexpr uint64_t kS2 = 0x0000fedcba98;
constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";

std::string hex(uint64_t v, int digits) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%0*llx", digits, static_cast<unsigned long long>(v));
  return buf;
}
std::string p1hex(uint64_t s) { return hex(s & kPart1Mask, 10); }

struct L {
  int64_t t = 0;
  int64_t du = 0;
  std::string dir;
  std::string proto;
  std::string msg;
  std::string f;
};
L rrc(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "") {
  return L{t, du, dir, "RRC", msg, f};
}
L f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "") {
  return L{t, du, dir, "F1AP", msg, f};
}
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

// 미완료 흐름 Q (21_ §7.8). random이면 RRCSetupRequest가 randomValue(AN07-T5), reject면 RRCSetup 대신 RRCReject — OCUDU처럼 같은
// 시각에 UEContextReleaseCommand가 오고(cmd_first면 명령 줄이 먼저) 5 ms 뒤 완료(AN07-T4). release가 false면 해제 줄이 없다
// (stale_setup·reused로 닫힘)
struct QOpt {
  bool random = false;
  bool reject = false;
  bool cmd_first = false;
  bool release = true;
};
std::vector<L> Q(int64_t t0, int64_t du, uint64_t s, const QOpt& o = {}) {
  const std::string ident = o.random ? R"("ue_identity":{"type":"randomValue"})"
                                     : R"("ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" + p1hex(s) + R"("})";
  std::vector<L> v = {rrc(t0, du, "UL", "RRCSetupRequest", R"("est_cause":"mo-Signalling",)" + ident)};
  if (o.reject) {
    if (o.cmd_first) v.push_back(f1ap(t0, du, "DL", "UEContextReleaseCommand"));
    v.push_back(rrc(t0, du, "DL", "RRCReject"));
    if (!o.release) return v;
    if (!o.cmd_first) v.push_back(f1ap(t0, du, "DL", "UEContextReleaseCommand"));
    v.push_back(f1ap(t0 + 5, du, "UL", "UEContextReleaseComplete"));
    return v;
  }
  v.push_back(rrc(t0, du, "DL", "RRCSetup"));
  if (!o.release) return v;
  v.push_back(f1ap(t0 + 1995, du, "DL", "UEContextReleaseCommand"));
  v.push_back(f1ap(t0 + 2000, du, "UL", "UEContextReleaseComplete"));
  return v;
}
// 같은 Part1의 Q를 n번 (시작 t0, 간격 gap, du는 du0부터)
std::vector<L> Qn(int n, int64_t t0, int64_t gap, int64_t du0, uint64_t s, const QOpt& o = {}) {
  std::vector<L> v;
  for (int i = 0; i < n; ++i) v = v + Q(t0 + gap * i, du0 + i, s, o);
  return v;
}
// 정상 등록(연결) — 같은 Part1로 Setup·Complete까지 가고 1.2 s 뒤 해제 (AN07-T1)
std::vector<L> Connected(int64_t t0, int64_t du, uint64_t s) {
  return {rrc(t0, du, "UL", "RRCSetupRequest", R"("ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" + p1hex(s) + R"("})"),
          rrc(t0, du, "DL", "RRCSetup"), rrc(t0 + 10, du, "UL", "RRCSetupComplete", R"("s_tmsi":")" + hex(s, 12) + "\""),
          f1ap(t0 + 1195, du, "DL", "UEContextReleaseCommand"), f1ap(t0 + 1200, du, "UL", "UEContextReleaseComplete")};
}

// 엔진 + AN-07 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1)
class Harness {
 public:
  explicit Harness(SetupRepeatConfig cfg = {}, bool record = false)
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, UeTableConfig{}), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<SetupRepeatRule>(cfg);
    rule = r.get();
    engine.add_ue_rule(std::move(r));
    hello("S");
  }
  void hello(const std::string& session) {
    if (session != session_) {
      session_ = session;
      seq_ = 0;
    }
    feed(R"({"type":"hello","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cells":[{"cell_id":1,"max_conn":null}],"period_ms":100,)"
         R"("noreply_timeout_ms":1000,"clock":"realtime","ue_evt":true})");
  }
  void line(const L& l) {
    advance(l.t);
    feed(R"({"type":"ue_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + l.t) + R"(,"cell_id":1,"du_ue_id":)" + std::to_string(l.du) +
         R"(,"crnti":)" + std::to_string(17000 + l.du) + R"(,"dir":")" + l.dir + R"(","proto":")" + l.proto +
         R"(","msg":")" + l.msg + "\"" + (l.f.empty() ? "" : R"(,"f":{)" + l.f + "}") + "}");
  }
  void play(std::vector<L> v) {
    std::stable_sort(v.begin(), v.end(), [](const L& a, const L& b) { return a.t < b.t; });
    for (const L& l : v) line(l);
  }
  // F1Reset(그 du_ue_id만) — 열린 항목을 du_reset으로 닫는다 (2_ §6.7)
  void f1_reset(int64_t t, int64_t du) {
    advance(t);
    feed(R"({"type":"f1_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + t) + R"(,"msg":"F1Reset","cells":[1],"du_ue_ids":[)" +
         std::to_string(du) + "]}");
  }
  void kpm(int64_t t) {
    next_t_ = t + 100;
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":1,"t_start_ms":)" + std::to_string(kT0 + t) + R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) +
         R"(,"cc":)" + kCc + R"(,"ue_evt_lost":[]})");
  }
  void advance(int64_t t) {
    while (next_t_ + 100 <= t) kpm(next_t_);
  }
  void tick_to(int64_t t) {
    while (next_t_ < t) kpm(next_t_);
  }
  void feed(const std::string& line) {
    EngineOutput out = engine.feed_line(line);
    for (const auto& a : out.alerts) {
      alerts.push_back(a);
      logs.push_back(format_log_line(a));
    }
    if (record_) rec.on_feed(engine.series(), engine.ue_table(), out);
  }
  std::vector<std::string> drain() {
    queue.close();
    std::vector<std::string> v;
    EvidenceRecord r;
    while (queue.pop(r)) v.push_back(r.line);
    return v;
  }

  Engine engine;
  EvidenceQueue queue;
  EvidenceRecorder rec;
  SetupRepeatRule* rule = nullptr;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

const std::vector<std::string> kCands = {"L3-11-V1", "L3-11-V2"};

}  // namespace

// AN07-T1: 정상 등록 × 3(같은 Part1) — CONNECTED에 닿아 걸림 없음
TEST(SetupRepeat, T01ConnectedNotCounted) {
  Harness h;
  h.play(Connected(1000, 10, kS) + Connected(11000, 11, kS) + Connected(21000, 12, kS));
  h.tick_to(25000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN07-T2: Q × 3 — 3번째 닫힘(t 23,000)에서 K 3 → K(23,000) = 23,100에 RAISE. 후보 고정, 로그 줄·레코드
TEST(SetupRepeat, T02ThreeIncomplete) {
  Harness h({}, true);
  h.play(Qn(3, 1000, 10000, 10, kS));
  h.tick_to(24000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "AN-07");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_FALSE(e.branch);
  EXPECT_EQ(e.t, kT0 + 23100);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"setup_repeat_no_complete"}));
  EXPECT_EQ(e.candidates, kCands);
  EXPECT_EQ(e.values.dump(), R"({"fail_ues":1,"extra":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"window_ms":60000,"n_fail":3,"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.du_ue_id, 12);
  EXPECT_FALSE(u.s_tmsi);
  EXPECT_EQ(u.t_hit, kT0 + 23000);
  EXPECT_EQ(u.cond, (std::vector<std::string>{"setup_repeat_no_complete"}));
  EXPECT_EQ(u.values.dump(), R"({"fail_n":3,"reason":"released","rrc_last":"RELEASING","part1":")" + p1hex(kS) + "\"}");
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-07 cell=1 t=" + std::to_string(kT0 + 23100) + " kind=anomaly ue=1/12/3 part1=" +
                           p1hex(kS) +
                           " fail_n=3 n_fail=3 window_ms=60000 severity=medium mode=normal candidates=L3-11-V1,L3-11-V2");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"AN-07","stage":4,"unit":"ue","kind":"anomaly","cell":1)"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("evidence":true)"), std::string::npos);  // 닫힌 연결의 recent가 보관돼 있다
}

// AN07-T3: Q × 2 / Q × 3 중 간격 61 s(창 60 s 밖으로 앞 연결이 빠짐) — 경보 없음
TEST(SetupRepeat, T03BelowThresholdOrOutsideWindow) {
  {
    Harness h;
    h.play(Qn(2, 1000, 10000, 10, kS));
    h.tick_to(15000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    h.play(Qn(3, 1000, 61000, 10, kS));
    h.tick_to(126000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN07-T4 (11/04 사용자 결정 — '거절을 봤는지'): RRCSetup 대신 RRCReject × 3. 뒤에 UEContextReleaseCommand가 오면 rrc는 RELEASING으로
// 덮이지만 세지 않는다(명령 줄이 먼저 와도 같음) / 해제 줄 없이 stale_setup으로 닫혀도(rrc REJECTED) 세지 않는다
TEST(SetupRepeat, T04NetworkRejectNotCounted) {
  {
    Harness h;
    QOpt rej;
    rej.reject = true;
    QOpt rej_cmd_first = rej;
    rej_cmd_first.cmd_first = true;
    h.play(Q(1000, 10, kS, rej) + Q(11000, 11, kS, rej_cmd_first) + Q(21000, 12, kS, rej));
    h.tick_to(25000);
    EXPECT_TRUE(h.alerts.empty());
    const auto recs = h.engine.ue_table().history_part1(kS & kPart1Mask, 0);
    ASSERT_EQ(recs.size(), 3u);
    for (const ConnRecord* r : recs) {
      EXPECT_EQ(r->rrc_last, RrcState::Releasing);
      EXPECT_TRUE(r->rejected);
    }
  }
  {
    Harness h;
    QOpt rej;
    rej.reject = true;
    rej.release = false;
    h.play(Qn(3, 1000, 10000, 10, kS, rej));
    h.tick_to(52000);
    EXPECT_TRUE(h.alerts.empty());
    EXPECT_EQ(h.engine.ue_table().history_part1(kS & kPart1Mask, 0).size(), 3u);
  }
}

// AN07-T5: randomValue로 Q × 3 — Part1이 없어 잇지 못함(1단계 몫) / 첫 줄이 RRCSetupRequest가 아닌 mid_join도 Part1이 없어 빠진다
TEST(SetupRepeat, T05NoPart1) {
  Harness h;
  QOpt random;
  random.random = true;
  h.play(Qn(3, 1000, 10000, 10, kS, random));
  std::vector<L> mj;
  for (int i = 0; i < 3; ++i) {
    mj.push_back(rrc(31000 + 10000 * i, 20 + i, "DL", "RRCSetup"));
    mj.push_back(f1ap(33000 + 10000 * i, 20 + i, "UL", "UEContextReleaseComplete"));
  }
  h.play(mj);
  h.tick_to(56000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN07-T6: Q × 3 중 둘째가 해제 줄 없이 stale_setup으로 닫힘(t_last 11,000 + 30 s = 41,000) — 센다(후보 이유). 셋째 닫힘(23,000)에는
// 둘째가 아직 열려 있어 K 2, 둘째가 닫힐 때 K 3 → 마감을 처리한 그 kpm2(t_end 41,000)에서 RAISE
TEST(SetupRepeat, T06StaleSetupCounted) {
  Harness h;
  QOpt no_release;
  no_release.release = false;
  h.play(Q(1000, 10, kS) + Q(11000, 11, kS, no_release) + Q(21000, 12, kS));
  h.tick_to(40900);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(41000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + 41000);
  const AlertUe& u = h.alerts[0].ues[0];
  EXPECT_EQ(u.du_ue_id, 11);
  EXPECT_EQ(u.t_hit, kT0 + 41000);
  EXPECT_EQ(u.values.at("reason"), "stale_setup");
  EXPECT_EQ(u.values.at("rrc_last"), "SETUP");
}

// 같은 du_ue_id로 RRCSetupRequest가 다시 와 옛 항목이 reused로 닫힘(해제 줄을 놓친 모양) — 후보 이유라 센다
TEST(SetupRepeat, ReusedCounted) {
  Harness h;
  QOpt no_release;
  no_release.release = false;
  h.play(Q(1000, 10, kS, no_release) + Q(11000, 10, kS, no_release) + Q(21000, 10, kS, no_release) +
         Q(31000, 10, kS, no_release));
  h.tick_to(32000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + 31100);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("reason"), "reused");
}

// 11/04 구현 때 정함 (AN-04와 같음): 지난 레코드도 판정 이유만 센다 — 둘째가 F1Reset(du_reset)으로 닫히면 K 2, 경보 없음
TEST(SetupRepeat, DuResetNotCounted) {
  Harness h;
  QOpt no_release;
  no_release.release = false;
  h.play(Q(1000, 10, kS) + Q(11000, 11, kS, no_release));
  h.f1_reset(12000, 11);
  h.play(Q(21000, 12, kS));
  h.tick_to(24000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.engine.ue_table().history_part1(kS & kPart1Mask, 0).size(), 3u);  // 레코드는 셋 다 — 세지 않을 뿐
}

// 11/04 (21_ §1.1 원칙 — AN-04와 같음): Q × 4 — RAISE 1번(UE 칸 하나, fail_n 3 그대로), 4번째는 경보 values.extra. 다른 Part1이
// 경보 중에 걸리면 UPDATE에 누적값이 실린다
TEST(SetupRepeat, RepeatIsExtra) {
  Harness h;
  h.play(Qn(4, 1000, 10000, 10, kS) + Qn(3, 25000, 10000, 20, kS2));
  h.tick_to(48000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("fail_n"), 3);
  const AlertEvent& u = h.alerts[1];
  EXPECT_EQ(u.kind, AlertEventKind::Update);
  EXPECT_EQ(u.t, kT0 + 47100);
  ASSERT_EQ(u.ues.size(), 1u);
  EXPECT_EQ(u.ues[0].values.at("part1"), p1hex(kS2));
  EXPECT_EQ(u.values.dump(), R"({"fail_ues":2,"extra":1,"evicted":0})");
}

// AN07-T7 해제: 마지막 걸림(23,000) + 60 s 이상인 첫 kpm2(t_end 83,000)에 CLEAR
TEST(SetupRepeat, T07Clear) {
  Harness h;
  h.play(Qn(3, 1000, 10000, 10, kS));
  h.tick_to(82900);
  ASSERT_EQ(h.alerts.size(), 1u);
  h.tick_to(83000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=AN-07 cell=1 t=" + std::to_string(kT0 + 83000) + " duration_ms=59900 ues_total=1");
}

// 회복 (21_ §7.3-2): 걸린 Part1이 창 W 동안 미완료 연결을 만들지 않으면 회복 — 다시 반복하면 새 UE로 RAISE한다
TEST(SetupRepeat, RecoveredPart1IsNewAgain) {
  Harness h;
  h.play(Qn(3, 1000, 10000, 10, kS) + Qn(3, 100000, 10000, 20, kS));
  h.tick_to(123000);
  ASSERT_EQ(h.alerts.size(), 3u);  // RAISE, CLEAR, RAISE
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[2].t, kT0 + 122100);
  EXPECT_EQ(h.alerts[2].ues[0].values.at("fail_n"), 3);
  EXPECT_EQ(h.alerts[2].values.at("extra"), 0);
}

// 재생 결정성 (AN07-T7) — RAISE·UPDATE 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(SetupRepeat, Deterministic) {
  auto run = [] {
    Harness h({}, true);
    h.play(Qn(4, 1000, 10000, 10, kS) + Qn(3, 25000, 10000, 20, kS2));
    h.tick_to(50000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 2u);
}

// END: 세션이 바뀌면 END(session_reset) / 입력 침묵이면 END(input_silent)
TEST(SetupRepeat, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(Qn(3, 1000, 10000, 10, kS));
    h.tick_to(24000);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
  }
  {
    Harness h;
    h.play(Qn(3, 1000, 10000, 10, kS));
    h.tick_to(24000);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
  }
}

// 증거 지평 (21_ §1.1): 1,000 ms + alert.update_min_ms
TEST(SetupRepeat, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
}
