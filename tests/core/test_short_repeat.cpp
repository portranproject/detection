// 4단계 룰 AN-04 같은 UE의 짧은 연결 반복 테스트 — 21_ §6.8 AN04-T1~T8 (설정 범위는 test_config.cpp) + 11/04 구현 때 정한 것
// (반복은 경보 values.extra, 지난 레코드도 판정 이유만 셈, src "48bit"·"part1"). 합성 ue_evt·kpm2 줄로 한다(같은 시나리오의 재생
// 데이터는 tests/data/stage4_yellow/SAN04_* — tools/gen_stage4.py). 시각은 kT0 기준 ms. 짧은 연결 흐름 P: 같은 S-TMSI로
// RRCSetupRequest(Part1, est_cause) → RRCSetupComplete(s_tmsi) → ServiceRequest → ServiceAccept → 시작 + 1.2 s에 해제 완료, 20 s 간격.
// 닫힐 때 판정하고(21_ §1.3) RAISE는 닫힌 시각이 든 창의 kpm2에서 낸다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/short_repeat.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <map>
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
std::string stmsi(uint64_t v) { return R"("s_tmsi":")" + hex(v, 12) + "\""; }

struct L {
  int64_t t = 0;
  int64_t du = 0;
  std::string dir;
  std::string proto;
  std::string msg;
  std::string f;
  int sht = 0;
};
L rrc(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "") {
  return L{t, du, dir, "RRC", msg, f, 0};
}
L nas(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "", int sht = 0) {
  return L{t, du, dir, "NAS", msg, f, sht};
}
L f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "") {
  return L{t, du, dir, "F1AP", msg, f, 0};
}
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

// 짧은 연결 흐름 P (21_ §6.8). full이 false면 RRC·NAS에 48비트가 없고 Part1만 안다(AN04-T6). du_release면 해제 전에 DU가
// UEContextReleaseRequest(rl-failure)를 보낸다(AN04-T4). release가 false면 해제 줄을 내지 않는다(AN04-T7 — 정리로 닫힘)
struct POpt {
  std::string est = "mt-Access";
  bool full = true;
  int64_t len = 1200;
  bool du_release = false;
  bool release = true;
};
std::vector<L> P(int64_t t0, int64_t du, uint64_t s, const POpt& o = {}) {
  std::vector<L> v = {
      rrc(t0, du, "UL", "RRCSetupRequest",
          R"("est_cause":")" + o.est + R"(","ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" +
              hex(s & kPart1Mask, 10) + R"("})"),
      rrc(t0, du, "DL", "RRCSetup"), rrc(t0 + 10, du, "UL", "RRCSetupComplete", o.full ? stmsi(s) : ""),
      nas(t0 + 20, du, "UL", "ServiceRequest", o.full ? stmsi(s) : "", 1), nas(t0 + 30, du, "DL", "ServiceAccept", "", 2)};
  if (!o.release) return v;
  if (o.du_release)
    v.push_back(f1ap(t0 + o.len - 20, du, "UL", "UEContextReleaseRequest", R"("cause":"radioNetwork:rl-failure")"));
  v.push_back(rrc(t0 + o.len - 10, du, "DL", "RRCRelease", R"("suspend":false)"));
  v.push_back(f1ap(t0 + o.len - 5, du, "DL", "UEContextReleaseCommand"));
  v.push_back(f1ap(t0 + o.len, du, "UL", "UEContextReleaseComplete"));
  return v;
}
// 같은 S-TMSI의 P를 n번 (시작 t0, 간격 gap, du는 du0부터)
std::vector<L> Pn(int n, int64_t t0, int64_t gap, int64_t du0, uint64_t s, const POpt& o = {}) {
  std::vector<L> v;
  for (int i = 0; i < n; ++i) v = v + P(t0 + gap * i, du0 + i, s, o);
  return v;
}

// 엔진 + AN-04 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1). conn_max(창 시작 → 값)를
// 두면 그 창 kpm2에 si.RRC.ConnMax를 싣는다 — 유령 정리로 닫히는 연결(AN04-T7)
class Harness {
 public:
  explicit Harness(ShortRepeatConfig cfg = {}, bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<ShortRepeatRule>(cfg);
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
    std::string extra;
    if (l.proto == "NAS") extra = R"(,"via":"F1","sht":)" + std::to_string(l.sht);
    feed(R"({"type":"ue_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + l.t) + R"(,"cell_id":1,"du_ue_id":)" + std::to_string(l.du) +
         R"(,"crnti":)" + std::to_string(17000 + l.du) + R"(,"dir":")" + l.dir + R"(","proto":")" + l.proto +
         R"(","msg":")" + l.msg + "\"" + extra + (l.f.empty() ? "" : R"(,"f":{)" + l.f + "}") + "}");
  }
  void play(std::vector<L> v) {
    std::stable_sort(v.begin(), v.end(), [](const L& a, const L& b) { return a.t < b.t; });
    for (const L& l : v) line(l);
  }
  void kpm(int64_t t) {
    next_t_ = t + 100;
    auto cm = conn_max.find(t);
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":1,"t_start_ms":)" + std::to_string(kT0 + t) + R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) +
         R"(,"cc":)" + kCc +
         (cm == conn_max.end() ? "" : R"(,"si":{"RRC.ConnMax":)" + std::to_string(cm->second) + "}") +
         R"(,"ue_evt_lost":[]})");
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
  ShortRepeatRule* rule = nullptr;
  std::map<int64_t, int64_t> conn_max;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

const std::vector<std::string> kPaging = {"L3-02-Oa", "L3-34-OV", "L3-12-V"};

}  // namespace

// AN04-T1: 정상 긴 세션(60 s 뒤 해제) × 3 — 길이 > short_ms라 걸림 없음 / CONNECTED에 닿지 못한 반복(AN-07 몫)도 아님
TEST(ShortRepeat, T01LongSessionsOrNotConnected) {
  {
    Harness h;
    POpt longer;
    longer.len = 60000;
    h.play(Pn(3, 1000, 70000, 10, kS, longer));
    h.tick_to(220000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    std::vector<L> v;
    for (int i = 0; i < 3; ++i) {
      std::vector<L> p = P(1000 + 20000 * i, 10 + i, kS);
      p.erase(p.begin() + 2, p.begin() + 5);  // RRCSetupComplete·서비스 요청·수락 없음
      v = v + p;
    }
    h.play(v);
    h.tick_to(50000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN04-T2: P × 3 — 3번째 닫힘(t 42,200)에서 K 3 → K(42,200) = 42,300에 RAISE. 후보는 페이징에 답한 접속 셋. 로그 줄·레코드
TEST(ShortRepeat, T02ThreeShortConnections) {
  Harness h({}, true);
  h.play(Pn(3, 1000, 20000, 10, kS));
  h.tick_to(43000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "AN-04");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_FALSE(e.branch);
  EXPECT_EQ(e.t, kT0 + 42300);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"short_repeat"}));
  EXPECT_EQ(e.candidates, kPaging);
  EXPECT_EQ(e.values.dump(), R"({"short_ues":1,"extra":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"short_ms":5000,"window_ms":300000,"n_short":3,"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.du_ue_id, 12);
  EXPECT_EQ(u.t_hit, kT0 + 42200);
  EXPECT_EQ(u.cond, (std::vector<std::string>{"short_repeat"}));
  EXPECT_EQ(u.values.dump(),
            R"({"short_n":3,"len_ms":1200,"est_cause":"mt-Access","reason":"released","rel_req_cause":null,"src":"48bit"})");
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-04 cell=1 t=" + std::to_string(kT0 + 42300) +
                           " kind=anomaly ue=1/12/3 s_tmsi=0x0123456789ab short_n=3 len_ms=1200 est_cause=mt-Access"
                           " n_short=3 window_ms=300000 severity=medium mode=normal candidates=L3-02-Oa,L3-34-OV,L3-12-V");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"AN-04","stage":4,"unit":"ue","kind":"anomaly","cell":1)"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("evidence":true)"), std::string::npos);  // 닫힌 연결의 recent가 보관돼 있다
}

// AN04-T3: P × 2 / P × 3 중 간격 200 s(창 300 s 밖으로 첫째가 빠짐) — 경보 없음
TEST(ShortRepeat, T03BelowThresholdOrOutsideWindow) {
  {
    Harness h;
    h.play(Pn(2, 1000, 20000, 10, kS));
    h.tick_to(30000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    h.play(Pn(3, 1000, 200000, 10, kS));
    h.tick_to(410000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN04-T4: est_cause mo-Data, 해제가 DU의 UEContextReleaseRequest(rl-failure) 뒤 — 후보 ["L3-33-V"], UE 칸에 rel_req_cause
TEST(ShortRepeat, T04DuReleaseCandidate) {
  Harness h;
  POpt o;
  o.est = "mo-Data";
  o.du_release = true;
  h.play(Pn(3, 1000, 20000, 10, kS, o));
  h.tick_to(43000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].candidates, (std::vector<std::string>{"L3-33-V"}));
  EXPECT_EQ(h.alerts[0].ues[0].values.at("rel_req_cause"), "radioNetwork:rl-failure");
  EXPECT_EQ(h.alerts[0].ues[0].values.at("est_cause"), "mo-Data");
}

// AN04-T5 (11/04 — 반복은 경보 values.extra): P × 4 — RAISE 1번(UE 칸 하나), 4번째는 extra. 다른 S-TMSI가 경보 중에 걸리면 UPDATE에
// 누적값이 실린다
TEST(ShortRepeat, T05RepeatIsExtra) {
  Harness h;
  h.play(Pn(4, 1000, 20000, 10, kS) + Pn(3, 45000, 20000, 20, kS2));
  h.tick_to(87000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  const AlertEvent& u = h.alerts[1];
  EXPECT_EQ(u.kind, AlertEventKind::Update);
  EXPECT_EQ(u.t, kT0 + 86300);
  ASSERT_EQ(u.ues.size(), 1u);
  EXPECT_EQ(u.ues[0].s_tmsi, kS2);
  EXPECT_EQ(u.values.dump(), R"({"short_ues":2,"extra":1,"evicted":0})");
}

// AN04-T6: Part1만 아는 연결(RRCSetupComplete·서비스 요청에 s_tmsi 없음) × 3 — Part1 색인으로 세어 RAISE, src part1, 로그 part1=
TEST(ShortRepeat, T06Part1Only) {
  Harness h;
  POpt o;
  o.full = false;
  h.play(Pn(3, 1000, 20000, 10, kS, o));
  h.tick_to(43000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("src"), "part1");
  EXPECT_FALSE(h.alerts[0].ues[0].s_tmsi);
  EXPECT_NE(h.logs[0].find(" part1=" + hex(kS & kPart1Mask, 10) + " "), std::string::npos);
}

// AN04-T7 (11/04 — 지난 레코드도 판정 이유만 셈): P × 3 중 둘째가 유령 정리(ghost_purge)로 닫힘 — 그 연결은 세지 않아 K 2, 경보 없음.
// 둘째가 CONNECTED인 창 [21,100, 21,200)에 si.RRC.ConnMax 0을 실어 정리한다(문턱 1 × 0 + 0)
TEST(ShortRepeat, T07GhostPurgedNotCounted) {
  UeTableConfig ue_cfg;
  ue_cfg.ghost_k = 1.0;
  ue_cfg.ghost_margin = 0;
  ue_cfg.ghost_hold_ms = 0;
  Harness h({}, false, ue_cfg);
  h.conn_max[21100] = 0;
  POpt no_release;
  no_release.release = false;
  h.play(P(1000, 10, kS) + P(21000, 11, kS, no_release) + P(41000, 12, kS));
  h.tick_to(43000);
  EXPECT_EQ(h.engine.ue_table().counts(1).ghost_purged, 1);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.engine.ue_table().history(kS, 0).size(), 3u);  // 레코드는 셋 다 있다 — 세지 않을 뿐
}

// AN04-T8 해제: 마지막 걸림(42,200) + 60 s 이상인 첫 kpm2(t_end 102,200)에 CLEAR
TEST(ShortRepeat, T08Clear) {
  Harness h;
  h.play(Pn(3, 1000, 20000, 10, kS));
  h.tick_to(102100);
  ASSERT_EQ(h.alerts.size(), 1u);
  h.tick_to(102200);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=AN-04 cell=1 t=" + std::to_string(kT0 + 102200) +
                           " duration_ms=59900 ues_total=1");
}

// 회복 (21_ §6.3-2): 걸린 S-TMSI가 창 W 동안 짧은 연결을 만들지 않으면 회복 — 다시 반복하면 새 UE로 RAISE한다
TEST(ShortRepeat, RecoveredStmsiIsNewAgain) {
  Harness h;
  h.play(Pn(3, 1000, 20000, 10, kS) + Pn(3, 400000, 20000, 20, kS));
  h.tick_to(442000);
  ASSERT_EQ(h.alerts.size(), 3u);  // RAISE, CLEAR, RAISE
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[2].t, kT0 + 441300);
  EXPECT_EQ(h.alerts[2].ues[0].values.at("short_n"), 3);
  EXPECT_EQ(h.alerts[2].values.at("extra"), 0);
}

// 재생 결정성 (AN04-T8) — T2·T5 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(ShortRepeat, Deterministic) {
  auto run = [] {
    Harness h({}, true);
    h.play(Pn(4, 1000, 20000, 10, kS) + Pn(3, 45000, 20000, 20, kS2));
    h.tick_to(90000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 2u);
}

// END: 세션이 바뀌면 END(session_reset)와 기록 비움 — 같은 S-TMSI가 새 세션에서 다시 걸릴 수 있다 / 입력 침묵이면 END(input_silent)
TEST(ShortRepeat, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(Pn(3, 1000, 20000, 10, kS));
    h.tick_to(43000);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
  }
  {
    Harness h;
    h.play(Pn(3, 1000, 20000, 10, kS));
    h.tick_to(43000);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
  }
}

// 증거 지평 (21_ §1.1): 1,000 ms + alert.update_min_ms
TEST(ShortRepeat, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
}

// CLEAR 뒤 다른 S-TMSI (23_ §3.1-2, 이슈 #84): S1 × 3 → RAISE → 60 s 조용 → CLEAR → S2 × 3(150 s부터, 창 W 300 s 안) — 둘째 RAISE는
// CLEAR 뒤 걸림(S2)만 싣는다(ues_total 1). 그전에는 창에 남은 S1 걸림이 다시 실려 ues_total 2였다(재생 데이터 SAN04_AN-04_CLEAR뒤다른STMSI_RAISE)
TEST(ShortRepeat, ClearThenOtherStmsiListsOnlyNew) {
  Harness h;
  h.play(Pn(3, 1000, 20000, 10, kS) + Pn(3, 150000, 20000, 20, kS2));
  h.tick_to(260000);
  ASSERT_EQ(h.alerts.size(), 4u);  // RAISE, CLEAR, RAISE, CLEAR
  EXPECT_EQ(h.alerts[0].t, kT0 + 42300);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 102200);
  const AlertEvent& e = h.alerts[2];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.t, kT0 + 191300);
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].s_tmsi, std::optional<uint64_t>(kS2));
  EXPECT_EQ(e.ues_total, 1);
  EXPECT_EQ(e.values.dump(), R"({"short_ues":1,"extra":0,"evicted":0})");
  EXPECT_NE(h.logs[2].find(" ue=1/22/"), std::string::npos);
  EXPECT_EQ(h.alerts[3].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[3].ues_total, 1);
}

// 지속 공격 — 지금 동작 고정 (Q-69 미결, 23_ §3.1-1): 같은 S-TMSI가 20 s 간격 20회 — 3번째 닫힘에서 RAISE, 4번째부터 경보 values.extra,
// 마지막 걸림 + 60 s에 CLEAR, 그 뒤 17회가 이어져도 경보가 없다(회복 전 반복은 해제 시계를 늘리지 않고 CLEAR 뒤 누적 수는 버려짐 —
// 명세 21_ §6.3-2·§6.5대로). Q-69 결정(W-28) 뒤 기대값을 바꾼다(재생 데이터 SAN04_AN-04_지속공격_CLEAR)
TEST(ShortRepeat, SustainedRepeat_CurrentBehavior) {
  Harness h;
  h.play(Pn(20, 1000, 20000, 10, kS));
  h.tick_to(420000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].t, kT0 + 42300);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 102200);
}
