// 4단계 룰 AN-01 인증 동기 실패 재인증 테스트 — 21_ §3.8 AN01-T1~T12 (T11 설정은 test_config.cpp). 합성 ue_evt·kpm2 줄로 한다
// (같은 시나리오의 재생 데이터는 tests/data/stage4_yellow/ — tools/gen_stage4.py). 시각은 kT0 기준 ms, 연결 시작 t0 = kB(창 시작).
// 기본 흐름 F는 20_ §3.8과 같고, 동기 실패 흐름 S는 F에서 t0+118 AuthenticationResponse 대신 AuthenticationFailure(f.cause 21) →
// t0+160 AuthenticationRequest(재인증) → t0+173 AuthenticationResponse → 그 뒤 F의 NAS SMC부터 55 ms 늦춤(21_ §3.8).
// K(t) = t를 품은 창의 t_end_ms — 걸림이 든 창의 kpm2에서 RAISE한다(21_ §1.1)
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/sync_failure.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace detect;

namespace {

constexpr int64_t kT0 = 1793005200000;
constexpr int64_t kB = 1000;  // 연결 시작 t0 (상대 ms, 창 시작)
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
const std::string kRandom = R"("ue_identity":{"type":"randomValue"})";

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
L f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg) { return L{t, du, dir, "F1AP", msg, "", 0}; }
L auth_fail(int64_t t, int64_t du, const std::string& f = R"("cause":21)") {
  return nas(t, du, "UL", "AuthenticationFailure", f);
}

// F의 보안 모드 이후(NAS SMC t0+125 …) — S는 이것을 55 ms 늦춘다
std::vector<L> after_auth(int64_t t0, int64_t du) {
  return {nas(t0 + 125, du, "DL", "SecurityModeCommand", R"("cipher":"5G-EA0","integrity":"5G-IA2")", 3),
          nas(t0 + 131, du, "UL", "SecurityModeComplete", "", 4),
          rrc(t0 + 140, du, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")"),
          rrc(t0 + 150, du, "UL", "SecurityModeComplete"),
          rrc(t0 + 160, du, "DL", "UECapabilityEnquiry"),
          rrc(t0 + 175, du, "UL", "UECapabilityInformation"),
          nas(t0 + 190, du, "DL", "RegistrationAccept", "", 2),
          nas(t0 + 200, du, "UL", "RegistrationComplete", "", 2)};
}
std::vector<L> head(int64_t t0, int64_t du) {
  return {rrc(t0, du, "UL", "RRCSetupRequest", kRandom), rrc(t0, du, "DL", "RRCSetup"),
          rrc(t0 + 91, du, "UL", "RRCSetupComplete"),
          nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")"),
          nas(t0 + 105, du, "DL", "AuthenticationRequest")};
}
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}
// 기본 흐름 F (20_ §3.8)
std::vector<L> F(int64_t t0, int64_t du) {
  return head(t0, du) + std::vector<L>{nas(t0 + 118, du, "UL", "AuthenticationResponse")} + after_auth(t0, du);
}
// 동기 실패 흐름 S (21_ §3.8). fail_f = 실패 줄의 f
std::vector<L> S(int64_t t0, int64_t du, const std::string& fail_f = R"("cause":21)") {
  return head(t0, du) + std::vector<L>{auth_fail(t0 + 118, du, fail_f), nas(t0 + 160, du, "DL", "AuthenticationRequest"),
                                       nas(t0 + 173, du, "UL", "AuthenticationResponse")} +
         after_auth(t0 + 55, du);
}
std::vector<L> release(int64_t t, int64_t du) {
  return {f1ap(t, du, "DL", "UEContextReleaseCommand"), f1ap(t, du, "UL", "UEContextReleaseComplete")};
}

// 엔진 + AN-01 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1). 창별 ue_evt_lost는 loss
class Harness {
 public:
  explicit Harness(SyncFailureConfig cfg = {}, bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<SyncFailureRule>(cfg);
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
    auto it = loss.find(t);
    const std::string lost = it == loss.end() ? "[]" : it->second;
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":1,"t_start_ms":)" + std::to_string(kT0 + t) + R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) +
         R"(,"cc":)" + kCc + R"(,"ue_evt_lost":)" + lost + "}");
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
  SyncFailureRule* rule = nullptr;
  std::map<int64_t, std::string> loss;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

SyncFailureConfig n_sync(int64_t n) {
  SyncFailureConfig c;
  c.n_sync = n;
  return c;
}

const std::vector<std::string> kCand = {"L3-07-OV"};

}  // namespace

// AN01-T1: F + 해제 — 실패 줄이 없다
TEST(SyncFailure, T01NormalFlow) {
  Harness h;
  h.play(F(kB, 3) + release(kB + 1000, 3));
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN01-T2: S — t0+118 걸림, K = t0+200에 RAISE. 경보 값의 reauth 1은 t0+160 재인증이 RAISE 칸 안이라서다. UE 칸 값은 걸릴 때 값
// (21_ §1.1). 로그 줄·레코드(kind anomaly·stage 4, branch·conditions 없음)
TEST(SyncFailure, T02SyncFailureRaise) {
  Harness h({}, true);
  h.play(S(kB, 3));
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "AN-01");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.unit, "ue");
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.t, kT0 + kB + 200);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_FALSE(e.branch);
  EXPECT_FALSE(e.conditions);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"sync_count"}));
  EXPECT_EQ(e.candidates, kCand);
  EXPECT_EQ(e.values.dump(), R"({"sync_w":1,"sync_total":1,"extra":0,"reauth":1,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"window_ms":60000,"n_sync":1,"clear_quiet_ms":60000})");
  EXPECT_EQ(e.alert_id.rfind("S-AN-01-1-", 0), 0u);
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.cond, (std::vector<std::string>{"sync_failure"}));
  EXPECT_EQ(u.t_hit, kT0 + kB + 118);
  EXPECT_EQ(u.values.dump(), R"({"cause":21,"auth_req_n":1,"id_type":"SUCI","nas_sec":"AUTH"})");
  EXPECT_TRUE(u.uncertain.empty());
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-01 cell=1 t=" + std::to_string(kT0 + kB + 200) +
                           " kind=anomaly sync_w=1 n_sync=1 window_ms=60000 ue=1/3/1 cause=21 severity=medium mode=normal"
                           " candidates=L3-07-OV");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"AN-01","stage":4,"unit":"ue","kind":"anomaly","cell":1)"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("cond":["sync_count"],"candidates":["L3-07-OV"],"values")"), std::string::npos);
}

// AN01-T3: 두 번째 동기 실패 — t0+160 재인증 요청 뒤 t0+173에 다시 실패(21), t0+180 AuthenticationReject. RAISE 1번(연결당 한 번),
// 경보 값 extra 1·reauth 1(둘 다 RAISE 칸 안)
TEST(SyncFailure, T03SecondSyncFailure) {
  Harness h;
  h.play(head(kB, 3) + std::vector<L>{auth_fail(kB + 118, 3), nas(kB + 160, 3, "DL", "AuthenticationRequest"),
                                      auth_fail(kB + 173, 3), nas(kB + 180, 3, "DL", "AuthenticationReject")});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].values.dump(), R"({"sync_w":1,"sync_total":1,"extra":1,"reauth":1,"evicted":0})");
  EXPECT_EQ(h.alerts[0].ues_total, 1);
}

// AN01-T4·T5: MAC 실패(f.cause 20) / 원인값 없음 — 걸림 없음(L3-21 몫, 원인을 모름)
TEST(SyncFailure, T04T05OtherOrNoCause) {
  for (const std::string f : {R"("cause":20)", ""}) {
    Harness h;
    h.play(S(kB, 3, f));
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty()) << f;
  }
}

// AN01-T6: n_sync 2 — UE A S(t0), UE B S(t0+500) → 둘째 걸림 칸 K(t0+618) = t0+700에 RAISE(ues 2, sync_w 2) / UE A만 → 경보 없음
TEST(SyncFailure, T06TwoNeeded) {
  {
    Harness h(n_sync(2));
    h.play(S(kB, 1) + S(kB + 500, 2));
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 700);
    ASSERT_EQ(h.alerts[0].ues.size(), 2u);
    EXPECT_EQ(h.alerts[0].values.at("sync_w"), 2);
    EXPECT_EQ(h.alerts[0].values.at("reauth"), 2);
    EXPECT_EQ(h.logs[0].find("ue=1/2/2 cause=21") != std::string::npos, true);  // 성립을 일으킨 가장 최근 걸림
  }
  {
    Harness h(n_sync(2));
    h.play(S(kB, 1));
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN01-T7: 창 밖 — n_sync 2, UE A S 뒤 61 s에 UE B S → S_W 1, 경보 없음
TEST(SyncFailure, T07OutsideWindow) {
  Harness h(n_sync(2));
  h.play(S(kB, 1) + S(kB + 61000, 2));
  h.tick_to(kB + 62000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN01-T8: 첫 줄이 AuthenticationFailure(21)(mid_join) — 걸림, uncertain mid_join, id_type 모름(null), nas_sec UNKNOWN
TEST(SyncFailure, T08MidJoin) {
  Harness h;
  h.play({auth_fail(kB + 50, 5)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"mid_join"}));
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"cause":21,"auth_req_n":0,"id_type":null,"nas_sec":"UNKNOWN"})");
}

// AN01-T9: 실패 줄이 든 창 ue_evt_lost ["UL","DL"] — 보류 없이 T2와 같은 RAISE, uncertain loss(그 창 kpm2에서 붙은 표시)
TEST(SyncFailure, T09LossStillRaises) {
  Harness h;
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(S(kB, 3));
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"loss"}));
}

// AN01-T10: 해제 — T2 뒤 마지막 걸림(t0+118) + 60 s 이상인 첫 kpm2에 CLEAR / (Q-56) RAISE 뒤 밀어내기 — 마지막 걸림 + 60 s에도
// CLEAR하지 않고 밀어내기를 본 칸 + 60 s에 푼다
TEST(SyncFailure, T10Clear) {
  {
    Harness h;
    h.play(S(kB, 3));
    h.tick_to(kB + 60100);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.tick_to(kB + 60200);  // t_end 61200 − 1118 ≥ 60000
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + kB + 60200);
    EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=AN-01 cell=1 t=" + std::to_string(kT0 + kB + 60200) +
                             " duration_ms=60000 ues_total=1");
    // clear에는 누적값만 — 창 안 수(sync_w)는 없다 (21_ §3.6, 14_ §8.3 — 11/04 Q-69 W-28)
    EXPECT_EQ(h.alerts[1].values.dump(), R"({"sync_total":1,"extra":0,"reauth":1,"evicted":0})");
  }
  {
    UeTableConfig ue_cfg;
    ue_cfg.max_ues = 100;
    Harness h({}, false, ue_cfg);
    h.play(S(kB, 3));
    h.tick_to(30000);
    ASSERT_EQ(h.alerts.size(), 1u);
    std::vector<L> v;
    for (int64_t i = 0; i < 101; ++i) {
      v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupRequest", kRandom));
      v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupComplete"));
    }
    h.play(v);
    h.tick_to(61300);  // 밀어내기가 없었다면 61,200에 CLEAR
    EXPECT_GT(h.engine.ue_table().counts(1).evicted, 0);
    EXPECT_EQ(h.alerts.size(), 1u);
    h.tick_to(90100);  // 밀어내기를 본 칸 30,100 + 60 s
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + 90100);
  }
}

// 두 UE (21_ §3.5): A S(t0) → RAISE, A가 t0+300에 또 동기 실패(경보에 실린 뒤라 바로 extra), B S(t0+500) → 1 s 모음 UPDATE.
// UPDATE 값에 누적 수(extra 1, reauth 2 — B의 t0+660 재인증은 B가 실릴 때 함께), UE 칸은 B만
TEST(SyncFailure, UpdateCarriesCounts) {
  Harness h;
  std::vector<L> a = head(kB, 1) + std::vector<L>{auth_fail(kB + 118, 1), nas(kB + 160, 1, "DL", "AuthenticationRequest"),
                                                  auth_fail(kB + 300, 1)};
  h.play(a + S(kB + 500, 2));
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 2u);
  const AlertEvent& u = h.alerts[1];
  EXPECT_EQ(u.kind, AlertEventKind::Update);
  EXPECT_EQ(u.t, kT0 + kB + 1200);
  EXPECT_EQ(u.ues_total, 2);
  ASSERT_EQ(u.ues.size(), 1u);
  EXPECT_EQ(u.ues[0].du_ue_id, 2);
  EXPECT_EQ(u.values.dump(), R"({"sync_w":2,"sync_total":2,"extra":1,"reauth":2,"evicted":0})");
  EXPECT_TRUE(u.candidates.empty());  // raise에만 (14_ §8.3, 21_ §1)
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=AN-01 cell=1 t=" + std::to_string(kT0 + kB + 1200) +
                           " ues_new=1 ues_total=2 severity=medium");
}

// 같은 창에서 걸린 뒤 닫힘 — 마지막 상태로 판정에 남는다(K에 RAISE), pre 증거는 보관된 recent
TEST(SyncFailure, ClosedBeforeTick) {
  Harness h({}, true);
  h.play(head(kB, 3) + std::vector<L>{auth_fail(kB + 118, 3)} + release(kB + 150, 3));
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[0].values.at("reauth"), 0);
  const std::vector<std::string> recs = h.drain();
  EXPECT_NE(recs[0].find(R"("evidence":true)"), std::string::npos);
}

// AN01-T12: 재생 결정성 — T2·T6 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(SyncFailure, T12Deterministic) {
  auto run = [](int64_t n) {
    Harness h(n_sync(n), true);
    h.play(S(kB, 1) + S(kB + 500, 2));
    h.tick_to(3000);
    return std::make_pair(h.logs, h.drain());
  };
  for (int64_t n : {1, 2}) {
    const auto a = run(n);
    EXPECT_EQ(a, run(n)) << n;
    EXPECT_FALSE(a.first.empty()) << n;
  }
}

// END: 세션이 바뀌면 진행 중 경보 END(session_reset)와 기록 비움 / 입력 침묵이면 END(input_silent)만
TEST(SyncFailure, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(S(kB, 3));
    h.tick_to(1300);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.alerts[1].stage, 4);
  }
  {
    Harness h;
    h.play(S(kB, 3));
    h.tick_to(1300);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
  }
}

// 증거 지평 (21_ §1.1): 3단계와 같이 1,000 ms + alert.update_min_ms — 기본값으로 2,000 ms, 셀 창 W와 무관(11/04 사용자 결정 —
// W를 더하면 늦은 줄 제외 길이가 늘어 2단계 판정이 막힌다). 상태표는 여유 1 s를 더한다
TEST(SyncFailure, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 3000);
  SyncFailureConfig wide;
  wide.window_ms = 600000;
  AlertConfig a;
  a.update_min_ms = 5000;
  EXPECT_EQ(SyncFailureRule(wide, a).evidence_horizon_ms(), 6000);
}

// 연결 키 룰은 그대로 (21_ §1.1 — 11/04 Q-69 (가)는 S-TMSI 키 룰만): 같은 연결의 두 번째 동기 실패(extra)는 해제 시계를 늘리지 않는다 —
// CLEAR는 첫 걸림(t0+118) + 60 s. CLEAR·END(입력 침묵) 레코드 values에 누적값 extra 1·reauth 1
TEST(SyncFailure, ExtraDoesNotDelayClearAndCountsOnClearEnd) {
  std::vector<L> v = head(kB, 3) + std::vector<L>{auth_fail(kB + 118, 3), nas(kB + 160, 3, "DL", "AuthenticationRequest"),
                                                  auth_fail(kB + 30000, 3)};
  {
    Harness h;
    h.play(v);
    h.tick_to(kB + 60100);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.tick_to(kB + 60200);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + kB + 60200);
    EXPECT_EQ(h.alerts[1].values.dump(), R"({"sync_total":1,"extra":1,"reauth":1,"evicted":0})");
  }
  {
    Harness h;
    h.play(v);
    h.tick_to(kB + 31000);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].values.dump(), R"({"sync_total":1,"extra":1,"reauth":1,"evicted":0})");
  }
}
