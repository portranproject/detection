// 룰 L3-06 NAS 카운터 비동기화(요청 없는 Security Mode Reject) 테스트 — 20_ §5.8 L06-T1~T20 (T20 설정은 test_config.cpp).
// 합성 ue_evt·kpm2 줄로 한다(같은 시나리오의 재생 데이터는 tests/data/stage3_lightgreen/S06_* — tools/gen_stage3.py).
// 시각은 kT0 기준 ms, 연결 시작 t0 = kB(창 시작). 기본 흐름 F는 20_ §3.8 그대로 — NAS SecurityModeCommand t0+125·Complete t0+131,
// RRC SecurityModeCommand t0+140·Complete t0+150. 공격 줄 J1 = t0+98(보안 전 주입), J2 = t0+135(정상 명령·완료 뒤 주입) (20_ §5.8).
// K(t) = t를 품은 창의 t_end_ms — '요청 없는 응답'의 판정·RAISE 시각이다(20_ §1.2-3). 틀은 test_imsi_extractor.cpp와 같다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/nas_desync.h"

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
const std::string kNasAlg = R"("cipher":"5G-EA0","integrity":"5G-IA2")";

// ue_evt 한 줄 (2_ §6.2)
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
// 후보가 되는 줄 — NAS SecurityModeReject(UL). 원인값은 판정에 쓰지 않는다(20_ §5.2)
L reject(int64_t t, int64_t du) { return nas(t, du, "UL", "SecurityModeReject", R"("cause":24)"); }
L smc(int64_t t, int64_t du) { return nas(t, du, "DL", "SecurityModeCommand", kNasAlg, 3); }

// 기본 흐름 F (20_ §3.8)
std::vector<L> F(int64_t t0, int64_t du, const std::string& integrity = "nia2") {
  std::vector<L> v;
  v.push_back(rrc(t0, du, "UL", "RRCSetupRequest", kRandom));
  v.push_back(rrc(t0, du, "DL", "RRCSetup"));
  v.push_back(rrc(t0 + 91, du, "UL", "RRCSetupComplete"));
  v.push_back(nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")"));
  v.push_back(nas(t0 + 105, du, "DL", "AuthenticationRequest"));
  v.push_back(nas(t0 + 118, du, "UL", "AuthenticationResponse"));
  v.push_back(smc(t0 + 125, du));
  v.push_back(nas(t0 + 131, du, "UL", "SecurityModeComplete", "", 4));
  v.push_back(rrc(t0 + 140, du, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":")" + integrity + "\""));
  v.push_back(rrc(t0 + 150, du, "UL", "SecurityModeComplete"));
  v.push_back(rrc(t0 + 160, du, "DL", "UECapabilityEnquiry"));
  v.push_back(rrc(t0 + 175, du, "UL", "UECapabilityInformation"));
  v.push_back(nas(t0 + 190, du, "DL", "RegistrationAccept", "", 2));
  v.push_back(nas(t0 + 200, du, "UL", "RegistrationComplete", "", 2));
  return v;
}
// 흐름 앞부분만 — RRC 보안 전에 머무는 연결 (t0 RRCSetupRequest·RRCSetup → t0+91 RRCSetupComplete·RegistrationRequest)
std::vector<L> head(int64_t t0, int64_t du) {
  std::vector<L> v = F(t0, du);
  v.resize(4);
  return v;
}
// 인증까지 (head + t0+105 인증 요청 + t0+118 응답) — 보안 모드 명령 앞
std::vector<L> to_auth(int64_t t0, int64_t du) {
  std::vector<L> v = F(t0, du);
  v.resize(6);
  return v;
}
std::vector<L> release(int64_t t, int64_t du) {
  return {f1ap(t, du, "DL", "UEContextReleaseCommand"), f1ap(t, du, "UL", "UEContextReleaseComplete")};
}
void drop(std::vector<L>& v, const std::string& proto, const std::string& msg) {
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.proto == proto && l.msg == msg; }), v.end());
}
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

// 엔진 + L3-06 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다 — 같은 창의 ue_evt는 그 창
// kpm2보다 먼저 온다(2_ §6.1). 창별 ue_evt_lost는 loss(창 시작 → 값), 없으면 default_lost
class Harness {
 public:
  explicit Harness(bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<NasDesyncRule>();
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
  // 줄들을 시각 순으로(sorted = false면 넣은 순서 그대로 — 순서 위반 시험) 넣는다
  void play(std::vector<L> v, bool sorted = true) {
    if (sorted) std::stable_sort(v.begin(), v.end(), [](const L& a, const L& b) { return a.t < b.t; });
    for (const L& l : v) line(l);
  }
  void kpm(int64_t t) {
    next_t_ = t + 100;
    auto it = loss.find(t);
    const std::string& lost = it == loss.end() ? default_lost : it->second;
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":1,"t_start_ms":)" + std::to_string(kT0 + t) + R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) +
         R"(,"cc":)" + kCc + R"(,"ue_evt_lost":)" + lost + "}");
  }
  void advance(int64_t t) {
    while (next_t_ + 100 <= t) kpm(next_t_);
  }
  // 창 시작 < t인 kpm2를 모두 낸다 — 셀 시계가 t가 된다
  void tick_to(int64_t t) {
    while (next_t_ < t) kpm(next_t_);
  }

  void feed(const std::string& line) {
    EngineOutput out = engine.feed_line(line);
    for (const auto& a : out.alerts) {
      alerts.push_back(a);
      logs.push_back(format_log_line(a));
    }
    for (const auto& d : out.diags) diags.push_back(d.kind);
    if (record_) rec.on_feed(engine.series(), engine.ue_table(), out);
  }
  std::vector<std::string> drain() {
    queue.close();
    std::vector<std::string> v;
    EvidenceRecord r;
    while (queue.pop(r)) v.push_back(r.line);
    return v;
  }
  const LookbackMarks::Mark* mark(int64_t du, int64_t uid) const {
    return rule->marks().find(UeKey{1, du}, uid, "unsolicited");
  }
  bool has_diag(DiagKind k) const { return std::find(diags.begin(), diags.end(), k) != diags.end(); }

  Engine engine;
  EvidenceQueue queue;
  EvidenceRecorder rec;
  NasDesyncRule* rule = nullptr;
  std::map<int64_t, std::string> loss;
  std::string default_lost = "[]";
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;
  std::vector<DiagKind> diags;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

const std::vector<std::string> kCond = {"unsolicited"};
const std::vector<std::string> kPremise = {"mitm_ul_relay"};

int count_phase(const std::vector<std::string>& recs, const std::string& phase, const std::string& needle = "") {
  return static_cast<int>(std::count_if(recs.begin(), recs.end(), [&](const std::string& r) {
    return r.find(R"("type":"evidence")") != std::string::npos &&
           r.find(R"("phase":")" + phase + "\"") != std::string::npos &&
           (needle.empty() || r.find(needle) != std::string::npos);
  }));
}

}  // namespace

// L06-T1: F + 해제 — 정상 명령 → Complete, Reject가 없다
TEST(NasDesync, T01NormalFlow) {
  Harness h;
  h.play(F(kB, 3) + release(kB + 1000, 3));
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L06-T2: 정상 거부 — t0+131 Complete 대신 UE가 망의 명령을 거부(Reject), 그 뒤 AMF 거절·해제. Reject 때 R = 1, A = 0 → 후보 없음
TEST(NasDesync, T02NormalReject) {
  Harness h;
  h.play(to_auth(kB, 3) + std::vector<L>{smc(kB + 125, 3), reject(kB + 131, 3),
                                         nas(kB + 140, 3, "DL", "RegistrationReject", R"("cause":23)")} +
         release(kB + 150, 3));
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L06-T3: AMF 재전송(T3560) — 명령 t0+125·t0+6,125에 Reject 한 번(t0+6,131 — R 2·A 0) / 명령마다 Reject(t0+131·t0+6,131 —
// 둘째 Reject 때 R 2·A 1). 둘 다 후보 없음
TEST(NasDesync, T03AmfRetransmission) {
  for (bool each : {false, true}) {
    Harness h;
    std::vector<L> v = to_auth(kB, 3) + std::vector<L>{smc(kB + 125, 3), smc(kB + 6125, 3), reject(kB + 6131, 3)};
    if (each) v.push_back(reject(kB + 131, 3));
    h.play(v + release(kB + 6200, 3));
    h.tick_to(8000);
    EXPECT_TRUE(h.alerts.empty()) << each;
    EXPECT_EQ(h.rule->marks().size(), 0u) << each;
  }
}

// L06-T4: F에 J1(t0+98, 보안 전 주입) — K = t0+100에 RAISE. 값·로그 줄·레코드·pre 증거(연결 시작부터 Reject까지)
TEST(NasDesync, T04InjectedBeforeSecurity) {
  Harness h(true);
  h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-06");
  EXPECT_EQ(e.stage, 3);
  EXPECT_EQ(e.unit, "ue");
  EXPECT_EQ(e.alert_kind, "attack");
  EXPECT_EQ(e.t, kT0 + kB + 100);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_FALSE(e.branch);
  EXPECT_EQ(e.cond, kCond);
  EXPECT_TRUE(e.candidates.empty());  // 같은 모양을 만드는 다른 공격이 목록에 없다 (20_ §5.1)
  ASSERT_TRUE(e.conditions);
  EXPECT_EQ(*e.conditions, kPremise);
  EXPECT_EQ(e.values.dump(), R"({"extra":0,"held":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"clear_quiet_ms":60000})");
  EXPECT_EQ(e.alert_id.rfind("S-L3-06-1-", 0), 0u);
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.du_ue_id, 3);
  EXPECT_EQ(u.cond, kCond);
  EXPECT_EQ(u.t_hit, kT0 + kB + 98);
  EXPECT_EQ(u.values.dump(), R"({"req":0,"resp":1,"rej":1,"rrc_sec":"OFF","nas_sec":"NONE"})");
  EXPECT_TRUE(u.uncertain.empty());
  EXPECT_FALSE(u.conditions);  // UE 칸에는 싣지 않는다 (20_ §5.6)
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-06 cell=1 t=" + std::to_string(kT0 + kB + 100) +
                           " ue=1/3/1 req=0 resp=1 rej=1 rrc_sec=OFF nas_sec=NONE severity=medium mode=normal "
                           "conditions=mitm_ul_relay candidates=");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"L3-06","stage":3,"unit":"ue","kind":"attack")"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("candidates":[],"conditions":["mitm_ul_relay"],"values")"), std::string::npos);
  EXPECT_EQ(count_phase(recs, "pre"), 5);  // RRCSetupRequest·RRCSetup·RRCSetupComplete·RegistrationRequest·Reject
}

// L06-T5: F에 J2(t0+135, 정상 명령·완료 뒤 주입) — R 1·A 1(Complete를 응답으로 셈) → K = t0+200에 RAISE, nas_sec ON (20_ §5.3)
TEST(NasDesync, T05InjectedAfterNormalComplete) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{reject(kB + 135, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[0].ues[0].t_hit, kT0 + kB + 135);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"req":1,"resp":2,"rej":1,"rrc_sec":"OFF","nas_sec":"ON"})");
}

// L06-T6: AS 무결성 뒤(t0+220) Reject — 후보 없음 / RRC 보안이 nia0이면 연결 내내 판정 → K = t0+300에 RAISE(rrc_sec ON) /
// RRC 보안 모드 명령 뒤·완료 전(t0+145, CMD) → K = t0+200에 RAISE
TEST(NasDesync, T06AsIntegrity) {
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{reject(kB + 220, 3)});
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
    EXPECT_EQ(h.rule->marks().size(), 0u);
  }
  {
    Harness h;
    h.play(F(kB, 3, "nia0") + std::vector<L>{reject(kB + 220, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 300);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("rrc_sec"), "ON");
  }
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{reject(kB + 145, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("rrc_sec"), "CMD");
  }
}

// L06-T7: T4 + 같은 연결 t0+135(J1 뒤 J2 — R 1·A 2)·t0+250(AS 무결성 뒤)에 Reject — RAISE 1번, 결정된 표시의 extra 1(뒤 것은
// 세지 않음), UPDATE는 나지 않는다(§5.3-4). 다음 update가 나면 values.extra 1로 실린다. 두 줄은 active 증거
TEST(NasDesync, T07ExtraOnHitConnection) {
  Harness h(true);
  h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3), reject(kB + 135, 3), reject(kB + 250, 3)});
  h.tick_to(1900);
  ASSERT_EQ(h.alerts.size(), 1u);
  const LookbackMarks::Mark* m = h.mark(3, 1);
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->phase, LookbackMarks::Phase::Hit);
  EXPECT_EQ(m->extra, 1);
  // 다른 UE가 걸려 UPDATE가 나면 누적 extra가 실린다
  h.play(F(2000, 4) + std::vector<L>{reject(2098, 4)});
  h.tick_to(2200);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].values.dump(), R"({"extra":1,"held":0,"evicted":0})");
  EXPECT_FALSE(h.alerts[1].conditions);  // 바뀌지 않으므로 update에는 싣지 않는다
  EXPECT_EQ(count_phase(h.drain(), "active", "SecurityModeReject"), 2);
}

// L06-T8: 같은 창 t0+60·t0+98에 Reject 둘(첫 표시가 대기 중) — K = t0+100에 RAISE 1번, values.extra 1
TEST(NasDesync, T08TwoInSameWindow) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{reject(kB + 60, 3), reject(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  EXPECT_EQ(h.alerts[0].values.at("extra"), 1);
  EXPECT_EQ(h.alerts[0].ues[0].t_hit, kT0 + kB + 60);
}

// L06-T9: 명령 줄 로스 — T2에서 SecurityModeCommand 줄(t0+125)을 빼고 그 창 [t0+100, t0+200)이 양방향 로스. Reject(t0+131)가
// R 0·A 0으로 후보 → 연결 시작 뒤 DL 로스로 보류 → K = t0+200에 불확실 경보(kind anomaly) RAISE. 60 s 조용하면 CLEAR
TEST(NasDesync, T09CommandLostHeld) {
  Harness h;
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(to_auth(kB, 3) + std::vector<L>{reject(kB + 131, 3),
                                         nas(kB + 140, 3, "DL", "RegistrationReject", R"("cause":23)")} +
         release(kB + 150, 3));
  h.tick_to(1200);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.stage, 3);
  EXPECT_EQ(e.t, kT0 + kB + 200);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"held_count"}));
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-06"}));
  EXPECT_FALSE(e.conditions);  // 불확실 경보에는 싣지 않는다 (20_ §5.7)
  EXPECT_EQ(e.values.dump(), R"({"held_w":1})");
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"held"}));
  EXPECT_EQ(e.ues[0].t_hit, kT0 + kB + 132);  // 마감
  EXPECT_EQ(e.ues[0].uncertain, (std::vector<std::string>{"loss"}));
  EXPECT_EQ(e.ues[0].values.dump(), R"({"wait_ms":131,"dir":"DL"})");  // t_r − t_s
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-06 cell=1 t=" + std::to_string(kT0 + kB + 200) +
                           " kind=anomaly held_w=1 severity=medium mode=normal candidates=L3-06");
  h.tick_to(61100);
  EXPECT_EQ(h.alerts.size(), 1u);
  h.tick_to(61200);  // 마지막 보류 1132 + 60 s
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
}

// L06-T10: T4에서 로스 창이 연결 시작 전 [t0−100, t0) → loss_end[DL] = t0 ≤ t_s → RAISE / T5에서 로스 창 [t0, t0+100) → 보류
TEST(NasDesync, T10LossBeforeAndAfterStart) {
  {
    Harness h;
    h.loss[kB - 100] = R"(["UL","DL"])";
    h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].alert_kind, "attack");
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  }
  {
    Harness h;
    h.loss[kB] = R"(["UL","DL"])";
    h.play(F(kB, 3) + std::vector<L>{reject(kB + 135, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"wait_ms":135,"dir":"DL"})");
  }
}

// L06-T11: T4에서 Reject 창이 UL만 로스 — DL 로스가 아니라 T4와 같은 RAISE. 항목의 loss 표시는 ues[].uncertain에 남는다
TEST(NasDesync, T11UlOnlyLoss) {
  Harness h;
  h.loss[kB] = R"(["UL"])";
  h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].alert_kind, "attack");
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"loss"}));
}

// L06-T12: 창 경계 — t_r = t0+100(앞 창의 t_end와 같음). t0+100 kpm2에서는 꺼내지 않고 K = t0+200에서
TEST(NasDesync, T12WindowBoundary) {
  Harness h;
  h.play(head(kB, 3) + std::vector<L>{reject(kB + 100, 3)});
  h.tick_to(kB + 100);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(kB + 200);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
}

// L06-T13: T4 + 같은 창 t0+99 해제(released) — 마감 때 복사본으로 판정해 K = t0+100에 RAISE. pre 증거는 보관된 recent
TEST(NasDesync, T13ClosedBeforeDeadline) {
  Harness h(true);
  h.play(head(kB, 3) + std::vector<L>{reject(kB + 98, 3)} + release(kB + 99, 3));
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"req":0,"resp":1,"rej":1,"rrc_sec":"OFF","nas_sec":"NONE"})");
  EXPECT_EQ(h.rule->marks().size(), 0u);  // 닫힌 항목 — 판정 뒤 지움
  const std::vector<std::string> recs = h.drain();
  EXPECT_EQ(count_phase(recs, "pre"), 7);  // 해제 두 줄까지
}

// L06-T14: 첫 줄이 SecurityModeReject(mid_join) — 연결 앞부분을 못 봐 후보 없음
TEST(NasDesync, T14MidJoin) {
  Harness h;
  h.play({reject(kB + 50, 5), rrc(kB + 60, 5, "UL", "MeasurementReport")});
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L06-T15: 늦은 줄 — J1 줄(t_ms t0+98)이 t0+100 kpm2 뒤에 도착. late_until ≥ 마감 → 판정 없음, 표시도 지움
TEST(NasDesync, T15LateLine) {
  Harness h;
  h.play(head(kB, 3));
  h.tick_to(kB + 100);
  h.line(reject(kB + 98, 3));
  EXPECT_TRUE(h.has_diag(DiagKind::UeLate));
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L06-T16: 해제 — T4 뒤 마지막 걸림(t_r = t0+98) + 60 s 이상인 첫 kpm2에 CLEAR / 같은 연결 t0+30,000의 extra(RRC 보안 전에 머문
// 연결)는 해제를 늦추지 않는다
TEST(NasDesync, T16Clear) {
  for (bool extra : {false, true}) {
    Harness h;
    std::vector<L> v = extra ? head(kB, 3) : F(kB, 3);
    v.push_back(reject(kB + 98, 3));
    if (extra) v.push_back(reject(kB + 30000, 3));
    h.play(v);
    h.tick_to(kB + 60000);
    ASSERT_EQ(h.alerts.size(), 1u) << extra;
    h.tick_to(kB + 60100);  // t_end 61100 − 1098 ≥ 60000
    ASSERT_EQ(h.alerts.size(), 2u) << extra;
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + kB + 60100);
    EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=L3-06 cell=1 t=" + std::to_string(kT0 + kB + 60100) +
                             " duration_ms=60000 ues_total=1");
    if (extra) {
      EXPECT_EQ(h.mark(3, 1)->extra, 1);
    }
  }
}

// L06-T17: 두 UE — A는 T4, B는 t0+500에 J1. RAISE + UPDATE(update_min_ms 1 s 모음), ues_total 2, 심각도 그대로
TEST(NasDesync, T17TwoUesUpdate) {
  Harness h;
  h.play(F(kB, 1) + std::vector<L>{reject(kB + 98, 1)} + F(kB + 500, 2) + std::vector<L>{reject(kB + 598, 2)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  const AlertEvent& u = h.alerts[1];
  EXPECT_EQ(u.kind, AlertEventKind::Update);
  EXPECT_EQ(u.t, kT0 + kB + 1100);
  EXPECT_EQ(u.severity, Severity::Medium);
  EXPECT_EQ(u.ues_total, 2);
  ASSERT_EQ(u.ues.size(), 1u);
  EXPECT_EQ(u.ues[0].du_ue_id, 2);
  EXPECT_EQ(u.ues[0].t_hit, kT0 + kB + 598);
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-06 cell=1 t=" + std::to_string(kT0 + kB + 1100) +
                           " ues_new=1 ues_total=2 severity=medium");
}

// L06-T18 (Q-56): T4 RAISE 뒤 그 셀에 상태표 밀어내기 — 마지막 걸림 + 60 s에도 CLEAR하지 않고, 직전 60 s 밀어내기가 0건인 칸에서
// 푼다. 상한 100, 정상 연결 101대로 밀어내기 2회(다음 kpm2 t_end 30,100에서 셈) — L24-T23과 같은 모양
TEST(NasDesync, T18EvictionHoldsClear) {
  UeTableConfig ue_cfg;
  ue_cfg.max_ues = 100;
  Harness h(false, ue_cfg);
  h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3)});
  h.tick_to(30000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].values.at("evicted"), 0);
  std::vector<L> v;
  for (int64_t i = 0; i < 101; ++i) {
    v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupRequest", kRandom));
    v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupComplete"));
  }
  h.play(v);
  h.tick_to(61200);  // 밀어내기가 없었다면 61,100에 CLEAR
  EXPECT_EQ(h.engine.ue_table().counts(1).evicted, 2);
  EXPECT_EQ(h.alerts.size(), 1u);
  h.tick_to(90100);  // 밀어내기 30,100 + 60 s
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 90100);
}

// L06-T19: 전제 위반(20_ §5.7) — 명령 줄이 Complete 줄 뒤에 옴(같은 창, 보안 전) + 그 뒤 주입 Reject 없음 → 경보 없음(Complete는
// 후보 줄이 아니라 집합의 횟수에만 든다) / Reject 줄이 두 번 옴(정상 거부 뒤 같은 줄 중복 — R 1·A 1) → RAISE. 오탐을 기록해 두는 시험
TEST(NasDesync, T19PremiseViolations) {
  {
    Harness h;
    std::vector<L> v = to_auth(kB, 3);
    v.push_back(nas(kB + 131, 3, "UL", "SecurityModeComplete", "", 4));
    v.push_back(smc(kB + 125, 3));
    h.play(v, false);
    const std::vector<L> f = F(kB, 3);
    h.play(std::vector<L>(f.begin() + 8, f.end()));  // RRC 보안 모드부터 나머지
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
    EXPECT_EQ(h.rule->marks().size(), 0u);
  }
  {
    Harness h;
    h.play(to_auth(kB, 3) + std::vector<L>{smc(kB + 125, 3), reject(kB + 131, 3), reject(kB + 131, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.dump(),
              R"({"req":1,"resp":2,"rej":2,"rrc_sec":"OFF","nas_sec":"REJECTED"})");
  }
}

// L06-T20 재생 결정성 — T4·T5·T9 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다 (설정 범위는 test_config.cpp)
TEST(NasDesync, T20Deterministic) {
  auto run = [] {
    Harness h(true);
    h.loss[kB + 100] = R"(["UL","DL"])";
    h.play(to_auth(kB, 1) + std::vector<L>{reject(kB + 131, 1)} + F(2000, 2) + std::vector<L>{reject(2098, 2)} +
           F(2500, 3) + std::vector<L>{reject(2635, 3)});
    h.tick_to(4000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 4u);  // 불확실 RAISE, 불확실 CLEAR + 공격 RAISE, UPDATE
  EXPECT_GT(a.second.size(), 4u);
}

// 불확실 경보가 열린 셀에서 공격이 걸리면 같은 줄에서 불확실 CLEAR 다음 공격 RAISE(14_ §8.2). 공격 RAISE의 held는 직전 60 s 보류 수
TEST(NasDesync, HeldThenAttack) {
  Harness h;
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(to_auth(kB, 1) + std::vector<L>{reject(kB + 131, 1)} + F(2000, 2) + std::vector<L>{reject(2098, 2)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
  EXPECT_EQ(h.alerts[1].t, kT0 + 2100);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[2].alert_kind, "attack");
  EXPECT_EQ(h.alerts[2].values.at("held"), 1);
}

// DL 미관측 — 모든 kpm2 ue_evt_lost ["DL"], DL 줄 없음. 정상 거부(T2)의 Reject가 R 0으로 후보가 되나 로스로 보류 → 불확실 경보만
// (20_ §5.7 표). 5 s 뒤 진단 dl_unobserved
TEST(NasDesync, DlUnobserved) {
  Harness h;
  h.default_lost = R"(["DL"])";
  std::vector<L> v = to_auth(kB, 3) + std::vector<L>{smc(kB + 125, 3), reject(kB + 131, 3)};
  v.erase(std::remove_if(v.begin(), v.end(), [](const L& l) { return l.dir == "DL"; }), v.end());
  h.play(v);
  h.tick_to(7000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_TRUE(h.has_diag(DiagKind::DlUnobserved));
}

// NAS 암호(20_ §5.7 표) — NAS 보안 뒤 Complete가 ProtectedNAS로 오면 A에 세지 않아, 그 뒤 주입의 Reject는 R 1·A 0으로 놓친다.
// 보안 전 주입(R 0)은 판정된다
TEST(NasDesync, ProtectedNasComplete) {
  {
    Harness h;
    std::vector<L> v = F(kB, 3);
    drop(v, "NAS", "SecurityModeComplete");
    v.push_back(nas(kB + 131, 3, "UL", "ProtectedNAS", "", 4));
    h.play(v + std::vector<L>{reject(kB + 135, 3)});
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    std::vector<L> v = F(kB, 3);
    drop(v, "NAS", "SecurityModeComplete");
    v.push_back(nas(kB + 131, 3, "UL", "ProtectedNAS", "", 4));
    h.play(v + std::vector<L>{reject(kB + 98, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
  }
}

// END: 세션이 바뀌면 진행 중 경보 END(session_reset)와 표시 비움 / 입력 침묵이면 END(input_silent)만 — 표시는 그대로
TEST(NasDesync, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3)});
    h.tick_to(1200);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.alerts[1].stage, 3);
    EXPECT_EQ(h.rule->marks().size(), 0u);
  }
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{reject(kB + 98, 3)});
    h.tick_to(1200);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
    EXPECT_EQ(o.alerts[0].t, kT0 + 1200);
    EXPECT_EQ(h.rule->marks().size(), 1u);
  }
}

// 증거 지평 (20_ §5.4·§1.2-6): 1,000 ms + alert.update_min_ms — 기본값으로 2,000 ms. 상태표는 여유 1 s를 더해 recent를 보관한다
TEST(NasDesync, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 3000);
  AlertConfig a;
  a.update_min_ms = 5000;
  EXPECT_EQ(NasDesyncRule({}, a).evidence_horizon_ms(), 6000);
}
