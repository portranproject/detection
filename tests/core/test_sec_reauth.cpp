// 4단계 룰 AN-06a 보안 수립 뒤 재인증·SMC 재등장 테스트 — 21_ §4.8 AN06a-T1~T10 (T10 설정 범위는 test_config.cpp). 합성 ue_evt·
// kpm2 줄로 한다(같은 시나리오의 재생 데이터는 tests/data/stage4_yellow/SAN06a_* — tools/gen_stage4.py). 시각은 kT0 기준 ms,
// 연결 시작 t0 = kB(창 시작). 기본 흐름 F는 20_ §3.8과 같고(NAS SMC t0+125·완료 t0+131), 재등장 흐름 R은 F가 등록 완료(t0+200)까지
// 간 뒤 t0+1,250 AuthenticationRequest → t0+1,263 응답 → t0+1,270 NAS SMC → t0+1,276 완료(21_ §4.8).
// K(t) = t를 품은 창의 t_end_ms — 걸림이 든 창의 kpm2에서 RAISE한다(21_ §1.1)
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/sec_reauth.h"

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
L auth_req(int64_t t, int64_t du) { return nas(t, du, "DL", "AuthenticationRequest"); }
L smc(int64_t t, int64_t du) { return nas(t, du, "DL", "SecurityModeCommand", kNasAlg, 3); }
L smc_done(int64_t t, int64_t du) { return nas(t, du, "UL", "SecurityModeComplete", "", 4); }

std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}
void drop(std::vector<L>& v, const std::string& proto, const std::string& msg) {
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.proto == proto && l.msg == msg; }), v.end());
}
// 흐름 앞부분 — 연결 시작 → t0+91 등록 요청 → t0+105 인증 요청
std::vector<L> head(int64_t t0, int64_t du) {
  return {rrc(t0, du, "UL", "RRCSetupRequest", kRandom), rrc(t0, du, "DL", "RRCSetup"),
          rrc(t0 + 91, du, "UL", "RRCSetupComplete"),
          nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")"), auth_req(t0 + 105, du)};
}
// 기본 흐름 F (20_ §3.8)
std::vector<L> F(int64_t t0, int64_t du) {
  return head(t0, du) +
         std::vector<L>{nas(t0 + 118, du, "UL", "AuthenticationResponse"), smc(t0 + 125, du), smc_done(t0 + 131, du),
                        rrc(t0 + 140, du, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")"),
                        rrc(t0 + 150, du, "UL", "SecurityModeComplete"), rrc(t0 + 160, du, "DL", "UECapabilityEnquiry"),
                        rrc(t0 + 175, du, "UL", "UECapabilityInformation"),
                        nas(t0 + 190, du, "DL", "RegistrationAccept", "", 2),
                        nas(t0 + 200, du, "UL", "RegistrationComplete", "", 2)};
}
// 재등장 흐름 R (21_ §4.8)
std::vector<L> R(int64_t t0, int64_t du) {
  return F(t0, du) + std::vector<L>{auth_req(t0 + 1250, du), nas(t0 + 1263, du, "UL", "AuthenticationResponse"),
                                    smc(t0 + 1270, du), smc_done(t0 + 1276, du)};
}
std::vector<L> release(int64_t t, int64_t du) {
  return {f1ap(t, du, "DL", "UEContextReleaseCommand"), f1ap(t, du, "UL", "UEContextReleaseComplete")};
}

// 엔진 + AN-06a (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1). 창별 ue_evt_lost는 loss
class Harness {
 public:
  explicit Harness(SecReauthConfig cfg = {}, bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<SecReauthRule>(cfg);
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
  SecReauthRule* rule = nullptr;
  std::map<int64_t, std::string> loss;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

SecReauthConfig n_reauth(int64_t n) {
  SecReauthConfig c;
  c.n_reauth = n;
  return c;
}

}  // namespace

// AN06a-T1: F + 해제 — 보안 뒤 명령이 다시 오지 않는다
TEST(SecReauth, T01NormalFlow) {
  Harness h;
  h.play(F(kB, 3) + release(kB + 1000, 3));
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN06a-T2: R — t0+1,250 걸림(msg AuthenticationRequest), K = t0+1,300에 RAISE. t0+1,270 NAS SMC는 갱신 전 AUTH_OK라 재등장이
// 아니다(extra 0). 로그 줄·레코드(kind anomaly·stage 4)
TEST(SecReauth, T02ReauthAfterSecurity) {
  Harness h({}, true);
  h.play(R(kB, 3));
  h.tick_to(4000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "AN-06a");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.unit, "ue");
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.t, kT0 + kB + 1300);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_FALSE(e.branch);
  EXPECT_FALSE(e.conditions);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"reauth_after_sec"}));
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-06-O1"}));
  EXPECT_EQ(e.values.dump(), R"({"reauth_ues":1,"extra":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"n_reauth":1,"clear_quiet_ms":60000})");
  EXPECT_EQ(e.alert_id.rfind("S-AN-06a-1-", 0), 0u);
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.cond, (std::vector<std::string>{"reauth_after_sec"}));
  EXPECT_EQ(u.t_hit, kT0 + kB + 1250);
  EXPECT_EQ(u.values.dump(), R"({"msg":"AuthenticationRequest","auth_req_n":2,"smc_n":1,"rrc_sec":"ON"})");
  EXPECT_TRUE(u.uncertain.empty());
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-06a cell=1 t=" + std::to_string(kT0 + kB + 1300) +
                           " kind=anomaly ue=1/3/1 msg=AuthenticationRequest n_reauth=1 severity=medium mode=normal"
                           " candidates=L3-06-O1");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"AN-06a","stage":4,"unit":"ue","kind":"anomaly","cell":1)"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("cond":["reauth_after_sec"],"candidates":["L3-06-O1"],"values")"), std::string::npos);
}

// AN06a-T3: 재인증 없이 t0+1,250에 NAS SecurityModeCommand만 다시 옴 — 걸림(msg SecurityModeCommand), RAISE
TEST(SecReauth, T03SmcOnly) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{smc(kB + 1250, 3), smc_done(kB + 1256, 3)});
  h.tick_to(4000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 1300);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(),
            R"({"msg":"SecurityModeCommand","auth_req_n":1,"smc_n":2,"rrc_sec":"ON"})");
  EXPECT_NE(h.logs[0].find(" msg=SecurityModeCommand "), std::string::npos);
}

// AN06a-T4: AMF 재전송 — t0+131 완료를 빼고 t0+6,125에 SMC 재전송(갱신 전 CMD) / t0+118 응답 없이 t0+6,105에 인증 요청 재전송
// (갱신 전 AUTH — 응답이 없으면 AMF는 보안 모드로 넘어가지 않으므로 흐름은 인증 요청에서 멈춘다) → 둘 다 걸림 없음
TEST(SecReauth, T04AmfRetransmission) {
  {
    Harness h;
    std::vector<L> v = F(kB, 3);
    drop(v, "NAS", "SecurityModeComplete");
    h.play(v + std::vector<L>{smc(kB + 6125, 3)});
    h.tick_to(9000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    h.play(head(kB, 3) + std::vector<L>{auth_req(kB + 6105, 3)});
    h.tick_to(9000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN06a-T5: R 뒤 t0+2,250에 또 인증 요청(두 번째 재등장 — t0+1,276 완료로 다시 ON) — RAISE 1번, 경보 값 extra 1. 다음 경보 이벤트
// (UE B가 걸린 UPDATE)에 누적값으로 실린다(21_ §1.1)
TEST(SecReauth, T05SecondReappearanceIsExtra) {
  Harness h;
  h.play(R(kB, 3) + std::vector<L>{auth_req(kB + 2250, 3)} + R(kB + 3000, 4));
  h.tick_to(7000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].values.at("extra"), 0);
  const AlertEvent& u = h.alerts[1];
  EXPECT_EQ(u.kind, AlertEventKind::Update);
  EXPECT_EQ(u.t, kT0 + kB + 4300);  // B 걸림 t0+4,250 → K = t0+4,300 (RAISE t0+1,300 뒤 1 s 넘음)
  ASSERT_EQ(u.ues.size(), 1u);
  EXPECT_EQ(u.ues[0].du_ue_id, 4);
  EXPECT_EQ(u.values.dump(), R"({"reauth_ues":2,"extra":1,"evicted":0})");
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=AN-06a cell=1 t=" + std::to_string(kT0 + kB + 4300) +
                           " ues_new=1 ues_total=2 severity=medium");
}

// AN06a-T6: n_reauth 2 — R만 → 경보 없음 / R + T5(t0+2,250) → 둘째 재등장에서 걸림·K = t0+2,300에 RAISE
TEST(SecReauth, T06TwoNeeded) {
  {
    Harness h(n_reauth(2));
    h.play(R(kB, 3));
    h.tick_to(4000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h(n_reauth(2));
    h.play(R(kB, 3) + std::vector<L>{auth_req(kB + 2250, 3)});
    h.tick_to(4000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 2300);
    EXPECT_EQ(h.alerts[0].ues[0].t_hit, kT0 + kB + 2250);
    EXPECT_EQ(h.alerts[0].ues[0].values.dump(),
              R"({"msg":"AuthenticationRequest","auth_req_n":3,"smc_n":2,"rrc_sec":"ON"})");
    EXPECT_EQ(h.alerts[0].params.at("n_reauth"), 2);
  }
}

// AN06a-T7: 첫 줄이 AuthenticationRequest(mid_join) — nas_sec UNKNOWN(보안이 섰는지 모름)이라 걸림 없음
TEST(SecReauth, T07MidJoin) {
  Harness h;
  h.play({auth_req(kB + 50, 5), nas(kB + 60, 5, "UL", "AuthenticationResponse")});
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN06a-T8: F에서 t0+131 완료 줄을 로스로 놓침(그 창 ue_evt_lost ["UL","DL"]) — nas_sec이 CMD로 남아 R의 재등장을 못 본다(보류 아님)
TEST(SecReauth, T08CompleteLost) {
  Harness h;
  std::vector<L> v = R(kB, 3);
  v.erase(std::find_if(v.begin(), v.end(), [](const L& l) { return l.msg == "SecurityModeComplete" && l.proto == "NAS"; }));
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(v);
  h.tick_to(4000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN06a-T9: 해제 — T2 뒤 마지막 걸림(t0+1,250) + 60 s 이상인 첫 kpm2에 CLEAR(t0+61,300) / (Q-56) RAISE 뒤 밀어내기 — 마지막 걸림
// + 60 s에도 CLEAR하지 않고 밀어내기를 본 칸 + 60 s에 푼다
TEST(SecReauth, T09Clear) {
  {
    Harness h;
    h.play(R(kB, 3));
    h.tick_to(kB + 61200);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.tick_to(kB + 61300);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + kB + 61300);
    EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=AN-06a cell=1 t=" + std::to_string(kT0 + kB + 61300) +
                             " duration_ms=60000 ues_total=1");
  }
  {
    UeTableConfig ue_cfg;
    ue_cfg.max_ues = 100;
    Harness h({}, false, ue_cfg);
    h.play(R(kB, 3));
    h.tick_to(30000);
    ASSERT_EQ(h.alerts.size(), 1u);
    std::vector<L> v;
    for (int64_t i = 0; i < 101; ++i) {
      v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupRequest", kRandom));
      v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupComplete"));
    }
    h.play(v);
    h.tick_to(62400);  // 밀어내기가 없었다면 62,300에 CLEAR
    EXPECT_GT(h.engine.ue_table().counts(1).evicted, 0);
    EXPECT_EQ(h.alerts.size(), 1u);
    h.tick_to(90100);  // 밀어내기를 본 칸 30,100 + 60 s
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + 90100);
  }
}

// AN06a-T10 재생 결정성 — T2·T6 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다 (설정 범위는 test_config.cpp)
TEST(SecReauth, T10Deterministic) {
  auto run = [](int64_t n) {
    Harness h(n_reauth(n), true);
    h.play(R(kB, 1) + std::vector<L>{auth_req(kB + 2250, 1)} + R(kB + 500, 2));
    h.tick_to(4000);
    return std::make_pair(h.logs, h.drain());
  };
  for (int64_t n : {1, 2}) {
    const auto a = run(n);
    EXPECT_EQ(a, run(n)) << n;
    EXPECT_FALSE(a.first.empty()) << n;
  }
}

// END: 세션이 바뀌면 진행 중 경보 END(session_reset) / 입력 침묵이면 END(input_silent)만
TEST(SecReauth, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(R(kB, 3));
    h.tick_to(2400);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.alerts[1].stage, 4);
  }
  {
    Harness h;
    h.play(R(kB, 3));
    h.tick_to(2400);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
  }
}

// 증거 지평 (21_ §1.1): 1,000 ms + alert.update_min_ms — 기본값으로 2,000 ms
TEST(SecReauth, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 3000);
}
