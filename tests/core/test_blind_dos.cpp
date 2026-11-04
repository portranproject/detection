// 룰 L3-20 Blind DoS 테스트 — 15_ §2.8 L20-T1~T27. 합성 ue_evt·kpm2 줄로 한다(데이터 파일은 설정 키·데이터 이슈).
// 시각은 kT0 기준 ms. RAISE는 t₀ + accept_wait_ms 이상인 첫 kpm2에서 나온다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/blind_dos.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace detect;

namespace {

constexpr int64_t kT0 = 1793005200000;
constexpr uint64_t kS = 0x0123456789ab;   // 피해자 A의 5G-S-TMSI
constexpr uint64_t kS2 = 0x00000fedcba9;  // 피해자 B
constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
const std::string kCcDlMissing =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":null})";
const std::string kRandom = R"("ue_identity":{"type":"randomValue"})";
const std::string kSmc = R"("cipher":"nea0","integrity":"nia2")";

std::string hex(uint64_t v, int digits) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%0*llx", digits, static_cast<unsigned long long>(v));
  return buf;
}
std::string stmsi(uint64_t v) { return R"("s_tmsi":")" + hex(v, 12) + "\""; }
std::string part1(uint64_t v) {
  return R"("ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" + hex(v & kPart1Mask, 10) + R"("})";
}

// 엔진 + L3-20 (+ 증거 기록기). 시각은 kT0 기준 ms
class Harness {
 public:
  explicit Harness(SeriesConfig scfg = {}, bool record = false, UeTableConfig ue_cfg = {})
      : engine(scfg, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue), record_(record) {
    auto r = std::make_unique<BlindDosRule>();
    rule = r.get();
    engine.add_ue_rule(std::move(r));
    hello("S");
  }

  void hello(const std::string& session) {
    if (session != session_) {
      session_ = session;
      seq_ = 0;
      next_t_.clear();
    }
    feed(R"({"type":"hello","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cells":[{"cell_id":1,"max_conn":null},{"cell_id":2,"max_conn":null}],"period_ms":100,)"
         R"("noreply_timeout_ms":1000,"clock":"realtime","ue_evt":true})");
  }
  void ue(int64_t t, int64_t du, const std::string& dir, const std::string& proto, const std::string& msg,
          const std::string& f, const std::string& extra, int64_t cell) {
    feed(R"({"type":"ue_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + t) + R"(,"cell_id":)" + std::to_string(cell) + R"(,"du_ue_id":)" +
         std::to_string(du) + R"(,"crnti":)" + std::to_string(17000 + du) + R"(,"dir":")" + dir + R"(","proto":")" +
         proto + R"(","msg":")" + msg + "\"" + extra + (f.empty() ? "" : R"(,"f":{)" + f + "}") + "}");
  }
  void rrc(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "",
           int64_t cell = 1) {
    ue(t, du, dir, "RRC", msg, f, "", cell);
  }
  void nas(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "",
           int sht = 0, int64_t cell = 1) {
    ue(t, du, dir, "NAS", msg, f, R"(,"via":"F1","sht":)" + std::to_string(sht), cell);
  }
  void f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg, int64_t cell = 1) {
    ue(t, du, dir, "F1AP", msg, "", "", cell);
  }
  void f1(int64_t t, const std::string& cells) {
    feed(R"({"type":"f1_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + t) + R"(,"msg":"F1SetupRequest","cells":)" + cells + "}");
  }
  void kpm(int64_t t, const std::string& lost = "[]", int64_t cell = 1) {
    next_t_[cell] = t + 100;
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":)" + std::to_string(cell) + R"(,"t_start_ms":)" + std::to_string(kT0 + t) +
         R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) + (cc.empty() ? "" : R"(,"cc":)" + cc) +
         (lost.empty() ? "" : R"(,"ue_evt_lost":)" + lost) + "}");
  }
  void tick_to(int64_t t, int64_t cell = 1) {
    while (next_t_[cell] < t) kpm(next_t_[cell], "[]", cell);
  }

  // 정상 UE가 자기 S-TMSI로 붙어 망 수락을 받음 — 공격의 피해자(짝)가 된다
  void victim(int64_t du, uint64_t s, int64_t t, int64_t cell = 1) {
    rrc(t, du, "UL", "RRCSetupRequest", part1(s), cell);
    rrc(t, du, "DL", "RRCSetup", "", cell);
    rrc(t + 50, du, "UL", "RRCSetupComplete", stmsi(s), cell);
    nas(t + 50, du, "UL", "ServiceRequest", stmsi(s), 1, cell);
    nas(t + 80, du, "DL", "ServiceAccept", "", 2, cell);
  }
  // 피해자 S-TMSI로 연 공격 연결 — t₀ = t + 50(RRCSetupComplete), 인증 요청에 응답하지 않는다
  void attack(int64_t du, uint64_t s, int64_t t, int64_t cell = 1) {
    rrc(t, du, "UL", "RRCSetupRequest", part1(s), cell);
    rrc(t, du, "DL", "RRCSetup", "", cell);
    rrc(t + 50, du, "UL", "RRCSetupComplete", stmsi(s), cell);
    nas(t + 50, du, "UL", "ServiceRequest", stmsi(s), 1, cell);
    nas(t + 60, du, "DL", "AuthenticationRequest", "", 0, cell);
  }
  void release(int64_t t, int64_t du, int64_t cell = 1) {
    f1ap(t, du, "DL", "UEContextReleaseCommand", cell);
    f1ap(t, du, "UL", "UEContextReleaseComplete", cell);
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
  BlindDosRule* rule = nullptr;
  std::string cc = kCc;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  std::map<int64_t, int64_t> next_t_;
};

const std::vector<std::string> kCondConcurrent = {"same_stmsi", "concurrent", "not_accepted"};
const std::vector<std::string> kCondUncertain = {"same_stmsi", "peer_uncertain", "not_accepted"};

}  // namespace

// L20-T1: 정상 첫 등록(randomValue, SUCI) + 해제 — 대기 없음, 경보 없음
TEST(BlindDos, T01NormalFirstRegistration) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest", kRandom);
  h.rrc(0, 3, "DL", "RRCSetup");
  h.rrc(50, 3, "UL", "RRCSetupComplete");
  h.nas(50, 3, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")");
  h.nas(60, 3, "DL", "AuthenticationRequest");
  h.nas(70, 3, "UL", "AuthenticationResponse");
  h.rrc(90, 3, "DL", "SecurityModeCommand", kSmc);
  h.nas(100, 3, "DL", "RegistrationAccept", stmsi(kS), 2);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.release(1000, 3);
  h.tick_to(10000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T2: 해제 3분 뒤 같은 S-TMSI로 재접속 — 짝 없음 → 대기 없음
TEST(BlindDos, T02NormalReconnect) {
  Harness h;
  h.victim(3, kS, 0);
  h.release(1000, 3);
  h.tick_to(181000);
  h.victim(4, kS, 181000);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(190000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T3: 정상 충돌(RLF) — 옛 항목이 열린 채 새 연결 → 300 ms 뒤 RRC SecurityModeCommand로 수락 → 대기 풀림
TEST(BlindDos, T03RlfCollisionAccepted) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.rrc(1000, 4, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(1050, 4, "UL", "RRCSetupComplete", stmsi(kS));
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.rrc(1350, 4, "DL", "SecurityModeCommand", kSmc);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.release(1400, 3);
  h.tick_to(7000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T4: CONNECTED형 공격 + 피해자 해제 +20 ms — t₀ + 5,000 이상인 첫 kpm2에 RAISE, high (15_ §2.3·§2.6)
TEST(BlindDos, T04ConnectedAttackHigh) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);  // t₀ = 1050, 마감 6050
  h.f1ap(1070, 3, "DL", "UEContextReleaseCommand");
  h.tick_to(6000);
  EXPECT_TRUE(h.alerts.empty());
  h.kpm(6000);  // 마감이 든 창
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-20");
  EXPECT_EQ(e.t, kT0 + 6100);
  EXPECT_EQ(e.severity, Severity::High);
  EXPECT_EQ(e.cond, kCondConcurrent);
  EXPECT_TRUE(e.candidates.empty());
  EXPECT_EQ(e.alert_id.rfind("S-L3-20-1-", 0), 0u);
  EXPECT_EQ(e.values.dump(), R"({"concurrent":1,"peer_uncertain":0,"victims":1,"held":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"accept_wait_ms":5000,"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.du_ue_id, 7);
  EXPECT_EQ(u.uid, 2);
  EXPECT_EQ(u.s_tmsi, kS);
  EXPECT_EQ(u.t_hit, kT0 + 6050);
  EXPECT_EQ(u.cond, kCondConcurrent);
  EXPECT_EQ(u.peers, (std::vector<std::vector<int64_t>>{{1, 3, 1}}));
  EXPECT_EQ(u.values.dump(),
            R"({"peer":"concurrent","nas":"ServiceRequest","wait_ms":5000,"closed_ms":null,"victim_released":true,"repeat":1})");
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-20 cell=1 t=" + std::to_string(kT0 + 6100) +
                           " peer=concurrent ue=1/7/2 s_tmsi=0x0123456789ab peers=1/3/1 nas=ServiceRequest wait_ms=5000 "
                           "victim_released=1 severity=high mode=normal candidates=");
}

// L20-T5: 피해자 해제 없음 — 같은 시각 RAISE, medium
TEST(BlindDos, T05NoVictimReleaseMedium) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + 6100);
  EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("victim_released"), false);
  EXPECT_NE(h.logs[0].find("victim_released=0 severity=medium"), std::string::npos);
}

// L20-T6: 공격 연결이 1초 뒤 해제됨(ServiceReject → 해제) — 표시를 남겨 마감 때 RAISE, closed_ms 1,000 (15_ §1)
TEST(BlindDos, T06ClosedBeforeDeadline) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(2000);
  h.nas(2050, 7, "DL", "ServiceReject", R"("cause":9)");
  h.release(2050, 7);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + 6100);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("closed_ms"), 1000);
}

// L20-T7: IDLE형 — 피해자 해제 3분 뒤 공격 연결 → 짝 없음 → 대기 없음(탐지하지 않음, 15_ §2.1).
// L20-T8: 이어서 피해자가 다시 접속해 수락됨 — 피해자 쪽 concurrent 대기가 수락으로 풀림, 경보 없음(15_ §2.7 한계)
TEST(BlindDos, T07T08IdleTypeNotDetected) {
  Harness h;
  h.victim(3, kS, 0);
  h.release(1000, 3);
  h.tick_to(181000);
  h.attack(7, kS, 181000);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(182000);
  h.rrc(182000, 8, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(182050, 8, "UL", "RRCSetupComplete", stmsi(kS));
  EXPECT_EQ(h.rule->waiting(), 1u);  // 피해자 쪽이 판정 대상
  h.nas(182050, 8, "UL", "ServiceRequest", stmsi(kS), 1);
  h.nas(182080, 8, "DL", "ServiceAccept", "", 2);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(190000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T9: 수락 경계 — ServiceAccept가 t₀ + 4,999면 제때(경보 없음), t₀ + 5,000이면 늦은 수락(RAISE, 14_ §6.1-5)
TEST(BlindDos, T09AcceptBoundary) {
  for (int64_t at : {6049, 6050}) {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);
    h.tick_to(6000);
    h.nas(at, 7, "DL", "ServiceAccept", "", 2);
    h.kpm(6000);
    EXPECT_EQ(h.alerts.size(), at == 6049 ? 0u : 1u) << at;
  }
}

// L20-T10: NAS 암호 — Accept 이름이 ProtectedNAS로 가려져도 RRC SecurityModeCommand로 수락을 본다 (15_ §1.1)
TEST(BlindDos, T10NasCipheredAcceptedBySmc) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.rrc(1000, 7, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(1050, 7, "UL", "RRCSetupComplete", stmsi(kS));
  h.nas(1050, 7, "UL", "ServiceRequest", stmsi(kS), 1);
  h.nas(1200, 7, "DL", "ProtectedNAS", "", 2);
  h.rrc(1300, 7, "DL", "SecurityModeCommand", kSmc);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(7000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T11~T13: 대기 구간의 로스 (14_ §6.2) — ["UL","DL"]이면 보류(공격 경보 없음 — 이슈 #48부터는 보류 1건으로 불확실 경보),
// ["UL"]만이면 DL 대기라 보류 안 함, 카운터 null(DL 미관측 모드)은 2단계가 보지 않아 보류 안 함
TEST(BlindDos, T11T12T13LossDuringWait) {
  auto run = [](const std::string& lost, const std::string& cc) {
    Harness h;
    h.cc = cc;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);
    h.tick_to(3000);
    h.kpm(3000, lost);
    h.tick_to(6100);
    EXPECT_EQ(h.alerts.size(), 1u);
    return h.alerts.empty() ? std::string() : h.alerts[0].alert_kind;
  };
  EXPECT_EQ(run(R"(["UL","DL"])", kCc), "anomaly");
  EXPECT_EQ(run(R"(["UL"])", kCc), "attack");
  EXPECT_EQ(run("[]", kCcDlMissing), "attack");
}

// L20-T29 (14_ §6.2 불확실 경보 — Q-58 해결, 이슈 #48): 짝 대기 중 DL 로스 한 칸으로 보류 1건, 공격 경보 없음 → 마감 처리 칸에서
// 불확실 경보 RAISE(kind anomaly, held_w 1, candidates L3-20, ues[] cond held·uncertain loss). 그 뒤 로스 없이 걸림 → 같은 줄에서
// 불확실 CLEAR 뒤 공격 RAISE(alert_id 다름). 60 s 조용하면 불확실 경보도 CLEAR
TEST(BlindDos, T29HeldAlert) {
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);  // t₀ 1050 → 마감 6050
    h.tick_to(1500);
    h.kpm(1500, R"(["DL"])");  // loss_end[DL] 1600 > 1050 → 보류
    h.tick_to(6000);
    EXPECT_TRUE(h.alerts.empty());
    h.tick_to(6100);
    ASSERT_EQ(h.alerts.size(), 1u);
    const AlertEvent e = h.alerts[0];  // 복사 — 뒤에 alerts가 늘어난다
    EXPECT_EQ(e.kind, AlertEventKind::Raise);
    EXPECT_EQ(e.alert_kind, "anomaly");
    EXPECT_EQ(e.t, kT0 + 6100);
    EXPECT_EQ(e.severity, Severity::Medium);
    EXPECT_EQ(e.cond, (std::vector<std::string>{"held_count"}));
    EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-20"}));
    EXPECT_EQ(e.values.dump(), R"({"held_w":1})");
    EXPECT_EQ(e.params.dump(), R"({"accept_wait_ms":5000,"clear_quiet_ms":60000})");
    ASSERT_EQ(e.ues.size(), 1u);
    EXPECT_EQ(e.ues[0].du_ue_id, 7);
    EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"held"}));
    EXPECT_EQ(e.ues[0].t_hit, kT0 + 6050);
    EXPECT_EQ(e.ues[0].uncertain, (std::vector<std::string>{"loss"}));
    EXPECT_EQ(e.ues[0].values.dump(), R"({"wait_ms":5000,"dir":"DL"})");
    EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-20 cell=1 t=" + std::to_string(kT0 + 6100) +
                             " kind=anomaly held_w=1 wait_ms=5000 severity=medium mode=normal candidates=L3-20");
    // 그 뒤 로스 없이 공격 연결 8 → 마감 12050 → 12100에서 불확실 CLEAR 다음 공격 RAISE
    h.attack(8, kS, 7000);
    h.tick_to(12100);
    ASSERT_EQ(h.alerts.size(), 3u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
    EXPECT_EQ(h.alerts[1].alert_id, e.alert_id);
    EXPECT_EQ(h.alerts[1].t, kT0 + 12100);
    EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
    EXPECT_EQ(h.alerts[2].alert_kind, "attack");
    EXPECT_NE(h.alerts[2].alert_id, e.alert_id);
    EXPECT_EQ(h.alerts[2].values.at("held"), 1);  // 직전 60 s 보류 1건
  }
  {
    Harness h;  // 60 s 조용하면 불확실 경보 CLEAR
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);
    h.tick_to(1500);
    h.kpm(1500, R"(["DL"])");
    h.tick_to(66000);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.tick_to(66100);  // 마지막 보류 6050 + 60 s
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + 66100);
  }
}

// L20-T14: 짝이 loss 불확실(로스 뒤 줄 없음 — 유령일 수 있음) — peer_uncertain, medium
TEST(BlindDos, T14PeerUncertain) {
  Harness h;
  h.victim(3, kS, 0);
  h.kpm(0, R"(["UL","DL"])");  // 피해자의 마지막 줄 뒤 로스 창
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].cond, kCondUncertain);
  EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
  EXPECT_EQ(h.alerts[0].values.at("peer_uncertain"), 1);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("peer"), "peer_uncertain");
}

// L20-T15: 같은 피해자로 공격 연결 3번(1초 간격) — RAISE + UPDATE(1초에 1번까지), ues_total 3, repeat 1·2·3, victims 1
TEST(BlindDos, T15RepeatedAttack) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(2000);
  h.attack(8, kS, 2000);
  h.tick_to(3000);
  h.attack(9, kS, 3000);
  h.tick_to(8200);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Update);
  for (int i = 0; i < 3; ++i) EXPECT_EQ(h.alerts[i].ues[0].values.at("repeat"), i + 1);
  EXPECT_EQ(h.alerts[2].ues_total, 3);
  EXPECT_EQ(h.alerts[2].values.dump(), R"({"concurrent":3,"peer_uncertain":0,"victims":1,"held":0,"evicted":0})");
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-20 cell=1 t=" + std::to_string(kT0 + 7100) +
                           " ues_new=1 ues_total=2 severity=medium");
}

// L20-T16: 해제 — 마지막 걸림 뒤 60초면 그 뒤 첫 kpm2에 CLEAR. 59.9초에 새로 걸리면 그 걸림부터 다시 60초 (15_ §2.5)
TEST(BlindDos, T16ClearAfterQuiet) {
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);  // 걸림 6050
    h.tick_to(66000);
    EXPECT_EQ(h.alerts.size(), 1u);
    h.kpm(66000);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=L3-20 cell=1 t=" + std::to_string(kT0 + 66100) +
                             " duration_ms=60000 ues_total=1");
  }
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);  // 걸림 6050
    h.tick_to(60900);
    h.attack(8, kS, 60900);  // 걸림 65950 — 첫 걸림 뒤 59.9초
    h.tick_to(125900);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
    h.kpm(125900);
    ASSERT_EQ(h.alerts.size(), 3u);
    EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[2].t, kT0 + 126000);
  }
}

// L20-T17: 해제를 기다리는 동안 보류만 있음(마지막 걸림 뒤 30초) — 보류는 해제를 막지 않는다 (15_ §1)
TEST(BlindDos, T17HeldDoesNotBlockClear) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);  // 걸림 6050
  h.tick_to(31000);
  h.attack(8, kS, 31000);  // 마감 36050
  h.tick_to(32000);
  h.kpm(32000, R"(["UL","DL"])");  // 그 대기 구간의 로스 창 — 보류
  h.tick_to(66100);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 66100);
}

// L20-T18: 새 연결 NAS가 RegistrationRequest(5G-GUTI)·DeregistrationRequest — 후보 (15_ §2.6).
// RRC에는 randomValue, NAS 안에만 S-TMSI를 넣어도 그 NAS 줄이 t₀다 (15_ §2.2)
TEST(BlindDos, T18CandidatesByNas) {
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.rrc(1000, 7, "UL", "RRCSetupRequest", kRandom);
    h.rrc(1050, 7, "UL", "RRCSetupComplete");
    h.nas(1050, 7, "UL", "RegistrationRequest", R"("reg_type":"mobility","id_type":"5G-GUTI",)" + stmsi(kS));
    h.tick_to(6100);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].candidates, (std::vector<std::string>{"L3-19-Va", "L3-21"}));
    EXPECT_EQ(h.alerts[0].ues[0].values.at("nas"), "RegistrationRequest");
    EXPECT_NE(h.logs[0].find("nas=RegistrationRequest"), std::string::npos);
    EXPECT_NE(h.logs[0].find("candidates=L3-19-Va,L3-21"), std::string::npos);
  }
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.rrc(1000, 7, "UL", "RRCSetupRequest", part1(kS));
    h.rrc(1050, 7, "UL", "RRCSetupComplete", stmsi(kS));
    h.nas(1050, 7, "UL", "DeregistrationRequest", R"("switch_off":false)", 1);
    h.tick_to(6100);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].candidates, (std::vector<std::string>{"L3-23-O", "L3-19-Va"}));
  }
}

// L20-T19: Part1만 내고 RRCSetupComplete 없이 해제 — 판정하지 않음 (15_ §2.2)
TEST(BlindDos, T19Part1OnlyNotJudged) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.rrc(1000, 7, "UL", "RRCSetupRequest", part1(kS));
  h.f1ap(1500, 7, "UL", "UEContextReleaseComplete");
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(7000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T20: f1_evt(셀 1) 뒤 같은 S-TMSI들이 다시 접속, 하나는 수락 없음 — 옛 항목이 du_reset으로 닫혀 짝이 없다
TEST(BlindDos, T20DuResetNoPeers) {
  Harness h;
  h.victim(3, kS, 0);
  h.victim(4, kS2, 0);
  h.tick_to(1000);
  h.f1(1000, "[1]");
  h.victim(5, kS, 1100);
  h.rrc(1100, 6, "UL", "RRCSetupRequest", part1(kS2));
  h.rrc(1150, 6, "UL", "RRCSetupComplete", stmsi(kS2));  // 수락 없음
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(7000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T21: 피해자 셀 1, 공격 연결 셀 2 — 경보 셀은 공격 연결(n)의 셀, peers는 셀 1 (S-TMSI 색인은 gNB 전체, 14_ §3.1)
TEST(BlindDos, T21CrossCell) {
  Harness h;
  h.victim(3, kS, 0, 1);
  h.tick_to(1000, 1);
  h.tick_to(1000, 2);
  h.attack(7, kS, 1000, 2);
  h.tick_to(6100, 2);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].cell_id, 2);
  EXPECT_EQ(h.alerts[0].ues[0].peers, (std::vector<std::vector<int64_t>>{{1, 3, 1}}));
}

// L20-T22: 첫 줄이 RRCSetupComplete인 n(mid_join) — 판정 없음 (15_ §2.3-1)
TEST(BlindDos, T22MidJoinNotJudged) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.rrc(1000, 7, "UL", "RRCSetupComplete", stmsi(kS));
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(7000);
  EXPECT_TRUE(h.alerts.empty());
}

// L20-T23: 피해자가 SUCI로 등록해 CONNECTED — S-TMSI는 RegistrationAccept에만 있다(상태표가 저장, 10/29 검수 A3) →
// 그 S-TMSI로 연 공격 연결이 걸린다
TEST(BlindDos, T23VictimRegisteredWithSuci) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest", kRandom);
  h.rrc(0, 3, "DL", "RRCSetup");
  h.rrc(50, 3, "UL", "RRCSetupComplete");
  h.nas(50, 3, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")");
  h.nas(60, 3, "DL", "AuthenticationRequest");
  h.nas(70, 3, "UL", "AuthenticationResponse");
  h.rrc(90, 3, "DL", "SecurityModeCommand", kSmc);
  h.nas(100, 3, "DL", "RegistrationAccept", stmsi(kS), 2);
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].cond, kCondConcurrent);
  EXPECT_EQ(h.alerts[0].ues[0].peers, (std::vector<std::vector<int64_t>>{{1, 3, 1}}));
}

// L20-T24: peer_uncertain 걸림으로 열린 경보 중 concurrent 걸림(피해자 해제 있음) — 기다리지 않고 UPDATE, medium → high
TEST(BlindDos, T24SeverityRiseUpdate) {
  Harness h;
  h.victim(3, kS, 0);
  h.kpm(0, R"(["UL","DL"])");  // 피해자 A 불확실
  h.victim(5, kS2, 200);       // 피해자 B — 로스 창 뒤
  h.tick_to(1000);
  h.attack(7, kS, 1000);  // A의 S-TMSI — peer_uncertain, 걸림 6050
  h.tick_to(1500);
  h.attack(8, kS2, 1500);  // B의 S-TMSI — concurrent, 걸림 6550
  h.f1ap(1570, 5, "DL", "UEContextReleaseCommand");
  h.tick_to(6700);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].severity, Severity::High);
  EXPECT_EQ(h.alerts[1].t, kT0 + 6600);  // 1초 간격을 기다리지 않음
  EXPECT_EQ(h.alerts[1].values.at("victims"), 2);
}

// L20-T25: 재생 결정성 — 같은 입력을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(BlindDos, T25Deterministic) {
  auto run = [] {
    Harness h({}, true);
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);
    h.f1ap(1070, 3, "DL", "UEContextReleaseCommand");
    h.tick_to(2000);
    h.attack(8, kS, 2000);
    h.tick_to(9000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 2u);
  EXPECT_GT(a.second.size(), 2u);  // alert 레코드 + 걸린 UE의 pre 증거
}

// L20-T26: 짝이 loss지만 로스 창 뒤에 줄이 있음(t_last > t_loss) — 확실한 짝 → concurrent (10/29 검수 B4)
TEST(BlindDos, T26LossyPeerWithLaterLineIsCertain) {
  Harness h;
  h.victim(3, kS, 0);
  h.kpm(0, R"(["UL","DL"])");
  h.rrc(200, 3, "UL", "MeasurementReport");
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].cond, kCondConcurrent);
}

// L20-T27: 공격 연결이 1초 뒤 닫히고 같은 du_ue_id가 2초 뒤 정상 UE에 재사용 — 옛 연결만 마감 때 걸리고(옛 uid),
// 새 UE는 판정에 섞이지 않는다 (10/29 검수 A2)
TEST(BlindDos, T27KeyReuseKeepsOldUid) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(2000);
  h.release(2050, 7);
  h.tick_to(3000);
  h.rrc(3050, 7, "UL", "RRCSetupRequest", kRandom);
  h.rrc(3100, 7, "UL", "RRCSetupComplete");
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].uid, 2);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("closed_ms"), 1000);
  EXPECT_EQ(h.engine.ue_table().find(UeKey{1, 7})->uid, 3);
}

// END (15_ §2.5): 입력이 끊겨 series가 input_lost를 내면 그 셀 경보를, 새 세션이면 모든 경보를 끝낸다
TEST(BlindDos, EndOnInputLostAndSessionReset) {
  {
    SeriesConfig scfg;
    scfg.h_hold_ms = 3000;  // 창 채움 시간 1,900 ms보다 길게 — 더 짧으면 series가 채움 + P로 올려 쓴다 (3_ §8, 11/05 W-31)
    Harness h(scfg);
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);
    h.tick_to(6100);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.cc.clear();  // 1단계 필수 키가 빠진 칸 — 보류가 H_hold를 넘으면 input_lost (보류 시작 6100 → 9200 칸에서)
    h.tick_to(9400);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "input_lost");
  }
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1000);
    h.attack(7, kS, 1000);
    h.tick_to(6100);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.rule->waiting(), 0u);
  }
}

// 입력 침묵 (14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 경보 중 실행 파일이 침묵을 알리면 END(reason=input_silent, t = 경보가 마지막으로 본
// 칸). 대기 표시는 그대로라 kpm2가 다시 오면 기다리던 공격 연결의 마감이 평소처럼 걸려 새 RAISE
TEST(BlindDos, EndOnInputSilent) {
  Harness h;
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);
  h.tick_to(6100);  // 마감 6050 → 6100에서 RAISE
  ASSERT_EQ(h.alerts.size(), 1u);
  h.attack(8, kS, 6100);  // 다음 공격 연결 — t₀ 6150, 마감 11150
  h.tick_to(6200);
  EXPECT_EQ(h.rule->waiting(), 1u);
  EngineOutput o = h.engine.on_input_silent(10000);
  ASSERT_EQ(o.alerts.size(), 1u);
  EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
  EXPECT_EQ(o.alerts[0].reason, "input_silent");
  EXPECT_EQ(o.alerts[0].alert_id, h.alerts[0].alert_id);
  EXPECT_EQ(o.alerts[0].t, kT0 + 6200);
  ASSERT_EQ(o.diags.size(), 1u);
  EXPECT_EQ(o.diags[0].kind, DiagKind::InputSilent);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(11200);  // 재개 — 마감 11150이 11200에서 걸림 → 새 RAISE
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[1].t, kT0 + 11200);
  EXPECT_NE(h.alerts[1].alert_id, h.alerts[0].alert_id);
  EXPECT_EQ(h.rule->waiting(), 0u);
}

// late_until (14_ §4.3 — Q-57 해결, 이슈 #46): 공격 연결의 줄이 늦게 오면(순서 역전) 늦은 줄 + 6 s까지만 판정에서 빠진다.
// 마감(t₀ + 5 s)이 그 안이면 걸림 없음, 뒤면 걸림 — ues[].uncertain에 late
TEST(BlindDos, LateUntil) {
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1100);          // 워터마크 1100
    h.attack(7, kS, 1000);    // 1000~1060 모두 늦음 → late_until 7060, t₀ 1050 → 마감 6050 < 7060 → 판정 없음
    EXPECT_EQ(h.rule->waiting(), 1u);
    h.tick_to(7200);
    EXPECT_EQ(h.rule->waiting(), 0u);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    h.victim(3, kS, 0);
    h.tick_to(1100);
    h.rrc(1000, 7, "UL", "RRCSetupRequest", part1(kS));  // 늦은 줄 → late_until 7000
    h.tick_to(2100);
    h.rrc(2100, 7, "DL", "RRCSetup");
    h.rrc(2150, 7, "UL", "RRCSetupComplete", stmsi(kS));  // t₀ 2150 → 마감 7150 ≥ 7000 → 판정
    h.nas(2150, 7, "UL", "ServiceRequest", stmsi(kS), 1);
    h.tick_to(7200);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + 7200);
    ASSERT_EQ(h.alerts[0].ues.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"late"}));
  }
}

// L20-T28 (15_ §2.5 — Q-56 해결, 이슈 #44): RAISE 뒤 그 셀에 상태표 밀어내기가 이어지면 마지막 걸림 + clear_quiet_ms가
// 지나도 CLEAR하지 않고, 직전 clear_quiet_ms 동안 밀어내기가 0건이 된 칸에서 푼다. 상한 100, 정상 연결 101대로 밀어내기를 만든다
TEST(BlindDos, T28EvictionHoldsClear) {
  UeTableConfig ue_cfg;
  ue_cfg.max_ues = 100;
  Harness h(SeriesConfig{}, false, ue_cfg);
  h.victim(3, kS, 0);
  h.tick_to(1000);
  h.attack(7, kS, 1000);  // t₀ 1050 → 마감 6050 → RAISE 6100, 마지막 걸림 6050
  h.tick_to(30000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].values.at("evicted"), 0);
  for (int64_t i = 0; i < 101; ++i) {  // 2 + 101 > 100 → 밀어내기 3회, 다음 kpm2(t_end 30100)에서 셈
    h.rrc(30000 + i, 1000 + i, "UL", "RRCSetupRequest", kRandom);
    h.rrc(30000 + i, 1000 + i, "UL", "RRCSetupComplete");
  }
  h.tick_to(66200);  // 보류가 없었다면 6050 + 60 s → 66100에 CLEAR
  EXPECT_EQ(h.engine.ue_table().counts(1).evicted, 3);
  EXPECT_EQ(h.alerts.size(), 1u);
  h.tick_to(90100);  // 밀어내기 시각 30100 + 60 s = 90100 — 그 칸에서 창 밖(≤ now − 60 s)이라 풀린다
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 90100);
}

// 증거 지평 (14_ §1.1): 수락 대기 + UPDATE 모음 지연. 상태표는 여기에 여유 1 s를 더해 닫힌 항목의 recent를 보관한다
TEST(BlindDos, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 6000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 7000);
}
