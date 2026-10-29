// 룰 L3-21 상향 DoS 테스트 — 15_ §5.8 L21-T1~T21. 합성 ue_evt·kpm2 줄로 한다(데이터 파일은 설정 키·데이터 이슈).
// 시각은 kT0 기준 ms. 갈래 ① 실패 UE는 t_f + fail_accept_wait_ms 이상인 첫 kpm2에서 정해지고, 갈래 ②는 걸린 줄에서 바로 낸다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/auth_stall.h"
#include "detect/rules/uplink_dos.h"

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace detect;

namespace {

constexpr int64_t kT0 = 1793005200000;
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
const std::string kRandom = R"("ue_identity":{"type":"randomValue"})";
const std::string kSuci = R"("reg_type":"initial","id_type":"SUCI")";

struct Opt {
  UplinkDosConfig cfg;
  SeriesConfig scfg;
  UeTableConfig ue_cfg;     // 상태표 상한 등 (밀어내기 시험 L21-T23, 이슈 #44)
  bool record = false;      // 증거 기록기도 돌린다
  bool auth_stall = false;  // L3-01-O도 함께 (L01-T18)
};

std::string stmsi(uint64_t v) {
  char buf[48];
  std::snprintf(buf, sizeof(buf), R"("s_tmsi":"0x%012llx")", static_cast<unsigned long long>(v));
  return buf;
}

// 엔진 + L3-21 (+ L3-01-O, 증거 기록기). ue_evt를 넣기 전에 그 셀 시계를 그 줄이 든 창 앞까지 kpm2로 올린다 —
// 같은 창의 ue_evt는 그 kpm2보다 먼저 온다(2_ §6.1). 줄은 셀마다 시각 순으로 넣는다
class Harness {
 public:
  explicit Harness(Opt o = {})
      : engine(o.scfg, kDefaultMaxLineBytes, o.ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(o.record) {
    if (o.auth_stall) engine.add_ue_rule(std::make_unique<AuthStallRule>());
    auto r = std::make_unique<UplinkDosRule>(o.cfg);
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
         R"(,"cells":[{"cell_id":1,"max_conn":null}],"period_ms":100,"noreply_timeout_ms":1000,"clock":"realtime","ue_evt":true})");
  }
  void ue(int64_t t, int64_t du, const std::string& dir, const std::string& proto, const std::string& msg,
          const std::string& f, const std::string& extra, int64_t cell = 1) {
    tick_to(t - t % 100, cell);
    feed(R"({"type":"ue_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + t) + R"(,"cell_id":)" + std::to_string(cell) + R"(,"du_ue_id":)" +
         std::to_string(du) + R"(,"crnti":)" + std::to_string(17000 + du) + R"(,"dir":")" + dir + R"(","proto":")" +
         proto + R"(","msg":")" + msg + "\"" + extra + (f.empty() ? "" : R"(,"f":{)" + f + "}") + "}");
  }
  void rrc(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "") {
    ue(t, du, dir, "RRC", msg, f, "");
  }
  void nas(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "") {
    ue(t, du, dir, "NAS", msg, f, R"(,"via":"F1","sht":0)");
  }
  void kpm(int64_t t, int64_t cell = 1) {
    next_t_[cell] = t + 100;
    const auto lost = lost_.find(t);
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":)" + std::to_string(cell) + R"(,"t_start_ms":)" + std::to_string(kT0 + t) +
         R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) + (cc.empty() ? "" : R"(,"cc":)" + cc) +
         R"(,"ue_evt_lost":)" + (lost == lost_.end() ? "[]" : lost->second) + "}");
  }
  // 그 셀 kpm2를 창 시작 < t인 것까지 보낸다 — 마지막 창의 t_end_ms ≥ t
  void tick_to(int64_t t, int64_t cell = 1) {
    while (next_t_[cell] < t) kpm(next_t_[cell], cell);
  }
  void lost(int64_t window, const std::string& dirs) { lost_[window] = dirs; }

  // 연결과 등록 요청 — RegistrationRequest는 t + 10
  void connect(int64_t t, int64_t du, const std::string& f_complete = "", const std::string& f_reg = kSuci) {
    rrc(t, du, "UL", "RRCSetupRequest", kRandom);
    rrc(t, du, "DL", "RRCSetup");
    rrc(t + 10, du, "UL", "RRCSetupComplete", f_complete);
    nas(t + 10, du, "UL", "RegistrationRequest", f_reg);
  }
  void reject(int64_t t, int64_t du, int64_t cause = 3, const std::string& msg = "RegistrationReject") {
    nas(t, du, "DL", msg, R"("cause":)" + std::to_string(cause));
  }
  void release(int64_t t, int64_t du) {
    ue(t, du, "DL", "F1AP", "UEContextReleaseCommand", "", "");
    ue(t, du, "UL", "F1AP", "UEContextReleaseComplete", "", "");
  }
  // 원형 연결 하나 — 무효 등록 요청 → t_f에 RegistrationReject → 20 ms 뒤 해제. 실패 UE = t_f + 5,000 (closed_ms 20)
  void fail_conn(int64_t t_f, int64_t du) {
    connect(t_f - 20, du);
    reject(t_f, du);
    release(t_f + 20, du);
  }
  // 변형 — 한 연결에서 RegistrationRequest → 거부(t + 20) → RegistrationRequest(t + 500) → RegistrationRequest(t + 1000):
  // 세 번째 등록 요청 줄(t + 1000)에서 갈래 ②로 걸린다. 첫 실패 t + 20의 갈래 ① 마감은 t + 5,020
  void repeat_ue(int64_t t, int64_t du) {
    connect(t, du);
    reject(t + 20, du);
    nas(t + 500, du, "UL", "RegistrationRequest", kSuci);
    nas(t + 1000, du, "UL", "RegistrationRequest", kSuci);
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
  std::vector<const AlertEvent*> of(const std::string& rule_id) const {
    std::vector<const AlertEvent*> v;
    for (const auto& a : alerts)
      if (a.rule == rule_id) v.push_back(&a);
    return v;
  }
  int64_t seq() const { return seq_; }

  Engine engine;
  EvidenceQueue queue;
  EvidenceRecorder rec;
  UplinkDosRule* rule = nullptr;
  std::string cc = kCc;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  std::map<int64_t, int64_t> next_t_;
  std::map<int64_t, std::string> lost_;
};

// L21-T4 원형: 1 s마다 다른 연결에서 무효 요청 → RegistrationReject. t_f = 1000·…, 실패 UE = 6000·7000·…
void flood(Harness& h, int n, int64_t du0 = 10, int64_t t0 = 1000) {
  for (int i = 0; i < n; ++i) h.fail_conn(t0 + 1000 * i, du0 + i);
}

std::vector<int64_t> dus(const AlertEvent& e) {
  std::vector<int64_t> v;
  for (const auto& u : e.ues) v.push_back(u.du_ue_id);
  return v;
}

std::string t_str(int64_t t) { return std::to_string(kT0 + t); }

}  // namespace

// L21-T1: 정상 등록 — 실패 메시지가 없어 기다림도 경보도 없다
TEST(UplinkDos, T01NormalRegistration) {
  Harness h;
  h.connect(1000, 3);
  h.nas(1020, 3, "DL", "AuthenticationRequest");
  h.nas(1030, 3, "UL", "AuthenticationResponse");
  h.rrc(1040, 3, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")");
  h.nas(1050, 3, "DL", "RegistrationAccept");
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(20000);
  EXPECT_EQ(h.rule->failed_ues(), 0);
  EXPECT_TRUE(h.alerts.empty());
}

// L21-T2: 정상 동기 실패 — AuthenticationFailure → 재인증 → 300 ms 뒤 RRC SecurityModeCommand로 수락 → 실패 UE 아님
TEST(UplinkDos, T02SyncFailureRecovers) {
  Harness h;
  h.connect(1000, 3);
  h.nas(1020, 3, "DL", "AuthenticationRequest");
  h.nas(1030, 3, "UL", "AuthenticationFailure", R"("cause":21)");
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.nas(1040, 3, "DL", "AuthenticationRequest");
  h.nas(1050, 3, "UL", "AuthenticationResponse");
  h.rrc(1330, 3, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")");
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(20000);
  EXPECT_EQ(h.rule->failed_ues(), 0);
  EXPECT_TRUE(h.alerts.empty());
}

// L21-T3: 설정이 잘못된 단말 1대 — 10 s마다 새 연결로 거부. 실패 UE가 10 s에 1개라 문턱 미만, 경보 없음
TEST(UplinkDos, T03MisconfiguredDevice) {
  Harness h;
  for (int i = 0; i < 6; ++i) h.fail_conn(1000 + 10000 * i, 10 + i);
  h.tick_to(70000);
  EXPECT_EQ(h.rule->failed_ues(), 6);
  EXPECT_TRUE(h.alerts.empty());
}

// L21-T4: 원형 — 1 s마다 다른 연결에서 무효 요청 → RegistrationReject. 5번째 실패 UE = t₀ + 4 s + 5 s(10000) →
// 그 뒤 첫 kpm2(t_end 10000)에 갈래 ① RAISE (15_ §5.3·§5.6)
TEST(UplinkDos, T04FloodRaisesBranch1) {
  Harness h;
  flood(h, 5);
  h.tick_to(9900);
  EXPECT_EQ(h.rule->failed_ues(), 4);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(10000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-21");
  EXPECT_EQ(e.stage, 2);
  EXPECT_EQ(e.unit, "ue");
  EXPECT_EQ(e.t, kT0 + 10000);
  EXPECT_EQ(e.branch, "1");
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"fail_count"}));
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"AN-01"}));
  EXPECT_EQ(e.alert_id.rfind("S-L3-21-1-", 0), 0u);
  EXPECT_EQ(e.values.dump(), R"({"fails_w":5,"branch1_ues":5,"branch2_ues":0,"held":0,"evicted":0,"fail_msgs_w":5})");
  EXPECT_EQ(e.params.dump(),
            R"({"window_ms":10000,"n_fail":5,"fail_accept_wait_ms":5000,"reg_repeat":3,"clear_quiet_ms":60000,"ignore_causes":[]})");
  ASSERT_EQ(e.ues.size(), 5u);
  for (std::size_t i = 0; i < 5; ++i) {
    const AlertUe& u = e.ues[i];
    EXPECT_EQ(u.du_ue_id, static_cast<int64_t>(10 + i));
    EXPECT_EQ(u.t_hit, kT0 + 6000 + 1000 * static_cast<int64_t>(i));
    EXPECT_EQ(u.cond, (std::vector<std::string>{"fail_not_accepted"}));
    EXPECT_EQ(u.values.dump(),
              R"({"branch":"1","reg_req_n":1,"fails":["RegistrationReject"],"causes":[3],"id_type":"SUCI","closed_ms":20})");
  }
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-21 cell=1 t=" + t_str(10000) +
                           " branch=1 fails_w=5 n_fail=5 window_ms=10000 severity=medium mode=normal candidates=AN-01");
}

// L21-T5: 10 s 안 실패 UE 4개 / 5개 — 앞은 경보 없음, 뒤는 RAISE(T4). 창은 (t_hit − W, t_hit]이라 정확히 10 s에 걸친
// 5개는 4개로 센다
TEST(UplinkDos, T05Threshold) {
  {
    Harness h;
    flood(h, 4);
    h.tick_to(30000);
    EXPECT_EQ(h.rule->failed_ues(), 4);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    for (int i = 0; i < 5; ++i) h.fail_conn(1000 + 2500 * i, 10 + i);  // 실패 UE 6000 … 16000 — 6000은 창 밖
    h.tick_to(30000);
    EXPECT_EQ(h.rule->failed_ues(), 5);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// L21-T6: 변형 — 한 연결에서 RegistrationRequest → RegistrationReject → RegistrationRequest → RegistrationRequest.
// 3번째 등록 요청 줄에서 즉시 갈래 ② RAISE — 경보 t와 alert_id의 seq는 그 줄의 것이다 (15_ §5.3·§5.6)
TEST(UplinkDos, T06RepeatRaisesBranch2) {
  Harness h;
  h.repeat_ue(1000, 3);  // 세 번째 등록 요청 2000
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.t, kT0 + 2000);
  EXPECT_EQ(e.alert_id, "S-L3-21-1-" + std::to_string(h.seq()));
  EXPECT_EQ(e.branch, "2");
  EXPECT_EQ(e.cond, (std::vector<std::string>{"reg_repeat", "fail"}));
  EXPECT_EQ(e.values.dump(), R"({"fails_w":0,"branch1_ues":0,"branch2_ues":1,"held":0,"evicted":0,"fail_msgs_w":1})");
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].t_hit, kT0 + 2000);
  EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"reg_repeat", "fail"}));
  EXPECT_EQ(e.ues[0].values.dump(),
            R"({"branch":"2","reg_req_n":3,"fails":["RegistrationReject"],"causes":[3],"id_type":"SUCI","closed_ms":null})");
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-21 cell=1 t=" + t_str(2000) +
                           " branch=2 ue=1/3/1 reg_req_n=3 fails=RegistrationReject severity=medium mode=normal "
                           "candidates=AN-01");
  const std::string rec = alert_record_line(e, 0, 0);
  EXPECT_NE(rec.find(R"("mode":"normal","branch":"2","cond":["reg_repeat","fail"])"), std::string::npos);
  h.nas(2500, 3, "UL", "RegistrationRequest", kSuci);  // 연결당 한 번
  EXPECT_EQ(h.alerts.size(), 1u);
}

// L21-T7: 한 연결에서 RegistrationRequest 3번, 실패 없음(응답 없는 재전송) — 갈래 ② 아님(L3-01-O 쪽)
TEST(UplinkDos, T07RepeatWithoutFailure) {
  Harness h;
  h.connect(1000, 3);
  h.nas(1500, 3, "UL", "RegistrationRequest", kSuci);
  h.nas(2000, 3, "UL", "RegistrationRequest", kSuci);
  h.tick_to(20000);
  EXPECT_EQ(h.rule->waiting(), 0u);
  EXPECT_TRUE(h.alerts.empty());
}

// L21-T8: 한 연결에서 RegistrationRequest 2번 + 실패 — 갈래 ② 아님 (실패 UE 1개는 문턱 미만)
TEST(UplinkDos, T08TwoRequestsAndFailure) {
  Harness h;
  h.connect(1000, 3);
  h.reject(1020, 3);
  h.nas(1500, 3, "UL", "RegistrationRequest", kSuci);
  h.tick_to(20000);
  EXPECT_EQ(h.rule->failed_ues(), 1);
  EXPECT_TRUE(h.alerts.empty());
}

// L21-T9: 실패 뒤 수락 t_ms = t_f + 4,999 / t_f + 5,000 — 앞은 실패 UE 아님, 뒤는 실패 UE(늦은 수락, 14_ §6.1-5)
TEST(UplinkDos, T09AcceptBoundary) {
  {
    Harness h;
    h.connect(980, 3);
    h.reject(1000, 3);
    h.nas(5999, 3, "DL", "RegistrationAccept");
    h.tick_to(10000);
    EXPECT_EQ(h.rule->failed_ues(), 0);
  }
  {
    Harness h;
    h.connect(980, 3);
    h.reject(1000, 3);
    h.nas(6000, 3, "DL", "RegistrationAccept");
    h.tick_to(10000);
    EXPECT_EQ(h.rule->failed_ues(), 1);
  }
}

// L21-T10: T4 중 대기 구간에 ue_evt_lost ["UL","DL"] 창 — 그 UE는 보류(held 증가), 나머지로 성립 판단 (14_ §6.2)
TEST(UplinkDos, T10LossHolds) {
  Harness h;
  h.lost(1500, R"(["UL","DL"])");  // loss_end[DL] = 1600 — t_f 1000인 첫 UE만 보류
  flood(h, 7);                      // 나머지 실패 UE 7000 … 12000
  h.tick_to(10900);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(11000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.rule->held(), 1);
  EXPECT_EQ(h.alerts[0].values.dump(), R"({"fails_w":5,"branch1_ues":5,"branch2_ues":0,"held":1,"evicted":0,"fail_msgs_w":6})");
  EXPECT_EQ(h.alerts[0].ues[0].du_ue_id, 11);
}

// L21-T11: 갈래 ① 경보 중 갈래 ② UE가 걸림 — 근거가 겹쳐 바로 UPDATE, high (15_ §5.3 심각도)
TEST(UplinkDos, T11Branch2DuringBranch1High) {
  Harness h;
  flood(h, 5);
  h.tick_to(10000);
  ASSERT_EQ(h.alerts.size(), 1u);
  h.repeat_ue(12000, 20);  // 갈래 ② 13000
  ASSERT_EQ(h.alerts.size(), 2u);
  const AlertEvent& e = h.alerts[1];
  EXPECT_EQ(e.kind, AlertEventKind::Update);
  EXPECT_EQ(e.t, kT0 + 13000);
  EXPECT_EQ(e.severity, Severity::High);
  EXPECT_EQ(e.branch, "1");
  EXPECT_EQ(dus(e), (std::vector<int64_t>{20}));
  EXPECT_EQ(e.values.dump(), R"({"fails_w":5,"branch1_ues":5,"branch2_ues":1,"held":0,"evicted":0,"fail_msgs_w":3})");
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-21 cell=1 t=" + t_str(13000) + " ues_new=1 ues_total=6 branch=1 severity=high");
}

// L21-T12: 해제 — 공격이 멈춘 뒤 정상 실패 1건(경보에는 실리지만 성립은 아님) → 마지막 성립(10000) + 60 s 뒤 CLEAR
TEST(UplinkDos, T12ClearAfterQuiet) {
  Harness h;
  flood(h, 5);
  h.fail_conn(30000, 30);  // 실패 UE 35000
  h.tick_to(35000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  h.tick_to(69900);
  EXPECT_EQ(h.alerts.size(), 2u);
  h.tick_to(70000);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[2].branch, "1");
  EXPECT_EQ(h.logs[2], "ALERT CLEAR rule=L3-21 cell=1 t=" + t_str(70000) + " duration_ms=60000 ues_total=6");
}

// L21-T13: 위조 ServiceRequest(S-TMSI 있음) → ServiceReject, 연결마다 반복 — 갈래 ①, candidates ["AN-01","L3-20"]
TEST(UplinkDos, T13ForgedServiceRequest) {
  Harness h;
  for (int i = 0; i < 5; ++i) {
    const int64_t t_f = 1000 + 1000 * i;
    const int64_t du = 10 + i;
    h.rrc(t_f - 20, du, "UL", "RRCSetupRequest", kRandom);
    h.rrc(t_f - 10, du, "UL", "RRCSetupComplete", stmsi(0x0123456789ab));
    h.nas(t_f - 10, du, "UL", "ServiceRequest", stmsi(0x0123456789ab));
    h.reject(t_f, du, 9, "ServiceReject");
    h.release(t_f + 20, du);
  }
  h.tick_to(10000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].branch, "1");
  EXPECT_EQ(h.alerts[0].candidates, (std::vector<std::string>{"AN-01", "L3-20"}));
  EXPECT_EQ(h.alerts[0].ues[0].values.at("fails"), nlohmann::ordered_json::array({"ServiceReject"}));
  EXPECT_EQ(h.alerts[0].ues[0].values.at("reg_req_n"), 0);
  EXPECT_TRUE(h.alerts[0].ues[0].values.at("id_type").is_null());
}

// L21-T14: AuthenticationFailure 뒤 응답 없음·수락 없음 — 실패 UE (L3-01-O 고착은 아님 — 응답이 있었음)
TEST(UplinkDos, T14AuthFailureNoAccept) {
  Harness h;
  h.connect(970, 3);
  h.nas(1000, 3, "DL", "AuthenticationRequest");
  h.nas(1010, 3, "UL", "AuthenticationFailure", R"("cause":21)");
  h.tick_to(7000);
  EXPECT_EQ(h.rule->failed_ues(), 1);
}

// L21-T15: SecurityModeReject만 있는 연결 — 실패로 세지 않는다 (#3 쪽 신호, 15_ §5.2)
TEST(UplinkDos, T15SecurityModeRejectNotFailure) {
  Harness h;
  h.connect(970, 3);
  h.nas(1000, 3, "DL", "SecurityModeCommand", R"("cipher":"5G-EA0","integrity":"5G-IA2")");
  h.nas(1010, 3, "UL", "SecurityModeReject", R"("cause":24)");
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(10000);
  EXPECT_EQ(h.rule->failed_ues(), 0);
}

// L21-T16: 갈래 ② UE가 mid_join — 판정하고 uncertain에 mid_join. 갈래 ① 기다림은 시작하지 않는다 (15_ §5.7)
TEST(UplinkDos, T16Branch2MidJoin) {
  Harness h;
  h.nas(1000, 3, "UL", "RegistrationRequest", kSuci);  // 첫 줄
  h.reject(1010, 3);
  h.nas(1500, 3, "UL", "RegistrationRequest", kSuci);
  h.nas(2000, 3, "UL", "RegistrationRequest", kSuci);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"mid_join"}));
  EXPECT_EQ(h.rule->waiting(), 0u);
}

// L21-T17: 재생 결정성 — T4·T6을 두 번 재생하면 경보·증거 바이트 동일
TEST(UplinkDos, T17Deterministic) {
  auto run = [] {
    Opt o;
    o.record = true;
    Harness h(o);
    flood(h, 5);
    h.repeat_ue(11000, 3);
    h.tick_to(80000);
    std::vector<std::string> v = h.logs;
    for (std::string& line : h.drain()) v.push_back(std::move(line));
    return v;
  };
  const std::vector<std::string> a = run();
  const std::vector<std::string> b = run();
  EXPECT_EQ(a, b);
  ASSERT_GE(a.size(), 3u);
  EXPECT_EQ(a[0].rfind("ALERT RAISE rule=L3-21", 0), 0u);
}

// L21-T18: 망 컨텍스트 소실 — 정상 UE 5대가 1 s 간격으로 ServiceRequest → ServiceReject(#9) → 해제 → 새 연결에서 SUCI 등록·
// 수락. ignore_causes []면 5번째 실패 UE에서 갈래 ① RAISE(한계로 기록), [9]면 실패로 세지 않아 경보 없음 (15_ §5.2·§5.7)
TEST(UplinkDos, T18ContextLossIgnoreCauses) {
  auto run = [](std::vector<int64_t> ignore) {
    Opt o;
    o.cfg.ignore_causes = std::move(ignore);
    auto h = std::make_unique<Harness>(o);
    for (int i = 0; i < 5; ++i) {
      const int64_t t_f = 1000 + 1000 * i;
      const int64_t du = 10 + 2 * i;
      h->rrc(t_f - 20, du, "UL", "RRCSetupRequest", kRandom);
      h->rrc(t_f - 10, du, "UL", "RRCSetupComplete", stmsi(0x000000000100 + i));
      h->nas(t_f - 10, du, "UL", "ServiceRequest", stmsi(0x000000000100 + i));
      h->reject(t_f, du, 9, "ServiceReject");
      h->release(t_f + 20, du);
      h->connect(t_f + 100, du + 1);
      h->nas(t_f + 200, du + 1, "DL", "RegistrationAccept", stmsi(0x000000000200 + i));
    }
    h->tick_to(20000);
    return h;
  };
  const auto off = run({});
  ASSERT_EQ(off->alerts.size(), 1u);
  EXPECT_EQ(off->alerts[0].t, kT0 + 10000);
  const auto on = run({9});
  EXPECT_EQ(on->rule->waiting(), 0u);
  EXPECT_EQ(on->rule->failed_ues(), 0);
  EXPECT_TRUE(on->alerts.empty());
}

// L21-T19: 이미 수락된 연결(rrc_sec ON)에서 ServiceRequest → ServiceReject, 1 s 뒤 RegistrationRequest → RegistrationAccept —
// 상태로는 다시 수락될 수 없지만 수락 근거 메시지로 풀린다 → 실패 UE 아님 (15_ §5.3-2, 10/29 이슈 #31)
TEST(UplinkDos, T19AcceptMessageAfterAcceptedConnection) {
  auto run = [](bool accept_again) {
    auto h = std::make_unique<Harness>();
    h->connect(970, 3);
    h->nas(990, 3, "DL", "AuthenticationRequest");
    h->nas(1000, 3, "UL", "AuthenticationResponse");
    h->rrc(1010, 3, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")");
    h->rrc(1020, 3, "UL", "SecurityModeComplete");
    h->nas(1030, 3, "DL", "RegistrationAccept");
    h->nas(2000, 3, "UL", "ServiceRequest");
    h->reject(2010, 3, 9, "ServiceReject");
    EXPECT_EQ(h->rule->waiting(), 1u);
    h->nas(3000, 3, "UL", "RegistrationRequest", R"("reg_type":"mobility","id_type":"5G-GUTI")");
    if (accept_again) h->nas(3010, 3, "DL", "RegistrationAccept");
    h->tick_to(10000);
    return h->rule->failed_ues();
  };
  EXPECT_EQ(run(true), 0);
  EXPECT_EQ(run(false), 1);
}

// L21-T20: 한 연결에서 거부를 1 s마다 되풀이 — 실패 UE는 수락 전까지 연결당 1번 / 수락 뒤 새 실패는 새로 기다린다
// (15_ §5.3-1, 10/29 이슈 #31). 같은 연결의 반복은 갈래 ②가 잡는다
TEST(UplinkDos, T20CountOncePerConnectionUntilAccept) {
  Harness h;
  h.rrc(990, 3, "UL", "RRCSetupRequest", kRandom);
  h.rrc(1000, 3, "UL", "RRCSetupComplete");
  for (int k = 0; k < 8; ++k) {
    h.nas(1000 + 1000 * k, 3, "UL", "RegistrationRequest", kSuci);
    h.reject(1010 + 1000 * k, 3);
  }
  EXPECT_EQ(h.rule->waiting(), 0u);  // 첫 실패(1010)의 마감 6010을 지나 실패 UE로 셌다 — 뒤의 실패로는 새로 기다리지 않는다
  h.tick_to(20000);
  EXPECT_EQ(h.rule->failed_ues(), 1);
  ASSERT_FALSE(h.alerts.empty());
  EXPECT_EQ(h.alerts[0].branch, "2");  // 3번째 등록 요청에서 갈래 ②

  h.nas(20000, 3, "DL", "RegistrationAccept");
  h.reject(21000, 3);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(27000);
  EXPECT_EQ(h.rule->failed_ues(), 2);
}

// L21-T21 (가): 갈래 ② UE가 마감 뒤 실패 UE로도 판정 — 같은 UE가 두 칸(branch "2"·"1"), 증거(pre)는 한 번 (15_ §5.5)
TEST(UplinkDos, T21SameUeInBothBranches) {
  Opt o;
  o.record = true;
  Harness h(o);
  h.repeat_ue(1000, 3);  // 갈래 ② 2000, 첫 실패 1020 → 실패 UE 6020
  h.tick_to(6100);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].branch, "2");  // 갈래 ①은 성립하지 않았다
  ASSERT_EQ(h.alerts[1].ues.size(), 1u);
  EXPECT_EQ(h.alerts[1].ues[0].du_ue_id, 3);
  EXPECT_EQ(h.alerts[1].ues[0].values.at("branch"), "1");
  EXPECT_EQ(h.alerts[1].values.at("branch1_ues"), 1);
  EXPECT_EQ(h.alerts[1].values.at("branch2_ues"), 1);
  int pre = 0;
  for (const std::string& line : h.drain())
    if (line.find(R"("phase":"pre")") != std::string::npos && line.find(R"("ue":[1,3,1])") != std::string::npos) ++pre;
  EXPECT_EQ(pre, 7);  // RAISE 때 recent 7줄(연결 4줄·거부·등록 요청 2줄) — UPDATE로 다시 실려도 다시 내지 않는다
}

// L21-T21 (나): 갈래 ② 경보 중 갈래 ①이 처음 성립 — 창 안 실패 UE 가운데 아직 안 실린 것(경보 전에 판정된 A)을 함께 싣고
// 바로 UPDATE, branch "1"·high (15_ §5.5, 10/29 이슈 #31)
TEST(UplinkDos, T21Branch1FirstSatisfiedInBranch2Alert) {
  Harness h;
  h.fail_conn(1000, 10);  // A — 실패 UE 6000 (경보 전)
  h.fail_conn(2000, 11);  // B — 7000
  h.fail_conn(3000, 12);  // C — 8000
  h.fail_conn(4000, 13);  // D — 9000
  h.connect(4990, 9);     // 갈래 ② UE — 거부 5010, 등록 요청 5500·6500
  h.reject(5010, 9);
  h.nas(5500, 9, "UL", "RegistrationRequest", kSuci);
  h.tick_to(6000);
  EXPECT_TRUE(h.alerts.empty());
  h.nas(6500, 9, "UL", "RegistrationRequest", kSuci);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].branch, "2");
  h.tick_to(10000);  // B·C·D는 경보 중에 실려 UPDATE로 나갔다
  ASSERT_EQ(h.alerts.size(), 4u);
  h.tick_to(10100);  // 갈래 ② UE 자신이 실패 UE(10010) — F_W 5로 갈래 ① 첫 성립
  ASSERT_EQ(h.alerts.size(), 5u);
  const AlertEvent& e = h.alerts[4];
  EXPECT_EQ(e.kind, AlertEventKind::Update);
  EXPECT_EQ(e.severity, Severity::High);
  EXPECT_EQ(e.branch, "1");
  EXPECT_EQ(dus(e), (std::vector<int64_t>{10, 9}));
  EXPECT_EQ(e.ues_total, 6);
  EXPECT_EQ(e.values.at("fails_w"), 5);
  EXPECT_EQ(e.values.at("branch1_ues"), 5);
  EXPECT_EQ(e.values.at("branch2_ues"), 1);
}

// L01-T18의 L3-21 쪽 (15_ §4.1 전제): 임의 SUCI 등록 반복 — RegistrationRequest(SUCI) → RegistrationReject, 1 s마다 새 연결.
// AuthenticationRequest가 없어 L3-01-O는 경보가 없고, L3-21 갈래 ①이 받는다
TEST(UplinkDos, L01T18RandomSuciGoesToBranch1) {
  Opt o;
  o.auth_stall = true;
  Harness h(o);
  flood(h, 20);
  h.tick_to(30000);
  EXPECT_TRUE(h.of("L3-01-O").empty());
  ASSERT_FALSE(h.of("L3-21").empty());
  EXPECT_EQ(h.of("L3-21")[0]->kind, AlertEventKind::Raise);
  EXPECT_EQ(h.of("L3-21")[0]->branch, "1");
  EXPECT_EQ(h.of("L3-21")[0]->t, kT0 + 10000);
}

// END (15_ §5.5): 입력이 끊겨 series가 input_lost를 내면 그 셀 경보를, 새 세션이면 모든 경보를 끝낸다. branch는 END에도 싣는다
TEST(UplinkDos, EndOnInputLostAndSessionReset) {
  {
    Opt o;
    o.scfg.h_hold_ms = 3000;  // 기동 직후 1단계 보류(2 s)보다 길게
    Harness h(o);
    flood(h, 5);
    h.tick_to(10000);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.cc.clear();  // 1단계 필수 키가 빠진 칸 — 보류(10000부터)가 H_hold를 넘으면 input_lost
    h.tick_to(13100);
    EXPECT_EQ(h.alerts.size(), 1u);
    h.tick_to(13200);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "input_lost");
    EXPECT_EQ(h.alerts[1].branch, "1");
  }
  {
    Harness h;
    h.repeat_ue(1000, 3);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.alerts[1].branch, "2");
    EXPECT_EQ(h.rule->waiting(), 0u);
  }
}

// late_until (14_ §4.3 — Q-57 해결, 이슈 #46): 연결·거부 줄이 늦게 온 UE의 갈래 ① 마감(t_f + 5 s)이 늦은 줄 + 16 s 안이면
// 실패 UE로 세지 않고, 그 뒤의 새 실패(마감이 late_until 뒤)는 센다 — n_fail 1로 RAISE까지, ues[].uncertain에 late
TEST(UplinkDos, LateUntil) {
  Opt o;
  o.cfg.n_fail = 1;
  Harness h(o);
  h.tick_to(1100);          // 워터마크 1100
  h.connect(1000, 10);      // 1000·1010 늦음
  h.reject(1020, 10);       // 늦음 → late_until 17020, t_f 1020 → 마감 6020 < 17020 → 판정 없음
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(7000);
  EXPECT_EQ(h.rule->failed_ues(), 0);
  EXPECT_EQ(h.rule->waiting(), 0u);
  EXPECT_TRUE(h.alerts.empty());
  h.reject(17100, 10);      // 늦지 않은 새 실패 → 마감 22100 ≥ 17020 → 실패 UE → RAISE 22100
  h.tick_to(22100);
  EXPECT_EQ(h.rule->failed_ues(), 1);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + 22100);
  EXPECT_EQ(h.alerts[0].branch, "1");
  ASSERT_EQ(h.alerts[0].ues.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"late"}));
}

// L21-T23 (15_ §5.5 — Q-56 해결, 이슈 #44): 갈래 ① RAISE 뒤 그 셀에 상태표 밀어내기가 있으면 마지막 성립 + clear_quiet_ms가
// 지나도 CLEAR하지 않고, 직전 clear_quiet_ms 동안 밀어내기가 0건이 된 칸에서 푼다
TEST(UplinkDos, T23EvictionHoldsClear) {
  Opt o;
  o.ue_cfg.max_ues = 100;
  Harness h(o);
  for (int i = 0; i < 5; ++i) h.fail_conn(1000 + 200 * i, 10 + i);  // 실패 UE 5개: 마지막 t_f 1800 + 5 s = 6800 → RAISE 6800
  h.tick_to(30000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].t, kT0 + 6800);
  EXPECT_EQ(h.alerts[0].values.at("evicted"), 0);
  for (int64_t i = 0; i < 101; ++i) h.connect(30000 + 10 * i, 1000 + i);  // 실패 연결은 해제됐으므로 101번째(31000)에서 밀어내기 1회
  h.tick_to(66900);  // 보류가 없었다면 6800 + 60 s → 66800에 CLEAR
  EXPECT_EQ(h.engine.ue_table().counts(1).evicted, 1);
  EXPECT_EQ(h.alerts.size(), 1u);
  h.tick_to(91100);  // 밀어내기를 본 칸 31100 + 60 s
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 91100);
}

// 증거 지평 (14_ §1.1): 실패 뒤 수락 대기 + 셀 창 + UPDATE 모음 지연. 상태표는 여기에 여유 1 s를 더해 닫힌 항목의 recent를 보관한다
TEST(UplinkDos, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 16000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 17000);
}
