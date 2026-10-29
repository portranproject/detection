// 룰 L3-01-O 인증 단계 고착 테스트 — 15_ §4.8 L01-T1~T19, 상태표 포화(이슈 #42 → #44), 입력 침묵(이슈 #50). 합성 ue_evt·kpm2 줄로 한다(데이터 파일은 설정 키·데이터 이슈).
// 시각은 kT0 기준 ms. k번째 고착은 그 UE의 t₀ + auth_wait_ms, 경보는 그 시각 이상인 첫 kpm2(최대 100 ms 뒤)에서 나온다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/auth_stall.h"
#include "detect/rules/bts_variant.h"

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
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
const std::string kCells = R"([{"cell_id":1,"max_conn":null},{"cell_id":2,"max_conn":null}])";
const std::string kRandom = R"("ue_identity":{"type":"randomValue"})";
const std::string kSuci = R"("reg_type":"initial","id_type":"SUCI")";

struct Opt {
  AuthStallConfig cfg;
  SeriesConfig scfg;
  UeTableConfig ue_cfg;  // 상태표 상한 등 (포화 시험, 이슈 #42)
  AlertConfig alert;     // 불확실 경보 켜기 등 (이슈 #48)
  bool record = false;  // 증거 기록기도 돌린다
  bool stage1 = false;  // 1단계 L3-01-V도 함께 (L01-T15)
  std::string cells = kCells;
};

Opt n_stall(int64_t n) {
  Opt o;
  o.cfg.n_stall = n;
  return o;
}

// 엔진 + L3-01-O (+ 1단계, 증거 기록기). ue_evt를 넣기 전에 그 셀 시계를 그 줄이 든 창 앞까지 kpm2로 올린다 —
// 같은 창의 ue_evt는 그 kpm2보다 먼저 온다(2_ §6.1). 줄은 셀마다 시각 순으로 넣는다
class Harness {
 public:
  explicit Harness(Opt o = {})
      : engine(o.scfg, kDefaultMaxLineBytes, o.ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(o.record), cells_(o.cells) {
    if (o.stage1) engine.add_rule(std::make_unique<BtsVariantRule>());
    auto r = std::make_unique<AuthStallRule>(o.cfg, o.alert);
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
         R"(,"cells":)" + cells_ + R"(,"period_ms":100,"noreply_timeout_ms":1000,"clock":"realtime","ue_evt":true})");
  }
  void ue(int64_t t, int64_t du, const std::string& dir, const std::string& proto, const std::string& msg,
          const std::string& f, const std::string& extra, int64_t cell) {
    tick_to(t - t % 100, cell);
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
           int64_t cell = 1) {
    ue(t, du, dir, "NAS", msg, f, R"(,"via":"F1","sht":0)", cell);
  }
  void kpm(int64_t t, int64_t cell = 1) {
    next_t_[cell] = t + 100;
    const auto lost = lost_.find({cell, t});
    const auto cx = uectx_.find({cell, t});
    feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"cell_id":)" + std::to_string(cell) + R"(,"t_start_ms":)" + std::to_string(kT0 + t) +
         R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) + (cc.empty() ? "" : R"(,"cc":)" + cc) +
         (cx == uectx_.end() ? "" : R"(,"ext":{"UeCtxMax":)" + std::to_string(cx->second) + "}") +
         R"(,"ue_evt_lost":)" + (lost == lost_.end() ? "[]" : lost->second) + "}");
  }
  // 그 셀 kpm2를 창 시작 < t인 것까지 보낸다 — 마지막 창의 t_end_ms ≥ t
  void tick_to(int64_t t, int64_t cell = 1) {
    while (next_t_[cell] < t) kpm(next_t_[cell], cell);
  }
  void lost(int64_t window, const std::string& dirs, int64_t cell = 1) { lost_[{cell, window}] = dirs; }
  void uectx(int64_t window, int64_t v, int64_t cell = 1) { uectx_[{cell, window}] = v; }

  // 연결과 등록 요청(SUCI) — 인증 요청 전까지. f_complete는 RRCSetupComplete의 f(S-TMSI 등)
  void connect(int64_t t, int64_t du, int64_t cell = 1, const std::string& f_complete = "") {
    rrc(t, du, "UL", "RRCSetupRequest", kRandom, cell);
    rrc(t, du, "DL", "RRCSetup", "", cell);
    rrc(t + 10, du, "UL", "RRCSetupComplete", f_complete, cell);
    nas(t + 10, du, "UL", "RegistrationRequest", kSuci, cell);
  }
  void auth_req(int64_t t, int64_t du, int64_t cell = 1) { nas(t, du, "DL", "AuthenticationRequest", "", cell); }
  // 공격 UE — t₀ = 인증 요청 시각, 응답하지 않는다. 마감 = t₀ + auth_wait_ms
  void stall_ue(int64_t t0, int64_t du, int64_t cell = 1, const std::string& f_complete = "") {
    connect(t0 - 30, du, cell, f_complete);
    auth_req(t0, du, cell);
  }
  // 정상 UE — 인증 요청 뒤 13 ms에 응답 (15_ §4.8 L01-T1)
  void normal_ue(int64_t t0, int64_t du, int64_t cell = 1) {
    connect(t0 - 30, du, cell);
    auth_req(t0, du, cell);
    nas(t0 + 13, du, "UL", "AuthenticationResponse", "", cell);
  }
  void release(int64_t t, int64_t du, int64_t cell = 1) {
    ue(t, du, "DL", "F1AP", "UEContextReleaseCommand", "", "", cell);
    ue(t, du, "UL", "F1AP", "UEContextReleaseComplete", "", "", cell);
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

  Engine engine;
  EvidenceQueue queue;
  EvidenceRecorder rec;
  AuthStallRule* rule = nullptr;
  std::string cc = kCc;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string cells_;
  std::string session_;
  int64_t seq_ = 0;
  std::map<int64_t, int64_t> next_t_;
  std::map<std::pair<int64_t, int64_t>, std::string> lost_;
  std::map<std::pair<int64_t, int64_t>, int64_t> uectx_;
};

// L01-T3 공격: 초당 3건 — t₀ = 1000 + 333·i (i = 0..n−1), 마감 3000·3333·3666·3999·4332·…
void attack(Harness& h, int n, int64_t du0 = 10) {
  for (int i = 0; i < n; ++i) h.stall_ue(1000 + 333 * i, du0 + i);
}

std::string t_str(int64_t t) { return std::to_string(kT0 + t); }

}  // namespace

// L01-T1: 정상 등록 — AuthenticationRequest 뒤 13 ms에 AuthenticationResponse → 고착 없음
TEST(AuthStall, T01NormalRegistration) {
  Harness h;
  h.normal_ue(1000, 3);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.nas(1100, 3, "DL", "RegistrationAccept");
  h.tick_to(20000);
  EXPECT_EQ(h.rule->stalls(), 0);
  EXPECT_TRUE(h.alerts.empty());
}

// L01-T2: 정상 UE 하나가 인증 요청 직후 무응답(전파 끊김) — 고착 1, 셀 문턱 N 미만이라 경보 없음
TEST(AuthStall, T02SingleStallNoAlert) {
  Harness h;
  h.stall_ue(1000, 3);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(20000);
  EXPECT_EQ(h.rule->stalls(), 1);
  EXPECT_TRUE(h.alerts.empty());
}

// L01-T3: 초당 3건 고착 — 5번째 고착 = t₀ + 4/3 s + 2 s(4332) → 그 뒤 첫 kpm2(t_end 4400)에 RAISE, stalls_w 5 (15_ §4.3·§4.6)
TEST(AuthStall, T03FloodRaises) {
  Harness h;
  attack(h, 5);
  h.tick_to(4300);
  EXPECT_EQ(h.rule->stalls(), 4);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(4400);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-01-O");
  EXPECT_EQ(e.stage, 2);
  EXPECT_EQ(e.unit, "ue");
  EXPECT_FALSE(e.branch.has_value());
  EXPECT_EQ(e.t, kT0 + 4400);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"stall_count"}));
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"AN-01"}));
  EXPECT_EQ(e.alert_id.rfind("S-L3-01-O-1-", 0), 0u);
  EXPECT_EQ(e.values.dump(), R"({"stalls_w":5,"stalls_total":5,"auth_req_w":5,"held":0,"evicted":0,"uectx":null})");
  EXPECT_EQ(e.params.dump(),
            R"({"auth_wait_ms":2000,"window_ms":10000,"n_stall":5,"clear_quiet_ms":60000,"max_conn":96})");
  EXPECT_EQ(e.ues_total, 5);
  ASSERT_EQ(e.ues.size(), 5u);
  const int64_t t_hit[] = {3000, 3333, 3666, 3999, 4332};
  for (std::size_t i = 0; i < 5; ++i) {
    const AlertUe& u = e.ues[i];
    EXPECT_EQ(u.du_ue_id, static_cast<int64_t>(10 + i));
    EXPECT_EQ(u.uid, static_cast<int64_t>(1 + i));
    EXPECT_EQ(u.crnti, 17010 + static_cast<int64_t>(i));
    EXPECT_FALSE(u.s_tmsi.has_value());
    EXPECT_EQ(u.t_hit, kT0 + t_hit[i]);
    EXPECT_EQ(u.cond, (std::vector<std::string>{"auth_no_resp"}));
    EXPECT_TRUE(u.uncertain.empty());
    EXPECT_TRUE(u.peers.empty());
    EXPECT_EQ(u.values.dump(),
              R"({"nas":"RegistrationRequest","id_type":"SUCI","wait_ms":2000,"closed_ms":null,"auth_req_n":1,"other_ul":0})");
  }
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-01-O cell=1 t=" + t_str(4400) +
                           " stalls_w=5 n_stall=5 window_ms=10000 auth_wait_ms=2000 uectx=null severity=medium "
                           "mode=normal candidates=AN-01");
}

// 경보 중 새 고착 UE는 모았다가 RAISE 뒤 alert.update_min_ms(1 s)가 지난 첫 kpm2에 UPDATE로 낸다 (15_ §4.5, 14_ §8.2)
TEST(AuthStall, T03LaterStallsUpdate) {
  Harness h;
  attack(h, 8);  // 6·7·8번째 마감 4665·4998·5331
  h.tick_to(5300);
  ASSERT_EQ(h.alerts.size(), 1u);
  h.tick_to(5400);
  ASSERT_EQ(h.alerts.size(), 2u);
  const AlertEvent& e = h.alerts[1];
  EXPECT_EQ(e.kind, AlertEventKind::Update);
  EXPECT_EQ(e.t, kT0 + 5400);
  ASSERT_EQ(e.ues.size(), 3u);
  EXPECT_EQ(e.ues[0].du_ue_id, 15);
  EXPECT_EQ(e.ues_total, 8);
  EXPECT_EQ(e.values.dump(), R"({"stalls_w":8,"stalls_total":8,"auth_req_w":8,"held":0,"evicted":0,"uectx":null})");
  EXPECT_TRUE(e.params.is_null());
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-01-O cell=1 t=" + t_str(5400) + " ues_new=3 ues_total=8 severity=medium");
}

// L01-T4: 10 s 안 고착 4건 / 5건 — 앞은 경보 없음, 뒤는 5번째 고착 시각에 RAISE. 창은 (t_hit − W, t_hit]이라
// 정확히 10 s에 걸친 5건은 4건으로 센다
TEST(AuthStall, T04ThresholdAndWindow) {
  {
    Harness h;
    for (int i = 0; i < 4; ++i) h.stall_ue(1000 + 2000 * i, 10 + i);  // 고착 3000·5000·7000·9000
    h.tick_to(30000);
    EXPECT_EQ(h.rule->stalls(), 4);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    for (int i = 0; i < 5; ++i) h.stall_ue(1000 + 2400 * i, 10 + i);  // 고착 3000 … 12600
    h.tick_to(12600);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + 12600);
    EXPECT_EQ(h.alerts[0].values.at("stalls_w"), 5);
  }
  {
    Harness h;
    for (int i = 0; i < 5; ++i) h.stall_ue(1000 + 2500 * i, 10 + i);  // 고착 3000 … 13000 — 3000은 창 밖
    h.tick_to(30000);
    EXPECT_EQ(h.rule->stalls(), 5);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// L01-T5: 응답이 AuthenticationFailure — 응답으로 본다 → 고착 없음(L3-21 쪽 모양)
TEST(AuthStall, T05AuthFailureIsResponse) {
  Harness h;
  h.connect(970, 3);
  h.auth_req(1000, 3);
  h.nas(1020, 3, "UL", "AuthenticationFailure", R"("cause":21)");
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(10000);
  EXPECT_EQ(h.rule->stalls(), 0);
}

// L01-T6: 응답 t_ms = t₀ + 1,999 / t₀ + 2,000 — 앞은 고착 없음, 뒤는 고착(늦은 응답, 14_ §6.1-5)
TEST(AuthStall, T06ResponseBoundary) {
  {
    Harness h;
    h.connect(970, 3);
    h.auth_req(1000, 3);
    h.nas(2999, 3, "UL", "AuthenticationResponse");
    h.tick_to(10000);
    EXPECT_EQ(h.rule->stalls(), 0);
  }
  {
    Harness h;
    h.connect(970, 3);
    h.auth_req(1000, 3);
    h.nas(3000, 3, "UL", "AuthenticationResponse");
    h.tick_to(10000);
    EXPECT_EQ(h.rule->stalls(), 1);
  }
  {  // 마감(3050)이 든 창 [3000,3100) 안의 늦은 응답 — 마감 처리 전에 도착해도 풀지 않고 고착으로 센다.
     // 응답이 왔으므로 다음 요청은 새로 기다린다
    Harness h;
    h.connect(1020, 3);
    h.auth_req(1050, 3);
    h.nas(3060, 3, "UL", "AuthenticationResponse");
    EXPECT_EQ(h.rule->waiting(), 1u);
    h.tick_to(5000);
    EXPECT_EQ(h.rule->stalls(), 1);
    h.auth_req(5000, 3);
    EXPECT_EQ(h.rule->waiting(), 1u);
  }
}

// L01-T7: 기다리는 중 AMF 재전송 → 기다림 다시 시작 안 함, 고착 1번, auth_req_n 2 / 고착 뒤 응답 없이 재전송(T3560 6 s)
// → 다시 세지 않음(10/29 이슈 #29 사용자 결정) / 응답 뒤 새 요청 → 새로 기다림
TEST(AuthStall, T07Retransmissions) {
  Harness h(n_stall(1));
  h.connect(970, 3);
  h.auth_req(1000, 3);
  h.auth_req(2000, 3);  // 기다리는 중 재전송
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("auth_req_n"), 2);
  EXPECT_EQ(h.alerts[0].ues[0].t_hit, kT0 + 3000);

  for (int64_t t : {9000, 15000, 21000}) {  // 마감 뒤 재전송 — 응답이 없으므로 새로 기다리지 않는다
    h.auth_req(t, 3);
    EXPECT_EQ(h.rule->waiting(), 0u);
  }
  h.tick_to(22000);
  EXPECT_EQ(h.rule->stalls(), 1);

  h.nas(22000, 3, "UL", "AuthenticationResponse");  // 응답 — 다음 요청은 새로 기다린다
  h.auth_req(23000, 3);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(25000);
  EXPECT_EQ(h.rule->stalls(), 2);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].ues[0].values.at("auth_req_n"), 1);
}

// L01-T8: AuthenticationFailure(동기 실패) 뒤 재인증 요청 → 응답 — 새 기다림이 응답으로 풀림, 고착 없음
TEST(AuthStall, T08SyncFailureThenReauth) {
  Harness h;
  h.connect(970, 3);
  h.auth_req(1000, 3);
  h.nas(1020, 3, "UL", "AuthenticationFailure", R"("cause":21)");
  h.auth_req(1040, 3);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.nas(1060, 3, "UL", "AuthenticationResponse");
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(10000);
  EXPECT_EQ(h.rule->stalls(), 0);
}

// L01-T9: 공격 중 대기 구간에 ue_evt_lost ["UL","DL"] 창 — 그 UE들은 보류(held 증가), 나머지로 성립 판단 (14_ §6.2)
TEST(AuthStall, T09LossHoldsSomeStalls) {
  Harness h;
  h.lost(1500, R"(["UL","DL"])");  // loss_end[UL] = 1600 — t₀ 1000·1333인 두 UE가 보류
  attack(h, 7);                    // 나머지 다섯의 마감 3666·3999·4332·4665·4998
  h.tick_to(4900);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(5000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.rule->held(), 2);
  // auth_req_w는 창 안에 AuthenticationRequest를 받은 UE 수 — 보류된 둘도 받았다 (참고용)
  EXPECT_EQ(h.alerts[0].values.dump(), R"({"stalls_w":5,"stalls_total":5,"auth_req_w":7,"held":2,"evicted":0,"uectx":null})");
  EXPECT_EQ(h.alerts[0].ues[0].du_ue_id, 12);
}

// L01-T10: 대기 구간에 ue_evt_lost ["DL"](2차 방향별) — UL을 기다리므로 보류 안 함
TEST(AuthStall, T10DlLossDoesNotHold) {
  Harness h(n_stall(1));
  h.lost(1500, R"(["DL"])");
  h.stall_ue(1000, 3);
  h.tick_to(3000);
  EXPECT_EQ(h.rule->held(), 0);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].values.at("held"), 0);
}

// L01-T11: 무응답 연결이 1 s 뒤 해제 — 마감 때 고착, closed_ms 1,000. 닫힌 UE의 recent는 상태표가 보관해 pre 증거로 낸다
TEST(AuthStall, T11ClosedBeforeDeadline) {
  Opt o = n_stall(1);
  o.record = true;
  Harness h(o);
  h.stall_ue(1000, 3);
  h.release(2000, 3);
  EXPECT_EQ(h.engine.ue_table().find(UeKey{1, 3}), nullptr);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertUe& u = h.alerts[0].ues[0];
  EXPECT_EQ(u.values.at("closed_ms"), 1000);
  EXPECT_EQ(u.du_ue_id, 3);
  EXPECT_EQ(u.uid, 1);
  int pre = 0;
  for (const std::string& line : h.drain())
    if (line.find(R"("phase":"pre")") != std::string::npos && line.find(R"("ue":[1,3,1])") != std::string::npos) ++pre;
  EXPECT_EQ(pre, 7);  // RRCSetupRequest·RRCSetup·RRCSetupComplete·RegistrationRequest·AuthenticationRequest·해제 두 줄
}

// L01-T12: 첫 줄이 AuthenticationRequest인 항목(mid_join) — 판정 없음 (14_ §4.3)
TEST(AuthStall, T12MidJoinNotJudged) {
  Harness h;
  h.auth_req(1000, 3);
  EXPECT_TRUE(h.engine.ue_table().find(UeKey{1, 3})->mid_join);
  EXPECT_EQ(h.rule->waiting(), 0u);
  h.tick_to(10000);
  EXPECT_EQ(h.rule->stalls(), 0);
}

// L01-T13: 해제 — 공격이 멈춘 뒤 30 s에 정상 고착 1건. 성립하지 않으므로 해제는 t_sat(4332) + 60 s 뒤 첫 kpm2 (15_ §4.5)
TEST(AuthStall, T13ClearAfterQuiet) {
  Harness h;
  attack(h, 5);
  h.stall_ue(32332, 30);  // 고착 34332 — 경보에는 실리지만 성립은 아니다
  h.tick_to(34400);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].values.at("stalls_w"), 1);
  h.tick_to(64300);
  EXPECT_EQ(h.alerts.size(), 2u);
  h.tick_to(64400);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.logs[2], "ALERT CLEAR rule=L3-01-O cell=1 t=" + t_str(64400) + " duration_ms=60000 ues_total=6");
}

// L01-T14: 성립 창에 ext.UeCtxMax 96 → high (96 ≥ 0.9 × 96), 없음 → medium(T3)
TEST(AuthStall, T14SeverityHighOnUeCtx) {
  Harness h;
  h.uectx(4000, 96);
  attack(h, 5);
  h.tick_to(4400);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].severity, Severity::High);
  EXPECT_EQ(h.alerts[0].values.at("uectx"), 96);
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-01-O cell=1 t=" + t_str(4400) +
                           " stalls_w=5 n_stall=5 window_ms=10000 auth_wait_ms=2000 uectx=96/96 severity=high "
                           "mode=normal candidates=AN-01");
}

// 경보 중 셀 자원이 차면 바로 UPDATE로 high (15_ §4.3 '경보 중 medium → high면 update')
TEST(AuthStall, T14SeverityRiseUpdates) {
  Harness h;
  attack(h, 5);
  h.uectx(5000, 96);
  h.tick_to(5100);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].severity, Severity::High);
  EXPECT_TRUE(h.alerts[1].ues.empty());
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-01-O cell=1 t=" + t_str(5100) +
                           " ues_new=0 ues_total=5 severity=high uectx=96/96");
  h.tick_to(8000);  // 다시 내지 않는다
  EXPECT_EQ(h.alerts.size(), 2u);
}

// max_conn: hello cells[].max_conn이 설정값보다 우선 (15_ §1.2) / 둘 다 없으면 high를 쓰지 않고 로그는 uectx=Cx
TEST(AuthStall, T14MaxConnSource) {
  {
    Opt o;
    o.cells = R"([{"cell_id":1,"max_conn":50}])";
    Harness h(o);
    h.uectx(4000, 45);  // 45 ≥ 0.9 × 50 (설정값 96이면 medium)
    attack(h, 5);
    h.tick_to(4400);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].severity, Severity::High);
    EXPECT_EQ(h.alerts[0].params.at("max_conn"), 50);
    EXPECT_NE(h.logs[0].find(" uectx=45/50 "), std::string::npos);
  }
  {
    Opt o;
    o.cfg.max_conn = std::nullopt;
    Harness h(o);
    h.uectx(4000, 96);
    attack(h, 5);
    h.tick_to(4400);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
    EXPECT_TRUE(h.alerts[0].params.at("max_conn").is_null());
    EXPECT_NE(h.logs[0].find(" uectx=96 "), std::string::npos);
  }
}

// L01-T15: T3을 1단계 룰과 함께 재생(Att·Succ 함께 증가) — L3-01-V 경보 없음, L3-01-O만 (15_ §4.1)
TEST(AuthStall, T15WithStage1) {
  Opt o;
  o.stage1 = true;
  Harness h(o);
  h.cc =
      R"({"RRC.ConnEstabAtt":{"total":1},"RRC.ConnEstabSucc":{"total":1},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
  attack(h, 5);
  h.tick_to(40000);
  EXPECT_TRUE(h.of("L3-01-V").empty());
  ASSERT_EQ(h.of("L3-01-O").size(), 1u);
  EXPECT_EQ(h.of("L3-01-O")[0]->t, kT0 + 4400);
}

// L01-T16: 고착 UE 중 하나가 RRCSetupComplete에 S-TMSI를 냄 — candidates ["AN-01","L3-20"] (15_ §4.6)
TEST(AuthStall, T16StmsiAddsL320Candidate) {
  Harness h;
  for (int i = 0; i < 5; ++i) h.stall_ue(1000 + 333 * i, 10 + i, 1, i == 2 ? R"("s_tmsi":"0x0123456789ab")" : "");
  h.tick_to(4400);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].candidates, (std::vector<std::string>{"AN-01", "L3-20"}));
  EXPECT_EQ(h.alerts[0].ues[2].s_tmsi, uint64_t{0x0123456789ab});
  EXPECT_NE(h.logs[0].find(" candidates=AN-01,L3-20"), std::string::npos);
}

// L01-T17: 재생 결정성 — T3을 두 번 재생하면 경보·증거 바이트 동일
TEST(AuthStall, T17Deterministic) {
  auto run = [] {
    Opt o;
    o.record = true;
    Harness h(o);
    attack(h, 8);
    h.tick_to(70000);
    std::vector<std::string> v = h.logs;
    for (std::string& line : h.drain()) v.push_back(std::move(line));
    return v;
  };
  const std::vector<std::string> a = run();
  const std::vector<std::string> b = run();
  EXPECT_EQ(a, b);
  ASSERT_GE(a.size(), 3u);
  EXPECT_EQ(a[2].rfind("ALERT CLEAR rule=L3-01-O", 0), 0u);
}

// L01-T18: 임의 SUCI 등록 반복 — RegistrationRequest(SUCI) → RegistrationReject, 1 s마다 새 연결. AuthenticationRequest가
// 없어 기다림이 없다 → L3-01-O 경보 없음(15_ §4.1 전제). L3-21 갈래 ① RAISE는 L3-21 이슈에서 확인한다
TEST(AuthStall, T18RandomSuciRejectNotStall) {
  Harness h;
  for (int i = 0; i < 20; ++i) {
    const int64_t t = 1000 + 1000 * i;
    h.connect(t, 10 + i);
    h.nas(t + 20, 10 + i, "DL", "RegistrationReject", R"("cause":3)");
    EXPECT_EQ(h.rule->waiting(), 0u);
    h.release(t + 40, 10 + i);
  }
  h.tick_to(30000);
  EXPECT_EQ(h.rule->stalls(), 0);
  EXPECT_TRUE(h.alerts.empty());
}

// L01-T19: AuthenticationRequest 뒤 응답 대신 RegistrationRequest만 다시 옴 — 기다림 안 풀림 → 고착, other_ul 1 (검수 B2)
TEST(AuthStall, T19OtherUlDoesNotRelease) {
  Harness h(n_stall(1));
  h.connect(970, 3);
  h.auth_req(1000, 3);
  h.nas(1500, 3, "UL", "RegistrationRequest", kSuci);
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("other_ul"), 1);
}

// 앞선 요청이 ServiceRequest면 nas = ServiceRequest, id_type = null. 등록 중 끊고 나가는 UE(UL DeregistrationRequest)는
// 응답으로 본다 (15_ §4.2·§4.6·§4.9)
TEST(AuthStall, RequestKindAndDeregistration) {
  Harness h(n_stall(1));
  h.rrc(970, 3, "UL", "RRCSetupRequest", kRandom);
  h.rrc(980, 3, "UL", "RRCSetupComplete", R"("s_tmsi":"0x0123456789ab")");
  h.nas(980, 3, "UL", "ServiceRequest", R"("s_tmsi":"0x0123456789ab")");
  h.auth_req(1000, 3);
  h.connect(1170, 4);
  h.auth_req(1200, 4);
  h.nas(1300, 4, "UL", "DeregistrationRequest", R"("switch_off":false)");
  EXPECT_EQ(h.rule->waiting(), 1u);
  h.tick_to(3200);
  EXPECT_EQ(h.rule->stalls(), 1);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].ues[0].values.at("nas"), "ServiceRequest");
  EXPECT_TRUE(h.alerts[0].ues[0].values.at("id_type").is_null());
}

// END (15_ §4.5): 입력이 끊겨 series가 input_lost를 내면 그 셀 경보를, 새 세션이면 모든 경보를 끝낸다
TEST(AuthStall, EndOnInputLostAndSessionReset) {
  {
    Opt o;
    o.scfg.h_hold_ms = 3000;  // 기동 직후 1단계 보류(2 s)보다 길게
    Harness h(o);
    attack(h, 5);
    h.tick_to(4400);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.cc.clear();  // 1단계 필수 키가 빠진 칸 — 보류(4400부터)가 H_hold를 넘으면 input_lost
    h.tick_to(7500);
    EXPECT_EQ(h.alerts.size(), 1u);
    h.tick_to(7600);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "input_lost");
    EXPECT_EQ(h.logs[1], "ALERT END rule=L3-01-O cell=1 t=" + t_str(7600) + " duration_ms=3200 reason=input_lost");
  }
  {
    Harness h;
    attack(h, 6);
    h.tick_to(4400);
    EXPECT_EQ(h.rule->waiting(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.rule->waiting(), 0u);
  }
}

// 입력 침묵 (14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 공격 경보 중 실행 파일이 침묵을 알리면 END(reason=input_silent, t = 경보가
// 마지막으로 본 칸)와 진단 1회. 대기 표시·셀 기록은 그대로라(on_session_reset과 다름) kpm2가 다시 오면 남은 마감이 평소처럼 판정된다 —
// 창 안 고착 수가 N 이상이면 새 RAISE. 열린 불확실 경보도 같은 이유로 END
TEST(AuthStall, EndOnInputSilent) {
  {
    Harness h;
    attack(h, 6);  // 마감 3000·3333·3666·3999·4332·4665 — 다섯째로 4400에서 RAISE, 여섯째는 아직 대기
    h.tick_to(4400);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.rule->waiting(), 1u);
    const std::size_t ues = h.engine.ue_table().size();
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
    EXPECT_EQ(o.alerts[0].alert_kind, "attack");
    EXPECT_EQ(o.alerts[0].alert_id, h.alerts[0].alert_id);
    EXPECT_EQ(o.alerts[0].t, kT0 + 4400);
    EXPECT_EQ(format_log_line(o.alerts[0]),
              "ALERT END rule=L3-01-O cell=1 t=" + t_str(4400) + " duration_ms=0 reason=input_silent");
    ASSERT_EQ(o.diags.size(), 1u);
    EXPECT_EQ(o.diags[0].kind, DiagKind::InputSilent);
    EXPECT_EQ(h.rule->waiting(), 1u);  // 대기 표시·상태표·셀 시계 유지
    EXPECT_EQ(h.engine.ue_table().size(), ues);
    EXPECT_EQ(h.engine.deadlines().clock(1), kT0 + 4400);
    // 재개: 여섯째 마감(4665)이 4700에서 고착으로 — 창 안 고착 6 ≥ 5 → 새 경보로 RAISE
    h.tick_to(4700);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Raise);
    EXPECT_EQ(h.alerts[1].t, kT0 + 4700);
    EXPECT_NE(h.alerts[1].alert_id, h.alerts[0].alert_id);
    EXPECT_EQ(h.rule->stalls(), 6);
    EXPECT_EQ(h.rule->waiting(), 0u);
  }
  {
    Harness h;  // 불확실 경보 중 — 같이 END
    h.lost(2500, R"(["UL"])");
    attack(h, 5);
    h.tick_to(4400);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].alert_kind, "anomaly");
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
    EXPECT_EQ(o.alerts[0].alert_id, h.alerts[0].alert_id);
  }
}

// 상태표 포화 (이슈 #44 — 14_ §4.4 보호 무리, 16_ §3.1-1 실험 F; 이슈 #42의 '현재 동작 고정'을 뒤집은 것).
// 고착 공격 20/s(50 ms 간격, 해제 줄 없음)로 상한 100이 CONNECTED 고착 연결로 차도, 새 항목(최근 줄)·대기 표시가 걸린 항목은
// 보호 무리라 밀리지 않고 보호 밖의 오래된 고착 항목이 밀린다. 보호 무리만 남은 포화 직후에도 예비 순서(마감 없는 것 중 가장
// 오래된 것)가 막 연 항목을 지켜 판정이 이어진다. kpm2에 si가 없어 유령 정리는 돌지 않는다. 밀어내기가 이어지는 동안 CLEAR는
// 나지 않는다(15_ §4.5 — 해제 보류는 이슈 #44 커밋 ③). 줄은 UE끼리 섞이도록 시각 순으로 넣는다
TEST(AuthStall, SaturationKeepsVerdicts) {
  Opt o;
  o.ue_cfg.max_ues = 100;
  Harness h(o);
  // UE i: RRCSetupRequest t_i = 1000 + 50 i, RRCSetup t_i + 1, RRCSetupComplete t_i + 90, RegistrationRequest t_i + 91,
  // AuthenticationRequest t_i + 105 (gen_stage2.py의 auth_stall과 같은 간격). 1,400대 = 70 s
  struct Ev {
    int64_t t;
    int64_t du;
    int step;
  };
  std::vector<Ev> evs;
  for (int64_t i = 0; i < 1400; ++i) {
    const int64_t t = 1000 + 50 * i;
    const int64_t du = 10 + i;
    evs.push_back({t, du, 0});
    evs.push_back({t + 1, du, 1});
    evs.push_back({t + 90, du, 2});
    evs.push_back({t + 91, du, 3});
    evs.push_back({t + 105, du, 4});
  }
  std::stable_sort(evs.begin(), evs.end(), [](const Ev& a, const Ev& b) { return a.t < b.t; });
  for (const Ev& e : evs) {
    switch (e.step) {
      case 0: h.rrc(e.t, e.du, "UL", "RRCSetupRequest", kRandom); break;
      case 1: h.rrc(e.t, e.du, "DL", "RRCSetup"); break;
      case 2: h.rrc(e.t, e.du, "UL", "RRCSetupComplete"); break;
      case 3: h.nas(e.t, e.du, "UL", "RegistrationRequest", kSuci); break;
      default: h.auth_req(e.t, e.du); break;
    }
  }
  h.tick_to(72000);
  // 표는 UE 99의 RRCSetupRequest(5950)에 100으로 찬다. 그 뒤 새 UE마다 가장 오래된 고착 항목이 하나씩 밀리고 새 UE는 판정된다
  // (이슈 #42 때는 99건에서 멈추고 68.1 s에 CLEAR). 마지막 UE 1399의 마감 72055는 72000 밖이라 1,400에 조금 못 미친다
  EXPECT_GE(h.rule->stalls(), 1370);
  EXPECT_LE(h.rule->stalls(), 1400);
  EXPECT_GE(h.engine.ue_table().counts(1).evicted, 1000);  // 상한 100 뒤 UE마다 하나씩
  EXPECT_LT(h.engine.ue_table().counts(1).evicted, 1400);  // 연쇄(밀린 UE가 다시 열려 또 밀림)가 없다
  ASSERT_GE(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts.front().kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts.front().t, kT0 + 3400);  // 5번째 고착 UE 4: 1000 + 200 + 105 + 2000 = 3305 → 다음 칸 3400
  const AlertEvent& last = h.alerts.back();
  EXPECT_EQ(last.kind, AlertEventKind::Update);  // 72 s까지 CLEAR 없음 — 밀어내기가 이어지는 동안은 풀지 않는다 (15_ §4.5)
  EXPECT_GE(last.t, kT0 + 71000);
  EXPECT_GE(last.ues_total, 1360);
  EXPECT_GT(last.values.at("evicted").get<int64_t>(), 0);
  for (std::size_t i = 1; i < h.alerts.size(); ++i) EXPECT_EQ(h.alerts[i].kind, AlertEventKind::Update);
}

// L01-T22 (15_ §4.5·§4.6 — Q-56 해결, 이슈 #44): 경보 중 그 셀에 상태표 밀어내기가 있으면 직전 clear_quiet_ms 동안
// 밀어내기가 0건이 될 때까지 CLEAR하지 않고, update의 values.evicted에 경보가 열린 뒤의 밀어내기 수를 싣는다
TEST(AuthStall, T22EvictionHoldsClear) {
  Opt o;
  o.ue_cfg.max_ues = 100;
  Harness h(o);
  attack(h, 5);  // RAISE 4400, t_sat 4332
  h.tick_to(30000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].values.at("evicted"), 0);
  // 정상 연결 101대(인증 전) — 5 + 101 > 100이라 96번째부터 밀어내기 6회(공격 항목 5 + 정상 1). 시각은 그 칸 kpm2의 t_end
  for (int64_t i = 0; i < 101; ++i) h.connect(30000 + 10 * i, 1000 + i);
  h.stall_ue(32000, 20);  // 연결(31970)에서 밀어내기 7번째, 고착 34000 → UPDATE 34000
  h.tick_to(34000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].t, kT0 + 34000);
  EXPECT_EQ(h.alerts[1].values.at("evicted"), 7);
  EXPECT_EQ(h.engine.ue_table().counts(1).evicted, 7);
  h.tick_to(91900);  // 보류가 없었다면 4332 + 60 s → 64400에 CLEAR. 마지막 밀어내기는 32000 칸에서 셈 → 92000까지 보류
  EXPECT_EQ(h.alerts.size(), 2u);
  h.tick_to(92000);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[2].t, kT0 + 92000);
}

// L01-T21 (15_ §1, 14_ §4.3 late_until — Q-57 해결, 이슈 #46): 연결·등록 줄이 늦게 온(순서 역전) UE 5대 — 2 s 뒤 무응답 마감은
// late_until(늦은 줄 + 13 s) 안이라 판정 없음·경보 없음. 17 s 뒤 다시 AuthenticationRequest 무응답이면 마감이 late_until 뒤라
// 고착 5건 → RAISE, ues[].uncertain에 late
TEST(AuthStall, T21LateUntil) {
  Harness h;
  h.tick_to(1100);  // 워터마크 1100 — 아래 970~1080의 줄은 모두 늦다
  for (int i = 0; i < 5; ++i) h.stall_ue(1000 + 20 * i, 10 + i);  // 마지막 늦은 줄 1080 → late_until 14080
  EXPECT_EQ(h.rule->waiting(), 5u);
  h.tick_to(5000);  // 마감 3000~3080 < late_until → 판정 없음
  EXPECT_EQ(h.rule->stalls(), 0);
  EXPECT_EQ(h.rule->waiting(), 0u);
  EXPECT_TRUE(h.alerts.empty());
  for (int i = 0; i < 5; ++i) h.auth_req(17000 + 20 * i, 10 + i);  // 늦지 않은 줄, 마감 19000~19080 ≥ 14080
  h.tick_to(19100);
  EXPECT_EQ(h.rule->stalls(), 5);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].t, kT0 + 19100);
  ASSERT_EQ(h.alerts[0].ues.size(), 5u);
  for (const AlertUe& u : h.alerts[0].ues) EXPECT_EQ(u.uncertain, (std::vector<std::string>{"late"}));
}

// L01-T20·U-T30 (14_ §6.2·§8.2 불확실 경보 — Q-58 해결, 이슈 #48): 고착 대기 5건이 UL 로스 한 칸으로 모두 보류, 공격 경보 없음
// → 5번째 보류 칸에서 불확실 경보 RAISE(kind anomaly, held_w 5, candidates L3-01-O, ues[] cond held·uncertain loss). 그 뒤 보류
// 없이 고착 5건 → 같은 줄에서 불확실 CLEAR 뒤 공격 RAISE. 증거 기록기도 같은 순서로 alert 레코드를 낸다. 60 s 조용하면 CLEAR.
// alert.held_alert가 false면 불확실 경보 없음(보류 수는 그대로)
TEST(AuthStall, T20HeldAlert) {
  {
    Opt o;
    o.record = true;
    Harness h(o);
    h.lost(2500, R"(["UL"])");  // loss_end[UL] 2600 > t₀ 1000~2332 — 다섯 모두 보류(마감 3000~4332는 그 뒤)
    attack(h, 5);               // 마감 3000·3333·3666·3999·4332
    h.tick_to(4300);
    EXPECT_TRUE(h.alerts.empty());
    h.tick_to(4400);
    EXPECT_EQ(h.rule->held(), 5);
    EXPECT_EQ(h.rule->stalls(), 0);
    ASSERT_EQ(h.alerts.size(), 1u);
    const AlertEvent e = h.alerts[0];  // 복사 — 뒤에 alerts가 늘어난다
    EXPECT_EQ(e.kind, AlertEventKind::Raise);
    EXPECT_EQ(e.alert_kind, "anomaly");
    EXPECT_EQ(e.rule, "L3-01-O");
    EXPECT_EQ(e.t, kT0 + 4400);
    EXPECT_EQ(e.severity, Severity::Medium);
    EXPECT_EQ(e.cond, (std::vector<std::string>{"held_count"}));
    EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-01-O"}));
    EXPECT_EQ(e.values.dump(), R"({"held_w":5})");
    EXPECT_EQ(e.params.dump(), R"({"auth_wait_ms":2000,"window_ms":10000,"n_stall":5,"clear_quiet_ms":60000})");
    ASSERT_EQ(e.ues.size(), 5u);
    const int64_t t_hit[] = {3000, 3333, 3666, 3999, 4332};
    for (std::size_t i = 0; i < 5; ++i) {
      EXPECT_EQ(e.ues[i].du_ue_id, static_cast<int64_t>(10 + i));
      EXPECT_EQ(e.ues[i].cond, (std::vector<std::string>{"held"}));
      EXPECT_EQ(e.ues[i].t_hit, kT0 + t_hit[i]);
      EXPECT_EQ(e.ues[i].uncertain, (std::vector<std::string>{"loss"}));
      EXPECT_EQ(e.ues[i].values.dump(), R"({"wait_ms":2000,"dir":"UL"})");
    }
    EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-01-O cell=1 t=" + t_str(4400) +
                             " kind=anomaly held_w=5 n_stall=5 window_ms=10000 auth_wait_ms=2000 severity=medium "
                             "mode=normal candidates=L3-01-O");
    // U-T30: 그 뒤 로스 없이 고착 5건(t₀ 6000~7332, 마감 8000~9332) → 9400에서 불확실 CLEAR 다음 공격 RAISE
    for (int i = 0; i < 5; ++i) h.stall_ue(6000 + 333 * i, 20 + i);
    h.tick_to(9300);
    EXPECT_EQ(h.alerts.size(), 1u);
    h.tick_to(9400);
    ASSERT_EQ(h.alerts.size(), 3u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
    EXPECT_EQ(h.alerts[1].alert_id, e.alert_id);
    EXPECT_EQ(h.alerts[1].t, kT0 + 9400);
    EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=L3-01-O cell=1 t=" + t_str(9400) + " duration_ms=5000 ues_total=5");
    EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
    EXPECT_EQ(h.alerts[2].alert_kind, "attack");
    EXPECT_NE(h.alerts[2].alert_id, e.alert_id);
    EXPECT_EQ(h.alerts[2].values.at("held"), 5);  // 직전 60 s의 보류
    EXPECT_EQ(h.alerts[2].values.at("stalls_w"), 5);
    // 증거 레코드: alert raise(anomaly) → pre … → alert clear(anomaly) → alert raise(attack) 순
    std::vector<std::string> kinds;
    for (const std::string& line : h.drain())
      if (line.rfind(R"({"type":"alert")", 0) == 0) kinds.push_back(line);
    ASSERT_EQ(kinds.size(), 3u);
    EXPECT_NE(kinds[0].find(R"("event":"raise","rule":"L3-01-O","stage":2,"unit":"ue","kind":"anomaly")"), std::string::npos);
    EXPECT_NE(kinds[1].find(R"("event":"clear","rule":"L3-01-O","stage":2,"unit":"ue","kind":"anomaly")"), std::string::npos);
    EXPECT_NE(kinds[2].find(R"("event":"raise","rule":"L3-01-O","stage":2,"unit":"ue","kind":"attack")"), std::string::npos);
  }
  {
    Harness h;  // 60 s 조용하면 CLEAR — 마지막 보류 4332 + 60 s → 64400
    h.lost(2500, R"(["UL"])");
    attack(h, 5);
    h.tick_to(64300);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.tick_to(64400);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
    EXPECT_EQ(h.alerts[1].t, kT0 + 64400);
  }
  {
    Opt o;
    o.alert.held_alert = false;
    Harness h(o);
    h.lost(2500, R"(["UL"])");
    attack(h, 5);
    h.tick_to(10000);
    EXPECT_EQ(h.rule->held(), 5);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// 증거 지평 (14_ §1.1): 응답 대기 + 셀 창 + UPDATE 모음 지연. 상태표는 여기에 여유 1 s를 더해 닫힌 항목의 recent를 보관한다
TEST(AuthStall, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 13000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 14000);
}
