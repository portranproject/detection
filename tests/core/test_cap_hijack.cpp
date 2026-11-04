// 룰 L3-14 UE 능력 탈취 테스트 — 20_ §4.8 L14-T1~T21 (T20 설정은 test_config.cpp). 합성 ue_evt·kpm2 줄로 한다(같은 시나리오의
// 재생 데이터는 tests/data/stage3_lightgreen/ — tools/gen_stage3.py).
// 시각은 kT0 기준 ms, 연결 시작 t0 = kB(창 시작). 기본 흐름 F(능력 요청·응답은 RRC 보안 모드 완료 t0+150 뒤인 t0+160·t0+175),
// 공격 줄 C1(갈래 ① — t0+98 요청 없는 UECapabilityInformation), C2 흐름(갈래 ② — t0+120 RRC 보안 모드 명령 전에 CU가
// UECapabilityEnquiry, UE 응답 t0+130, F의 t0+160·t0+175는 없음)은 20_ §4.8 그대로. K(t) = t를 품은 창의 t_end_ms
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/cap_hijack.h"

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
const char* const kU = CapHijackRule::kTagUnsolicited;
const char* const kP = CapHijackRule::kTagPreSecEnquiry;

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
L cap_info(int64_t t, int64_t du) { return rrc(t, du, "UL", "UECapabilityInformation"); }
L cap_enq(int64_t t, int64_t du) { return rrc(t, du, "DL", "UECapabilityEnquiry"); }

// 기본 흐름 F (20_ §3.8). cap = t0+160 능력 요청·t0+175 응답을 둔다
struct FOpt {
  std::string integrity = "nia2";
  bool cap = true;
};
std::vector<L> F(int64_t t0, int64_t du, const FOpt& o = {}) {
  std::vector<L> v;
  v.push_back(rrc(t0, du, "UL", "RRCSetupRequest", kRandom));
  v.push_back(rrc(t0, du, "DL", "RRCSetup"));
  v.push_back(rrc(t0 + 91, du, "UL", "RRCSetupComplete"));
  v.push_back(nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")"));
  v.push_back(nas(t0 + 105, du, "DL", "AuthenticationRequest"));
  v.push_back(nas(t0 + 118, du, "UL", "AuthenticationResponse"));
  v.push_back(nas(t0 + 125, du, "DL", "SecurityModeCommand", R"("cipher":"5G-EA0","integrity":"5G-IA2")", 3));
  v.push_back(nas(t0 + 131, du, "UL", "SecurityModeComplete", "", 4));
  v.push_back(rrc(t0 + 140, du, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":")" + o.integrity + "\""));
  v.push_back(rrc(t0 + 150, du, "UL", "SecurityModeComplete"));
  if (o.cap) {
    v.push_back(cap_enq(t0 + 160, du));
    v.push_back(cap_info(t0 + 175, du));
  }
  v.push_back(nas(t0 + 190, du, "DL", "RegistrationAccept", "", 2));
  v.push_back(nas(t0 + 200, du, "UL", "RegistrationComplete", "", 2));
  return v;
}
// C2 흐름 (20_ §4.8): F에서 t0+160·t0+175를 빼고 t0+120 CU 능력 요청 → t0+130 UE 응답
std::vector<L> C2(int64_t t0, int64_t du) {
  std::vector<L> v = F(t0, du, {"nia2", false});
  v.push_back(cap_enq(t0 + 120, du));
  v.push_back(cap_info(t0 + 130, du));
  return v;
}
void drop(std::vector<L>& v, const std::string& proto, const std::string& msg) {
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.proto == proto && l.msg == msg; }), v.end());
}
void drop_dir(std::vector<L>& v, const std::string& dir) {
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.dir == dir; }), v.end());
}
void drop_from(std::vector<L>& v, int64_t t) {  // 시각 t 이후 줄을 뺀다
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.t >= t; }), v.end());
}
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

// 엔진 + L3-14 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1).
// 창별 ue_evt_lost는 loss(창 시작 → 값), 없으면 default_lost
class Harness {
 public:
  explicit Harness(bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<CapHijackRule>();
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
  const LookbackMarks::Mark* mark(int64_t du, int64_t uid, const char* tag) const {
    return rule->marks().find(UeKey{1, du}, uid, tag);
  }
  bool has_diag(DiagKind k) const { return std::find(diags.begin(), diags.end(), k) != diags.end(); }

  Engine engine;
  EvidenceQueue queue;
  EvidenceRecorder rec;
  CapHijackRule* rule = nullptr;
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

const std::vector<std::string> kMitm = {"mitm_ul_relay"};
const std::vector<std::string> kNone = {};
const std::vector<std::string> kMnmap = {"L3-28-V"};  // 갈래 ① candidates (20_ §4.6)

int count_phase(const std::vector<std::string>& recs, const std::string& phase) {
  return static_cast<int>(std::count_if(recs.begin(), recs.end(), [&](const std::string& r) {
    return r.find(R"("type":"evidence")") != std::string::npos && r.find(R"("phase":")" + phase + "\"") != std::string::npos;
  }));
}

}  // namespace

// L14-T1: F + 해제 — 능력 요청은 RRC 보안 뒤(ON), 응답은 짝이 있음(R 1·A 0) → 두 갈래 모두 후보 없음
TEST(CapHijack, T01NormalFlow) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{f1ap(kB + 1000, 3, "DL", "UEContextReleaseCommand"),
                                   f1ap(kB + 1000, 3, "UL", "UEContextReleaseComplete")});
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L14-T2: AMF가 단말 능력을 줘 능력 요청·응답이 없는 흐름
TEST(CapHijack, T02NoCapabilityExchange) {
  Harness h;
  h.play(F(kB, 3, {"nia2", false}));
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
}

// L14-T3: F에 C1 — K = t0+100에 갈래 ① RAISE. branch "1", medium, 전제 [mitm_ul_relay](경보·UE 칸), 값·로그 줄
TEST(CapHijack, T03Branch1Raise) {
  Harness h(true);
  h.play(F(kB, 3) + std::vector<L>{cap_info(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-14");
  EXPECT_EQ(e.stage, 3);
  EXPECT_EQ(e.alert_kind, "attack");
  EXPECT_EQ(e.t, kT0 + kB + 100);
  EXPECT_EQ(e.branch, std::optional<std::string>("1"));
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"unsolicited"}));
  EXPECT_EQ(e.candidates, kMnmap);  // 갈래 ① — #28 MNmap 중간자 변형 (20_ §4.1·§4.6, 4_ §6.3 #1)
  ASSERT_TRUE(e.conditions);
  EXPECT_EQ(*e.conditions, kMitm);
  EXPECT_EQ(e.values.dump(), R"({"branch1_ues":1,"branch2_ues":0,"extra":0,"held":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.t_hit, kT0 + kB + 98);
  EXPECT_EQ(u.cond, (std::vector<std::string>{"unsolicited"}));
  ASSERT_TRUE(u.conditions);
  EXPECT_EQ(*u.conditions, kMitm);
  EXPECT_EQ(u.values.dump(), R"({"branch":"1","req":0,"resp":1,"rrc_sec":"OFF"})");
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-14 cell=1 t=" + std::to_string(kT0 + kB + 100) +
                           " branch=1 ue=1/3/1 req=0 resp=1 rrc_sec=OFF severity=medium mode=normal "
                           "conditions=mitm_ul_relay candidates=L3-28-V");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("candidates":["L3-28-V"],"conditions":["mitm_ul_relay"],"values")"), std::string::npos);
}

// L14-T4: C2 흐름 — K = t0+200에 갈래 ② RAISE. branch "2", high, 전제 [], t0+130 응답은 짝이라 갈래 ① 없음. 레코드 모양(20_ §4.6 예)
TEST(CapHijack, T04Branch2Raise) {
  Harness h(true);
  h.play(C2(kB, 3));
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.t, kT0 + kB + 200);
  EXPECT_EQ(e.branch, std::optional<std::string>("2"));
  EXPECT_EQ(e.severity, Severity::High);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"enquiry_before_as_sec"}));
  EXPECT_TRUE(e.candidates.empty());  // 갈래 ②를 만드는 다른 공격은 없다 (20_ §4.1)
  ASSERT_TRUE(e.conditions);
  EXPECT_EQ(*e.conditions, kNone);
  EXPECT_EQ(e.values.dump(), R"({"branch1_ues":0,"branch2_ues":1,"extra":0,"held":0,"evicted":0})");
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].t_hit, kT0 + kB + 120);
  EXPECT_EQ(e.ues[0].values.dump(), R"({"branch":"2","req":1,"resp":0,"rrc_sec":"OFF"})");
  ASSERT_TRUE(e.ues[0].conditions);
  EXPECT_EQ(*e.ues[0].conditions, kNone);
  EXPECT_EQ(h.mark(3, 1, kU), nullptr);  // 갈래 ① 표시 없음
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-14 cell=1 t=" + std::to_string(kT0 + kB + 200) +
                           " branch=2 ue=1/3/1 req=1 resp=0 rrc_sec=OFF severity=high mode=normal conditions= candidates=");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("branch":"2","cond":["enquiry_before_as_sec"],"candidates":[],"conditions":[],"values")"),
            std::string::npos);
  EXPECT_NE(recs[0].find(R"("uncertain":[],"conditions":[],"seq_range")"), std::string::npos);
}

// L14-T5: 갈래 ② 경계 — 보안 모드 명령 뒤·완료 전(CMD) → 후보 없음 / RRC SecurityModeFailure 뒤(FAILED) → RAISE / 완료 뒤(ON) → 없음
TEST(CapHijack, T05Branch2Boundary) {
  {
    Harness h;
    h.play(F(kB, 3, {"nia2", false}) + std::vector<L>{cap_enq(kB + 145, 3)});
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    std::vector<L> v = F(kB, 3, {"nia2", false});
    drop(v, "RRC", "SecurityModeComplete");
    v.push_back(rrc(kB + 145, 3, "UL", "SecurityModeFailure"));
    v.push_back(cap_enq(kB + 150, 3));
    h.play(v);
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("rrc_sec"), "FAILED");
  }
  {
    Harness h;
    h.play(F(kB, 3, {"nia2", false}) + std::vector<L>{cap_enq(kB + 155, 3)});
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// L14-T6: 정상인데 능력 요청 줄 로스 — t0+175 응답은 AS 무결성 뒤라 갈래 ① 후보가 아님 → 보류도 불확실 경보도 없음
TEST(CapHijack, T06RequestLostAfterSecurity) {
  Harness h;
  std::vector<L> v = F(kB, 3);
  drop(v, "RRC", "UECapabilityEnquiry");
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(v);
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L14-T7: RRC SecurityModeCommand 줄 로스 — rrc_sec이 OFF로 남아 t0+160 능력 요청이 갈래 ② 후보 → 연결 시작 뒤 DL 로스로 보류 →
// K = t0+200에 불확실 경보(candidates [L3-14], held_w 1, branch·conditions 없음). t0+175 응답은 짝이라 갈래 ① 없음
TEST(CapHijack, T07SmcLostHeld) {
  Harness h;
  std::vector<L> v = F(kB, 3);
  v.erase(std::remove_if(v.begin(), v.end(), [](const L& l) { return l.proto == "RRC" && l.msg == "SecurityModeCommand"; }),
          v.end());
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(v);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.t, kT0 + kB + 200);
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-14"}));
  EXPECT_EQ(e.values.dump(), R"({"held_w":1})");
  EXPECT_FALSE(e.branch);
  EXPECT_FALSE(e.conditions);
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].t_hit, kT0 + kB + 161);
  EXPECT_EQ(e.ues[0].values.dump(), R"({"wait_ms":160,"dir":"DL"})");  // t_e − t_s
  EXPECT_FALSE(e.ues[0].conditions);
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-14 cell=1 t=" + std::to_string(kT0 + kB + 200) +
                           " kind=anomaly held_w=1 severity=medium mode=normal candidates=L3-14");
  EXPECT_EQ(h.mark(3, 1, kP)->phase, LookbackMarks::Phase::Held);
  EXPECT_EQ(h.mark(3, 1, kU), nullptr);
}

// L14-T8: 갈래 섞임 — A C1 → RAISE("1", medium, [mitm]), B C2 → 바로 UPDATE("2", high — 심각도 상승, 전제 합은 그대로라 conditions 없음) /
// 순서를 바꿈 — B C2 → RAISE("2", high, []), A C1이 0.9 s 뒤 → 전제가 [mitm]로 바뀌어 바로 UPDATE(branch 그대로 "2").
// candidates는 RAISE를 일으킨 UE의 갈래 후보이고 update에는 싣지 않는다 — 앞은 [L3-28-V], 뒤는 [] (20_ §4.6, 14_ §8.3)
TEST(CapHijack, T08MixedBranches) {
  {
    Harness h;
    h.play(F(kB, 1) + std::vector<L>{cap_info(kB + 98, 1)} + C2(kB + 400, 2));
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[0].branch, std::optional<std::string>("1"));
    EXPECT_EQ(h.alerts[0].candidates, kMnmap);
    EXPECT_EQ(*h.alerts[0].conditions, kMitm);
    const AlertEvent& u = h.alerts[1];
    EXPECT_EQ(u.kind, AlertEventKind::Update);
    EXPECT_EQ(u.t, kT0 + kB + 600);  // B의 t_e = t0+520
    EXPECT_EQ(u.branch, std::optional<std::string>("2"));
    EXPECT_EQ(u.severity, Severity::High);
    EXPECT_FALSE(u.conditions);
    ASSERT_EQ(u.ues.size(), 1u);
    EXPECT_EQ(*u.ues[0].conditions, kNone);
    EXPECT_EQ(u.values.dump(), R"({"branch1_ues":1,"branch2_ues":1,"extra":0,"held":0,"evicted":0})");
    EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-14 cell=1 t=" + std::to_string(kT0 + kB + 600) +
                             " ues_new=1 ues_total=2 branch=2 severity=high");
  }
  {
    Harness h;
    h.play(C2(kB, 2) + F(kB + 1000, 1) + std::vector<L>{cap_info(kB + 1098, 1)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[0].branch, std::optional<std::string>("2"));
    EXPECT_TRUE(h.alerts[0].candidates.empty());
    EXPECT_EQ(*h.alerts[0].conditions, kNone);
    const AlertEvent& u = h.alerts[1];
    EXPECT_EQ(u.kind, AlertEventKind::Update);
    EXPECT_EQ(u.t, kT0 + kB + 1100);  // RAISE 뒤 0.9 s — 모음 간격 전이지만 전제가 바뀌어 바로
    EXPECT_EQ(u.branch, std::optional<std::string>("2"));
    EXPECT_EQ(u.severity, Severity::High);
    ASSERT_TRUE(u.conditions);
    EXPECT_EQ(*u.conditions, kMitm);
    EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-14 cell=1 t=" + std::to_string(kT0 + kB + 1100) +
                             " ues_new=1 ues_total=2 branch=2 severity=high conditions=mitm_ul_relay");
  }
}

// L14-T9: 한 연결 두 갈래 — C2 흐름 + t0+135 요청 없는 능력 응답(R 1·A 1). 같은 K = t0+200에서 갈래 ② RAISE(마감 t0+121) 직후
// 갈래 ① 걸림(마감 t0+136)으로 전제가 [] → [mitm]이 되어 같은 칸 UPDATE. 두 칸, ues_total 2, branch "2", 증거는 UE당 한 번
TEST(CapHijack, T09BothBranchesOneConnection) {
  Harness h(true);
  const std::vector<L> v = C2(kB, 3) + std::vector<L>{cap_info(kB + 135, 3)};
  h.play(v);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(*h.alerts[0].conditions, kNone);
  const AlertEvent& u = h.alerts[1];
  EXPECT_EQ(u.kind, AlertEventKind::Update);
  EXPECT_EQ(u.t, kT0 + kB + 200);
  EXPECT_EQ(u.branch, std::optional<std::string>("2"));
  EXPECT_EQ(*u.conditions, kMitm);
  EXPECT_EQ(u.ues_total, 2);
  ASSERT_EQ(u.ues.size(), 1u);
  EXPECT_EQ(u.ues[0].du_ue_id, 3);
  EXPECT_EQ(u.ues[0].values.dump(), R"({"branch":"1","req":1,"resp":2,"rrc_sec":"OFF"})");
  EXPECT_EQ(u.values.dump(), R"({"branch1_ues":1,"branch2_ues":1,"extra":0,"held":0,"evicted":0})");
  const int before_raise = static_cast<int>(std::count_if(v.begin(), v.end(), [](const L& l) { return l.t < kB + 200; }));
  EXPECT_EQ(count_phase(h.drain(), "pre"), before_raise);  // 두 칸이어도 pre는 한 번
}

// L14-T10: 연결당 한 번 — C2 흐름에 t0+125 보안 전 능력 요청 하나 더 → 갈래 ② 걸림 1번, values.extra 1
TEST(CapHijack, T10OncePerConnection) {
  Harness h;
  h.play(C2(kB, 3) + std::vector<L>{cap_enq(kB + 125, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].values.at("extra"), 1);
  EXPECT_EQ(h.alerts[0].values.at("branch2_ues"), 1);
  EXPECT_EQ(h.mark(3, 1, kP)->extra, 1);
}

// L14-T11: nia0 — RRC 보안이 nia0이면 t0+220 요청 없는 능력 응답(R 1·A 1)도 판정 → K = t0+300에 갈래 ① RAISE(rrc_sec ON)
TEST(CapHijack, T11Nia0) {
  Harness h;
  h.play(F(kB, 3, {"nia0", true}) + std::vector<L>{cap_info(kB + 220, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 300);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"branch":"1","req":1,"resp":2,"rrc_sec":"ON"})");
}

// L14-T12: CU 설정 오류 — 5개 UE가 200 ms 간격으로 모두 C2. RAISE(첫 UE) + 1 s 모음 UPDATE(4개), branch2_ues 5, ues_total 5
TEST(CapHijack, T12CuMisconfig) {
  Harness h;
  std::vector<L> v;
  for (int64_t i = 0; i < 5; ++i) v = v + C2(kB + 200 * i, 10 + i);
  h.play(v);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].t, kT0 + kB + 1200);
  EXPECT_EQ(h.alerts[1].ues.size(), 4u);
  EXPECT_EQ(h.alerts[1].ues_total, 5);
  EXPECT_EQ(h.alerts[1].values.at("branch2_ues"), 5);
  EXPECT_FALSE(h.alerts[1].conditions);
}

// L14-T13: 첫 줄이 UECapabilityInformation 또는 UECapabilityEnquiry(mid_join) — 두 갈래 모두 후보 없음
TEST(CapHijack, T13MidJoin) {
  Harness h;
  h.play({cap_info(kB + 50, 5), cap_enq(kB + 50, 6)});
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L14-T14: 마감 전에 닫힘 — C2 흐름에서 t0+150 해제(released) → 마감 때 복사본으로 판정해 K = t0+200에 갈래 ② RAISE
TEST(CapHijack, T14ClosedBeforeDeadline) {
  Harness h;
  std::vector<L> v = C2(kB, 3);
  drop_from(v, kB + 140);
  v.push_back(f1ap(kB + 150, 3, "DL", "UEContextReleaseCommand"));
  v.push_back(f1ap(kB + 150, 3, "UL", "UEContextReleaseComplete"));
  h.play(v);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[0].branch, std::optional<std::string>("2"));
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L14-T15: 늦은 줄 — C1 줄(t_ms t0+98)이 t0+100 kpm2 뒤에 도착 → late로 판정 없음
TEST(CapHijack, T15LateLine) {
  // ① 요청 없는 늦은 응답(t0+98, t0+100 kpm2 뒤 도착) → 다음 kpm2(t0+200)에서 갈래 ① RAISE, ues[].uncertain에 late
  // (11/05 Q-74 해결, 이슈 #94 — 11/04까지는 late_until 안이라 판정 없음)
  {
    Harness h;
    std::vector<L> v = F(kB, 3);
    drop_from(v, kB + 100);
    h.play(v);
    h.tick_to(kB + 100);
    h.line(cap_info(kB + 98, 3));
    EXPECT_TRUE(h.has_diag(DiagKind::UeLate));
    h.tick_to(5000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].branch, "1");
    ASSERT_EQ(h.alerts[0].ues.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"late"}));
  }
  // ② 늦은 짝 요청(UECapabilityEnquiry)이 그 뒤에 오면 갈래 ① 대기 표시를 지워 경보 없음 — 놓친 요청이 뒤늦게 온 것. RRC 보안을
  // nia0으로 둬(연결 내내 갈래 ① 후보) 늦은 요청이 갈래 ② 후보(OFF·FAILED)가 되지 않게 한다
  {
    Harness h;
    h.play(F(kB, 3, {"nia0", false}));
    h.tick_to(kB + 300);
    h.line(cap_info(kB + 298, 3));
    EXPECT_EQ(h.rule->marks().size(), 1u);
    h.line(cap_enq(kB + 295, 3));
    EXPECT_EQ(h.rule->marks().size(), 0u);
    h.tick_to(5000);
    EXPECT_TRUE(h.alerts.empty());
  }
  // ③ 판정과 무관한 늦은 줄(UL MeasurementReport)은 막지 않는다 — 제때 온 요청 없는 응답(t0+150)은 K = t0+200에 RAISE
  {
    Harness h;
    std::vector<L> v = F(kB, 3);
    drop_from(v, kB + 100);
    h.play(v);
    h.tick_to(kB + 100);
    h.line(rrc(kB + 95, 3, "UL", "MeasurementReport"));
    h.line(cap_info(kB + 150, 3));
    h.tick_to(5000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"late"}));
  }
}

// L14-T22 (20_ §4.3 — 11/05 Q-70 해결, 이슈 #94): SecurityModeFailure(t0+145) 뒤 CU가 SecurityModeCommand를 재시도(t0+150)해
// Complete(t0+155)까지 가면 상태표가 CMD → ON으로 복구된다 — 그 뒤 정상 능력 요청(t0+160)은 갈래 ② 후보가 아니고 응답(t0+175)은
// AS 무결성 뒤라 갈래 ① 후보가 아니다 → 경보 없음(25_ 부록 A 3단계 X1). 재시도 '전' 능력 요청(t0+147)은 여전히 갈래 ②(FAILED)
TEST(CapHijack, T22RetryAfterFailure) {
  {
    Harness h;
    std::vector<L> v = F(kB, 3, {"nia2", false});
    drop(v, "RRC", "SecurityModeComplete");
    v.push_back(rrc(kB + 145, 3, "UL", "SecurityModeFailure"));
    v.push_back(rrc(kB + 150, 3, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")"));
    v.push_back(rrc(kB + 155, 3, "UL", "SecurityModeComplete"));
    v.push_back(cap_enq(kB + 160, 3));
    v.push_back(cap_info(kB + 175, 3));
    h.play(v);
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
    EXPECT_EQ(h.rule->marks().size(), 0u);
  }
  {
    Harness h;
    std::vector<L> v = F(kB, 3, {"nia2", false});
    drop(v, "RRC", "SecurityModeComplete");
    v.push_back(rrc(kB + 145, 3, "UL", "SecurityModeFailure"));
    v.push_back(cap_enq(kB + 147, 3));
    v.push_back(rrc(kB + 150, 3, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")"));
    v.push_back(rrc(kB + 155, 3, "UL", "SecurityModeComplete"));
    v.push_back(cap_info(kB + 175, 3));
    h.play(v);
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].branch, "2");
    EXPECT_EQ(h.alerts[0].ues[0].values.at("rrc_sec"), "FAILED");
  }
}

// L14-T16: DL 미관측 — 모든 kpm2 ue_evt_lost ["DL"], DL 줄 없음. 갈래 ②는 판정 없음, t0+175 응답은 rrc_sec OFF·R 0이라 후보 → 보류 →
// 불확실 경보만. 5 s 뒤 진단 dl_unobserved
TEST(CapHijack, T16DlUnobserved) {
  Harness h;
  h.default_lost = R"(["DL"])";
  std::vector<L> v = F(kB, 3);
  drop_dir(v, "DL");
  h.play(v);
  h.tick_to(7000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"wait_ms":175,"dir":"DL"})");
  EXPECT_TRUE(h.has_diag(DiagKind::DlUnobserved));
  EXPECT_EQ(h.mark(3, 1, kP), nullptr);
}

// L14-T17: 해제 — L14-T8 앞 경우 뒤 마지막 걸림(B의 t_e = t0+520) + 60 s 이상인 첫 kpm2에 CLEAR, branch "2"
TEST(CapHijack, T17Clear) {
  Harness h;
  h.play(F(kB, 1) + std::vector<L>{cap_info(kB + 98, 1)} + C2(kB + 400, 2));
  h.tick_to(kB + 60500);
  ASSERT_EQ(h.alerts.size(), 2u);
  h.tick_to(kB + 60600);  // t_end 61,600 − 1,520 ≥ 60,000
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[2].t, kT0 + kB + 60600);
  EXPECT_EQ(h.alerts[2].branch, std::optional<std::string>("2"));
  EXPECT_EQ(h.logs[2], "ALERT CLEAR rule=L3-14 cell=1 t=" + std::to_string(kT0 + kB + 60600) +
                           " duration_ms=60500 ues_total=2");
  // clear에도 누적값 (20_ §4.6, 14_ §8.3 — 11/04 Q-69 W-28)
  EXPECT_EQ(h.alerts[2].values.dump(), R"({"branch1_ues":1,"branch2_ues":1,"extra":0,"held":0,"evicted":0})");
}

// L14-T18 (Q-56): T3 RAISE 뒤 상태표 밀어내기 — 마지막 걸림 + 60 s에도 CLEAR하지 않고 밀어내기 뒤 60 s에 푼다(상한 100)
TEST(CapHijack, T18EvictionHoldsClear) {
  UeTableConfig ue_cfg;
  ue_cfg.max_ues = 100;
  Harness h(false, ue_cfg);
  h.play(F(kB, 3) + std::vector<L>{cap_info(kB + 98, 3)});
  h.tick_to(30000);
  ASSERT_EQ(h.alerts.size(), 1u);
  std::vector<L> v;
  for (int64_t i = 0; i < 101; ++i) {
    v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupRequest", kRandom));
    v.push_back(rrc(30000 + i / 2, 1000 + i, "UL", "RRCSetupComplete"));
  }
  h.play(v);
  h.tick_to(61200);
  EXPECT_EQ(h.engine.ue_table().counts(1).evicted, 2);
  EXPECT_EQ(h.alerts.size(), 1u);
  h.tick_to(90100);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 90100);
}

// L14-T19: 순서 위반 — RRC 보안 뒤 같은 창에서 능력 응답이 요청보다 먼저 옴 → 경보 없음(§1.2-1이 흡수) /
// RRC 보안 전 t0+120 응답·t0+125 요청 → 갈래 ① RAISE(마감 t0+121) 직후 같은 칸 갈래 ② UPDATE(high) — 오탐을 기록해 두는 시험
TEST(CapHijack, T19OrderViolation) {
  {
    Harness h;
    std::vector<L> v = F(kB, 3, {"nia2", false});
    std::stable_sort(v.begin(), v.end(), [](const L& a, const L& b) { return a.t < b.t; });
    auto at = std::find_if(v.begin(), v.end(), [](const L& l) { return l.t >= kB + 190; });
    v.insert(at, {cap_info(kB + 175, 3), cap_enq(kB + 160, 3)});
    h.play(v, false);
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    h.play(F(kB, 3, {"nia2", false}) + std::vector<L>{cap_info(kB + 120, 3), cap_enq(kB + 125, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
    EXPECT_EQ(h.alerts[0].branch, std::optional<std::string>("1"));
    EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
    EXPECT_EQ(h.alerts[1].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[1].branch, std::optional<std::string>("2"));
    EXPECT_EQ(h.alerts[1].severity, Severity::High);
    EXPECT_EQ(h.alerts[1].ues_total, 2);
  }
}

// L14-T21: 재생 결정성 — T3·T8·T12 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(CapHijack, T21Deterministic) {
  auto run = [] {
    Harness h(true);
    std::vector<L> v = F(kB, 1) + std::vector<L>{cap_info(kB + 98, 1)} + C2(kB + 400, 2);
    for (int64_t i = 0; i < 3; ++i) v = v + C2(kB + 1000 + 200 * i, 10 + i);
    h.play(v);
    h.tick_to(4000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 3u);  // RAISE, 심각도 UPDATE, 모음 UPDATE
  EXPECT_GT(a.second.size(), 3u);
}

// END: 세션이 바뀌면 END(session_reset)에도 그때의 branch, 표시 비움 / 입력 침묵이면 END(input_silent)만 — 표시는 그대로
TEST(CapHijack, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(C2(kB, 3));
    h.tick_to(1300);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.alerts[1].branch, std::optional<std::string>("2"));
    EXPECT_EQ(h.rule->marks().size(), 0u);
  }
  {
    Harness h;
    h.play(C2(kB, 3));
    h.tick_to(1300);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
    EXPECT_EQ(o.alerts[0].branch, std::optional<std::string>("2"));
    EXPECT_EQ(h.rule->marks().size(), 1u);
  }
}

// 불확실 경보가 열린 셀에서 공격이 걸리면 같은 줄에서 불확실 CLEAR 다음 공격 RAISE(14_ §8.2)
TEST(CapHijack, HeldThenAttack) {
  Harness h;
  std::vector<L> v = F(kB, 1);
  v.erase(std::remove_if(v.begin(), v.end(), [](const L& l) { return l.proto == "RRC" && l.msg == "SecurityModeCommand"; }),
          v.end());
  h.loss[kB + 100] = R"(["UL","DL"])";
  h.play(v + C2(2000, 2));
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
  EXPECT_FALSE(h.alerts[1].branch);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[2].alert_kind, "attack");
  EXPECT_EQ(h.alerts[2].values.at("held"), 1);
}

// 증거 지평 (20_ §4.4·§1.2-6): 1,000 ms + alert.update_min_ms
TEST(CapHijack, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
}
