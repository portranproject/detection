// 룰 L3-24 하향 IMSI 추출 테스트 — 20_ §3.8 L24-T1~T26 (T25 설정은 test_config.cpp). 합성 ue_evt·kpm2 줄로 한다(같은 시나리오의
// 재생 데이터는 tests/data/stage3_lightgreen/ — tools/gen_stage3.py).
// 시각은 kT0 기준 ms, 연결 시작 t0 = kB(창 시작). 기본 흐름 F와 공격 줄 I(t0+98 요청 없는 IdentityResponse)는 20_ §3.8 그대로.
// K(t) = t를 품은 창의 t_end_ms — '요청 없는 응답'의 판정·RAISE 시각이다(20_ §1.2-3)
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/imsi_extractor.h"

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
L id_resp(int64_t t, int64_t du, const std::string& f = "") { return nas(t, du, "UL", "IdentityResponse", f); }

// 기본 흐름 F (20_ §3.8). guti = 모르는 5G-GUTI로 등록, identity = t0+95 IdentityRequest → t0+100 IdentityResponse(L24-T2)
struct FOpt {
  bool guti = false;
  bool identity = false;
  std::string integrity = "nia2";
};
std::vector<L> F(int64_t t0, int64_t du, const FOpt& o = {}) {
  std::vector<L> v;
  v.push_back(rrc(t0, du, "UL", "RRCSetupRequest", kRandom));
  v.push_back(rrc(t0, du, "DL", "RRCSetup"));
  v.push_back(rrc(t0 + 91, du, "UL", "RRCSetupComplete"));
  v.push_back(nas(t0 + 91, du, "UL", "RegistrationRequest",
                  o.guti ? R"("reg_type":"initial","id_type":"5G-GUTI","s_tmsi":"0x0123456789ab")"
                         : R"("reg_type":"initial","id_type":"SUCI")"));
  if (o.identity) {
    v.push_back(nas(t0 + 95, du, "DL", "IdentityRequest"));
    v.push_back(id_resp(t0 + 100, du));
  }
  v.push_back(nas(t0 + 105, du, "DL", "AuthenticationRequest"));
  v.push_back(nas(t0 + 118, du, "UL", "AuthenticationResponse"));
  v.push_back(nas(t0 + 125, du, "DL", "SecurityModeCommand", R"("cipher":"5G-EA0","integrity":"5G-IA2")", 3));
  v.push_back(nas(t0 + 131, du, "UL", "SecurityModeComplete", "", 4));
  v.push_back(rrc(t0 + 140, du, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":")" + o.integrity + "\""));
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
// (proto, msg) 줄을 뺀다 — 'DL을 보지 못함', '요청 줄을 놓침' 등
void drop(std::vector<L>& v, const std::string& proto, const std::string& msg) {
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.proto == proto && l.msg == msg; }), v.end());
}
void drop_dir(std::vector<L>& v, const std::string& dir) {
  v.erase(std::remove_if(v.begin(), v.end(), [&](const L& l) { return l.dir == dir; }), v.end());
}
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

// 엔진 + L3-24 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다 — 같은 창의 ue_evt는 그 창
// kpm2보다 먼저 온다(2_ §6.1). 창별 ue_evt_lost는 loss(창 시작 → 값), 없으면 default_lost
class Harness {
 public:
  explicit Harness(bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<ImsiExtractorRule>();
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
  // F1AP ID에 잇지 못한 NGAP NAS 줄 (2_ §6.6)
  void ngap(int64_t t, const std::string& msg) {
    advance(t);
    feed(R"({"type":"ue_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
         R"(,"t_ms":)" + std::to_string(kT0 + t) +
         R"(,"cell_id":1,"du_ue_id":null,"cu_ue_id":3,"crnti":null,"dir":"UL","proto":"NAS","msg":")" + msg +
         R"(","via":"NGAP","sht":0})");
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
  ImsiExtractorRule* rule = nullptr;
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

// L24-T1: F + 해제 — 식별 요청·응답이 없다, 후보 없음
TEST(ImsiExtractor, T01NormalFlow) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{f1ap(kB + 1000, 3, "DL", "UEContextReleaseCommand"),
                                   f1ap(kB + 1000, 3, "UL", "UEContextReleaseComplete")});
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L24-T2: 모르는 5G-GUTI로 등록 → AMF가 IdentityRequest → 응답. 응답 때 R = 1, A = 0
TEST(ImsiExtractor, T02UnknownGutiIdentity) {
  Harness h;
  h.play(F(kB, 3, {true, true}));
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L24-T3: AMF 재전송(T3570) — 요청 2번에 늦게 한 번 답함 / 요청마다 답함(둘째 응답 때 R = 2, A = 1)
TEST(ImsiExtractor, T03AmfRetransmission) {
  for (bool twice : {false, true}) {
    Harness h;
    std::vector<L> v = head(kB, 3);
    v[3].f = R"("reg_type":"initial","id_type":"5G-GUTI","s_tmsi":"0x0123456789ab")";
    v.push_back(nas(kB + 95, 3, "DL", "IdentityRequest"));
    if (twice) v.push_back(id_resp(kB + 100, 3));
    v.push_back(nas(kB + 3095, 3, "DL", "IdentityRequest"));
    v.push_back(id_resp(kB + 3100, 3));
    std::vector<L> rest = F(kB + 3000, 3);
    rest.erase(rest.begin(), rest.begin() + 4);  // 인증부터 — 마지막 응답 뒤
    h.play(v + rest);
    h.tick_to(8000);
    EXPECT_TRUE(h.alerts.empty()) << twice;
    EXPECT_EQ(h.rule->marks().size(), 0u) << twice;
  }
}

// L24-T4: F에 공격 줄 I(t0+98) — K = t0+100에 RAISE. 값·로그 줄·pre 증거(연결 시작부터 응답까지)·뒤따르는 줄의 active 증거
TEST(ImsiExtractor, T04UnsolicitedRaise) {
  Harness h(true);
  h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-24");
  EXPECT_EQ(e.stage, 3);
  EXPECT_EQ(e.unit, "ue");
  EXPECT_EQ(e.alert_kind, "attack");
  EXPECT_EQ(e.t, kT0 + kB + 100);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_FALSE(e.branch);
  EXPECT_EQ(e.cond, kCond);
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-28-V"}));  // #28 MNmap 중간자 변형 (20_ §3.1·§3.6, 4_ §6.3 #1)
  ASSERT_TRUE(e.conditions);
  EXPECT_EQ(*e.conditions, kPremise);
  EXPECT_EQ(e.values.dump(), R"({"extra":0,"held":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"clear_quiet_ms":60000})");
  EXPECT_EQ(e.alert_id.rfind("S-L3-24-1-", 0), 0u);
  ASSERT_EQ(e.ues.size(), 1u);
  const AlertUe& u = e.ues[0];
  EXPECT_EQ(u.du_ue_id, 3);
  EXPECT_EQ(u.uid, 1);
  EXPECT_EQ(u.cond, kCond);
  EXPECT_EQ(u.t_hit, kT0 + kB + 98);
  EXPECT_EQ(u.values.dump(), R"({"req":0,"resp":1,"rrc_sec":"OFF","nas_sec":"NONE"})");
  EXPECT_TRUE(u.uncertain.empty());
  EXPECT_FALSE(u.conditions);  // L3-24는 UE 칸에 싣지 않는다 (20_ §3.6)
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-24 cell=1 t=" + std::to_string(kT0 + kB + 100) +
                           " ue=1/3/1 req=0 resp=1 rrc_sec=OFF nas_sec=NONE severity=medium mode=normal "
                           "conditions=mitm_ul_relay candidates=L3-28-V");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("stage":3,)"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("candidates":["L3-28-V"],"conditions":["mitm_ul_relay"],"values")"), std::string::npos);
  EXPECT_EQ(count_phase(recs, "pre"), 5);      // RRCSetupRequest·RRCSetup·RRCSetupComplete·RegistrationRequest·응답
  EXPECT_EQ(count_phase(recs, "active"), 10);  // t0+105 인증 요청부터 등록 완료까지
}

// L24-T5: 응답 줄에 약속에 없는 f(id_type)가 붙어 옴 — 무시, T4와 같은 RAISE
TEST(ImsiExtractor, T05UnexpectedFieldIgnored) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3, R"("id_type":"IMEI")")});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].severity, Severity::Medium);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"req":0,"resp":1,"rrc_sec":"OFF","nas_sec":"NONE"})");
}

// L24-T6: 정상 식별 절차 뒤 RRC 보안 전 t0+135에 응답 하나 더 — R = 1, A = 1 → K = t0+200에 RAISE, nas_sec ON
TEST(ImsiExtractor, T06InjectedAfterNormalIdentity) {
  Harness h;
  h.play(F(kB, 3, {true, true}) + std::vector<L>{id_resp(kB + 135, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_EQ(h.alerts[0].ues[0].t_hit, kT0 + kB + 135);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"req":1,"resp":2,"rrc_sec":"OFF","nas_sec":"ON"})");
}

// L24-T7: T4 + 같은 연결 t0+135(RRC 보안 전)·t0+250(AS 무결성 뒤)에 응답 — RAISE 1번, 결정된 표시의 extra 1(뒤 것은 세지 않음),
// UPDATE는 나지 않는다(§3.3-4). 다음 update가 나면 values.extra 1로 실린다. 두 줄은 active 증거
TEST(ImsiExtractor, T07ExtraOnHitConnection) {
  Harness h(true);
  h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3), id_resp(kB + 135, 3), id_resp(kB + 250, 3)});
  h.tick_to(1900);
  ASSERT_EQ(h.alerts.size(), 1u);
  const LookbackMarks::Mark* m = h.mark(3, 1);
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->phase, LookbackMarks::Phase::Hit);
  EXPECT_EQ(m->extra, 1);
  EXPECT_EQ(h.alerts[0].ues_total, 1);
  // 다른 UE가 걸려 UPDATE가 나면 누적 extra가 실린다
  h.play(F(2000, 4) + std::vector<L>{id_resp(2098, 4)});
  h.tick_to(2200);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].t, kT0 + 2100);
  EXPECT_EQ(h.alerts[1].values.dump(), R"({"extra":1,"held":0,"evicted":0})");
  EXPECT_FALSE(h.alerts[1].conditions);  // 바뀌지 않으므로 update에는 싣지 않는다
  EXPECT_EQ(count_phase(h.drain(), "active", "IdentityResponse"), 2);
}

// L24-T8: 같은 창 t0+60·t0+98에 요청 없는 응답 둘(첫 표시가 대기 중) — RAISE 1번, 대기 중 extra 1이 values.extra에
TEST(ImsiExtractor, T08TwoInSameWindow) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 60, 3), id_resp(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  EXPECT_EQ(h.alerts[0].values.at("extra"), 1);
  EXPECT_EQ(h.alerts[0].ues[0].t_hit, kT0 + kB + 60);
}

// L24-T9: 요청 줄 로스 — T2에서 IdentityRequest 줄을 빼고 그 창 [t0, t0+100)이 양방향 로스. 연결 시작 뒤 DL 로스로 보류 →
// K = t0+200에 불확실 경보(kind anomaly) RAISE. 60 s 조용하면 CLEAR
TEST(ImsiExtractor, T09RequestLostHeld) {
  Harness h;
  std::vector<L> v = F(kB, 3, {true, true});
  drop(v, "NAS", "IdentityRequest");
  h.loss[kB] = R"(["UL","DL"])";
  ASSERT_EQ(v[4].msg, "IdentityResponse");
  h.play(std::vector<L>(v.begin(), v.begin() + 5));  // 응답(t0+100)까지
  h.tick_to(kB + 100);
  EXPECT_TRUE(h.alerts.empty());  // 마감 t0+101 — 응답이 든 창의 kpm2(t0+200)에서
  h.play(std::vector<L>(v.begin() + 5, v.end()));  // 인증부터 나머지
  h.tick_to(1200);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.stage, 3);
  EXPECT_EQ(e.t, kT0 + kB + 200);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"held_count"}));
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-24"}));
  EXPECT_FALSE(e.conditions);  // 불확실 경보에는 싣지 않는다 (20_ §3.7)
  EXPECT_EQ(e.values.dump(), R"({"held_w":1})");
  EXPECT_EQ(e.params.dump(), R"({"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"held"}));
  EXPECT_EQ(e.ues[0].t_hit, kT0 + kB + 101);  // 마감
  EXPECT_EQ(e.ues[0].uncertain, (std::vector<std::string>{"loss"}));
  EXPECT_EQ(e.ues[0].values.dump(), R"({"wait_ms":100,"dir":"DL"})");  // t_r − t_s
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=L3-24 cell=1 t=" + std::to_string(kT0 + kB + 200) +
                           " kind=anomaly held_w=1 severity=medium mode=normal candidates=L3-24");
  ASSERT_NE(h.mark(3, 1), nullptr);
  EXPECT_EQ(h.mark(3, 1)->phase, LookbackMarks::Phase::Held);
  h.tick_to(61100);
  EXPECT_EQ(h.alerts.size(), 1u);
  h.tick_to(61200);  // 마지막 보류 1101 + 60 s
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].alert_kind, "anomaly");
}

// L24-T10: 로스 창이 연결 시작 전 [t0−100, t0) → loss_end[DL] = t0 ≤ t_s → RAISE / 연결 뒤·응답 창 앞 [t0, t0+100)이고 응답이
// t0+135 → 보류(불확실 경보)
TEST(ImsiExtractor, T10LossBeforeAndAfterStart) {
  {
    Harness h;
    h.loss[kB - 100] = R"(["UL","DL"])";
    h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].alert_kind, "attack");
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  }
  {
    Harness h;
    h.loss[kB] = R"(["UL","DL"])";
    h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 135, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"wait_ms":135,"dir":"DL"})");
  }
}

// L24-T11: 응답 창이 UL만 로스 — DL 로스가 아니라 RAISE. 항목의 loss 표시는 ues[].uncertain에 남는다(§1.2-4)
TEST(ImsiExtractor, T11UlOnlyLoss) {
  Harness h;
  h.loss[kB] = R"(["UL"])";
  h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3)});
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].alert_kind, "attack");
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"loss"}));
}

// L24-T12: 창 경계 — 응답 t_r = t0+100(앞 창의 t_end와 같음). t0+100 kpm2에서는 꺼내지 않고 K = t0+200에서
TEST(ImsiExtractor, T12WindowBoundary) {
  Harness h;
  h.play(head(kB, 3) + std::vector<L>{id_resp(kB + 100, 3)});
  h.tick_to(kB + 100);
  EXPECT_TRUE(h.alerts.empty());
  h.tick_to(kB + 200);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
}

// L24-T13: 같은 창 t0+99에 해제(released) — 마감 때 복사본으로 판정해 K = t0+100에 RAISE. pre 증거는 보관된 recent
TEST(ImsiExtractor, T13ClosedBeforeDeadline) {
  Harness h(true);
  h.play(head(kB, 3) + std::vector<L>{id_resp(kB + 98, 3), f1ap(kB + 99, 3, "DL", "UEContextReleaseCommand"),
                                      f1ap(kB + 99, 3, "UL", "UEContextReleaseComplete")});
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  h.tick_to(3000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"req":0,"resp":1,"rrc_sec":"OFF","nas_sec":"NONE"})");
  EXPECT_EQ(h.rule->marks().size(), 0u);  // 닫힌 항목 — 판정 뒤 지움
  const std::vector<std::string> recs = h.drain();
  EXPECT_EQ(count_phase(recs, "pre"), 7);  // 해제 두 줄까지
  EXPECT_NE(recs[0].find(R"("evidence":true)"), std::string::npos);
}

// L24-T14: 첫 줄이 IdentityResponse(mid_join) — 연결 앞부분을 못 봐 후보 없음
TEST(ImsiExtractor, T14MidJoin) {
  Harness h;
  h.play({id_resp(kB + 50, 5), rrc(kB + 60, 5, "UL", "MeasurementReport")});
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L24-T15: 늦은 줄 — 응답 줄(t_ms t0+98)이 t0+100 kpm2 뒤에 도착. late_until ≥ 마감 → 판정 없음, 표시도 지움
TEST(ImsiExtractor, T15LateLine) {
  Harness h;
  h.play(head(kB, 3));
  h.tick_to(kB + 100);
  h.line(id_resp(kB + 98, 3));
  EXPECT_TRUE(h.has_diag(DiagKind::UeLate));
  EXPECT_EQ(h.rule->marks().size(), 1u);
  h.tick_to(5000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.rule->marks().size(), 0u);
}

// L24-T16: AS 무결성 뒤(t0+220) 응답 — 후보 없음 / RRC 보안이 nia0이면 연결 내내 판정 → K = t0+300에 RAISE(rrc_sec ON) /
// 보안 모드 명령 뒤·완료 전(t0+145, CMD) → K = t0+200에 RAISE
TEST(ImsiExtractor, T16AsIntegrity) {
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 220, 3)});
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
    EXPECT_EQ(h.rule->marks().size(), 0u);
  }
  {
    Harness h;
    FOpt o;
    o.integrity = "nia0";
    h.play(F(kB, 3, o) + std::vector<L>{id_resp(kB + 220, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 300);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("rrc_sec"), "ON");
  }
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 145, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("rrc_sec"), "CMD");
  }
}

// L24-T17: NAS 암호 — 공격 응답이 ProtectedNAS면 이름이 보이지 않아 판정 없음
TEST(ImsiExtractor, T17ProtectedNas) {
  Harness h;
  h.play(F(kB, 3) + std::vector<L>{nas(kB + 98, 3, "UL", "ProtectedNAS", "", 2)});
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
}

// L24-T18: 해제 — 마지막 걸림(t_r = t0+98) + 60 s 이상인 첫 kpm2에 CLEAR / 같은 연결 t0+30,000의 extra는 해제를 늦추지 않는다
TEST(ImsiExtractor, T18Clear) {
  for (bool extra : {false, true}) {
    Harness h;
    std::vector<L> v = extra ? head(kB, 3) : F(kB, 3);
    v.push_back(id_resp(kB + 98, 3));
    if (extra) v.push_back(id_resp(kB + 30000, 3));  // RRC 보안 전에 머문 연결 — extra로 센다
    h.play(v);
    h.tick_to(kB + 60000);
    ASSERT_EQ(h.alerts.size(), 1u) << extra;
    h.tick_to(kB + 60100);  // t_end 61100 − 1098 ≥ 60000
    ASSERT_EQ(h.alerts.size(), 2u) << extra;
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
    EXPECT_EQ(h.alerts[1].t, kT0 + kB + 60100);
    EXPECT_EQ(h.alerts[1].duration_ms, 60000);
    EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=L3-24 cell=1 t=" + std::to_string(kT0 + kB + 60100) +
                             " duration_ms=60000 ues_total=1");
    if (extra) {
      EXPECT_EQ(h.mark(3, 1)->extra, 1);
    }
  }
}

// L24-T19: 두 UE — A는 T4, B는 t0+500에 같은 공격. RAISE + UPDATE(update_min_ms 1 s 모음), ues_total 2, 심각도 그대로
TEST(ImsiExtractor, T19TwoUesUpdate) {
  Harness h;
  h.play(F(kB, 1) + std::vector<L>{id_resp(kB + 98, 1)} + F(kB + 500, 2) + std::vector<L>{id_resp(kB + 598, 2)});
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
  EXPECT_EQ(u.values.dump(), R"({"extra":0,"held":0,"evicted":0})");
  EXPECT_EQ(h.logs[1], "ALERT UPDATE rule=L3-24 cell=1 t=" + std::to_string(kT0 + kB + 1100) +
                           " ues_new=1 ues_total=2 severity=medium");
}

// L24-T20: 보류된 연결(T9)에 요청 없는 응답이 더 옴 — 다시 후보를 만들지 않는다(held_w 그대로 1, 새 마감 없음), 표시의 extra 1.
//  (a) t0+135: 마감 처리 전(표시가 대기)
//  (b) t0+235: 보류 처리(K = t0+200) 뒤(표시가 결정됨). extra로 세려면 §1.2-1(AS 무결성 전)을 통과해야 하므로 이 경우만 RRC 보안
//      모드 줄을 뺐다 — 명세 표대로 F를 그대로 두면 t0+235는 AS 무결성(nia2) 뒤라 extra로 세지 않는다(c)
//  (c) 명세 표 그대로(F 유지) t0+235: 후보 조건 밖이라 extra 0 — 다시 판정하지 않는 것은 같다
TEST(ImsiExtractor, T20HeldConnectionMoreResponses) {
  struct Case {
    int64_t t;
    bool drop_rrc_smc;
    int64_t extra;
  };
  for (const Case& c : {Case{kB + 135, false, 1}, Case{kB + 235, true, 1}, Case{kB + 235, false, 0}}) {
    Harness h;
    std::vector<L> v = F(kB, 3, {true, true});
    drop(v, "NAS", "IdentityRequest");
    if (c.drop_rrc_smc) {
      drop(v, "RRC", "SecurityModeCommand");
      drop(v, "RRC", "SecurityModeComplete");
    }
    v.push_back(id_resp(c.t, 3));
    h.loss[kB] = R"(["UL","DL"])";
    h.play(v);
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u) << c.t;
    EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
    EXPECT_EQ(h.alerts[0].values.at("held_w"), 1);
    ASSERT_NE(h.mark(3, 1), nullptr);
    EXPECT_EQ(h.mark(3, 1)->phase, LookbackMarks::Phase::Held);
    EXPECT_EQ(h.mark(3, 1)->extra, c.extra) << c.t << " " << c.drop_rrc_smc;
    EXPECT_EQ(h.rule->marks().size(), 1u);
  }
}

// L24-T21: du_ue_id null인 IdentityResponse(via NGAP) — UE 항목에 붙지 않아 판정 없음
TEST(ImsiExtractor, T21NgapUnlinked) {
  Harness h;
  h.play(head(kB, 3));
  h.ngap(kB + 98, "IdentityResponse");
  h.tick_to(3000);
  EXPECT_TRUE(h.alerts.empty());
  EXPECT_EQ(h.engine.ue_table().counts(1).ngap_unlinked, 1);
}

// L24-T22: DL 미관측 — 모든 kpm2 ue_evt_lost ["DL"], DL 줄은 보이지 않음(T2). 응답이 후보가 되어 보류 → 불확실 경보만,
// 5 s 뒤 진단 dl_unobserved
TEST(ImsiExtractor, T22DlUnobserved) {
  Harness h;
  h.default_lost = R"(["DL"])";
  std::vector<L> v = F(kB, 3, {true, true});
  drop_dir(v, "DL");
  h.play(v);
  h.tick_to(7000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].alert_kind, "anomaly");
  EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
  EXPECT_TRUE(h.has_diag(DiagKind::DlUnobserved));
}

// L24-T23 (Q-56): RAISE 뒤 그 셀에 상태표 밀어내기 — 마지막 걸림 + 60 s에도 CLEAR하지 않고, 직전 60 s 밀어내기가 0건인 칸에서
// 푼다. 상한 100, 정상 연결 101대로 밀어내기 2회(다음 kpm2 t_end 30,100에서 셈)
TEST(ImsiExtractor, T23EvictionHoldsClear) {
  UeTableConfig ue_cfg;
  ue_cfg.max_ues = 100;
  Harness h(false, ue_cfg);
  h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3)});
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

// L24-T24: 전제 위반 — 같은 창에서 요청 줄이 응답 줄 뒤에 옴 / 응답 줄이 두 번 옴. 둘 다 RAISE — 오탐을 기록해 두는 시험(§3.7)
TEST(ImsiExtractor, T24PremiseViolations) {
  {
    Harness h;
    std::vector<L> v = head(kB, 3);
    v.push_back(id_resp(kB + 97, 3));
    v.push_back(nas(kB + 95, 3, "DL", "IdentityRequest"));
    h.play(v, false);
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 100);
  }
  {
    Harness h;
    h.play(F(kB, 3, {true, true}) + std::vector<L>{id_resp(kB + 100, 3)});
    h.tick_to(3000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].t, kT0 + kB + 200);
    EXPECT_EQ(h.alerts[0].ues[0].values.dump(), R"({"req":1,"resp":2,"rrc_sec":"OFF","nas_sec":"NONE"})");
  }
}

// L24-T26: 재생 결정성 — T4·T9·T19 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(ImsiExtractor, T26Deterministic) {
  auto run = [] {
    Harness h(true);
    std::vector<L> held = F(kB, 1, {true, true});
    drop(held, "NAS", "IdentityRequest");
    h.loss[kB] = R"(["UL","DL"])";
    h.play(held + F(2000, 2) + std::vector<L>{id_resp(2098, 2)} + F(2500, 3) + std::vector<L>{id_resp(2598, 3)});
    h.tick_to(4000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 4u);  // 불확실 RAISE, 불확실 CLEAR + 공격 RAISE, UPDATE
  EXPECT_GT(a.second.size(), 4u);
}

// 불확실 경보가 열린 셀에서 공격이 걸리면 같은 줄에서 불확실 CLEAR 다음 공격 RAISE(14_ §8.2). 공격 RAISE의 held는 직전 60 s 보류 수
TEST(ImsiExtractor, HeldThenAttack) {
  Harness h;
  std::vector<L> held = F(kB, 1, {true, true});
  drop(held, "NAS", "IdentityRequest");
  h.loss[kB] = R"(["UL","DL"])";
  h.play(held + F(2000, 2) + std::vector<L>{id_resp(2098, 2)});
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

// END: 세션이 바뀌면 진행 중 경보 END(session_reset)와 표시 비움 / 입력 침묵이면 END(input_silent)만 — 표시는 그대로
TEST(ImsiExtractor, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3)});
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
    h.play(F(kB, 3) + std::vector<L>{id_resp(kB + 98, 3)});
    h.tick_to(1200);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].kind, AlertEventKind::End);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
    EXPECT_EQ(o.alerts[0].t, kT0 + 1200);
    EXPECT_EQ(h.rule->marks().size(), 1u);
  }
}

// 증거 지평 (20_ §1.2-6): 1,000 ms + alert.update_min_ms — 기본값으로 2,000 ms. 상태표는 여유 1 s를 더해 recent를 보관한다
TEST(ImsiExtractor, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 3000);
  AlertConfig a;
  a.update_min_ms = 5000;
  EXPECT_EQ(ImsiExtractorRule({}, a).evidence_horizon_ms(), 6000);
}
