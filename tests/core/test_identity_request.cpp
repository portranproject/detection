// 4단계 룰 AN-02 식별 요청 증가 테스트 — 21_ §5.8 AN02-T1~T8 (T8 설정 범위는 test_config.cpp) + 11/04 결정(갈래 ①은 RRC 또는
// NAS의 S-TMSI가 할당 기억에 있으면 — 공격 모양 AN02-T9). 합성 ue_evt·kpm2 줄로 한다(같은 시나리오의 재생 데이터는
// tests/data/stage4_yellow/SAN02_* — tools/gen_stage4.py). 시각은 kT0 기준 ms. 등록 흐름 G: 연결 A가 SUCI로 등록해 RegistrationAccept
// (f.s_tmsi S)를 받고 해제 → 연결 B(새 du_ue_id)가 5G-GUTI S로 등록(RRC에도 S). K(t) = t를 품은 창의 t_end_ms (21_ §1.1)
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/identity_request.h"

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
constexpr uint64_t kS = 0x0123456789ab;   // 이 망이 준 S-TMSI
constexpr uint64_t kSx = 0x00fedcba9876;  // 모르는 S-TMSI
constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
const std::string kRandom = R"("ue_identity":{"type":"randomValue"})";

std::string hex(uint64_t v, int digits) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%0*llx", digits, static_cast<unsigned long long>(v));
  return buf;
}
std::string stmsi(uint64_t v) { return R"("s_tmsi":")" + hex(v, 12) + "\""; }
std::string part1(uint64_t v) {
  return R"("ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" + hex(v & kPart1Mask, 10) + R"("})";
}

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
L idreq(int64_t t, int64_t du) { return nas(t, du, "DL", "IdentityRequest"); }

std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}
// 인증부터 등록 완료까지 (기본 흐름 F의 t0+105~t0+200, 20_ §3.8)
std::vector<L> rest(int64_t t0, int64_t du, int64_t accept_s = 0) {
  return {nas(t0 + 105, du, "DL", "AuthenticationRequest"), nas(t0 + 118, du, "UL", "AuthenticationResponse"),
          nas(t0 + 125, du, "DL", "SecurityModeCommand", R"("cipher":"5G-EA0","integrity":"5G-IA2")", 3),
          nas(t0 + 131, du, "UL", "SecurityModeComplete", "", 4),
          rrc(t0 + 140, du, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")"),
          rrc(t0 + 150, du, "UL", "SecurityModeComplete"),
          nas(t0 + 190, du, "DL", "RegistrationAccept", accept_s ? stmsi(accept_s) : "", 2),
          nas(t0 + 200, du, "UL", "RegistrationComplete", "", 2)};
}
std::vector<L> release(int64_t t, int64_t du) {
  return {f1ap(t, du, "DL", "UEContextReleaseCommand"), f1ap(t, du, "UL", "UEContextReleaseComplete")};
}
// SUCI 첫 등록(F). accept_s면 RegistrationAccept가 그 S-TMSI를 준다(할당 기억)
std::vector<L> suci(int64_t t0, int64_t du, int64_t accept_s = 0) {
  return std::vector<L>{rrc(t0, du, "UL", "RRCSetupRequest", kRandom), rrc(t0, du, "DL", "RRCSetup"),
                        rrc(t0 + 91, du, "UL", "RRCSetupComplete"),
                        nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")")} +
         rest(t0, du, accept_s);
}
// 5G-GUTI 등록의 앞부분 — RRC에는 rrc_s(Part1 + RRCSetupComplete 48비트, rrc_full이 false면 Part1만), 등록 요청 GUTI는 nas_s
std::vector<L> guti_head(int64_t t0, int64_t du, uint64_t rrc_s, uint64_t nas_s, bool rrc_full = true) {
  return {rrc(t0, du, "UL", "RRCSetupRequest", part1(rrc_s)), rrc(t0, du, "DL", "RRCSetup"),
          rrc(t0 + 91, du, "UL", "RRCSetupComplete", rrc_full ? stmsi(rrc_s) : ""),
          nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"5G-GUTI",)" + stmsi(nas_s))};
}
// 등록 흐름 G의 A (21_ §5.8): SUCI 등록 → RegistrationAccept S → 해제
std::vector<L> conn_a(int64_t t0 = 1000) { return suci(t0, 1, kS) + release(t0 + 1000, 1); }

// 엔진 + AN-02 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1)
class Harness {
 public:
  explicit Harness(IdentityRequestConfig cfg = {}, bool record = false, UeTableConfig ue_cfg = {})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ue_cfg), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<IdentityRequestRule>(cfg);
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
  IdentityRequestRule* rule = nullptr;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

const std::vector<std::string> kCand = {"L3-25-OV"};

// UE du가 SUCI 등록 중 t0+95에 보안 전 IdentityRequest를 받음(AMF가 SUCI를 모르는 상황을 합성, AN02-T4)
std::vector<L> suci_idreq(int64_t t0, int64_t du) {
  return std::vector<L>{rrc(t0, du, "UL", "RRCSetupRequest", kRandom), rrc(t0 + 91, du, "UL", "RRCSetupComplete"),
                        nas(t0 + 91, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")"),
                        idreq(t0 + 95, du), nas(t0 + 100, du, "UL", "IdentityResponse")};
}

}  // namespace

// AN02-T1: SUCI 첫 등록 + 해제 / G에서 B가 식별 요청 없이 진행 — 걸림 없음
TEST(IdentityRequest, T01NoIdentityRequest) {
  Harness h;
  h.play(conn_a() + guti_head(5000, 2, kS, kS) + rest(5000, 2));
  h.tick_to(8000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN02-T2: G에서 B의 등록 요청(t0+91) 뒤 t0+96 IdentityRequest → 응답 → 인증. 갈래 ① 걸림, K = t0+100에 RAISE branch "1".
// 로그 줄·레코드(kind anomaly·stage 4·branch)
TEST(IdentityRequest, T02Branch1KnownGuti) {
  Harness h({}, true);
  h.play(conn_a() + guti_head(5000, 2, kS, kS) +
         std::vector<L>{idreq(5096, 2), nas(5099, 2, "UL", "IdentityResponse")} + rest(5000, 2));
  h.tick_to(8000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "AN-02");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.t, kT0 + 5100);
  EXPECT_EQ(e.branch, std::optional<std::string>("1"));
  EXPECT_EQ(e.cond, (std::vector<std::string>{"idreq_known_guti"}));
  EXPECT_EQ(e.candidates, kCand);
  EXPECT_EQ(e.values.dump(), R"({"idreq_w":1,"known_w":1,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"window_ms":60000,"n_idreq":5,"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"idreq_known_guti"}));
  EXPECT_EQ(e.ues[0].t_hit, kT0 + 5096);
  EXPECT_EQ(e.ues[0].values.dump(), R"({"branch":"1","id_type":"5G-GUTI","known":true,"nas_sec":"NONE"})");
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-02 cell=1 t=" + std::to_string(kT0 + 5100) +
                           " kind=anomaly branch=1 ue=1/2/2 id_type=5G-GUTI known=1 idreq_w=1 n_idreq=5 severity=medium"
                           " mode=normal candidates=L3-25-OV");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"AN-02","stage":4,"unit":"ue","kind":"anomaly","cell":1)"), std::string::npos);
  EXPECT_NE(recs[0].find(R"("branch":"1","cond":["idreq_known_guti"],"candidates":["L3-25-OV"],"values")"),
            std::string::npos);
}

// AN02-T9 (11/04 사용자 결정 — 갈래 ①은 RRC 또는 NAS): 공격 모양 — 중간자가 NAS 등록 요청의 GUTI만 모르는 값(S′)으로 바꾸고 RRC의
// S-TMSI는 원래 값(S, 할당됨) → 갈래 ①. RRC에 Part1만 있어도(RRCSetupComplete에 48비트 없음) Part1로 찾는다
TEST(IdentityRequest, T09AttackShapeRrcKnownNasUnknown) {
  for (bool rrc_full : {true, false}) {
    Harness h;
    h.play(conn_a() + guti_head(5000, 2, kS, kSx, rrc_full) + std::vector<L>{idreq(5096, 2)});
    h.tick_to(6000);
    ASSERT_EQ(h.alerts.size(), 1u) << rrc_full;
    EXPECT_EQ(h.alerts[0].branch, std::optional<std::string>("1")) << rrc_full;
    EXPECT_EQ(h.alerts[0].ues[0].values.at("known"), true) << rrc_full;
  }
}

// AN02-T3: B가 모르는 GUTI(S′ — RRC·NAS 모두)로 등록 → IdentityRequest. 갈래 ① 없음, 갈래 ② 수 1 → 경보 없음
TEST(IdentityRequest, T03UnknownGuti) {
  Harness h;
  h.play(conn_a() + guti_head(5000, 2, kSx, kSx) + std::vector<L>{idreq(5096, 2)});
  h.tick_to(8000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN02-T4: 5 UE가 60 s 안 각각 SUCI 등록 뒤 IdentityRequest — 5번째에서 창 안 5 → RAISE branch "2", ues 5, known_w 0
TEST(IdentityRequest, T04Branch2Count) {
  Harness h;
  std::vector<L> v;
  for (int64_t i = 0; i < 5; ++i) v = v + suci_idreq(1000 + 10000 * i, 10 + i);
  h.play(v);
  h.tick_to(50000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.t, kT0 + 41100);  // 5번째 요청 41,095 → K = 41,100
  EXPECT_EQ(e.branch, std::optional<std::string>("2"));
  EXPECT_EQ(e.cond, (std::vector<std::string>{"idreq_count"}));
  EXPECT_EQ(e.ues.size(), 5u);
  EXPECT_EQ(e.values.dump(), R"({"idreq_w":5,"known_w":0,"evicted":0})");
  EXPECT_EQ(e.ues[0].values.dump(), R"({"branch":"2","id_type":"SUCI","known":false,"nas_sec":"NONE"})");
  EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"idreq"}));
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-02 cell=1 t=" + std::to_string(kT0 + 41100) +
                           " kind=anomaly branch=2 idreq_w=5 known_w=0 n_idreq=5 window_ms=60000 severity=medium"
                           " mode=normal candidates=L3-25-OV");
}

// AN02-T5: 4 UE만 / 5번째가 첫 요청 뒤 61 s — 창 안 4 → 경보 없음
TEST(IdentityRequest, T05Branch2BelowOrOutside) {
  {
    Harness h;
    std::vector<L> v;
    for (int64_t i = 0; i < 4; ++i) v = v + suci_idreq(1000 + 10000 * i, 10 + i);
    h.play(v);
    h.tick_to(50000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    std::vector<L> v;
    for (int64_t i = 0; i < 4; ++i) v = v + suci_idreq(1000 + 10000 * i, 10 + i);
    v = v + suci_idreq(62000, 20);
    h.play(v);
    h.tick_to(70000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN02-T6: 보안 뒤 IdentityRequest(IMEISV — 갱신 전 nas_sec ON) — 후보 아님 / 같은 연결의 두 번째 요청(AMF 재전송)은 다시 세지 않음
TEST(IdentityRequest, T06AfterSecurityOrRepeat) {
  {
    IdentityRequestConfig one;
    one.n_idreq = 1;
    Harness h(one);
    h.play(suci(1000, 3) + std::vector<L>{idreq(1250, 3)});
    h.tick_to(3000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    IdentityRequestConfig two;
    two.n_idreq = 2;
    Harness h(two);
    h.play(suci_idreq(1000, 3) + std::vector<L>{idreq(4095, 3)});
    h.tick_to(6000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN02-T7: T2 + alloc_ms를 넘긴 뒤 B 등록 — 할당 기억이 지워져 갈래 ① 없음(갈래 ② 수 1)
TEST(IdentityRequest, T07AllocationExpired) {
  UeTableConfig ue_cfg;
  ue_cfg.alloc_ms = 60000;
  Harness h({}, false, ue_cfg);
  h.play(conn_a() + guti_head(62000, 2, kS, kS) + std::vector<L>{idreq(62096, 2)});
  h.tick_to(64000);
  EXPECT_TRUE(h.alerts.empty());
}

// mid_join — 첫 줄이 IdentityRequest면 등록 요청을 못 봐 갈래 ①은 판정하지 않고 갈래 ②에만 센다(n_idreq 1이면 branch "2" RAISE)
TEST(IdentityRequest, MidJoinCountsOnlyBranch2) {
  IdentityRequestConfig one;
  one.n_idreq = 1;
  Harness h(one);
  h.play({idreq(1050, 5)});
  h.tick_to(2000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].branch, std::optional<std::string>("2"));
  EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"mid_join"}));
  EXPECT_EQ(h.alerts[0].ues[0].values.at("nas_sec"), "UNKNOWN");
}

// AN02-T8 해제 (21_ §5.5): 기준은 마지막 성립 — T2 RAISE(갈래 ① t0+5,096) 뒤 30 s에 SUCI 식별 요청 UE 하나(창 안 2 < 5, 성립 아님)가
// UPDATE로 실려도 해제를 늦추지 않는다 → 갈래 ① + 60 s 칸(65,100)에 CLEAR, branch "1" 그대로
TEST(IdentityRequest, T08ClearOnLastSatisfied) {
  Harness h;
  h.play(conn_a() + guti_head(5000, 2, kS, kS) + std::vector<L>{idreq(5096, 2)} + suci_idreq(35000, 3));
  h.tick_to(65000);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.alerts[1].branch, std::optional<std::string>("1"));
  EXPECT_EQ(h.alerts[1].values.dump(), R"({"idreq_w":2,"known_w":1,"evicted":0})");
  h.tick_to(65100);
  ASSERT_EQ(h.alerts.size(), 3u);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[2].t, kT0 + 65100);
  EXPECT_EQ(h.alerts[2].branch, std::optional<std::string>("1"));
  EXPECT_EQ(h.logs[2], "ALERT CLEAR rule=AN-02 cell=1 t=" + std::to_string(kT0 + 65100) +
                           " duration_ms=60000 ues_total=2");
}

// 갈래 ① 걸림으로 RAISE할 때도 그때 창 안 식별 요청 연결을 모두 싣는다(11/04 해석 1) / 갈래 ① 걸림이 창 수도 N에 닿게 하면 cond는
// 둘 다(해석 2)
TEST(IdentityRequest, Branch1RaiseCarriesWindow) {
  {
    Harness h;
    h.play(suci_idreq(1000, 3) + conn_a(2000) + guti_head(5000, 2, kS, kS) + std::vector<L>{idreq(5096, 2)});
    h.tick_to(6000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues.size(), 2u);
    EXPECT_EQ(h.alerts[0].values.dump(), R"({"idreq_w":2,"known_w":1,"evicted":0})");
    EXPECT_EQ(h.alerts[0].cond, (std::vector<std::string>{"idreq_known_guti"}));
  }
  {
    IdentityRequestConfig two;
    two.n_idreq = 2;
    Harness h(two);
    h.play(suci_idreq(1000, 3) + conn_a(2000) + guti_head(5000, 2, kS, kS) + std::vector<L>{idreq(5096, 2)});
    h.tick_to(6000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].cond, (std::vector<std::string>{"idreq_known_guti", "idreq_count"}));
  }
}

// 재생 결정성 (AN02-T8) — T2·T4 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(IdentityRequest, Deterministic) {
  auto run = [] {
    Harness h({}, true);
    std::vector<L> v = conn_a() + guti_head(5000, 2, kS, kS) + std::vector<L>{idreq(5096, 2)};
    for (int64_t i = 0; i < 5; ++i) v = v + suci_idreq(6000 + 1000 * i, 10 + i);
    h.play(v);
    h.tick_to(14000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_GE(a.first.size(), 2u);
}

// END: 세션이 바뀌면 END(session_reset), 입력 침묵이면 END(input_silent) — END에도 branch
TEST(IdentityRequest, EndCarriesBranch) {
  {
    Harness h;
    h.play(conn_a() + guti_head(5000, 2, kS, kS) + std::vector<L>{idreq(5096, 2)});
    h.tick_to(6000);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
    EXPECT_EQ(h.alerts[1].branch, std::optional<std::string>("1"));
  }
  {
    Harness h;
    h.play(conn_a() + guti_head(5000, 2, kS, kS) + std::vector<L>{idreq(5096, 2)});
    h.tick_to(6000);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
    EXPECT_EQ(o.alerts[0].branch, std::optional<std::string>("1"));
  }
}

// 증거 지평 (21_ §1.1): 1,000 ms + alert.update_min_ms
TEST(IdentityRequest, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
}
