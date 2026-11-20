// 4단계 룰 AN-08 기존 UE들의 재등록 급증 테스트 — 21_ §8.8 AN08-T1~T8 (설정 범위는 test_config.cpp) + 11/04 결정(창 안 수는 서로
// 다른 S-TMSI, 회복 전 재등록은 경보 values.extra, S-TMSI는 RRC 또는 NAS, known은 alloc 먼저, known_src {"alloc","history"}).
// 합성 ue_evt·kpm2 줄로 한다(같은 시나리오의 재생 데이터는 tests/data/stage4_yellow/SAN08_* — tools/gen_stage4.py). 시각은 kT0 기준
// ms. 이동 등록 흐름 M: 5 UE가 먼저 등록해 RegistrationAccept로 S1~S5를 받고 해제(할당 기억·연결 레코드) → 2분 뒤 10 s 간격으로 각자
// RegistrationRequest(mobility, 5G-GUTI, Si). 등록 요청 줄에서 걸고(21_ §1.1) RAISE는 그 줄이 든 창의 kpm2에서 낸다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/rules/known_reg_burst.h"

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
constexpr uint64_t kBase = 0x0000a0000000;  // S_i = kBase + i
constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";

uint64_t S(int i) { return kBase + static_cast<uint64_t>(i); }
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
L f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg) { return L{t, du, dir, "F1AP", msg, "", 0}; }
std::vector<L> operator+(std::vector<L> a, const std::vector<L>& b) {
  a.insert(a.end(), b.begin(), b.end());
  return a;
}
std::vector<L> release(int64_t t, int64_t du) {
  return {f1ap(t - 5, du, "DL", "UEContextReleaseCommand"), f1ap(t, du, "UL", "UEContextReleaseComplete")};
}

// 첫 등록(SUCI) — RegistrationAccept가 s를 준다(할당 기억). accept가 false면 수락 없이 UE가 낸 S-TMSI로 서비스 요청만(이력만 — AN08-T5)
std::vector<L> Alloc(int64_t t0, int64_t du, uint64_t s, bool accept = true) {
  std::vector<L> v = {rrc(t0, du, "UL", "RRCSetupRequest", R"("ue_identity":{"type":"randomValue"})"),
                      rrc(t0, du, "DL", "RRCSetup")};
  if (accept) {
    v = v + std::vector<L>{rrc(t0 + 10, du, "UL", "RRCSetupComplete"),
                           nas(t0 + 10, du, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")"),
                           nas(t0 + 190, du, "DL", "RegistrationAccept", stmsi(s), 2)};
  } else {
    v = v + std::vector<L>{rrc(t0 + 10, du, "UL", "RRCSetupComplete", stmsi(s)), nas(t0 + 20, du, "UL", "ServiceRequest", stmsi(s), 1),
                           nas(t0 + 30, du, "DL", "ServiceAccept", "", 2)};
  }
  return v + release(t0 + 1000, du);
}
// 이동 등록 (21_ §8.8 M): RRC는 rrc_s(Part1 + RRCSetupComplete 48비트), 등록 요청은 reg_type·5G-GUTI nas_s — t0 + 20에 등록 요청(걸림),
// 시작 + 1 s에 해제. release가 false면 열어 둔다
std::vector<L> Mob(int64_t t0, int64_t du, uint64_t rrc_s, uint64_t nas_s, const std::string& reg_type = "mobility",
                   bool rel = true) {
  std::vector<L> v = {
      rrc(t0, du, "UL", "RRCSetupRequest",
          R"("est_cause":"mo-Signalling","ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" + hex(rrc_s & kPart1Mask, 10) +
              R"("})"),
      rrc(t0, du, "DL", "RRCSetup"), rrc(t0 + 10, du, "UL", "RRCSetupComplete", stmsi(rrc_s)),
      nas(t0 + 20, du, "UL", "RegistrationRequest",
          R"("reg_type":")" + reg_type + R"(","id_type":"5G-GUTI",)" + stmsi(nas_s))};
  return rel ? v + release(t0 + 1000, du) : v;
}
// 흐름 M의 앞부분: 5 UE(S1~S5)가 1 s부터 2 s 간격으로 첫 등록 (du 1~5)
std::vector<L> AllocAll(bool accept = true) {
  std::vector<L> v;
  for (int i = 1; i <= 5; ++i) v = v + Alloc(1000 + 2000 * (i - 1), i, S(i), accept);
  return v;
}

// 엔진 + AN-08 (+ 증거 기록기). 줄을 넣기 전에 그 줄 시각까지 끝난 창(t_end ≤ t)의 kpm2를 낸다(2_ §6.1). lost(창 시작)는 그 창
// kpm2의 ue_evt_lost
class Harness {
 public:
  explicit Harness(KnownRegBurstConfig cfg = {}, bool record = false)
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, UeTableConfig{}), queue(100000), rec(EvidenceConfig{}, queue),
        record_(record) {
    auto r = std::make_unique<KnownRegBurstRule>(cfg);
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
         R"(,"cc":)" + kCc + R"(,"ue_evt_lost":)" + (lost.count(t) ? R"(["UL","DL"])" : "[]") + "}");
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
  KnownRegBurstRule* rule = nullptr;
  std::map<int64_t, bool> lost;
  std::vector<AlertEvent> alerts;
  std::vector<std::string> logs;

 private:
  bool record_;
  std::string session_;
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

// 흐름 M의 뒷부분: S1~Sn이 121 s부터 gap 간격으로 이동 등록 (du 11~), 걸림은 시작 + 20
std::vector<L> MobAll(int n = 5, int64_t gap = 10000, const std::string& reg_type = "mobility") {
  std::vector<L> v;
  for (int i = 1; i <= n; ++i) v = v + Mob(121000 + gap * (i - 1), 10 + i, S(i), S(i), reg_type);
  return v;
}

const std::vector<std::string> kCands = {"L3-17-OV", "L3-26-O"};

}  // namespace

// AN08-T1: 정상 첫 등록 5 UE(initial) — 걸림 없음
TEST(KnownRegBurst, T01InitialRegistrations) {
  Harness h;
  h.play(AllocAll());
  h.tick_to(12000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN08-T2: M — 5번째 이동 등록(t 161,020)에서 R_W 5 → K = 161,100에 RAISE, ues 5, known alloc. 로그 줄·레코드. 창 앞쪽 UE의 연결은
// RAISE 3 s 넘게 전에 닫혀 pre 증거가 빠진다(21_ §1.1 한계) — 마지막 UE는 열려 있어 증거가 있다
TEST(KnownRegBurst, T02FiveKnownUes) {
  Harness h({}, true);
  h.play(AllocAll() + MobAll());
  h.tick_to(162000);
  ASSERT_EQ(h.alerts.size(), 1u);
  const AlertEvent& e = h.alerts[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "AN-08");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_FALSE(e.branch);
  EXPECT_EQ(e.t, kT0 + 161100);
  EXPECT_EQ(e.cond, (std::vector<std::string>{"known_reg_burst"}));
  EXPECT_EQ(e.candidates, kCands);
  EXPECT_EQ(e.values.dump(), R"({"reg_w":5,"known_src":{"alloc":5,"history":0},"extra":0,"evicted":0})");
  EXPECT_EQ(e.params.dump(), R"({"window_ms":60000,"n_reg":5,"known_ms":600000,"clear_quiet_ms":60000})");
  ASSERT_EQ(e.ues.size(), 5u);
  EXPECT_EQ(e.ues[0].du_ue_id, 11);
  EXPECT_EQ(e.ues[0].t_hit, kT0 + 121020);
  EXPECT_EQ(e.ues[0].s_tmsi, S(1));
  EXPECT_EQ(e.ues[0].cond, (std::vector<std::string>{"known_mobility_reg"}));
  EXPECT_EQ(e.ues[0].values.dump(),
            R"({"reg_type":"mobility","id_type":"5G-GUTI","known":"alloc","est_cause":"mo-Signalling"})");
  EXPECT_EQ(e.ues[4].du_ue_id, 15);
  EXPECT_EQ(h.logs[0], "ALERT RAISE rule=AN-08 cell=1 t=" + std::to_string(kT0 + 161100) +
                           " kind=anomaly reg_w=5 n_reg=5 window_ms=60000 severity=medium mode=normal"
                           " candidates=L3-17-OV,L3-26-O");
  const std::vector<std::string> recs = h.drain();
  ASSERT_FALSE(recs.empty());
  EXPECT_NE(recs[0].find(R"("rule":"AN-08","stage":4,"unit":"ue","kind":"anomaly","cell":1)"), std::string::npos);
  const std::string& r = recs[0];
  const auto first = r.find(R"("du_ue_id":11)");
  const auto last = r.find(R"("du_ue_id":15)");
  ASSERT_NE(first, std::string::npos);
  ASSERT_NE(last, std::string::npos);
  EXPECT_NE(r.find(R"("evidence":false)", first), std::string::npos);
  EXPECT_NE(r.find(R"("evidence":true)", last), std::string::npos);
}

// AN08-T3: M에서 4 UE만 / 5번째가 첫째의 61 s 뒤(창 안 4) — 경보 없음
TEST(KnownRegBurst, T03BelowThresholdOrOutsideWindow) {
  {
    Harness h;
    h.play(AllocAll() + MobAll(4));
    h.tick_to(165000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    h.play(AllocAll() + MobAll(4) + Mob(182000, 15, S(5), S(5)));
    h.tick_to(185000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN08-T4: M에서 reg_type periodic / initial(재시작 뒤 일제 재접속) — 세지 않음
TEST(KnownRegBurst, T04PeriodicOrInitialNotCounted) {
  for (const char* rt : {"periodic", "initial"}) {
    Harness h;
    h.play(AllocAll() + MobAll(5, 10000, rt));
    h.tick_to(165000);
    EXPECT_TRUE(h.alerts.empty()) << rt;
  }
}

// AN08-T5: 할당 기억 없이(RegistrationAccept 없음) UE가 낸 S-TMSI의 연결 레코드만 있음 — known history로 센다 / 그 레코드가
// known_ms보다 오래됐으면 최근 본 UE가 아니다
TEST(KnownRegBurst, T05HistoryOnly) {
  {
    Harness h;
    h.play(AllocAll(false) + MobAll());
    h.tick_to(162000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("known"), "history");
    EXPECT_EQ(h.alerts[0].values.at("known_src").dump(), R"({"alloc":0,"history":5})");
  }
  {
    KnownRegBurstConfig cfg;
    cfg.known_ms = 60000;  // 첫 연결은 2~10 s에 닫힘 — 121 s의 이동 등록에서 60 s 전보다 오래
    Harness h(cfg);
    h.play(AllocAll(false) + MobAll());
    h.tick_to(162000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// AN08-T6: 처음 보는 S-TMSI 5개의 이동 등록 — 최근 본 UE가 아님
TEST(KnownRegBurst, T06UnknownStmsi) {
  Harness h;
  h.play(MobAll());
  h.tick_to(165000);
  EXPECT_TRUE(h.alerts.empty());
}

// AN08-T7 해제: 마지막 성립(161,020) + 60 s 이상인 첫 kpm2(t_end 221,100)에 CLEAR
TEST(KnownRegBurst, T07Clear) {
  Harness h;
  h.play(AllocAll() + MobAll());
  h.tick_to(221000);
  ASSERT_EQ(h.alerts.size(), 1u);
  h.tick_to(221100);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.logs[1], "ALERT CLEAR rule=AN-08 cell=1 t=" + std::to_string(kT0 + 221100) + " duration_ms=60000 ues_total=5");
  EXPECT_EQ(h.alerts[1].values.dump(), R"({"extra":0,"evicted":0})");  // clear에는 누적값만 — 창 안 수는 없다 (14_ §8.3, 11/04)
}

// AN08-T8 (11/04 사용자 결정 — 서로 다른 S-TMSI 수): S1이 이동 등록을 10 s 간격 5번(실패 뒤 T3511 재시도 — 연결마다 새 du) — 서로
// 다른 S-TMSI 1이라 경보 없음 / 그 뒤 S2~S5가 창 안에 이동 등록 — R_W 5로 RAISE, S1 칸은 하나, values.extra 4(경보에 실릴 때 더함)
TEST(KnownRegBurst, T08RetriesOfOneUe) {
  std::vector<L> retries;
  for (int k = 0; k < 5; ++k) retries = retries + Mob(121000 + 10000 * k, 20 + k, S(1), S(1));
  {
    Harness h;
    h.play(AllocAll() + retries);
    h.tick_to(170000);
    EXPECT_TRUE(h.alerts.empty());
  }
  {
    Harness h;
    std::vector<L> others;
    for (int i = 2; i <= 5; ++i) others = others + Mob(163000 + 2000 * (i - 2), 30 + i, S(i), S(i));
    h.play(AllocAll() + retries + others);
    h.tick_to(170000);
    ASSERT_EQ(h.alerts.size(), 1u);
    const AlertEvent& e = h.alerts[0];
    EXPECT_EQ(e.t, kT0 + 169100);
    ASSERT_EQ(e.ues.size(), 5u);
    EXPECT_EQ(e.ues[0].s_tmsi, S(1));
    EXPECT_EQ(e.ues[0].du_ue_id, 20);
    EXPECT_EQ(e.values.dump(), R"({"reg_w":5,"known_src":{"alloc":5,"history":0},"extra":4,"evicted":0})");
  }
}

// 11/04 구현 때 정함 (AN-02와 같음): S-TMSI는 RRC 또는 NAS — NAS GUTI가 모르는 값이어도 RRC의 48비트가 최근 본 UE면 걸린다(그 값이
// 걸림 키) / 둘 다 모르는 값이면 걸리지 않는다
TEST(KnownRegBurst, RrcOrNas) {
  constexpr uint64_t kUnknown = 0x00fedcba9876;
  {
    KnownRegBurstConfig cfg;
    cfg.n_reg = 1;
    Harness h(cfg);
    h.play(Alloc(1000, 1, S(1)) + Mob(121000, 11, S(1), kUnknown));
    h.tick_to(122000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues[0].values.at("known"), "alloc");
  }
  {
    KnownRegBurstConfig cfg;
    cfg.n_reg = 1;
    Harness h(cfg);
    h.play(Alloc(1000, 1, S(1)) + Mob(121000, 11, kUnknown, kUnknown));
    h.tick_to(122000);
    EXPECT_TRUE(h.alerts.empty());
  }
}

// 같은 연결의 등록 요청 재전송은 다시 세지 않는다(extra도 아님) / mid_join(첫 줄이 등록 요청)도 판정하고 uncertain에 싣는다 / 걸린 줄이
// 든 창이 로스 창이면 kpm2에서 그 연결 상태로 다시 채워 uncertain에 loss (식별은 걸림 키가 아니라 실제 연결에서 — ref)
TEST(KnownRegBurst, SameConnectionMidJoinAndLoss) {
  KnownRegBurstConfig cfg;
  cfg.n_reg = 1;
  {
    Harness h(cfg);
    std::vector<L> m = Mob(121000, 11, S(1), S(1), "mobility", false);
    m.push_back(nas(121050, 11, "UL", "RegistrationRequest", R"("reg_type":"mobility","id_type":"5G-GUTI",)" + stmsi(S(1))));
    h.play(Alloc(1000, 1, S(1)) + m);
    h.tick_to(130000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].values.at("extra"), 0);
  }
  {
    Harness h(cfg);
    h.play(Alloc(1000, 1, S(1)) +
           std::vector<L>{nas(121020, 11, "UL", "RegistrationRequest",
                              R"("reg_type":"mobility","id_type":"5G-GUTI",)" + stmsi(S(1)))});
    h.tick_to(122000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"mid_join"}));
    EXPECT_EQ(h.alerts[0].ues[0].values.at("est_cause"), nullptr);
  }
  {
    Harness h(cfg);
    h.lost[121000] = true;
    h.play(Alloc(1000, 1, S(1)) + Mob(121000, 11, S(1), S(1)));
    h.tick_to(122000);
    ASSERT_EQ(h.alerts.size(), 1u);
    EXPECT_EQ(h.alerts[0].ues[0].du_ue_id, 11);
    EXPECT_EQ(h.alerts[0].ues[0].uncertain, (std::vector<std::string>{"loss"}));
  }
}

// 회복 (21_ §8.3-1): 걸린 S-TMSI가 창 W 동안 걸리는 이동 등록을 하지 않으면 회복 — 다시 오면 새 걸림(n_reg 1이라 새 RAISE)
TEST(KnownRegBurst, RecoveredStmsiIsNewAgain) {
  KnownRegBurstConfig cfg;
  cfg.n_reg = 1;
  Harness h(cfg);
  h.play(Alloc(1000, 1, S(1)) + Mob(121000, 11, S(1), S(1)) + Mob(141000, 12, S(1), S(1)) + Mob(260000, 13, S(1), S(1)));
  h.tick_to(262000);
  ASSERT_EQ(h.alerts.size(), 3u);  // RAISE, CLEAR, RAISE
  EXPECT_EQ(h.alerts[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.alerts[2].t, kT0 + 260100);
  EXPECT_EQ(h.alerts[2].ues[0].du_ue_id, 13);
  EXPECT_EQ(h.alerts[2].values.at("extra"), 0);
}

// 재생 결정성 (AN08-T7) — T8 모양을 두 번 재생하면 경보 줄·증거 레코드가 바이트 단위로 같다
TEST(KnownRegBurst, Deterministic) {
  auto run = [] {
    Harness h({}, true);
    std::vector<L> v = AllocAll();
    for (int k = 0; k < 5; ++k) v = v + Mob(121000 + 10000 * k, 20 + k, S(1), S(1));
    for (int i = 2; i <= 5; ++i) v = v + Mob(163000 + 2000 * (i - 2), 30 + i, S(i), S(i));
    h.play(v);
    h.tick_to(175000);
    return std::make_pair(h.logs, h.drain());
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.first.size(), 1u);
}

// END: 세션이 바뀌면 END(session_reset) / 입력 침묵이면 END(input_silent)
TEST(KnownRegBurst, EndOnSessionResetAndInputSilent) {
  {
    Harness h;
    h.play(AllocAll() + MobAll());
    h.tick_to(162000);
    ASSERT_EQ(h.alerts.size(), 1u);
    h.hello("S2");
    ASSERT_EQ(h.alerts.size(), 2u);
    EXPECT_EQ(h.alerts[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.alerts[1].reason, "session_reset");
  }
  {
    Harness h;
    h.play(AllocAll() + MobAll());
    h.tick_to(162000);
    EngineOutput o = h.engine.on_input_silent(10000);
    ASSERT_EQ(o.alerts.size(), 1u);
    EXPECT_EQ(o.alerts[0].reason, "input_silent");
  }
}

// 증거 지평 (21_ §1.1): 1,000 ms + alert.update_min_ms
TEST(KnownRegBurst, EvidenceHorizon) {
  Harness h;
  EXPECT_EQ(h.rule->evidence_horizon_ms(), 2000);
}

// 지속 공격 (21_ §8.3-1·§8.5 — 11/04 Q-69 (가), 이슈 #86): S1~S5가 20 s 간격으로 12회씩 이동 등록 — 5번째(129,020)에서 RAISE, 그 뒤
// 회복 전 재등록 55회가 extra이고 반복마다 마지막 성립 시각이 밀려 공격 내내 경보 하나. CLEAR는 마지막 재등록(349,020) + 60 s,
// CLEAR values extra 55. 재생 데이터 SAN08_AN-08_지속공격_CLEAR
TEST(KnownRegBurst, SustainedRepeatKeepsAlertOpen) {
  Harness h;
  std::vector<L> v = AllocAll();
  int64_t du = 100;
  for (int k = 0; k < 12; ++k)
    for (int i = 1; i <= 5; ++i) v = v + Mob(121000 + 20000 * k + 2000 * (i - 1), du++, S(i), S(i));
  h.play(v);
  h.tick_to(409000);
  ASSERT_EQ(h.alerts.size(), 1u);
  EXPECT_EQ(h.alerts[0].t, kT0 + 129100);
  h.tick_to(409100);
  ASSERT_EQ(h.alerts.size(), 2u);
  EXPECT_EQ(h.alerts[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.alerts[1].t, kT0 + 409100);
  EXPECT_EQ(h.alerts[1].ues_total, 5);
  EXPECT_EQ(h.alerts[1].values.dump(), R"({"extra":55,"evicted":0})");
}
