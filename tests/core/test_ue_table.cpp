// UE 상태표·마감 목록·2단계 분배 테스트 — 14_ §10 공통 테스트 U-T1~U-T29(U-T26·U-T27은 이슈 #44 유령 정리·보호 무리, U-T28은 이슈 #46 late_until, U-T29는 이슈 #48 진단),
// 입력 침묵의 엔진 몫(이슈 #50 — 소켓 통합 시험 U-T31은 tests/integration).
// U-T13(1단계 alert 형식 이전)은 이슈 #17에서 확인했고, U-T20(경보당 증거 UE 상한)은 UE 증거 이슈에서 한다.
// S-TMSI 이력 표(14_ §3.2 — U-T1·U-T11의 기억 표 부분, U-T32~U-T35)는 11/04 이슈 #74, 레코드 rejected(U-T36)는 이슈 #80.
// 대기 표시가 필요한 시험은 15_ 룰의 대기 규칙(14_ §2.4·§6)을 그대로 따르는 테스트용 룰(WaitRule)로 한다
#include "detect/engine.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace detect;

namespace {

constexpr int64_t kT0 = 1793005200000;
constexpr uint64_t kS = 0x0123456789ab;   // 48비트 5G-S-TMSI
constexpr uint64_t kS2 = 0x0000fedcba98;
constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;

// 1단계 카운터가 있는 정상 kpm2 cc, DL 미관측 모드 cc(FailCause null)
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";
const std::string kCcDlMissing =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":null})";

std::string hex(uint64_t v, int digits) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%0*llx", digits, static_cast<unsigned long long>(v));
  return buf;
}
std::string stmsi(uint64_t v) { return R"("s_tmsi":")" + hex(v, 12) + "\""; }
std::string part1(uint64_t v) {
  return R"("ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":")" + hex(v & kPart1Mask, 10) + R"("})";
}

// 테스트용 2단계 룰: NAS AuthenticationRequest(DL) 뒤 kWait ms 안에 AuthenticationResponse(UL)가 없으면 '걸림'.
// 대기 표시는 (키, uid)로 두고 15_ §1·14_ §2.4의 규칙을 따른다 — released·reused·stale_setup이면 표시를 남겨 마감 때
// 판정, du_reset·evicted·session_reset이면 지움, 꺼낼 때 uid·t_from 대조, 방향별 보류, mid_join·late(late_until까지)는 판정 안 함
class WaitRule : public UeRule {
 public:
  static constexpr int64_t kWait = 2000;

  struct Mark {
    int64_t t_from = 0;
    int64_t deadline = 0;
    bool closed = false;
    bool mid_join = false;
    bool late = false;
    std::optional<int64_t> late_until;  // 닫힌 항목의 늦은 줄 제외 기간 (14_ §4.3, 이슈 #46)
  };
  struct Hit {
    UeKey key;
    int64_t uid = 0;
    int64_t at = 0;
    bool closed = false;
  };

  std::map<std::pair<UeKey, int64_t>, Mark> marks;
  std::vector<Hit> hits;
  int held = 0;
  int discarded = 0;
  int skipped = 0;  // mid_join·late(late_until 안)라 판정 안 함
  int resets = 0;
  std::vector<std::string> log;  // 호출 순서 — "event 1/3/1 RRCSetupRequest", "close 1/3/1 released"
  std::vector<std::tuple<int64_t, bool, bool, bool>> ticks;  // (셀, loss.ul, loss.dl, input_lost)
  // 닫힘 통지를 받을 때 S-TMSI 이력 표에 이 연결의 레코드가 이미 있었나 (14_ §3.2·§7 ⑦ — 레코드 먼저)
  std::vector<bool> record_seen_at_close;

  static std::string name(const UeState& s) {
    return std::to_string(s.key.cell_id) + "/" + std::to_string(s.key.du_ue_id) + "/" + std::to_string(s.uid);
  }

  const char* id() const override { return "TEST-WAIT"; }
  int64_t evidence_horizon_ms() const override { return kWait; }

  void on_ue_event(const UeEvt& e, const UeState&, const UeState& after, const UeRuleCtx& ctx, RuleOutput&) override {
    log.push_back("event " + name(after) + " " + e.msg);
    const auto k = std::make_pair(after.key, after.uid);
    if (e.proto == Proto::NAS && e.dir == Dir::DL && e.msg == "AuthenticationRequest") {
      if (marks.count(k)) return;  // 기다리는 중 재전송은 다시 시작하지 않는다
      Mark m;
      m.t_from = e.t_ms;
      m.deadline = e.t_ms + kWait;
      marks[k] = m;
      ctx.add_deadline(e.t_ms + kWait, after.key, after.uid, "auth_resp", Dir::UL, e.t_ms);
    } else if (e.proto == Proto::NAS && e.dir == Dir::UL && e.msg == "AuthenticationResponse") {
      auto it = marks.find(k);
      if (it != marks.end() && e.t_ms < it->second.deadline) marks.erase(it);  // 제때 응답 (14_ §6.1-5)
    }
  }

  void on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput&) override {
    auto it = marks.find({d.key, d.uid});
    if (it == marks.end() || it->second.t_from != d.t_from) {
      ++discarded;
      return;
    }
    const Mark m = it->second;
    marks.erase(it);
    if (ctx.deadlines.held(d.key.cell_id, d.dir, d.t_from)) {
      ++held;
      return;
    }
    bool mid_join = m.mid_join;
    bool late = m.late && m.late_until && d.at < *m.late_until;  // 14_ §4.3 late_until — 닫힌 항목은 표시의 복사본으로
    if (const UeState* s = ctx.table.find(d.key); s && s->uid == d.uid) {
      mid_join = s->mid_join;
      late = s->late_blocks(d.at);
    }
    if (mid_join || late) {
      ++skipped;
      return;
    }
    hits.push_back(Hit{d.key, d.uid, d.at, m.closed});
  }

  void on_ue_close(const UeState& last, CloseReason reason, int64_t, const UeRuleCtx& ctx, RuleOutput&) override {
    log.push_back("close " + name(last) + " " + to_string(reason));
    if (last.s_tmsi || last.s_tmsi_part1) {
      const auto recs = last.s_tmsi ? ctx.table.history(*last.s_tmsi, 0)
                                    : ctx.table.history_part1(*last.s_tmsi_part1, 0);
      record_seen_at_close.push_back(!recs.empty() && recs.back()->uid == last.uid);
    }
    auto it = marks.find({last.key, last.uid});
    if (it == marks.end()) return;
    if (reason == CloseReason::Released || reason == CloseReason::Reused || reason == CloseReason::StaleSetup) {
      it->second.closed = true;
      it->second.mid_join = last.mid_join;
      it->second.late = last.late;
      it->second.late_until = last.late_until;
    } else {
      marks.erase(it);
    }
  }

  void on_cell_tick(int64_t cell, const Kpm2&, const CellLoss& loss, bool input_lost, const UeRuleCtx&,
                    RuleOutput&) override {
    ticks.emplace_back(cell, loss.ul, loss.dl, input_lost);
  }

  void on_session_reset(const UeRuleCtx&, RuleOutput&) override {
    ++resets;
    marks.clear();
    log.push_back("reset");
  }
};

// 엔진 + WaitRule. 시각은 kT0 기준 ms로 받는다
class Harness {
 public:
  explicit Harness(UeTableConfig cfg = {}, bool ue_evt = true, SeriesConfig scfg = {})
      : engine(scfg, kDefaultMaxLineBytes, cfg) {
    auto r = std::make_unique<WaitRule>();
    rule = r.get();
    engine.add_ue_rule(std::move(r));
    hello(ue_evt);
  }

  // hello. 다른 session이면 seq를 1부터
  EngineOutput hello(bool ue_evt = true, const std::string& session = "S") {
    if (session != session_) {
      session_ = session;
      seq_ = 0;
      next_t_.clear();
    }
    return feed(R"({"type":"hello","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
                R"(,"cells":[{"cell_id":1,"max_conn":null},{"cell_id":2,"max_conn":null}],"period_ms":100,)"
                R"("noreply_timeout_ms":1000,"clock":"realtime")" +
                (ue_evt ? R"(,"ue_evt":true)" : "") + "}");
  }

  EngineOutput rrc(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "",
                   int64_t cell = 1) {
    return ue(t, cell, std::to_string(du), dir, "RRC", msg, f, "");
  }
  EngineOutput nas(int64_t t, int64_t du, const std::string& dir, const std::string& msg, const std::string& f = "",
                   int sht = 0, int64_t cell = 1) {
    return ue(t, cell, std::to_string(du), dir, "NAS", msg, f, R"(,"via":"F1","sht":)" + std::to_string(sht));
  }
  EngineOutput f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg, int64_t cell = 1) {
    return ue(t, cell, std::to_string(du), dir, "F1AP", msg, "", "");
  }
  // ue_evt 한 줄 (2_ §6.2). du = "null"이면 du_ue_id·crnti가 null
  EngineOutput ue(int64_t t, int64_t cell, const std::string& du, const std::string& dir, const std::string& proto,
                  const std::string& msg, const std::string& f, const std::string& extra) {
    const std::string crnti = du == "null" ? "null" : std::to_string(17000 + std::stoll(du));
    return feed(R"({"type":"ue_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
                R"(,"t_ms":)" + std::to_string(kT0 + t) + R"(,"cell_id":)" + std::to_string(cell) +
                R"(,"du_ue_id":)" + du + R"(,"crnti":)" + crnti + R"(,"dir":")" + dir + R"(","proto":")" + proto +
                R"(","msg":")" + msg + "\"" + extra + (f.empty() ? "" : R"(,"f":{)" + f + "}") + "}");
  }
  // f1_evt (2_ §6.7)
  EngineOutput f1(int64_t t, const std::string& msg, const std::string& cells, const std::string& du_ue_ids = "") {
    return feed(R"({"type":"f1_evt","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
                R"(,"t_ms":)" + std::to_string(kT0 + t) + R"(,"msg":")" + msg + R"(","cells":)" + cells +
                (du_ue_ids.empty() ? "" : R"(,"du_ue_ids":)" + du_ue_ids) + "}");
  }
  // kpm2 한 칸 [t, t+100) — 그 셀 시계를 t+100으로 올린다. lost = ue_evt_lost 값(빈 문자열이면 키 없음).
  // conn_max(cell, v)를 두면 si.RRC.ConnMax로 실린다 (유령 정리 U-T26, 이슈 #44)
  EngineOutput kpm(int64_t t, const std::string& lost = "[]", int64_t cell = 1, const std::string& cc = kCc) {
    next_t_[cell] = t + 100;
    const auto cm = conn_max_.find(cell);
    return feed(R"({"type":"kpm2","ver":1,"session":")" + session_ + R"(","seq":)" + std::to_string(++seq_) +
                R"(,"cell_id":)" + std::to_string(cell) + R"(,"t_start_ms":)" + std::to_string(kT0 + t) +
                R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) + (cc.empty() ? "" : R"(,"cc":)" + cc) +
                (cm == conn_max_.end() ? "" : R"(,"si":{"RRC.ConnMax":)" + std::to_string(cm->second) + "}") +
                (lost.empty() ? "" : R"(,"ue_evt_lost":)" + lost) + "}");
  }
  void conn_max(int64_t cell, int64_t v) { conn_max_[cell] = v; }
  // 그 셀 시계를 끊김 없이 t까지 올린다 (100 ms 칸, ue_evt_lost [])
  void tick_to(int64_t t, int64_t cell = 1) {
    while (next_t_[cell] < t) kpm(next_t_[cell], "[]", cell);
  }

  EngineOutput feed(const std::string& line) {
    last_line = line;
    EngineOutput out = engine.feed_line(line);
    diags.insert(diags.end(), out.diags.begin(), out.diags.end());
    return out;
  }

  int count(DiagKind k) const {
    return static_cast<int>(std::count_if(diags.begin(), diags.end(), [&](const Diag& d) { return d.kind == k; }));
  }
  const UeState* ue_state(int64_t du, int64_t cell = 1) const { return engine.ue_table().find(UeKey{cell, du}); }
  bool logged(const std::string& s) const {
    return std::find(rule->log.begin(), rule->log.end(), s) != rule->log.end();
  }
  // a가 b보다 먼저 기록됐는지
  bool before(const std::string& a, const std::string& b) const {
    auto ia = std::find(rule->log.begin(), rule->log.end(), a);
    auto ib = std::find(rule->log.begin(), rule->log.end(), b);
    return ia != rule->log.end() && ib != rule->log.end() && ia < ib;
  }

  Engine engine;
  WaitRule* rule = nullptr;
  std::vector<Diag> diags;
  std::string last_line;

 private:
  std::string session_;
  int64_t seq_ = 0;
  std::map<int64_t, int64_t> next_t_;
  std::map<int64_t, int64_t> conn_max_;
};

// UE du가 CONNECTED로 붙는다 (RRCSetupRequest + RRCSetupComplete, 같은 시각)
void connect(Harness& h, int64_t t, int64_t du) {
  h.rrc(t, du, "UL", "RRCSetupRequest");
  h.rrc(t, du, "UL", "RRCSetupComplete");
}

}  // namespace

// U-T1: 정상 첫 등록(2_ §6.4) + 해제 — 상태 전이가 14_ §5대로, released로 닫히고 색인에서 빠짐
TEST(UeTable, UT01NormalRegistrationAndRelease) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest", R"("est_cause":"mo-Signalling","ue_identity":{"type":"randomValue"})");
  const UeState* s = h.ue_state(3);
  ASSERT_TRUE(s);
  EXPECT_EQ(s->uid, 1);
  EXPECT_FALSE(s->mid_join);
  EXPECT_EQ(s->rrc, RrcState::Setup);
  EXPECT_EQ(s->nas, NasState::Unknown);
  EXPECT_EQ(s->rrc_sec, RrcSecState::Off);
  EXPECT_EQ(s->nas_sec, NasSecState::None);
  EXPECT_EQ(s->crnti, 17003);
  EXPECT_EQ(s->t_start, kT0);

  h.rrc(0, 3, "DL", "RRCSetup");
  EXPECT_EQ(h.ue_state(3)->t_rrc_setup, kT0);
  h.rrc(91, 3, "UL", "RRCSetupComplete");
  EXPECT_EQ(h.ue_state(3)->rrc, RrcState::Connected);
  h.nas(91, 3, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")");
  EXPECT_EQ(h.ue_state(3)->nas, NasState::RegInitiated);
  h.nas(105, 3, "DL", "AuthenticationRequest");
  EXPECT_EQ(h.ue_state(3)->nas_sec, NasSecState::Auth);
  h.nas(118, 3, "UL", "AuthenticationResponse");
  EXPECT_EQ(h.ue_state(3)->nas_sec, NasSecState::AuthOk);
  h.nas(125, 3, "DL", "SecurityModeCommand", R"("cipher":"5G-EA0","integrity":"5G-IA2")", 3);
  EXPECT_EQ(h.ue_state(3)->nas_sec, NasSecState::Cmd);
  ASSERT_TRUE(h.ue_state(3)->nas_alg);
  EXPECT_EQ(h.ue_state(3)->nas_alg->cipher, "5G-EA0");
  EXPECT_EQ(h.ue_state(3)->nas_alg->integrity, "5G-IA2");
  h.nas(130, 3, "UL", "SecurityModeComplete", "", 4);
  EXPECT_EQ(h.ue_state(3)->nas_sec, NasSecState::On);
  h.rrc(140, 3, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")");
  EXPECT_EQ(h.ue_state(3)->rrc_sec, RrcSecState::Cmd);
  ASSERT_TRUE(h.ue_state(3)->rrc_alg);
  EXPECT_EQ(h.ue_state(3)->rrc_alg->integrity, "nia2");
  h.rrc(150, 3, "UL", "SecurityModeComplete");
  EXPECT_EQ(h.ue_state(3)->rrc_sec, RrcSecState::On);
  h.nas(160, 3, "DL", "RegistrationAccept", stmsi(kS), 2);
  EXPECT_EQ(h.ue_state(3)->nas, NasState::Registered);
  EXPECT_EQ(h.ue_state(3)->s_tmsi, kS);
  h.nas(170, 3, "UL", "RegistrationComplete", "", 2);
  EXPECT_EQ(h.ue_state(3)->t_reg_complete, kT0 + 170);

  // (proto, msg)별 횟수 — RRC와 NAS의 SecurityModeCommand를 따로 센다 (14_ §2.3)
  EXPECT_EQ(h.ue_state(3)->count(Proto::NAS, "SecurityModeCommand"), 1);
  EXPECT_EQ(h.ue_state(3)->count(Proto::RRC, "SecurityModeCommand"), 1);
  EXPECT_EQ(h.ue_state(3)->count(Proto::NAS, "RegistrationReject"), 0);
  // 최근 메시지는 받은 원본 줄 그대로 (14_ §2.3)
  const auto* recent = h.engine.ue_table().recent(UeKey{1, 3});
  ASSERT_TRUE(recent);
  EXPECT_EQ(recent->size(), 12u);
  EXPECT_EQ(recent->back().raw, h.last_line);
  EXPECT_EQ(h.ue_state(3)->last.msg, "RegistrationComplete");

  h.f1ap(5000, 3, "DL", "UEContextReleaseCommand");
  EXPECT_EQ(h.ue_state(3)->rrc, RrcState::Releasing);
  h.f1ap(5010, 3, "UL", "UEContextReleaseComplete");
  EXPECT_FALSE(h.ue_state(3));
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  EXPECT_TRUE(h.engine.ue_table().by_s_tmsi(kS).empty());
  // 닫히는 줄도 룰이 먼저 보고(⑤) 닫힘을 받는다(⑦) — 14_ §7
  ASSERT_GE(h.rule->log.size(), 2u);
  EXPECT_EQ(h.rule->log[h.rule->log.size() - 2], "event 1/3/1 UEContextReleaseComplete");
  EXPECT_EQ(h.rule->log.back(), "close 1/3/1 released");

  // S-TMSI 이력 표 (14_ §3.2): 닫힌 연결이 레코드로 남고, 망이 RegistrationAccept로 준 S-TMSI는 할당 기억에 있다
  EXPECT_EQ(h.engine.ue_table().allocated(kS), kT0 + 160);
  const auto recs = h.engine.ue_table().history(kS, 0);
  ASSERT_EQ(recs.size(), 1u);
  const ConnRecord& r = *recs[0];
  EXPECT_EQ(r.uid, 1);
  EXPECT_EQ(r.key.du_ue_id, 3);
  EXPECT_EQ(r.t_start, kT0);
  EXPECT_EQ(r.t_end, kT0 + 5010);
  EXPECT_EQ(r.reason, CloseReason::Released);
  EXPECT_TRUE(r.connected);
  EXPECT_TRUE(r.accepted);
  EXPECT_EQ(r.rrc_last, RrcState::Releasing);
  EXPECT_EQ(r.nas_last, NasState::Registered);
  EXPECT_EQ(std::string(r.src()), "net");  // SUCI 등록 — S-TMSI는 RegistrationAccept에만 있다(14_ §2.1)
  EXPECT_EQ(r.est_cause, "mo-Signalling");
  EXPECT_EQ(r.reg_type, "initial");
  EXPECT_EQ(r.id_type, "SUCI");
  EXPECT_FALSE(r.rel_req_cause);
  EXPECT_EQ(r.part1, kS & kPart1Mask);
  EXPECT_EQ(h.engine.ue_table().history_part1(kS & kPart1Mask, 0).size(), 1u);
  EXPECT_EQ(h.rule->record_seen_at_close, (std::vector<bool>{true}));
}

// U-T2: 이미 등록한 UE의 ServiceRequest → ServiceAccept — nas SR_INITIATED → REGISTERED, S-TMSI 색인
TEST(UeTable, UT02ServiceRequestAccept) {
  Harness h;
  h.rrc(0, 5, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(0, 5, "DL", "RRCSetup");
  h.rrc(50, 5, "UL", "RRCSetupComplete", stmsi(kS));
  h.nas(50, 5, "UL", "ServiceRequest", stmsi(kS), 1);
  EXPECT_EQ(h.ue_state(5)->nas, NasState::SrInitiated);
  const auto hit = h.engine.ue_table().by_s_tmsi(kS);
  ASSERT_EQ(hit.size(), 1u);
  EXPECT_TRUE(hit[0]->key == (UeKey{1, 5}));
  h.nas(80, 5, "DL", "ServiceAccept", "", 2);
  EXPECT_EQ(h.ue_state(5)->nas, NasState::Registered);
}

// U-T3: 같은 S-TMSI 두 연결(다른 셀) — 색인은 gNB 전체라 둘 다 나온다 (14_ §3.1)
TEST(UeTable, UT03SameStmsiTwoCells) {
  Harness h;
  for (int64_t cell : {1, 2}) {
    h.rrc(0, 3, "UL", "RRCSetupRequest", "", cell);
    h.rrc(50, 3, "UL", "RRCSetupComplete", stmsi(kS), cell);
  }
  const auto hit = h.engine.ue_table().by_s_tmsi(kS);
  ASSERT_EQ(hit.size(), 2u);
  EXPECT_TRUE(hit[0]->key == (UeKey{1, 3}));
  EXPECT_TRUE(hit[1]->key == (UeKey{2, 3}));
}

// U-T4: UEContextReleaseComplete를 놓친 뒤 같은 du_ue_id의 RRCSetupRequest — 옛 항목 reused, 새 항목 정상.
// 열면서 닫은 옛 항목은 새 항목의 이벤트보다 먼저 알린다
TEST(UeTable, UT04ReusedKey) {
  Harness h;
  h.rrc(0, 4, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(50, 4, "UL", "RRCSetupComplete", stmsi(kS));
  h.rrc(300, 4, "UL", "RRCSetupRequest");
  const UeState* s = h.ue_state(4);
  ASSERT_TRUE(s);
  EXPECT_EQ(s->uid, 2);
  EXPECT_EQ(s->rrc, RrcState::Setup);
  EXPECT_FALSE(s->mid_join);
  EXPECT_FALSE(s->s_tmsi);
  EXPECT_TRUE(h.before("close 1/4/1 reused", "event 1/4/2 RRCSetupRequest"));
  EXPECT_TRUE(h.engine.ue_table().by_s_tmsi(kS).empty());
  EXPECT_TRUE(h.engine.ue_table().by_part1(kS & kPart1Mask).empty());
}

// U-T5: 첫 줄이 SecurityModeComplete인 키 — mid_join, rrc·보안 상태 UNKNOWN.
// 보안 헤더가 있는 NAS 줄(sht ≥ 1)을 보면 CONNECTED로 본다 (14_ §5.1). mid_join에는 stale_setup 마감을 걸지 않는다
TEST(UeTable, UT05MidJoin) {
  Harness h;
  h.rrc(0, 6, "UL", "SecurityModeComplete");
  const UeState* s = h.ue_state(6);
  ASSERT_TRUE(s);
  EXPECT_TRUE(s->mid_join);
  EXPECT_EQ(s->rrc, RrcState::Unknown);
  EXPECT_EQ(s->rrc_sec, RrcSecState::Unknown);
  EXPECT_EQ(s->nas_sec, NasSecState::Unknown);
  EXPECT_EQ(s->nas, NasState::Unknown);
  EXPECT_EQ(h.engine.deadlines().size(), 0u);

  h.nas(10, 6, "UL", "RegistrationComplete", "", 2);
  EXPECT_EQ(h.ue_state(6)->rrc, RrcState::Connected);
  h.nas(0, 7, "UL", "RegistrationRequest", "", 0);  // sht 0 — 보안을 쓰지 않음
  EXPECT_EQ(h.ue_state(7)->rrc, RrcState::Unknown);
}

// U-T6: 마감 등록 → ① 마감 전 응답 ② 응답 없음 ③ 마감 전 닫힘(released) ④ 응답 뒤 다시 기다림.
// on_deadline이 ①·④의 옛 마감은 버리고 ②는 성립, ③은 표시를 남겨 마감 때 판정 (14_ §6.1-3, §2.4, 15_ §1)
TEST(UeTable, UT06DeadlineCases) {
  Harness h;
  for (int64_t du : {10, 11, 12, 13}) h.rrc(0, du, "UL", "RRCSetupRequest");
  for (int64_t du : {10, 11, 12, 13}) h.nas(100, du, "DL", "AuthenticationRequest");
  h.nas(200, 13, "UL", "AuthenticationResponse");
  h.nas(300, 10, "UL", "AuthenticationResponse");
  h.nas(500, 13, "DL", "AuthenticationRequest");
  h.f1ap(1000, 12, "UL", "UEContextReleaseComplete");
  h.tick_to(2100);  // 마감 kT0+2100이 든 창 [2000, 2100)까지
  ASSERT_EQ(h.rule->hits.size(), 2u);
  EXPECT_EQ(h.rule->hits[0].key.du_ue_id, 11);
  EXPECT_FALSE(h.rule->hits[0].closed);
  EXPECT_EQ(h.rule->hits[1].key.du_ue_id, 12);
  EXPECT_TRUE(h.rule->hits[1].closed);
  EXPECT_EQ(h.rule->discarded, 2);  // ①, ④의 첫 마감(t_from이 다름)
  h.tick_to(2500);
  ASSERT_EQ(h.rule->hits.size(), 3u);
  EXPECT_EQ(h.rule->hits[2].key.du_ue_id, 13);
  EXPECT_EQ(h.rule->hits[2].at, kT0 + 2500);
}

// U-T7: 대기 구간에 로스 창 — 보류(held), 항목에 loss·t_loss (14_ §4.3·§6.2)
TEST(UeTable, UT07LossDuringWaitIsHeld) {
  Harness h;
  h.rrc(0, 20, "UL", "RRCSetupRequest");
  h.nas(100, 20, "DL", "AuthenticationRequest");
  h.tick_to(500);
  h.kpm(500, R"(["UL","DL"])");
  EXPECT_TRUE(h.ue_state(20)->loss);
  EXPECT_EQ(h.ue_state(20)->t_loss, kT0 + 600);
  h.tick_to(2200);
  EXPECT_EQ(h.rule->held, 1);
  EXPECT_TRUE(h.rule->hits.empty());
}

// U-T8: 상한 초과 — t_last가 가장 오래된 항목부터 evicted, 진단·셀별 수 (14_ §4.4)
TEST(UeTable, UT08Evicted) {
  UeTableConfig cfg;
  cfg.max_ues = 3;
  Harness h(cfg);
  for (int64_t du : {1, 2, 3}) h.rrc(du * 10, du, "UL", "RRCSetupRequest");
  h.rrc(40, 4, "UL", "RRCSetupRequest");
  EXPECT_FALSE(h.ue_state(1));
  EXPECT_EQ(h.engine.ue_table().size(), 3u);
  EXPECT_EQ(h.engine.ue_table().counts(1).evicted, 1);
  EXPECT_EQ(h.count(DiagKind::UeEvicted), 1);
  EXPECT_TRUE(h.before("close 1/1/1 evicted", "event 1/4/4 RRCSetupRequest"));
}

// U-T9: CONNECTED 뒤 10분 무신호 — 시간으로 닫지 않는다 (14_ §4.2 'CONNECTED 이후는 시간 만료 없음')
TEST(UeTable, UT09ConnectedNeverExpires) {
  Harness h;
  h.rrc(0, 30, "UL", "RRCSetupRequest");
  h.rrc(50, 30, "UL", "RRCSetupComplete");
  h.kpm(0);
  h.kpm(600000);  // 10분 뒤 칸 (그 사이 끊김)
  EXPECT_TRUE(h.ue_state(30));
  EXPECT_EQ(h.engine.deadlines().size(), 0u);  // stale_setup 마감은 CONNECTED라 버렸다
}

// U-T10: SETUP 상태 30초 무신호 — stale_setup (14_ §4.2·§6.1 표)
TEST(UeTable, UT10StaleSetup) {
  Harness h;
  h.rrc(0, 31, "UL", "RRCSetupRequest");
  h.tick_to(29900);
  EXPECT_TRUE(h.ue_state(31));
  h.kpm(29900);  // 마감 kT0+30000이 든 창
  EXPECT_FALSE(h.ue_state(31));
  EXPECT_EQ(h.rule->log.back(), "close 1/31/1 stale_setup");
}

// U-T11: 새 hello — 상태표·색인·마감 목록을 모두 비우고 룰은 진행 중 경보를 끝낸다. uid는 1부터 (14_ §7 hello)
TEST(UeTable, UT11NewSessionClearsEverything) {
  Harness h;
  h.rrc(0, 40, "UL", "RRCSetupRequest", part1(kS));
  h.nas(100, 40, "DL", "AuthenticationRequest");
  EXPECT_EQ(h.engine.deadlines().size(), 2u);  // stale_setup + 룰의 대기
  h.rrc(100, 42, "UL", "RRCSetupRequest");
  h.nas(110, 42, "DL", "RegistrationAccept", stmsi(kS2), 2);  // 할당 기억
  h.f1ap(120, 42, "UL", "UEContextReleaseComplete");          // 연결 레코드
  EXPECT_EQ(h.engine.ue_table().history_size(), 1u);
  EXPECT_EQ(h.engine.ue_table().alloc_size(), 1u);
  h.hello(true, "S2");
  EXPECT_EQ(h.rule->resets, 1);
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  EXPECT_EQ(h.engine.deadlines().size(), 0u);
  EXPECT_TRUE(h.engine.ue_table().by_part1(kS & kPart1Mask).empty());
  EXPECT_EQ(h.engine.ue_table().history_size(), 0u);  // S-TMSI 이력 표도 비운다 (14_ §3.2)
  EXPECT_EQ(h.engine.ue_table().alloc_size(), 0u);
  h.rrc(0, 41, "UL", "RRCSetupRequest");
  EXPECT_EQ(h.ue_state(41)->uid, 1);
  h.hello(true, "S2");  // 같은 세션·같은 파라미터(재연결) — 상태 유지
  EXPECT_EQ(h.rule->resets, 1);
  EXPECT_TRUE(h.ue_state(41));
}

// U-T12: 재생 결정성 — 같은 입력을 두 번 재생하면 전이·마감·닫힘·진단이 같다
TEST(UeTable, UT12Deterministic) {
  auto run = [] {
    UeTableConfig cfg;
    cfg.max_ues = 4;
    Harness h(cfg);
    for (int64_t du = 1; du <= 6; ++du) {
      h.rrc(du * 10, du, "UL", "RRCSetupRequest", part1(kS + static_cast<uint64_t>(du % 2)));
      h.nas(100 + du, du, "DL", "AuthenticationRequest");
    }
    h.kpm(0, R"(["UL","DL"])");
    h.nas(200, 5, "UL", "AuthenticationResponse");
    h.f1ap(300, 6, "UL", "UEContextReleaseComplete");
    h.f1(400, "F1Reset", "null", "[4]");
    h.tick_to(31000);
    std::vector<std::string> hits;
    for (const auto& x : h.rule->hits)
      hits.push_back(std::to_string(x.key.du_ue_id) + "/" + std::to_string(x.uid) + "@" + std::to_string(x.at));
    std::vector<std::string> diags;
    for (const auto& d : h.diags) diags.push_back(std::string(to_string(d.kind)) + " " + d.message);
    return std::make_tuple(h.rule->log, hits, diags, h.rule->held, h.rule->discarded);
  };
  EXPECT_EQ(run(), run());
}

// U-T14: 마감 경계 — 응답 t_ms = 마감 − 1은 제때, = 마감은 늦음. 둘 다 마감이 든 창 안에서 온다 (14_ §6.1-5)
TEST(UeTable, UT14DeadlineBoundary) {
  Harness h;
  for (int64_t du : {40, 41}) h.rrc(0, du, "UL", "RRCSetupRequest");
  for (int64_t du : {40, 41}) h.nas(150, du, "DL", "AuthenticationRequest");  // 마감 kT0+2150 — 창 [2100, 2200) 안
  h.tick_to(2100);
  h.nas(2149, 40, "UL", "AuthenticationResponse");
  h.nas(2150, 41, "UL", "AuthenticationResponse");
  h.kpm(2100);
  ASSERT_EQ(h.rule->hits.size(), 1u);
  EXPECT_EQ(h.rule->hits[0].key.du_ue_id, 41);
}

// U-T15: 로스 창 정의 (14_ §6.2) — ① DL 미관측(FailCause만 null, ue_evt_lost []) ⑤ 로스가 t_from 전에 끝남은 판정,
// ② ue_evt_lost 없음 ③ 구간 끊김 ④ 마감이 든 창이 로스 창은 보류
TEST(UeTable, UT15LossWindowDefinitions) {
  auto wait_then = [](const std::function<void(Harness&)>& windows) {
    Harness h;
    h.rrc(0, 50, "UL", "RRCSetupRequest");
    h.nas(150, 50, "DL", "AuthenticationRequest");  // 마감 kT0+2150
    windows(h);
    return std::make_pair(h.rule->hits.size(), h.rule->held);
  };
  // ① 카운터 null은 1단계용 — 2단계는 보지 않는다
  EXPECT_EQ(wait_then([](Harness& h) {
              for (int64_t t = 0; t <= 2100; t += 100) h.kpm(t, "[]", 1, kCcDlMissing);
            }),
            std::make_pair(std::size_t{1}, 0));
  // ② ue_evt_lost 없음 — 알 수 없으므로 양방향 로스
  EXPECT_EQ(wait_then([](Harness& h) {
              h.tick_to(500);
              h.kpm(500, "");
              h.tick_to(2200);
            }),
            std::make_pair(std::size_t{0}, 1));
  // ③ 구간 끊김 [1000, 1500)
  EXPECT_EQ(wait_then([](Harness& h) {
              h.tick_to(1000);
              h.kpm(1500);
              h.tick_to(2200);
            }),
            std::make_pair(std::size_t{0}, 1));
  // ④ 마감이 든 창 [2100, 2200)이 로스 창 — 로스 기록을 마감 처리보다 먼저 한다
  EXPECT_EQ(wait_then([](Harness& h) {
              h.tick_to(2100);
              h.kpm(2100, R"(["UL","DL"])");
            }),
            std::make_pair(std::size_t{0}, 1));
  // 2차(방향별) — UL을 기다리는데 DL 로스만 있으면 보류하지 않는다
  EXPECT_EQ(wait_then([](Harness& h) {
              h.tick_to(500);
              h.kpm(500, R"(["DL"])");
              h.tick_to(2200);
            }),
            std::make_pair(std::size_t{1}, 0));
}

// U-T16 (U-T15 ⑤): loss가 붙은 항목이라도 대기 시작이 마지막 로스 뒤면 '없음' 판정을 한다 (14_ §4.3)
TEST(UeTable, UT16LossBeforeWaitIsJudged) {
  Harness h;
  h.rrc(0, 60, "UL", "RRCSetupRequest");
  h.kpm(0, R"(["UL","DL"])");
  EXPECT_TRUE(h.ue_state(60)->loss);
  EXPECT_EQ(h.ue_state(60)->t_loss, kT0 + 100);
  h.nas(150, 60, "DL", "AuthenticationRequest");
  h.tick_to(2200);
  EXPECT_EQ(h.rule->hits.size(), 1u);
  EXPECT_EQ(h.rule->held, 0);
}

// U-T17: superseded (14_ §4.2) — 같은 S-TMSI의 새 항목이 받아들여질 때 불확실한(loss·mid_join) 옛 항목만 닫는다
TEST(UeTable, UT17Superseded) {
  {  // ① loss 붙은 옛 항목 + 새 항목 ServiceAccept → 옛 항목 superseded
    Harness h;
    h.rrc(0, 70, "UL", "RRCSetupRequest");
    h.rrc(50, 70, "UL", "RRCSetupComplete", stmsi(kS));
    h.kpm(0, R"(["UL","DL"])");
    h.rrc(200, 71, "UL", "RRCSetupRequest");
    h.rrc(250, 71, "UL", "RRCSetupComplete", stmsi(kS));
    h.nas(250, 71, "UL", "ServiceRequest", stmsi(kS), 1);
    EXPECT_TRUE(h.ue_state(70));
    h.nas(300, 71, "DL", "ServiceAccept", "", 2);
    EXPECT_FALSE(h.ue_state(70));
    EXPECT_TRUE(h.before("event 1/71/2 ServiceAccept", "close 1/70/1 superseded"));
    EXPECT_EQ(h.engine.ue_table().by_s_tmsi(kS).size(), 1u);
  }
  {  // ② 불확실하지 않은 옛 항목은 닫지 않는다 — 룰(L3-20)이 판단
    Harness h;
    h.rrc(0, 72, "UL", "RRCSetupRequest");
    h.rrc(50, 72, "UL", "RRCSetupComplete", stmsi(kS));
    h.rrc(200, 73, "UL", "RRCSetupRequest");
    h.rrc(250, 73, "UL", "RRCSetupComplete", stmsi(kS));
    h.nas(250, 73, "UL", "ServiceRequest", stmsi(kS), 1);
    h.nas(300, 73, "DL", "ServiceAccept", "", 2);
    EXPECT_TRUE(h.ue_state(72));
  }
  {  // ③ 새 항목이 받아들여지지 않으면 닫지 않는다. RRC SMC(CMD)로는 부족하고 ON이 되면 닫는다
    Harness h;
    h.rrc(0, 74, "UL", "RRCSetupComplete", stmsi(kS));  // mid_join
    h.rrc(200, 75, "UL", "RRCSetupRequest");
    h.rrc(250, 75, "UL", "RRCSetupComplete", stmsi(kS));
    h.nas(250, 75, "UL", "ServiceRequest", stmsi(kS), 1);
    h.nas(260, 75, "DL", "AuthenticationRequest");
    h.rrc(300, 75, "DL", "SecurityModeCommand", R"("cipher":"nea0","integrity":"nia2")");
    EXPECT_TRUE(h.ue_state(74));
    h.rrc(310, 75, "UL", "SecurityModeComplete");
    EXPECT_FALSE(h.ue_state(74));
    EXPECT_TRUE(h.logged("close 1/74/1 superseded"));
  }
}

// U-T18: f1_evt F1SetupRequest(셀 1) — 셀 1 열린 항목 전부 du_reset, 그 마감은 꺼낼 때 버림, 다른 셀·1단계 상태는 그대로.
// F1Reset의 du_ue_ids는 그 UE만 (2_ §6.7)
TEST(UeTable, UT18F1EvtDuReset) {
  Harness h;
  h.rrc(0, 80, "UL", "RRCSetupRequest", "", 1);
  h.rrc(0, 81, "UL", "RRCSetupRequest", "", 1);
  h.rrc(0, 80, "UL", "RRCSetupRequest", "", 2);
  h.rrc(0, 82, "UL", "RRCSetupRequest", "", 2);
  h.nas(100, 81, "DL", "AuthenticationRequest", "", 0, 1);
  h.tick_to(300, 1);
  const std::size_t slots = h.engine.series().cell(1)->size();
  h.f1(300, "F1SetupRequest", "[1]");
  EXPECT_FALSE(h.ue_state(80, 1));
  EXPECT_FALSE(h.ue_state(81, 1));
  EXPECT_TRUE(h.ue_state(80, 2));
  EXPECT_TRUE(h.logged("close 1/80/1 du_reset"));
  EXPECT_TRUE(h.logged("close 1/81/2 du_reset"));
  EXPECT_EQ(h.engine.series().cell(1)->size(), slots);
  h.tick_to(2200, 1);
  EXPECT_TRUE(h.rule->hits.empty());
  EXPECT_EQ(h.rule->discarded, 1);

  h.f1(400, "F1Reset", "null", "[82]");
  EXPECT_FALSE(h.ue_state(82, 2));
  EXPECT_TRUE(h.ue_state(80, 2));
}

// U-T19: 상한 초과 — 밀어낼 순서는 CONNECTED 아님 → CONNECTED지만 불확실 → 나머지, 같은 무리 안은 t_last 순 (14_ §4.4).
// 무리 순서는 보호 무리 밖에서 적용되므로 '최근 줄' 보호를 끈다(evict_protect_ms 0, 이슈 #44) — 보호 무리의 순서는 U-T27
TEST(UeTable, UT19EvictionOrder) {
  UeTableConfig cfg;
  cfg.max_ues = 3;
  cfg.evict_protect_ms = 0;
  Harness h(cfg);
  h.rrc(0, 1, "UL", "RRCSetupRequest");
  h.rrc(0, 1, "UL", "RRCSetupComplete");   // CONNECTED·확실 — 가장 오래됨
  h.rrc(10, 2, "UL", "RRCSetupComplete");  // mid_join → CONNECTED지만 불확실
  h.rrc(20, 3, "UL", "RRCSetupRequest");   // SETUP — 가장 새것
  h.rrc(30, 4, "UL", "RRCSetupRequest");
  h.rrc(30, 4, "UL", "RRCSetupComplete");
  h.rrc(40, 5, "UL", "RRCSetupRequest");
  h.rrc(40, 5, "UL", "RRCSetupComplete");
  h.rrc(50, 6, "UL", "RRCSetupRequest");
  std::vector<std::string> evicted;
  for (const auto& l : h.rule->log)
    if (l.size() > 8 && l.compare(l.size() - 8, 8, " evicted") == 0) evicted.push_back(l);
  EXPECT_EQ(evicted, (std::vector<std::string>{"close 1/3/3 evicted", "close 1/2/2 evicted", "close 1/1/1 evicted"}));
}

// U-T21: du_ue_id null인 NAS 줄(via NGAP) — 항목을 만들지 않고 ngap_unlinked만 센다. 진단은 셀마다 처음 1회
TEST(UeTable, UT21NgapUnlinked) {
  Harness h;
  h.ue(0, 1, "null", "DL", "NAS", "ServiceAccept", "", R"(,"via":"NGAP","sht":0)");
  h.ue(10, 1, "null", "DL", "NAS", "ServiceAccept", "", R"(,"via":"NGAP","sht":0)");
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  EXPECT_EQ(h.engine.ue_table().counts(1).ngap_unlinked, 2);
  EXPECT_EQ(h.count(DiagKind::NgapUnlinked), 1);
  EXPECT_TRUE(h.rule->log.empty());
}

// U-T22: S-TMSI 대소문자·앞자리 0과 무관하게 같은 값으로 색인, Part1만 받은 항목은 Part1 색인으로 찾음 (14_ §3.1).
// RRCSetupComplete에 Part2만 오면 Part1과 합쳐 48비트 (2_ §7-14)
TEST(UeTable, UT22StmsiIndexAndPart1) {
  Harness h;
  h.rrc(0, 90, "UL", "RRCSetupRequest");
  h.rrc(10, 90, "UL", "RRCSetupComplete", R"("s_tmsi":"0x0123456789AB")");
  h.rrc(0, 91, "UL", "RRCSetupRequest");
  h.rrc(10, 91, "UL", "RRCSetupComplete", R"("s_tmsi":"0x123456789ab")");
  EXPECT_EQ(h.engine.ue_table().by_s_tmsi(kS).size(), 2u);

  h.rrc(20, 92, "UL", "RRCSetupRequest", part1(kS));
  EXPECT_EQ(h.engine.ue_table().by_part1(kS & kPart1Mask).size(), 3u);
  EXPECT_EQ(h.engine.ue_table().by_s_tmsi(kS).size(), 2u);  // Part1만 아는 항목은 48비트 색인에 없다

  h.rrc(30, 92, "UL", "RRCSetupComplete", R"("s_tmsi_part2":")" + hex(kS >> 39, 3) + "\"");
  EXPECT_EQ(h.ue_state(92)->s_tmsi, kS);
  EXPECT_EQ(h.engine.ue_table().by_s_tmsi(kS).size(), 3u);
  EXPECT_EQ(h.engine.ue_table().by_part1(kS & kPart1Mask).size(), 3u);
}

// U-T23: SETUP 단계에서 줄이 띄엄띄엄 와서 30초 넘게 이어지면 닫지 않고(마감 다시 넣음), 마지막 줄 뒤 30초 무신호면 stale_setup
TEST(UeTable, UT23StaleSetupRearmed) {
  Harness h;
  h.rrc(0, 32, "UL", "RRCSetupRequest");
  h.tick_to(20000);
  h.rrc(20000, 32, "DL", "RRCSetup");
  h.tick_to(40000);
  h.rrc(40000, 32, "DL", "RRCSetup");
  h.tick_to(69900);
  EXPECT_TRUE(h.ue_state(32));
  h.kpm(69900);  // 마지막 줄(40000) 뒤 30 s
  EXPECT_FALSE(h.ue_state(32));
  EXPECT_EQ(h.rule->log.back(), "close 1/32/1 stale_setup");
}

// U-T24: RegistrationRequest를 놓치고 RegistrationAccept만 봐도 REGISTERED(10/29 검수 B11) /
// SUCI 등록 뒤 RegistrationAccept의 f.s_tmsi가 항목 s_tmsi가 되고 색인에 들어감(10/29 검수 A3)
TEST(UeTable, UT24RegistrationAccept) {
  Harness h;
  h.rrc(0, 95, "UL", "RRCSetupRequest");
  h.rrc(10, 95, "UL", "RRCSetupComplete");
  h.nas(100, 95, "DL", "RegistrationAccept", "", 2);
  EXPECT_EQ(h.ue_state(95)->nas, NasState::Registered);

  h.rrc(0, 96, "UL", "RRCSetupRequest");
  h.rrc(10, 96, "UL", "RRCSetupComplete");
  h.nas(10, 96, "UL", "RegistrationRequest", R"("reg_type":"initial","id_type":"SUCI")");
  EXPECT_FALSE(h.ue_state(96)->s_tmsi);
  h.nas(150, 96, "DL", "RegistrationAccept", stmsi(kS2), 2);
  EXPECT_EQ(h.ue_state(96)->s_tmsi, kS2);
  const auto hit = h.engine.ue_table().by_s_tmsi(kS2);
  ASSERT_EQ(hit.size(), 1u);
  EXPECT_TRUE(hit[0]->key == (UeKey{1, 96}));
}

// U-T25: released로 닫힌 뒤 같은 키가 새 UE로 열림 — 새 항목은 새 uid, 옛 마감은 옛 uid로 판정되고 섞이지 않는다
TEST(UeTable, UT25KeyReuseKeepsUid) {
  Harness h;
  h.rrc(0, 97, "UL", "RRCSetupRequest");
  h.nas(100, 97, "DL", "AuthenticationRequest");     // uid 1 기다림, 마감 kT0+2100
  h.f1ap(300, 97, "UL", "UEContextReleaseComplete");  // 마감 전 닫힘 — 표시는 남김
  h.rrc(400, 97, "UL", "RRCSetupRequest");
  EXPECT_EQ(h.ue_state(97)->uid, 2);
  h.nas(500, 97, "DL", "AuthenticationRequest");  // uid 2 기다림, 마감 kT0+2500
  h.nas(600, 97, "UL", "AuthenticationResponse");
  h.tick_to(2600);
  ASSERT_EQ(h.rule->hits.size(), 1u);
  EXPECT_EQ(h.rule->hits[0].uid, 1);
  EXPECT_TRUE(h.rule->hits[0].closed);
  EXPECT_EQ(h.rule->discarded, 1);
}

// 늦은 줄 (2_ §6.5): 셀 워터마크보다 이른 t_ms — late 표시·진단·셀별 수, 이력에는 넣는다
TEST(UeTable, LateLine) {
  Harness h;
  h.rrc(0, 98, "UL", "RRCSetupRequest");
  h.kpm(0);
  h.kpm(100);  // 워터마크 kT0+200
  h.rrc(150, 98, "DL", "RRCSetup");
  EXPECT_TRUE(h.ue_state(98)->late);
  EXPECT_EQ(h.ue_state(98)->t_rrc_setup, kT0 + 150);
  EXPECT_EQ(h.engine.ue_table().counts(1).late, 1);
  EXPECT_EQ(h.count(DiagKind::UeLate), 1);
  h.rrc(200, 98, "UL", "RRCSetupComplete");  // 워터마크와 같은 시각은 다음 창 — 늦지 않음
  EXPECT_EQ(h.engine.ue_table().counts(1).late, 1);
}

// hello.ue_evt가 없으면 2단계 이상 룰을 끈다 — 진단은 1회, ue_evt는 상태표에 넣지 않음 (2_ §6.5).
// 같은 세션에서 꺼지면 진행 중 경보를 끝내고 비운다
TEST(UeTable, Stage2OffWithoutHelloFlag) {
  Harness h({}, false);
  EXPECT_FALSE(h.engine.stage2());
  EXPECT_EQ(h.count(DiagKind::UeEvtOff), 1);
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.kpm(0);
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  EXPECT_TRUE(h.rule->log.empty());
  EXPECT_TRUE(h.rule->ticks.empty());
  h.hello(false);  // 재연결 — 이미 알렸다
  EXPECT_EQ(h.count(DiagKind::UeEvtOff), 1);

  h.hello(true);
  EXPECT_TRUE(h.engine.stage2());
  h.rrc(200, 4, "UL", "RRCSetupRequest");
  EXPECT_EQ(h.engine.ue_table().size(), 1u);
  h.hello(false);
  EXPECT_EQ(h.rule->resets, 1);
  EXPECT_EQ(h.engine.ue_table().size(), 0u);
  EXPECT_EQ(h.count(DiagKind::UeEvtOff), 2);
}

// 진단 (14_ §6.2) — U-T29 (10/29 Q-58 ③ 해결, 이슈 #48): ue_evt_lost 없는 kpm2는 그 첫 칸에서 셀마다 1회, 필드가 돌아왔다
// 또 빠지면 다시 1회(그전 '연속 50칸'). "DL"이 든 kpm2는 연속 dl_unobserved_ms(5 s = 50칸)에 1회 — 그대로
TEST(UeTable, UT29LostFieldDiagnostics) {
  Harness h;
  int64_t t = 0;
  h.kpm(t, "");
  t += 100;
  EXPECT_EQ(h.count(DiagKind::UeEvtLostMissing), 1);  // 첫 칸
  for (int i = 0; i < 60; ++i, t += 100) h.kpm(t, "");
  EXPECT_EQ(h.count(DiagKind::UeEvtLostMissing), 1);  // 돌아오기 전에는 다시 내지 않는다
  for (int i = 0; i < 10; ++i, t += 100) h.kpm(t, "[]");
  EXPECT_EQ(h.count(DiagKind::UeEvtLostMissing), 1);
  h.kpm(t, "");
  t += 100;
  EXPECT_EQ(h.count(DiagKind::UeEvtLostMissing), 2);  // 또 빠짐
  h.kpm(t, "[]", 2);  // 다른 셀은 따로
  h.kpm(t + 100, "", 2);
  EXPECT_EQ(h.count(DiagKind::UeEvtLostMissing), 3);
  for (int i = 0; i < 49; ++i, t += 100) h.kpm(t, R"(["DL"])");
  EXPECT_EQ(h.count(DiagKind::DlUnobserved), 0);
  h.kpm(t, R"(["DL"])");
  EXPECT_EQ(h.count(DiagKind::DlUnobserved), 1);
}

// on_cell_tick (14_ §1.1·§7 kpm2 ④): 그 창의 로스 방향(끊김이면 양방향)과 1단계 series의 input_lost를 넘긴다
TEST(UeTable, CellTickLossAndInputLost) {
  Harness h;
  h.kpm(0, R"(["UL"])");
  h.kpm(100);
  h.kpm(300);  // 끊김 [200, 300)
  ASSERT_EQ(h.rule->ticks.size(), 3u);
  EXPECT_EQ(h.rule->ticks[0], std::make_tuple(int64_t{1}, true, false, false));
  EXPECT_EQ(h.rule->ticks[1], std::make_tuple(int64_t{1}, false, false, false));
  EXPECT_EQ(h.rule->ticks[2], std::make_tuple(int64_t{1}, true, true, false));

  // 1단계 필수 키(A·S)가 없어 보류가 H_hold를 넘으면 series가 input_lost — 2단계 룰에도 그대로 넘긴다
  SeriesConfig scfg;
  scfg.h_hold_ms = 3000;  // 창 채움 시간 1,900 ms보다 길게 — 더 짧으면 series가 채움 + P로 올려 쓴다 (3_ §8, 11/05 W-31)
  Harness g({}, true, scfg);
  for (int64_t t = 0; t <= 3100; t += 100) g.kpm(t, "[]", 1, "");
  int lost = 0;
  for (const auto& x : g.rule->ticks) lost += std::get<3>(x) ? 1 : 0;
  EXPECT_EQ(lost, 1);
  EXPECT_TRUE(std::get<3>(g.rule->ticks.back()));
}

// 입력 침묵 (14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 엔진은 진단 1회를 내고 룰에 알리되(기본 구현은 무동작) 상태표·마감 목록·셀 시계·
// 대기 표시는 그대로다 — kpm2가 다시 오면 마감이 평소처럼 판정된다. 2단계가 꺼져 있으면(hello에 ue_evt 없음) 2단계 룰은 부르지 않는다
TEST(UeTable, InputSilentKeepsState) {
  Harness h;
  connect(h, 0, 3);
  h.nas(100, 3, "DL", "AuthenticationRequest");  // 마감 2100
  h.tick_to(1000);
  const std::size_t deadlines = h.engine.deadlines().size();  // 룰 몫(auth_resp) + 상태표 몫(stale_setup)
  EXPECT_EQ(deadlines, 2u);
  EngineOutput o = h.engine.on_input_silent(10000);
  ASSERT_EQ(o.diags.size(), 1u);
  EXPECT_EQ(o.diags[0].kind, DiagKind::InputSilent);
  EXPECT_FALSE(o.diags[0].cell_id);
  EXPECT_TRUE(o.alerts.empty());
  EXPECT_EQ(o.outcome, FeedOutcome::Dropped);
  EXPECT_NE(h.ue_state(3), nullptr);
  EXPECT_EQ(h.engine.deadlines().size(), deadlines);
  EXPECT_EQ(h.engine.deadlines().clock(1), kT0 + 1000);
  EXPECT_EQ(h.rule->marks.size(), 1u);
  EXPECT_EQ(h.rule->resets, 0);
  h.tick_to(2200);
  ASSERT_EQ(h.rule->hits.size(), 1u);
  EXPECT_EQ(h.rule->hits[0].at, kT0 + 2100);

  Harness off({}, false);  // 2단계 꺼짐 — 진단만, 상태표 없음
  EngineOutput p = off.engine.on_input_silent(10000);
  EXPECT_EQ(p.diags.size(), 1u);
  EXPECT_TRUE(p.alerts.empty());
}

// U-T26 (14_ §4.2 ghost_purge — 10/29 Q-56 해결, 이슈 #44): 해제 줄을 잃은 CONNECTED 유령 40개 + 정상 CONNECTED 5개가 열려 있고
// 셀 RRC 연결 수(si.RRC.ConnMax) 5가 ghost_hold_ms(5 s) 이어지면 초과분 45 − (2 × 5 + 16) = 19개를 t_last 오래된 순으로 닫는다.
// 룰 몫 마감이 걸린 항목(UE 1)은 건너뛰고, 정상 5개는 최근이라 남는다. si·ext가 둘 다 없으면 정리하지 않는다
TEST(UeTable, UT26GhostPurge) {
  Harness h;
  for (int64_t du = 1; du <= 40; ++du) connect(h, du, du);          // 유령 — t_last 1..40
  for (int64_t du = 41; du <= 45; ++du) connect(h, 100 + du, du);   // 정상 — t_last 141..145
  h.conn_max(1, 5);
  h.tick_to(4000);  // 첫 칸 [0,100)부터 45 > 2 × 5 + 16 = 26 — 초과 시작 since = 0
  h.nas(4000, 1, "DL", "AuthenticationRequest");  // UE 1: 룰 몫 마감 6000 → 정리 때 보호
  h.tick_to(4900);  // 마지막 칸 t_end 4900 − 0 < 5000 — 아직
  EXPECT_EQ(h.engine.ue_table().size(), 45u);
  EXPECT_EQ(h.count(DiagKind::GhostPurge), 0);
  h.kpm(4900);  // t_end 5000 − since 0 = 5000 ≥ ghost_hold_ms → 정리
  EXPECT_EQ(h.engine.ue_table().size(), 26u);
  EXPECT_EQ(h.engine.ue_table().counts(1).ghost_purged, 19);
  EXPECT_EQ(h.count(DiagKind::GhostPurge), 1);
  EXPECT_TRUE(h.ue_state(1));  // 마감이 걸려 보호
  for (int64_t du = 2; du <= 20; ++du) EXPECT_FALSE(h.ue_state(du)) << du;
  for (int64_t du = 21; du <= 45; ++du) EXPECT_TRUE(h.ue_state(du)) << du;
  EXPECT_TRUE(h.logged("close 1/2/2 ghost_purge"));
  EXPECT_TRUE(h.logged("close 1/20/20 ghost_purge"));
  EXPECT_EQ(h.rule->marks.size(), 1u);  // UE 1의 대기 표시 그대로
  h.kpm(5000);  // 26 ≤ 26 — 더 닫지 않는다
  EXPECT_EQ(h.engine.ue_table().size(), 26u);
  EXPECT_EQ(h.count(DiagKind::GhostPurge), 1);
  {
    Harness g;  // si·ext 없음 → 정리하지 않는다
    for (int64_t du = 1; du <= 45; ++du) connect(g, du, du);
    g.tick_to(12000);
    EXPECT_EQ(g.engine.ue_table().size(), 45u);
    EXPECT_EQ(g.count(DiagKind::GhostPurge), 0);
  }
}

// U-T27 (14_ §4.4 보호 무리 — 10/29 Q-56 해결, 이슈 #44): 상한 100이 CONNECTED 항목으로 찬 상태에서 새 RRCSetupRequest와
// 이어지는 AuthenticationRequest(룰 몫 마감) — 새 항목(최근 줄)·마감 걸린 항목은 밀리지 않고 보호 무리 밖의 가장 오래된
// CONNECTED가 밀린다. 보호 무리만 남으면 룰 몫 마감이 없는 것 중 t_last가 가장 오래된 것이 밀린다(무리 순서와 무관)
TEST(UeTable, UT27EvictionProtectsRecentAndWaiting) {
  {
    UeTableConfig cfg;
    cfg.max_ues = 100;
    Harness h(cfg);
    for (int64_t du = 1; du <= 100; ++du) connect(h, du, du);  // t_last 1..100 — 6 s 뒤에는 모두 보호 밖
    h.tick_to(6000);
    h.rrc(6000, 200, "UL", "RRCSetupRequest");  // 상한 → 보호 밖 가장 오래된 CONNECTED(UE 1) 밀림
    h.nas(6001, 200, "DL", "AuthenticationRequest");  // UE 200에 룰 몫 마감
    h.rrc(6002, 201, "UL", "RRCSetupRequest");  // UE 200은 SETUP(무리 ①)이지만 최근 줄·마감 → 보호, UE 2 밀림
    h.rrc(6003, 202, "UL", "RRCSetupRequest");  // UE 201도 최근 줄 → 보호, UE 3 밀림
    EXPECT_TRUE(h.ue_state(200));
    EXPECT_TRUE(h.ue_state(201));
    EXPECT_TRUE(h.ue_state(202));
    EXPECT_FALSE(h.ue_state(1));
    EXPECT_FALSE(h.ue_state(2));
    EXPECT_FALSE(h.ue_state(3));
    EXPECT_TRUE(h.ue_state(4));
    std::vector<std::string> evicted;
    for (const auto& l : h.rule->log)
      if (l.size() > 8 && l.compare(l.size() - 8, 8, " evicted") == 0) evicted.push_back(l);
    EXPECT_EQ(evicted, (std::vector<std::string>{"close 1/1/1 evicted", "close 1/2/2 evicted", "close 1/3/3 evicted"}));
  }
  {
    // 마감만으로도 보호된다 (최근 줄 보호 0): UE 200(마감 있음)은 남고, 마감 없는 UE 201(SETUP, 1 ms 전)이 밀린다
    UeTableConfig cfg;
    cfg.max_ues = 100;
    cfg.evict_protect_ms = 0;
    Harness h(cfg);
    for (int64_t du = 1; du <= 100; ++du) connect(h, du, du);
    h.tick_to(6000);
    h.rrc(6000, 200, "UL", "RRCSetupRequest");
    h.nas(6001, 200, "DL", "AuthenticationRequest");
    h.rrc(6002, 201, "UL", "RRCSetupRequest");  // 무리 ①에 UE 200(마감 → 보호)뿐 → 무리 ③ UE 2 밀림
    h.rrc(6003, 202, "UL", "RRCSetupRequest");  // 무리 ①: UE 200(보호), UE 201(마감 없음, 보호 밖) → UE 201 밀림
    EXPECT_TRUE(h.ue_state(200));
    EXPECT_FALSE(h.ue_state(201));
    EXPECT_TRUE(h.ue_state(202));
    EXPECT_FALSE(h.ue_state(1));
    EXPECT_FALSE(h.ue_state(2));
    EXPECT_TRUE(h.ue_state(3));
  }
  {
    // 보호 무리만 남음(모두 최근 5 s 안): 무리 순서가 아니라 마감 없는 것 중 t_last 가장 오래된 것 — 막 연 SETUP 항목이 밀리지 않는다
    UeTableConfig cfg;
    cfg.max_ues = 3;
    Harness h(cfg);
    connect(h, 0, 1);                        // CONNECTED, 가장 오래됨
    h.rrc(10, 2, "UL", "RRCSetupComplete");  // mid_join·CONNECTED
    h.rrc(20, 3, "UL", "RRCSetupRequest");   // SETUP — 무리 ①이지만 밀리지 않는다
    h.rrc(30, 4, "UL", "RRCSetupRequest");   // 상한 → UE 1
    EXPECT_FALSE(h.ue_state(1));
    EXPECT_TRUE(h.ue_state(3));
    h.nas(31, 2, "DL", "AuthenticationRequest");  // UE 2에 마감 → 보호
    h.rrc(40, 5, "UL", "RRCSetupRequest");        // 마감 없는 것 중 가장 오래된 UE 3
    EXPECT_TRUE(h.ue_state(2));
    EXPECT_FALSE(h.ue_state(3));
  }
}

// U-T28 (14_ §4.3 late_until — 10/29 Q-57 해결, 이슈 #46): 늦은 줄이 온 UE의 '없음' 판정 제외는 늦은 줄 t_ms + 등록된 룰의
// 증거 지평 최댓값(WaitRule 2 s)까지만. 늦은 줄 2 s 뒤 마감은 판정 없음(skipped), 그 뒤 마감은 판정(hits). late 표시는 남고,
// 늦은 줄이 또 오면 late_until이 늘어난다
TEST(UeTable, UT28LateUntil) {
  Harness h;
  h.rrc(0, 98, "UL", "RRCSetupRequest");
  h.kpm(0);
  h.kpm(100);                            // 워터마크 200
  h.rrc(150, 98, "DL", "RRCSetup");      // 늦은 줄 → late, late_until = 150 + 2000 = 2150
  EXPECT_TRUE(h.ue_state(98)->late);
  EXPECT_EQ(h.ue_state(98)->late_until, kT0 + 2150);
  EXPECT_EQ(h.engine.ue_table().late_horizon_ms(), WaitRule::kWait);
  h.rrc(200, 98, "UL", "RRCSetupComplete");
  h.nas(205, 98, "DL", "AuthenticationRequest");  // 마감 2205 ≥ late_until 2150 → 판정
  h.tick_to(2300);
  EXPECT_EQ(h.rule->skipped, 0);
  ASSERT_EQ(h.rule->hits.size(), 1u);
  EXPECT_EQ(h.rule->hits[0].at, kT0 + 2205);
  EXPECT_TRUE(h.ue_state(98)->late);  // 표시는 남는다
  {
    Harness g;
    g.rrc(0, 99, "UL", "RRCSetupRequest");
    g.kpm(0);
    g.kpm(100);
    g.rrc(150, 99, "DL", "RRCSetup");               // late_until 2150
    g.nas(300, 99, "DL", "AuthenticationRequest");  // 마감 2300 ≥ 2150 → 판정될 터
    g.kpm(200);
    g.kpm(300);
    g.kpm(400);                                     // 워터마크 500
    g.rrc(450, 99, "UL", "RRCSetupComplete");        // 두 번째 늦은 줄 → late_until 2450 > 마감 2300 → 판정 없음
    EXPECT_EQ(g.ue_state(99)->late_until, kT0 + 2450);
    g.tick_to(2400);
    EXPECT_EQ(g.rule->skipped, 1);
    EXPECT_TRUE(g.rule->hits.empty());
    g.nas(2500, 99, "DL", "AuthenticationRequest");  // 마감 4500 ≥ 2450 → 판정
    g.tick_to(4600);
    EXPECT_EQ(g.rule->hits.size(), 1u);
  }
  {
    Harness c;  // 마감 전에 닫힌 항목도 복사본의 late_until로 같은 판정 (14_ §2.4)
    c.rrc(0, 97, "UL", "RRCSetupRequest");
    c.kpm(0);
    c.kpm(100);
    c.rrc(150, 97, "DL", "RRCSetup");               // late_until 2150
    c.nas(300, 97, "DL", "AuthenticationRequest");  // 마감 2300
    c.f1ap(400, 97, "UL", "UEContextReleaseComplete");  // released — 표시에 복사
    c.tick_to(2400);
    EXPECT_EQ(c.rule->skipped, 0);
    ASSERT_EQ(c.rule->hits.size(), 1u);
    EXPECT_TRUE(c.rule->hits[0].closed);
  }
}

// 보안 상태 이름 (14_ §5.3·§5.4 철자) — 3단계 경보 ues[].values의 rrc_sec·nas_sec (20_ §3.6·§4.6)
TEST(UeTable, SecStateNames) {
  EXPECT_STREQ(to_string(RrcSecState::Off), "OFF");
  EXPECT_STREQ(to_string(RrcSecState::Unknown), "UNKNOWN");
  EXPECT_STREQ(to_string(RrcSecState::Cmd), "CMD");
  EXPECT_STREQ(to_string(RrcSecState::On), "ON");
  EXPECT_STREQ(to_string(RrcSecState::Failed), "FAILED");
  EXPECT_STREQ(to_string(NasSecState::None), "NONE");
  EXPECT_STREQ(to_string(NasSecState::Unknown), "UNKNOWN");
  EXPECT_STREQ(to_string(NasSecState::Auth), "AUTH");
  EXPECT_STREQ(to_string(NasSecState::AuthOk), "AUTH_OK");
  EXPECT_STREQ(to_string(NasSecState::AuthFail), "AUTH_FAIL");
  EXPECT_STREQ(to_string(NasSecState::Cmd), "CMD");
  EXPECT_STREQ(to_string(NasSecState::On), "ON");
  EXPECT_STREQ(to_string(NasSecState::Rejected), "REJECTED");
}

// U-T32 (14_ §3.2, 11/04 이슈 #74): S-TMSI 이력 표 연결 레코드 — 48비트를 아는 연결이 released로 닫힘 → 레코드 1개(48비트·
// Part1 색인 둘 다, src ue) / Part1만 아는 연결이 stale_setup으로 닫힘 → 레코드 1개(Part1 색인만, connected false) / S-TMSI를
// 모르는 연결 → 레코드 없음. DU가 먼저 해제를 요청하면 그 원인(rel_req_cause), 마지막 등록 요청의 종류
TEST(UeTable, UT32HistoryRecords) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest", R"("est_cause":"mt-Access",)" + part1(kS));
  h.rrc(10, 3, "UL", "RRCSetupComplete", stmsi(kS));
  h.nas(10, 3, "UL", "RegistrationRequest", R"("reg_type":"mobility","id_type":"5G-GUTI",)" + stmsi(kS));
  h.ue(500, 1, "3", "UL", "F1AP", "UEContextReleaseRequest", R"("cause":"radioNetwork:rl-failure")", "");
  h.f1ap(510, 3, "DL", "UEContextReleaseCommand");
  h.f1ap(520, 3, "UL", "UEContextReleaseComplete");
  ASSERT_EQ(h.engine.ue_table().history(kS, 0).size(), 1u);
  const ConnRecord& a = *h.engine.ue_table().history(kS, 0)[0];
  EXPECT_EQ(a.s_tmsi, kS);
  EXPECT_EQ(a.part1, kS & kPart1Mask);
  EXPECT_EQ(std::string(a.src()), "ue");
  EXPECT_EQ(a.reason, CloseReason::Released);
  EXPECT_TRUE(a.connected);
  EXPECT_FALSE(a.accepted);
  EXPECT_EQ(a.est_cause, "mt-Access");
  EXPECT_EQ(a.reg_type, "mobility");
  EXPECT_EQ(a.id_type, "5G-GUTI");
  EXPECT_EQ(a.rel_req_cause, "radioNetwork:rl-failure");
  EXPECT_FALSE(h.engine.ue_table().allocated(kS));  // UE가 낸 값은 할당 기억이 아니다
  ASSERT_EQ(h.engine.ue_table().history_part1(kS & kPart1Mask, 0).size(), 1u);

  h.rrc(1000, 4, "UL", "RRCSetupRequest", part1(kS2));  // Part1만 — RRCSetupComplete 없이 30 s
  h.tick_to(32000);
  EXPECT_FALSE(h.ue_state(4));
  EXPECT_TRUE(h.engine.ue_table().history(kS2, 0).empty());
  const auto p = h.engine.ue_table().history_part1(kS2 & kPart1Mask, 0);
  ASSERT_EQ(p.size(), 1u);
  EXPECT_FALSE(p[0]->s_tmsi);
  EXPECT_EQ(p[0]->reason, CloseReason::StaleSetup);
  EXPECT_FALSE(p[0]->connected);
  EXPECT_EQ(p[0]->rrc_last, RrcState::Setup);

  h.rrc(33000, 5, "UL", "RRCSetupRequest", R"("ue_identity":{"type":"randomValue"})");  // S-TMSI 모름
  h.rrc(33010, 5, "UL", "RRCSetupComplete");
  h.f1ap(33020, 5, "UL", "UEContextReleaseComplete");
  EXPECT_EQ(h.engine.ue_table().history_size(), 2u);
}

// U-T33 (14_ §3.2): 할당 기억 — RegistrationAccept f.s_tmsi 뒤 allocated(s) = 할당 시각 / 같은 값 재할당이면 시각 갱신(앞 마감은
// 지우지 않음) / alloc_ms 뒤 없음. 항목이 열려 있어도 넣는다
TEST(UeTable, UT33AllocationMemory) {
  UeTableConfig cfg;
  cfg.alloc_ms = 60000;
  Harness h(cfg);
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.nas(100, 3, "DL", "RegistrationAccept", stmsi(kS), 2);
  EXPECT_EQ(h.engine.ue_table().allocated(kS), kT0 + 100);
  EXPECT_TRUE(h.ue_state(3));
  h.nas(20000, 3, "DL", "RegistrationAccept", stmsi(kS), 2);  // 재할당
  EXPECT_EQ(h.engine.ue_table().allocated(kS), kT0 + 20000);
  EXPECT_EQ(h.engine.ue_table().alloc_size(), 1u);
  h.tick_to(60200);  // 첫 할당 + 60 s — 그 마감은 다시 할당됐으므로 지우지 않는다
  EXPECT_EQ(h.engine.ue_table().allocated(kS), kT0 + 20000);
  h.tick_to(80100);  // 재할당 + 60 s
  EXPECT_FALSE(h.engine.ue_table().allocated(kS));
  EXPECT_EQ(h.engine.ue_table().alloc_size(), 0u);
}

// U-T34 (14_ §3.2): 만료·상한 — tomb_ms 뒤 표 몫 마감으로 지움 / tomb_max 초과면 오래된 것부터 / alloc_max 초과 / du_reset은 비우지
// 않음(닫힌 연결도 레코드로) / 새 hello는 둘 다 비움(U-T11)
TEST(UeTable, UT34ExpiryAndCaps) {
  {
    UeTableConfig cfg;
    cfg.tomb_ms = 60000;
    Harness h(cfg);
    h.rrc(0, 3, "UL", "RRCSetupRequest", part1(kS));
    h.f1ap(100, 3, "UL", "UEContextReleaseComplete");
    EXPECT_EQ(h.engine.ue_table().history_size(), 1u);
    h.tick_to(60000);  // t_end 100 + 60 s = 60,100 — 마감 ≤ 셀 시계인 칸(t_end 60,100)에서 지운다 (14_ §6.1)
    EXPECT_EQ(h.engine.ue_table().history_size(), 1u);
    h.tick_to(60100);
    EXPECT_EQ(h.engine.ue_table().history_size(), 0u);
    EXPECT_TRUE(h.engine.ue_table().history_part1(kS & kPart1Mask, 0).empty());
  }
  {
    UeTableConfig cfg;
    cfg.tomb_max = 100;
    cfg.alloc_max = 100;
    Harness h(cfg);
    for (int64_t i = 0; i < 101; ++i) {
      const uint64_t s = kS + static_cast<uint64_t>(i);
      h.rrc(i * 10, 100 + i, "UL", "RRCSetupRequest", part1(s));
      h.nas(i * 10, 100 + i, "DL", "RegistrationAccept", stmsi(s), 2);
      h.f1ap(i * 10 + 5, 100 + i, "UL", "UEContextReleaseComplete");
    }
    EXPECT_EQ(h.engine.ue_table().history_size(), 100u);
    EXPECT_TRUE(h.engine.ue_table().history(kS, 0).empty());  // 가장 오래된 것부터
    EXPECT_EQ(h.engine.ue_table().history(kS + 100, 0).size(), 1u);
    EXPECT_EQ(h.engine.ue_table().alloc_size(), 100u);
    EXPECT_FALSE(h.engine.ue_table().allocated(kS));
    EXPECT_TRUE(h.engine.ue_table().allocated(kS + 100));
  }
  {
    Harness h;
    h.rrc(0, 3, "UL", "RRCSetupRequest", part1(kS));
    h.rrc(0, 3, "UL", "RRCSetupComplete", stmsi(kS));
    h.nas(10, 3, "DL", "RegistrationAccept", stmsi(kS), 2);
    h.rrc(20, 4, "UL", "RRCSetupRequest", part1(kS2));
    h.f1ap(30, 4, "UL", "UEContextReleaseComplete");
    h.f1(300, "F1SetupRequest", "[1]");  // du_reset — 열린 3도 레코드로, 지난 레코드·할당 기억은 그대로
    EXPECT_EQ(h.engine.ue_table().history_size(), 2u);
    EXPECT_EQ(h.engine.ue_table().history(kS, 0)[0]->reason, CloseReason::DuReset);
    EXPECT_EQ(std::string(h.engine.ue_table().history(kS, 0)[0]->src()), "both");
    EXPECT_TRUE(h.engine.ue_table().allocated(kS));
  }
}

// U-T35 (14_ §3.2·§7 ⑦): 룰이 읽는 것 — 같은 S-TMSI 연결 3건(5 s 간격) 뒤 history(s, since)는 t_end 순 3건, since로 거른다 /
// mid_join 연결 레코드에 표시가 남는다 / 닫힘 통지를 받을 때 그 연결의 레코드가 이미 있다(레코드 먼저)
TEST(UeTable, UT35RulesRead) {
  Harness h;
  for (int64_t i = 0; i < 3; ++i) {
    const int64_t t = i * 5000;
    h.rrc(t, 10 + i, "UL", "RRCSetupRequest", part1(kS));
    h.rrc(t + 10, 10 + i, "UL", "RRCSetupComplete", stmsi(kS));
    h.f1ap(t + 1200, 10 + i, "UL", "UEContextReleaseComplete");
  }
  const auto all = h.engine.ue_table().history(kS, 0);
  ASSERT_EQ(all.size(), 3u);
  EXPECT_EQ(all[0]->t_end, kT0 + 1200);
  EXPECT_EQ(all[1]->t_end, kT0 + 6200);
  EXPECT_EQ(all[2]->t_end, kT0 + 11200);
  EXPECT_EQ(h.engine.ue_table().history(kS, kT0 + 6200).size(), 2u);
  EXPECT_EQ(h.engine.ue_table().history(kS, kT0 + 6201).size(), 1u);
  EXPECT_EQ(h.engine.ue_table().history_part1(kS & kPart1Mask, kT0 + 6200).size(), 2u);
  EXPECT_EQ(h.rule->record_seen_at_close, (std::vector<bool>{true, true, true}));

  h.nas(20000, 20, "UL", "ServiceRequest", stmsi(kS2), 1);  // 첫 줄 — mid_join
  h.f1ap(20100, 20, "UL", "UEContextReleaseComplete");
  const auto mj = h.engine.ue_table().history(kS2, 0);
  ASSERT_EQ(mj.size(), 1u);
  EXPECT_TRUE(mj[0]->mid_join);
  EXPECT_FALSE(mj[0]->loss);
}

// U-T36 (14_ §3.2 — 11/04 AN-07 사용자 결정): 레코드 rejected는 그 연결에서 RRCReject를 봤는지다. 거절 뒤 CU가
// UEContextReleaseCommand로 DU 컨텍스트를 풀면 rrc는 RELEASING으로 덮이지만 rejected는 true / 해제 줄 없이 stale_setup으로 닫힌
// 거절도 true(rrc_last REJECTED) / RRCSetup 뒤 Complete 없이 해제된 연결은 false
TEST(UeTable, UT36RecordRejected) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(0, 3, "DL", "RRCReject");
  h.f1ap(0, 3, "DL", "UEContextReleaseCommand");
  h.f1ap(5, 3, "UL", "UEContextReleaseComplete");
  const auto a = h.engine.ue_table().history_part1(kS & kPart1Mask, 0);
  ASSERT_EQ(a.size(), 1u);
  EXPECT_EQ(a[0]->rrc_last, RrcState::Releasing);
  EXPECT_TRUE(a[0]->rejected);
  EXPECT_FALSE(a[0]->connected);

  h.rrc(1000, 4, "UL", "RRCSetupRequest", part1(kS2));
  h.rrc(1000, 4, "DL", "RRCReject");
  h.tick_to(32000);
  const auto b = h.engine.ue_table().history_part1(kS2 & kPart1Mask, 0);
  ASSERT_EQ(b.size(), 1u);
  EXPECT_EQ(b[0]->reason, CloseReason::StaleSetup);
  EXPECT_EQ(b[0]->rrc_last, RrcState::Rejected);
  EXPECT_TRUE(b[0]->rejected);

  h.rrc(33000, 5, "UL", "RRCSetupRequest", part1(kS));
  h.rrc(33000, 5, "DL", "RRCSetup");
  h.f1ap(35000, 5, "DL", "UEContextReleaseCommand");
  h.f1ap(35005, 5, "UL", "UEContextReleaseComplete");
  const auto c = h.engine.ue_table().history_part1(kS & kPart1Mask, kT0 + 1000);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_FALSE(c[0]->rejected);
  EXPECT_FALSE(c[0]->connected);
}
