#include "detect/rules/cap_hijack.h"

#include <algorithm>
#include <string>
#include <utility>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr const char* kEnq = "UECapabilityEnquiry";       // 능력 요청 (RRC DL)
constexpr const char* kInfo = "UECapabilityInformation";  // 능력 응답 (RRC UL)
constexpr const char* kPremise = "mitm_ul_relay";         // 갈래 ①의 전제 — 중간자가 UE 응답을 정상 망으로 넘김 (20_ §1.3)

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

std::vector<std::string> premise(bool mitm) {
  return mitm ? std::vector<std::string>{kPremise} : std::vector<std::string>{};
}

// 갈래별 후보 (20_ §4.1·§4.6): 갈래 ①의 모양은 #28 MNmap 중간자 변형(L3-28-V)도 만든다 — 11/03 결정으로 이 룰이 받는다
// (4단계 코드 작성 직전에 반영, 4_ §6.3 #1). 갈래 ②(CU의 보안 전 요청)를 만드는 다른 공격은 없다.
// 경보의 candidates는 실린 UE들 갈래 후보의 합이다 (L3-20과 같은 방식)
constexpr const char* kCandMnmap = "L3-28-V";

void add_candidates(const AlertUe& u, std::vector<std::string>& out) {
  if (u.values.at("branch").get<std::string>() != "1") return;
  if (std::find(out.begin(), out.end(), kCandMnmap) == out.end()) out.push_back(kCandMnmap);
}

}  // namespace

CapHijackRule::CapHijackRule(CapHijackConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), book_(kId, alert, "attack", 3), held_book_(kId, alert, "anomaly", 3) {}

// 증거 지평 (20_ §4.4·§1.2-6): L3-24와 같다 — 창 한 칸 몫 1,000 ms + UPDATE 모음 지연
int64_t CapHijackRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// 연결당 한 번 (20_ §1.2-2·§4.3-2): 이미 표시가 있는 연결의 같은 갈래 신호는 extra만 — 걸린 연결이고 경보가 열려 있으면
// values.extra에 더한다. UPDATE는 내지 않는다(새 판정이 아니다)
void CapHijackRule::count_extra(const UeState& n, const char* tag) {
  const int64_t cell = n.key.cell_id;
  const LookbackMarks::Mark* m = marks_.find(n.key, n.uid, tag);
  if (m && m->phase == LookbackMarks::Phase::Hit && book_.open(cell)) ++cells_[cell].extra_open;
}

// ue_evt 한 줄 (20_ §4.3):
//  - 갈래 ①: UECapabilityInformation(RRC UL)이 '요청 없는 응답'이면(갱신 전 R ≤ A, mid_join 아님, AS 무결성 전 — §1.2-1) 대기 표시.
//    정상 능력 응답은 RRC 보안 뒤에 오가므로 요청 줄을 로스로 놓쳐도 AS 무결성 조건으로 후보가 되지 않는다
//  - 갈래 ②: UECapabilityEnquiry(RRC DL) 때 갱신 전 rrc_sec이 OFF·FAILED면 대기 표시. CMD·ON은 DL 무결성이 이미 걸려
//    평문 노출·주입의 틈이 아니고(TS 38.331 §5.3.4.3), UNKNOWN(mid_join)은 판정하지 않는다. 바로 판정하지 않는 이유는
//    §1.2-3과 같다 — OFF는 보안 모드 명령 줄을 '보지 못했다'는 뜻이고 같은 창에서 로스로 놓쳤을 수 있다
// 표시에는 판정한 줄을 반영한 뒤의 요청·응답 수와 갱신 전 rrc_sec을 적는다(ues[].values, §4.6)
void CapHijackRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                                RuleOutput&) {
  if (evt.proto != Proto::RRC) return;
  if (evt.dir == Dir::UL && evt.msg == kInfo) {
    if (!unsolicited(before, Proto::RRC, kEnq, kInfo)) return;
    ojson snap;
    snap["branch"] = "1";
    snap["req"] = before.count(Proto::RRC, kEnq);
    snap["resp"] = before.count(Proto::RRC, kInfo) + 1;
    snap["rrc_sec"] = to_string(before.rrc_sec);
    if (!marks_.start(after, kTagUnsolicited, evt.t_ms, std::move(snap), ctx)) count_extra(after, kTagUnsolicited);
  } else if (evt.dir == Dir::DL && evt.msg == kEnq) {
    if (before.mid_join || (before.rrc_sec != RrcSecState::Off && before.rrc_sec != RrcSecState::Failed)) return;
    ojson snap;
    snap["branch"] = "2";
    snap["req"] = before.count(Proto::RRC, kEnq) + 1;
    snap["resp"] = before.count(Proto::RRC, kInfo);
    snap["rrc_sec"] = to_string(before.rrc_sec);
    if (!marks_.start(after, kTagPreSecEnquiry, evt.t_ms, std::move(snap), ctx)) count_extra(after, kTagPreSecEnquiry);
  }
}

// 마감 (20_ §4.3 갈래 ①·② 4): 걸리면 hit, 연결 시작 뒤 DL 로스면 두 갈래 모두 보류 — 공격 경보 중이면 values.held로만,
// 아니면 불확실 경보용으로 적어 둔다(판정은 held_tick, 14_ §6.2). late로 판정하지 않은 표시는 헬퍼가 지웠다
void CapHijackRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) {
  const LookbackMarks::Decision dc = marks_.on_deadline(d, ctx);
  const int64_t cell = d.key.cell_id;
  const int64_t now = ctx.deadlines.clock(cell).value_or(d.at);
  if (dc.verdict == LookbackMarks::Verdict::Held) {
    CellState& c = cells_[cell];
    c.held_times.push_back(now);
    if (book_.open(cell)) ++c.held_open;
    else if (alert_.held_alert) c.fresh_held.push_back(held_ue(dc, d.at));
  } else if (dc.verdict == LookbackMarks::Verdict::Hit) {
    hit(dc, now, ctx, out);
  }
}

// 걸린 UE (20_ §4.3·§4.5·§4.6): 갈래 ①은 cond unsolicited·medium·전제 [mitm_ul_relay], 갈래 ②는 cond enquiry_before_as_sec·
// high·전제 []. t_hit = 판정한 줄의 시각(t_r·t_e). 걸림마다 ues에 한 칸 — 한 연결이 두 갈래에 걸리면 두 칸(증거는 UE당 한 번).
// 심각도가 오르면(갈래 ② 첫 걸림) 묶음이 바로 UPDATE하고, 실린 UE들의 전제가 바뀌면(갈래 ② UE만 있던 경보에 갈래 ① UE가
// 실림) 룰이 바로 UPDATE를 부른다 — 묶음은 심각도·새 UE만 본다(14_ §8.2 11/03 트리거). 둘이 함께면 UPDATE 한 번에 싣는다
void CapHijackRule::hit(const LookbackMarks::Decision& dc, int64_t now, const UeRuleCtx& ctx, RuleOutput& out) {
  const int64_t cell = dc.n.key.cell_id;
  CellState& c = cells_[cell];
  const bool was_open = book_.open(cell);
  if (!was_open) {  // 새 경보 — 열린 불확실 경보는 같은 줄에서 먼저 CLEAR (14_ §8.2), 누적값은 처음부터
    close_held(cell, now, out);
    c.branch1_ues = 0;
    c.branch2_ues = 0;
    c.branch2_seen = false;
    c.premise_mitm = false;
    c.extra_open = 0;
    c.held_open = 0;
    c.evicted_open = 0;
  }
  const bool branch2 = dc.mark.tag == kTagPreSecEnquiry;
  ++(branch2 ? c.branch2_ues : c.branch1_ues);
  c.branch2_seen = c.branch2_seen || branch2;
  const bool premise_before = c.premise_mitm;
  c.premise_mitm = c.premise_mitm || !branch2;
  c.extra_open += dc.mark.extra;
  c.t_hit_last = std::max(c.t_hit_last, dc.mark.t_from);

  AlertUe u = alert_ue(dc.n);
  u.cond = {branch2 ? "enquiry_before_as_sec" : "unsolicited"};
  u.t_hit = dc.mark.t_from;
  u.values = dc.mark.snap;
  u.conditions = premise(!branch2);
  const Severity sev = branch2 ? Severity::High : Severity::Medium;
  const std::size_t from = out.alerts.size();
  std::vector<AlertUe> ues;
  ues.push_back(std::move(u));
  book_.add(cell, std::move(ues), sev, now, ctx.session, ctx.seq, out.alerts);
  const bool changed = was_open && premise_before != c.premise_mitm;
  if (changed && out.alerts.size() == from) book_.update(cell, *book_.severity(cell), now, out.alerts);
  decorate(from, out, changed);
}

// L3-14 값 채우기 (20_ §4.6): branch는 모든 이벤트에 그때의 갈래로(갈래 ②가 한 번이라도 걸렸으면 "2" — L3-21과 같음),
// raise·update에 values(branch1_ues·branch2_ues·extra는 경보가 열린 뒤 누적, held·evicted는 raise면 직전 clear_quiet_ms 이동 창·
// update면 누적), raise에 cond(RAISE를 일으킨 UE의 것)·candidates(실린 UE들 갈래 후보의 합 — 갈래 ① L3-28-V)·
// conditions(실린 UE들의 합)·params·로그 필드,
// 전제가 바뀐 update에 conditions
void CapHijackRule::decorate(std::size_t from, RuleOutput& out, bool premise_changed) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    CellState& c = cells_[e.cell_id];
    e.branch = c.branch2_seen ? "2" : "1";
    const bool raise = e.kind == AlertEventKind::Raise;
    // raise·update·clear·end 모두 (14_ §8.3 — 11/04 Q-69 W-28): 갈래별 걸림 수·extra·held·evicted는 경보가 열린 뒤 누적값
    e.values["branch1_ues"] = c.branch1_ues;
    e.values["branch2_ues"] = c.branch2_ues;
    e.values["extra"] = c.extra_open;
    e.values["held"] = raise ? held_window(c, e.t) : c.held_open;
    e.values["evicted"] = raise ? evicted_window(c, e.t) : c.evicted_open;
    if (!raise) {
      if (premise_changed) e.conditions = premise(c.premise_mitm);
      continue;
    }
    if (e.ues.empty()) continue;
    const AlertUe& u = e.ues.front();
    e.cond = u.cond;
    e.candidates.clear();
    for (const AlertUe& x : e.ues) add_candidates(x, e.candidates);
    e.conditions = premise(c.premise_mitm);
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (20_ §4.6): branch= ue=cell/du_ue_id/uid req= resp= rrc_sec= — RAISE 골격은 branch를 찍지 않아 룰이 맨 앞에 넣는다
    e.log_fields = {{"branch", u.values.at("branch").get<std::string>()},
                    {"ue", ue_name(u.cell, u.du_ue_id, u.uid)},
                    {"req", std::to_string(u.values.at("req").get<int64_t>())},
                    {"resp", std::to_string(u.values.at("resp").get<int64_t>())},
                    {"rrc_sec", u.values.at("rrc_sec").get<std::string>()}};
  }
}

// raise의 held — 직전 clear_quiet_ms 동안 보류된 판정 수 (L3-24와 같음)
int64_t CapHijackRule::held_window(CellState& c, int64_t now) const {
  while (!c.held_times.empty() && c.held_times.front() <= now - cfg_.clear_quiet_ms) c.held_times.pop_front();
  return static_cast<int64_t>(c.held_times.size());
}

// 셀 kpm2마다 (20_ §4.5): input_lost면 END, 모아 둔 UE를 UPDATE 간격에 맞춰 내고, 마지막 걸림(두 갈래 중 늦은 것) 뒤
// clear_quiet_ms면 CLEAR — extra는 t_hit를 늘리지 않는다. 보류는 해제를 막지 않고, 직전 clear_quiet_ms 동안 밀어내기가
// 있었으면 풀지 않는다(Q-56)
void CapHijackRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                 RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  CellState& c = cells_[cell];
  note_evictions(c, cell, t, ctx);
  const std::size_t from = out.alerts.size();
  if (input_lost) book_.end(cell, t, "input_lost", out.alerts);
  book_.flush(cell, t, out.alerts);
  if (book_.open(cell) && t - c.t_hit_last >= cfg_.clear_quiet_ms && evicted_window(c, t) == 0)
    book_.clear(cell, t, out.alerts);
  decorate(from, out);
  held_window(c, t);
  held_tick(cell, c, t, input_lost, ctx, out);
}

// 보류된 UE 한 칸 (14_ §6.2, 20_ §4.7): cond held, t_hit = 마감, uncertain에 loss. wait_ms = 판정 줄 − t_s(갈래 ①은 t_r,
// 갈래 ②는 t_e) — 되돌아본 구간
AlertUe CapHijackRule::held_ue(const LookbackMarks::Decision& dc, int64_t t_hit) const {
  AlertUe u = alert_ue(dc.n);
  u.cond = {"held"};
  u.t_hit = t_hit;
  if (std::find(u.uncertain.begin(), u.uncertain.end(), "loss") == u.uncertain.end()) u.uncertain.emplace_back("loss");
  u.values["wait_ms"] = dc.mark.t_from - dc.n.t_start;
  u.values["dir"] = "DL";
  return u;
}

// 불확실 경보 (14_ §6.2, 20_ §4.7 — 문턱 1, §3.7과 같음). 갈래와 관계없이 하나로 센다 — branch·conditions는 싣지 않는다
void CapHijackRule::held_tick(int64_t cell, CellState& c, int64_t t, bool input_lost, const UeRuleCtx& ctx,
                              RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  if (input_lost) held_book_.end(cell, t, "input_lost", out.alerts);
  for (AlertUe& u : c.fresh_held) {
    c.held_ues.push_back(u);
    while (c.held_ues.front().t_hit <= u.t_hit - cfg_.clear_quiet_ms) c.held_ues.pop_front();
    c.t_last_held = u.t_hit;
    if (book_.open(cell)) {
      ++c.held_open;
      continue;
    }
    std::vector<AlertUe> ues;
    if (held_book_.open(cell)) ues.push_back(u);
    else ues.assign(c.held_ues.begin(), c.held_ues.end());
    held_book_.add(cell, std::move(ues), Severity::Medium, t, ctx.session, ctx.seq, out.alerts);
  }
  c.fresh_held.clear();
  held_book_.flush(cell, t, out.alerts);
  if (held_book_.open(cell) && t - c.t_last_held >= cfg_.clear_quiet_ms) held_book_.clear(cell, t, out.alerts);
  decorate_held(from, out);
  if (!held_book_.open(cell))
    while (!c.held_ues.empty() && c.held_ues.front().t_hit <= t - cfg_.clear_quiet_ms) c.held_ues.pop_front();
}

// 공격 경보가 RAISE되기 직전 — 열린 불확실 경보를 같은 줄에서 먼저 CLEAR한다 (14_ §8.2)
void CapHijackRule::close_held(int64_t cell, int64_t t, RuleOutput& out) {
  if (!held_book_.open(cell)) return;
  const std::size_t from = out.alerts.size();
  held_book_.clear(cell, t, out.alerts);
  decorate_held(from, out);
}

// 불확실 경보 값 채우기 (14_ §6.2, 20_ §4.7): L3-24와 같다 — raise·update에 held_w, raise에 cond held_count·candidates [L3-14]·
// params·로그 필드(kind=anomaly held_w=N). branch·conditions는 싣지 않는다(L3-21의 불확실 경보와 같음)
void CapHijackRule::decorate_held(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const CellState& c = cells_[e.cell_id];
    e.values["held_w"] = static_cast<int64_t>(c.held_ues.size());
    if (e.kind != AlertEventKind::Raise) {
      e.log_fields = {{"kind", "anomaly"}};
      continue;
    }
    e.cond = {"held_count"};
    e.candidates = {kId};
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    e.log_fields = {{"kind", "anomaly"}, {"held_w", std::to_string(c.held_ues.size())}};
  }
}

// 상태표 셀별 누적 evicted(14_ §6.3)의 증가분을 이 칸 시각으로 적는다 — 경보가 열려 있으면 evicted_open도
void CapHijackRule::note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx) {
  const int64_t total = ctx.table.counts(cell).evicted;
  for (; c.evicted_seen < total; ++c.evicted_seen) {
    c.evict_times.push_back(t);
    if (book_.open(cell)) ++c.evicted_open;
  }
}

// 직전 clear_quiet_ms 동안의 밀어내기 수 (이동 창) — raise의 values.evicted와 해제 보류 기준
int64_t CapHijackRule::evicted_window(CellState& c, int64_t now) const {
  while (!c.evict_times.empty() && c.evict_times.front() <= now - cfg_.clear_quiet_ms) c.evict_times.pop_front();
  return static_cast<int64_t>(c.evict_times.size());
}

// 항목이 닫힘 (20_ §1.2-5·'표시의 생애'): 두 갈래 표시 모두 헬퍼가 닫힘 이유별로 처리한다
void CapHijackRule::on_ue_close(const UeState& last, CloseReason reason, int64_t, const UeRuleCtx&, RuleOutput&) {
  marks_.on_close(last, reason);
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고(END에도 그때의 branch) 표시·누적값을 모두 버린다
void CapHijackRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  book_.end_all("session_reset", out.alerts);
  decorate(from, out);
  held_book_.end_all("session_reset", out.alerts);
  marks_.clear();
  cells_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 공격·불확실 경보를 END(input_silent)로 끝낸다. 표시·셀 기록은 그대로
void CapHijackRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  book_.end_all("input_silent", out.alerts);
  decorate(from, out);
  held_book_.end_all("input_silent", out.alerts);
}

}  // namespace detect
