#include "detect/rules/uplink_dos.h"

#include <algorithm>
#include <string>
#include <utility>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

// 수락 근거 메시지 (15_ §1.1 표, §5.3-2): RegistrationAccept·ServiceAccept(NAS DL)와 RRC SecurityModeCommand(DL).
// 갈래 ①은 상태 전이가 아니라 이 메시지로 '새로 수락'을 본다 — 상태로 보면 이미 수락된 연결은 다시 수락될 수 없다
// (rrc_sec은 ON이 되면 그대로이고, REGISTERED에서 받은 ServiceReject는 nas를 바꾸지 않는다, 14_ §5) (10/29 이슈 #31)
bool is_accept(const UeEvt& e) {
  if (e.dir != Dir::DL) return false;
  if (e.proto == Proto::NAS) return e.msg == "RegistrationAccept" || e.msg == "ServiceAccept";
  return e.proto == Proto::RRC && e.msg == "SecurityModeCommand";
}

std::string ue_name(const AlertUe& u) {
  return std::to_string(u.cell) + "/" + std::to_string(u.du_ue_id) + "/" + std::to_string(u.uid);
}

}  // namespace

UplinkDosRule::UplinkDosRule(UplinkDosConfig cfg, AlertConfig alert)
    : cfg_(std::move(cfg)), alert_(alert), book_(kId, alert), held_book_(kId, alert, "anomaly") {}

// 증거 지평 (14_ §1.1): 실패 뒤 수락 대기 + 셀 창 + UPDATE 모음 지연 — 갈래 ① RAISE는 창 안의 실패 UE를 모두 싣고,
// 그 대부분은 거부 뒤 연결이 정리되어 경보 때 이미 닫혀 있다
int64_t UplinkDosRule::evidence_horizon_ms() const {
  return cfg_.fail_accept_wait_ms + cfg_.window_ms + alert_.update_min_ms;
}

// 실패 메시지 (15_ §5.2): RegistrationReject·ServiceReject·AuthenticationReject(DL), AuthenticationFailure(UL).
// ignore_causes의 원인값을 가진 Reject는 실패로 세지 않는다 — 망 컨텍스트 소실 뒤 정상 재접속의 거절을 거르는 정교화이고
// 기본은 끔이다(10/29 검수 B3). SecurityModeReject는 #3 쪽 신호라 넣지 않는다
bool UplinkDosRule::is_failure(const UeEvt& e) const {
  if (e.proto != Proto::NAS) return false;
  if (e.dir == Dir::UL) return e.msg == "AuthenticationFailure";
  if (e.msg != "RegistrationReject" && e.msg != "ServiceReject" && e.msg != "AuthenticationReject") return false;
  return !e.cause ||
         std::find(cfg_.ignore_causes.begin(), cfg_.ignore_causes.end(), *e.cause) == cfg_.ignore_causes.end();
}

// ue_evt 한 줄 (15_ §5.3):
//  - 수락 근거 메시지: 마감 전이면 갈래 ① 기다림을 푼다(정상 회복 — 동기 실패 뒤 재인증 등). 마감 이후면 늦은 수락이라
//    풀지 않는다(14_ §6.1-5). 실패 UE로 센 연결도 수락이 왔으므로 다음 실패는 새로 기다린다
//  - 실패 메시지: 연결 기록에 더하고, 기다리는 표시가 없으면 갈래 ① 기다림을 시작한다. 이미 수락된 연결이어도 시작한다
//    (수락 뒤의 거부도 실패다). 기다리는 중의 실패, 실패 UE로 센 뒤 새 수락이 없는 연결의 실패로는 시작하지 않는다 —
//    마감 뒤 실패마다 다시 세면 한 연결의 반복 거부가 '실패 UE 수'를 부풀리고 갈래 ②와 겹친다(10/29 이슈 #31 사용자 결정).
//    mid_join이면 시작하지 않는다(마감 때 '없음' 판정을 하지 않으므로 같은 결과, 14_ §4.3)
//  - 갈래 ②: RegistrationRequest R번 이상과 실패(ignore_causes 제외)가 이 연결에 함께 보이면 즉시 걸린다. 연결당 한 번.
//    본 것으로 판정하므로 기다림·로스 보류가 없고, 불확실한 항목도 판정해 uncertain에 표시한다
void UplinkDosRule::on_ue_event(const UeEvt& evt, const UeState&, const UeState& after, const UeRuleCtx& ctx,
                                RuleOutput& out) {
  const UeId id{after.key, after.uid};
  if (is_accept(evt)) {
    if (auto c = conns_.find(id); c != conns_.end()) c->second.counted = false;
    if (auto it = marks_.find(id); it != marks_.end()) {
      if (evt.t_ms < it->second.deadline) marks_.erase(it);
      else it->second.accepted_late = true;
    }
    return;
  }
  const bool reg = evt.proto == Proto::NAS && evt.dir == Dir::UL && evt.msg == "RegistrationRequest";
  const bool fail = is_failure(evt);
  if (!reg && !fail) return;
  Conn& c = conns_[id];
  if (reg) c.id_type = evt.id_type;
  if (fail) {
    c.fails.push_back(evt.msg);
    if (evt.cause) c.causes.push_back(*evt.cause);
    cells_[after.key.cell_id].fail_msgs.push_back(evt.t_ms);
    if (marks_.count(id) == 0 && !c.counted && !after.mid_join) start(id, evt.t_ms, ctx);
  }
  if (!c.branch2 && !c.fails.empty() && after.count(Proto::NAS, "RegistrationRequest") >= cfg_.reg_repeat) {
    c.branch2 = true;
    hit2(after, c, evt.t_ms, ctx, out);
  }
}

// 갈래 ① 기다림 시작 (15_ §5.3-1): tag fail_accept, 수락 근거가 DL이라 기다리는 방향도 DL, 마감 t_f + fail_accept_wait_ms
void UplinkDosRule::start(const UeId& id, int64_t t_f, const UeRuleCtx& ctx) {
  Mark m;
  m.t_from = t_f;
  m.deadline = t_f + cfg_.fail_accept_wait_ms;
  ctx.add_deadline(m.deadline, id.first, id.second, "fail_accept", Dir::DL, t_f);
  marks_[id] = std::move(m);
}

// 걸린 UE 한 칸 (15_ §5.6 ues[].values): branch, reg_req_n(걸린 때의 cnt), fails(실패로 센 메시지, 본 순서),
// causes(그 가운데 원인값이 있는 것, 없으면 []), id_type(마지막 RegistrationRequest), closed_ms(갈래 ①에서 마감 전에 닫힘)
AlertUe UplinkDosRule::make_ue(const UeState& n, const Conn* c, const char* branch, std::vector<std::string> cond,
                               int64_t t_hit, std::optional<int64_t> closed_ms) const {
  AlertUe u = alert_ue(n);
  u.cond = std::move(cond);
  u.t_hit = t_hit;
  u.values["branch"] = branch;
  u.values["reg_req_n"] = n.count(Proto::NAS, "RegistrationRequest");
  u.values["fails"] = c ? ojson(c->fails) : ojson::array();
  u.values["causes"] = c ? ojson(c->causes) : ojson::array();
  u.values["id_type"] = c && c->id_type ? ojson(*c->id_type) : ojson(nullptr);
  u.values["closed_ms"] = closed_ms ? ojson(*closed_ms) : ojson(nullptr);
  return u;
}

// 갈래 ② 걸림 (15_ §5.3·§5.5): 경보가 없으면 그 UE로 RAISE — 경보 t와 alert_id의 seq는 그 줄의 것이다(15_ §5.6).
// 경보 중이면 UPDATE로 모으고, 이 경보에서 갈래 ①이 성립했으면 근거가 겹쳐 high로 바로 올린다
void UplinkDosRule::hit2(const UeState& n, const Conn& c, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) {
  const int64_t cell = n.key.cell_id;
  CellState& cs = cells_[cell];
  cs.t_last_hit = std::max(cs.t_last_hit.value_or(t), t);
  cs.t_active = std::max(cs.t_active, t);
  if (!book_.open(cell)) {
    close_held(cell, t, out);  // 공격 RAISE 전에 열린 불확실 경보를 먼저 CLEAR (14_ §8.2)
    new_alert(cs);
  }
  cs.has2 = true;
  ++cs.branch2_ues;
  std::vector<AlertUe> one;
  one.push_back(make_ue(n, &c, "2", {"reg_repeat", "fail"}, t, std::nullopt));
  const std::size_t from = out.alerts.size();
  book_.add(cell, std::move(one), cs.sat1 ? Severity::High : Severity::Medium, t, ctx.session, ctx.seq, out.alerts);
  decorate(from, out);
}

// 새 경보 — 경보에 묶인 값을 처음부터 센다 (15_ §5.6 values는 경보가 열린 뒤의 누적)
void UplinkDosRule::new_alert(CellState& c) const {
  ++c.alert_no;
  c.sat1 = false;
  c.has2 = false;
  c.branch1_ues = 0;
  c.branch2_ues = 0;
  c.held_open = 0;
  c.evicted_open = 0;
}

// 항목이 닫힘 (15_ §1·§5.3-3, 14_ §2.4): 갈래 ① 대기 중인 n이 released·reused·stale_setup으로 닫히면 표시를 남기고
// 닫힐 때 상태와 연결 기록을 복사한다 — 마감 전에 닫혔다는 것은 수락 없이 끝났다는 뜻이고, 판정을 마감까지 미루는 것은
// 닫힌 줄이 든 창의 로스 여부가 그 창 kpm2가 와야 정해지기 때문이다(L3-20과 같은 이유). du_reset·evicted·ghost_purge·
// superseded·session_reset이면 표시를 지운다(ghost_purge는 이슈 #44). 연결 기록은 지운다
void UplinkDosRule::on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx&, RuleOutput&) {
  const UeId id{last.key, last.uid};
  auto c = conns_.find(id);
  if (auto it = marks_.find(id); it != marks_.end()) {
    if (reason == CloseReason::Released || reason == CloseReason::Reused || reason == CloseReason::StaleSetup) {
      it->second.closed = last;
      it->second.closed_at = t;
      if (c != conns_.end()) it->second.closed_conn = c->second;
    } else {
      marks_.erase(it);
    }
  }
  if (c != conns_.end()) conns_.erase(c);
}

// 갈래 ① 마감 처리 (15_ §5.3-4): 표시가 그대로(uid·t_from)이고 마감 전 수락이 없고(있었으면 표시를 지웠다), 대기 구간에
// DL 로스가 없고(있으면 보류 — 수락 근거가 DL이라 그 로스로 수락을 놓쳤을 수 있다, 14_ §6.2), n이 mid_join이 아니고
// 늦은 줄 제외 기간(late_until)이 지났으면(14_ §4.3, 이슈 #46) 실패 UE다. t_hit = 마감. 여기서는 기록만 하고 셀 단위 성립·RAISE는 같은 kpm2의 on_cell_tick에서 본다
// (L3-01-O와 같음, 10/29 이슈 #31). 실패 UE로 센 열린 연결은 새 수락이 올 때까지 다시 세지 않는다(15_ §5.3-1)
void UplinkDosRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput&) {
  const UeId id{d.key, d.uid};
  auto it = marks_.find(id);
  if (it == marks_.end() || it->second.t_from != d.t_from) return;
  const Mark m = std::move(it->second);
  marks_.erase(it);
  const int64_t cell = d.key.cell_id;
  CellState& cs = cells_[cell];
  const UeState* n = ctx.table.find(d.key);
  const Conn* c = nullptr;
  Conn* live = nullptr;  // 열린 연결의 기록 — 실패 UE로 셌다고 적는다
  if (n && n->uid == d.uid) {
    if (auto ci = conns_.find(id); ci != conns_.end()) c = live = &ci->second;
  } else {
    n = m.closed ? &*m.closed : nullptr;
    c = m.closed_conn ? &*m.closed_conn : nullptr;
  }
  if (ctx.deadlines.held(cell, Dir::DL, m.t_from)) {
    // 보류 (14_ §6.2): 공격 경보 중이면 values.held로만, 아니면 불확실 경보용으로 적어 둔다(판정은 held_tick) — 이슈 #48
    ++held_n_;
    cs.held_times.push_back(ctx.deadlines.clock(cell).value_or(d.at));
    if (book_.open(cell)) ++cs.held_open;
    else if (alert_.held_alert && n) cs.fresh_held.push_back(held_ue(*n, d.at));
    return;
  }
  if (!n || n->mid_join || n->late_blocks(d.at)) return;
  ++failed_n_;
  if (live && !m.accepted_late) live->counted = true;
  const std::optional<int64_t> closed_ms =
      m.closed_at ? std::optional<int64_t>(*m.closed_at - m.t_from) : std::nullopt;
  cs.fresh.push_back(make_ue(*n, c, "1", {"fail_not_accepted"}, d.at, closed_ms));
}

// 셀 kpm2마다 (15_ §5.3 갈래 ①·§5.5):
//  1) input_lost면 진행 중 경보를 END (14_ §1.1·§8.2)
//  2) 이번 마감 처리에서 정해진 실패 UE마다 (t_hit − W, t_hit] 안의 수 F_W를 센다. F_W ≥ N이면 갈래 ① 성립.
//     경보가 없을 때 성립하면 창 안의 실패 UE로 RAISE. 경보 중이면 새 실패 UE를 UPDATE로 모으고, 갈래 ②로 열린 경보에서
//     갈래 ①이 처음 성립하면 창 안 실패 UE 가운데 이 경보에 아직 실리지 않은 것을 함께 싣고 바로 UPDATE한다 —
//     branch가 "1"로 바뀌고, 갈래 ② UE가 있으므로 high다(15_ §5.5, 10/29 이슈 #31 사용자 결정)
//  3) 모아 둔 UE는 UPDATE 간격에 맞춰 내고, 마지막 갈래 ① 성립·갈래 ② 걸림 뒤 clear_quiet_ms가 지나면 CLEAR —
//     문턱 아래의 드문 실패(정상 단말)는 해제를 늦추지 않는다. 보류는 실패로 세지 않으므로 해제를 막지 않는다 (15_ §1)
void UplinkDosRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                 RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  CellState& cs = cells_[cell];
  note_evictions(cs, cell, t, ctx);
  std::size_t from = out.alerts.size();
  if (input_lost) book_.end(cell, t, "input_lost", out.alerts);
  decorate(from, out);

  for (AlertUe& u : cs.fresh) {
    const int64_t t_hit = u.t_hit;
    cs.failed.push_back(Failed{u, 0});
    while (cs.failed.front().ue.t_hit <= t_hit - cfg_.window_ms) cs.failed.pop_front();
    cs.t_last_hit = std::max(cs.t_last_hit.value_or(t_hit), t_hit);
    const bool sat = static_cast<int64_t>(cs.failed.size()) >= cfg_.n_fail;
    const bool was_open = book_.open(cell);
    if (!was_open && !sat) continue;  // 경보 밖의 문턱 아래 실패 — 창에만 둔다
    if (!was_open) {
      close_held(cell, t, out);  // 공격 RAISE 전에 열린 불확실 경보를 먼저 CLEAR (14_ §8.2)
      new_alert(cs);
    }
    const bool first_sat = sat && !cs.sat1;
    if (sat) {
      cs.sat1 = true;
      cs.t_active = std::max(cs.t_active, t_hit);
    }
    // 실을 UE: 새 경보나 갈래 ① 첫 성립이면 창 안의 아직 안 실린 실패 UE 전부, 아니면 이 UE만
    std::vector<AlertUe> ues;
    for (std::size_t i = first_sat ? 0 : cs.failed.size() - 1; i < cs.failed.size(); ++i) {
      if (cs.failed[i].loaded == cs.alert_no) continue;
      cs.failed[i].loaded = cs.alert_no;
      ues.push_back(cs.failed[i].ue);
    }
    cs.branch1_ues += static_cast<int64_t>(ues.size());
    from = out.alerts.size();
    book_.add(cell, std::move(ues), cs.sat1 && cs.has2 ? Severity::High : Severity::Medium, t, ctx.session, ctx.seq,
              out.alerts);
    if (was_open && first_sat && out.alerts.size() == from) book_.update(cell, *book_.severity(cell), t, out.alerts);
    decorate(from, out);
  }
  cs.fresh.clear();

  from = out.alerts.size();
  book_.flush(cell, t, out.alerts);
  // 직전 clear_quiet_ms 동안 그 셀에 상태표 밀어내기가 있었으면 풀지 않는다 (15_ §5.5, Q-56 해결 — 이슈 #44)
  if (book_.open(cell) && t - cs.t_active >= cfg_.clear_quiet_ms && evicted_window(cs, t) == 0)
    book_.clear(cell, t, out.alerts);
  decorate(from, out);

  // 창 밖 기록 정리. 경보 중에는 값의 기준이 가장 최근 걸림이고, 경보가 없으면 다음 기준은 앞으로의 걸림(≥ t)이다
  const int64_t bound = (book_.open(cell) && cs.t_last_hit ? *cs.t_last_hit : t) - cfg_.window_ms;
  while (!cs.fail_msgs.empty() && cs.fail_msgs.front() <= bound) cs.fail_msgs.pop_front();
  if (!book_.open(cell))
    while (!cs.failed.empty() && cs.failed.front().ue.t_hit <= bound) cs.failed.pop_front();
  held_window(cs, t);
  held_tick(cell, cs, t, input_lost, ctx, out);
}

// 보류된 UE 한 칸 (14_ §6.2 불확실 경보의 ues[]): cond held, t_hit = 마감, uncertain에 loss, 기다린 시간·방향
AlertUe UplinkDosRule::held_ue(const UeState& n, int64_t t_hit) const {
  AlertUe u = alert_ue(n);
  u.cond = {"held"};
  u.t_hit = t_hit;
  if (std::find(u.uncertain.begin(), u.uncertain.end(), "loss") == u.uncertain.end()) u.uncertain.emplace_back("loss");
  u.values["wait_ms"] = cfg_.fail_accept_wait_ms;
  u.values["dir"] = "DL";
  return u;
}

// 불확실 경보 (14_ §6.2 — Q-58 ② 해결, 이슈 #48): 이번 마감 처리에서 보류된 UE마다 (t_hit − W, t_hit] 안 보류 수 H_W를
// 세고, 공격 경보가 없으면 H_W ≥ N에서 창 안 보류 UE로 RAISE(kind anomaly, 갈래 없음), 경보 중이면 UPDATE로 모은다.
// 공격 경보가 이 칸에서 열렸으면 values.held로만 센다. 마지막 보류 뒤 clear_quiet_ms면 CLEAR, input_lost면 END
void UplinkDosRule::held_tick(int64_t cell, CellState& c, int64_t t, bool input_lost, const UeRuleCtx& ctx,
                              RuleOutput& out) {
  std::size_t from = out.alerts.size();
  if (input_lost) held_book_.end(cell, t, "input_lost", out.alerts);
  for (AlertUe& u : c.fresh_held) {
    c.held_ues.push_back(u);
    while (c.held_ues.front().t_hit <= u.t_hit - cfg_.window_ms) c.held_ues.pop_front();
    c.t_last_held = u.t_hit;
    if (book_.open(cell)) {
      ++c.held_open;
      continue;
    }
    const bool sat = static_cast<int64_t>(c.held_ues.size()) >= cfg_.n_fail;
    if (held_book_.open(cell)) {
      std::vector<AlertUe> one;
      one.push_back(u);
      held_book_.add(cell, std::move(one), Severity::Medium, t, ctx.session, ctx.seq, out.alerts);
    } else if (sat) {
      held_book_.add(cell, std::vector<AlertUe>(c.held_ues.begin(), c.held_ues.end()), Severity::Medium, t,
                     ctx.session, ctx.seq, out.alerts);
    }
  }
  c.fresh_held.clear();
  held_book_.flush(cell, t, out.alerts);
  if (held_book_.open(cell) && t - c.t_last_held >= cfg_.clear_quiet_ms) held_book_.clear(cell, t, out.alerts);
  decorate_held(from, out);
  if (!held_book_.open(cell))
    while (!c.held_ues.empty() && c.held_ues.front().t_hit <= t - cfg_.window_ms) c.held_ues.pop_front();
}

// 공격 경보가 RAISE되기 직전 — 열린 불확실 경보를 같은 줄에서 먼저 CLEAR한다 (14_ §8.2)
void UplinkDosRule::close_held(int64_t cell, int64_t t, RuleOutput& out) {
  if (!held_book_.open(cell)) return;
  const std::size_t from = out.alerts.size();
  held_book_.clear(cell, t, out.alerts);
  decorate_held(from, out);
}

// 불확실 경보 값 채우기 (14_ §6.2): raise·update에 values.held_w, raise에 cond held_count·candidates(이 룰)·params·로그 필드
// (맨 앞 kind=anomaly). 갈래는 없다(branch 비움). update 로그에는 kind=anomaly만
void UplinkDosRule::decorate_held(std::size_t from, RuleOutput& out) {
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
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_fail"] = cfg_.n_fail;
    e.params["fail_accept_wait_ms"] = cfg_.fail_accept_wait_ms;
    e.params["reg_repeat"] = cfg_.reg_repeat;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    e.params["ignore_causes"] = cfg_.ignore_causes;
    e.log_fields = {{"kind", "anomaly"},
                    {"held_w", std::to_string(c.held_ues.size())},
                    {"n_fail", std::to_string(cfg_.n_fail)},
                    {"window_ms", std::to_string(cfg_.window_ms)}};
  }
}

// L3-21 값 채우기 (15_ §5.6): branch는 모든 이벤트에 그때의 갈래로(갈래 ①이 한 번이라도 성립했으면 "1"). raise·update에
// values — fails_w·fail_msgs_w는 가장 최근 걸림 기준 창, branch1_ues·branch2_ues는 실린 걸림 수(누적), held는 L3-20과
// 같음. raise에 cond(RAISE를 일으킨 갈래의 것)·candidates·params·로그 필드. UPDATE 로그는 공통 골격 그대로(branch 포함)
void UplinkDosRule::decorate(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    CellState& cs = cells_[e.cell_id];
    e.branch = cs.sat1 ? "1" : "2";
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["fails_w"] = in_window(cs, false);
    e.values["branch1_ues"] = cs.branch1_ues;
    e.values["branch2_ues"] = cs.branch2_ues;
    e.values["held"] = raise ? held_window(cs, e.t) : cs.held_open;
    e.values["evicted"] = raise ? evicted_window(cs, e.t) : cs.evicted_open;  // 15_ §5.6 (이슈 #44)
    e.values["fail_msgs_w"] = in_window(cs, true);
    if (!raise) continue;
    e.cond = cs.sat1 ? std::vector<std::string>{"fail_count"} : std::vector<std::string>{"reg_repeat", "fail"};
    // 후보 (15_ §5.6): 같은 신호의 4단계 AN-01(#7 인증 동기 실패·#36 IMSI 크래킹 — #36과는 가르지 못함). 실린 UE에 S-TMSI가
    // 있으면 피해자 GUTI로 보낸 위조 ServiceRequest — Blind DoS(L3-20)일 수 있다 (15_ §5.1)
    e.candidates = {"AN-01"};
    if (std::any_of(e.ues.begin(), e.ues.end(), [](const AlertUe& u) { return u.s_tmsi.has_value(); }))
      e.candidates.push_back("L3-20");
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_fail"] = cfg_.n_fail;
    e.params["fail_accept_wait_ms"] = cfg_.fail_accept_wait_ms;
    e.params["reg_repeat"] = cfg_.reg_repeat;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    e.params["ignore_causes"] = cfg_.ignore_causes;
    // 로그 줄 (15_ §5.6): 갈래 ①은 창 안 실패 UE 수와 문턱, 갈래 ②는 걸린 UE와 그 연결의 등록 요청 수·실패 메시지(쉼표)
    if (cs.sat1) {
      e.log_fields = {{"branch", "1"},
                      {"fails_w", std::to_string(in_window(cs, false))},
                      {"n_fail", std::to_string(cfg_.n_fail)},
                      {"window_ms", std::to_string(cfg_.window_ms)}};
    } else if (!e.ues.empty()) {
      const AlertUe& u = e.ues.front();
      std::string fails;
      for (const auto& f : u.values.at("fails")) fails += (fails.empty() ? "" : ",") + f.get<std::string>();
      e.log_fields = {{"branch", "2"},
                      {"ue", ue_name(u)},
                      {"reg_req_n", std::to_string(u.values.at("reg_req_n").get<int64_t>())},
                      {"fails", fails}};
    }
  }
}

// 가장 최근 걸림 시각 t 기준 (t − W, t] 안의 실패 UE 수(msgs = false) 또는 실패 메시지 수(msgs = true) (15_ §5.6)
int64_t UplinkDosRule::in_window(const CellState& c, bool msgs) const {
  if (!c.t_last_hit) return 0;
  const int64_t hi = *c.t_last_hit;
  const int64_t lo = hi - cfg_.window_ms;
  if (msgs)
    return std::count_if(c.fail_msgs.begin(), c.fail_msgs.end(), [&](int64_t x) { return x > lo && x <= hi; });
  return std::count_if(c.failed.begin(), c.failed.end(),
                       [&](const Failed& f) { return f.ue.t_hit > lo && f.ue.t_hit <= hi; });
}

// raise의 held — 직전 clear_quiet_ms 동안 보류된 판정 수. 경보가 없을 때도 셀별 이동 창으로 센다 (L3-20 §2.6과 같음)
int64_t UplinkDosRule::held_window(CellState& c, int64_t now) const {
  while (!c.held_times.empty() && c.held_times.front() <= now - cfg_.clear_quiet_ms) c.held_times.pop_front();
  return static_cast<int64_t>(c.held_times.size());
}

// 상태표 셀별 누적 evicted(14_ §6.3)의 증가분을 이 칸 시각으로 적는다 — 경보가 열려 있으면 evicted_open도 (이슈 #44)
void UplinkDosRule::note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx) {
  const int64_t total = ctx.table.counts(cell).evicted;
  for (; c.evicted_seen < total; ++c.evicted_seen) {
    c.evict_times.push_back(t);
    if (book_.open(cell)) ++c.evicted_open;
  }
}

// 직전 clear_quiet_ms 동안의 밀어내기 수 (이동 창) — raise의 values.evicted와 해제 보류 기준
int64_t UplinkDosRule::evicted_window(CellState& c, int64_t now) const {
  while (!c.evict_times.empty() && c.evict_times.front() <= now - cfg_.clear_quiet_ms) c.evict_times.pop_front();
  return static_cast<int64_t>(c.evict_times.size());
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 대기 표시·연결 기록·셀 기록을 모두 버린다
void UplinkDosRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  book_.end_all("session_reset", out.alerts);
  decorate(from, out);
  held_book_.end_all("session_reset", out.alerts);  // 불확실 경보는 갈래가 없어 decorate 밖에서
  marks_.clear();
  conns_.clear();
  cells_.clear();
}

// 입력 침묵 (14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 진행 중 공격 경보(갈래 표시 포함)·불확실 경보를 END(input_silent)로 끝낸다 —
// END t는 각 경보가 마지막으로 본 칸. 대기 표시·연결 기록·셀 기록은 그대로 — kpm2가 다시 오면 마감이 평소처럼 판정된다
void UplinkDosRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  book_.end_all("input_silent", out.alerts);
  decorate(from, out);
  held_book_.end_all("input_silent", out.alerts);  // 불확실 경보는 갈래가 없어 decorate 밖에서
}

}  // namespace detect
