#include "detect/rules/auth_stall.h"

#include <algorithm>
#include <string>
#include <utility>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

// 응답 (15_ §4.2·§4.3-3): TS 24.501 §5.4.1.3에서 AuthenticationRequest의 응답은 Response·Failure뿐이다. ProtectedNAS는
// 암호라 종류를 모르는 줄, UL DeregistrationRequest는 등록 중 끊고 나가는 UE라(15_ §4.9) 응답으로 본다. 그 밖의 UL NAS를
// 응답으로 보면 공격자가 의미 없는 UL NAS 한 줄로 판정을 피한다(10/29 검수 B2)
bool is_response(const std::string& m) {
  return m == "AuthenticationResponse" || m == "AuthenticationFailure" || m == "ProtectedNAS" ||
         m == "DeregistrationRequest";
}

// 앞선 요청 (15_ §4.6 ues[].values.nas) — 인증을 부르는 UL NAS 요청
bool is_request(const std::string& m) { return m == "RegistrationRequest" || m == "ServiceRequest"; }

// 심각도의 max_conn: hello cells[].max_conn이 있으면 그 값, 없으면 설정 값 (15_ §1.2, 1단계 3_ §4와 같음)
std::optional<int64_t> max_conn_for(const Hello& h, int64_t cell, const AuthStallConfig& cfg) {
  for (const auto& c : h.cells)
    if (c.cell_id == cell && c.max_conn) return c.max_conn;
  return cfg.max_conn;
}

}  // namespace

AuthStallRule::AuthStallRule(AuthStallConfig cfg, AlertConfig alert) : cfg_(cfg), alert_(alert), book_(kId, alert) {}

// 증거 지평 (14_ §1.1): 응답 대기 + 셀 창 + UPDATE 모음 지연 — RAISE는 창 안의 고착 UE를 모두 싣고, 그 대부분은 경보 때
// 이미 닫혀 있다
int64_t AuthStallRule::evidence_horizon_ms() const {
  return cfg_.auth_wait_ms + cfg_.window_ms + alert_.update_min_ms;
}

// ue_evt 한 줄 (15_ §4.3 1~4). NAS 줄만 본다:
//  - DL AuthenticationRequest: 대기 표시가 없으면 기다림을 시작하고(1), 기다리는 중이면 재전송으로 세기만 한다(2).
//    mid_join이면 시작하지 않는다. 고착으로 센 UE에 응답 없이 다시 온 요청(마감 뒤 AMF 재전송)으로도 시작하지 않는다 —
//    재전송마다 다시 세면 응답 없는 UE 하나가 S_W를 부풀린다(4, 10/29 이슈 #29 사용자 결정)
//  - UL 응답: 마감 전이면 대기를 푼다. 마감 이후면 늦은 응답이라 풀지 않는다(14_ §6.1-5). 응답이 왔으므로 그 UE의 다음
//    요청은 새로 기다린다(4)
//  - 그 밖의 UL NAS: 대기를 풀지 않고 other_ul로 센다(3). RegistrationRequest·ServiceRequest는 앞선 요청으로 기억한다
void AuthStallRule::on_ue_event(const UeEvt& evt, const UeState&, const UeState& after, const UeRuleCtx& ctx,
                                RuleOutput&) {
  if (evt.proto != Proto::NAS) return;
  const UeId id{after.key, after.uid};
  auto it = marks_.find(id);
  if (evt.dir == Dir::DL) {
    if (evt.msg != "AuthenticationRequest") return;
    cells_[after.key.cell_id].auth_reqs.emplace_back(evt.t_ms, id);
    if (it != marks_.end()) {
      if (evt.t_ms < it->second.deadline) ++it->second.auth_req_n;
    } else if (!after.mid_join && stalled_.count(id) == 0) {
      start(id, evt, ctx);
    }
    return;
  }
  if (is_response(evt.msg)) {
    stalled_.erase(id);
    if (it == marks_.end()) return;
    if (evt.t_ms < it->second.deadline) marks_.erase(it);
    else it->second.responded_late = true;
    return;
  }
  if (is_request(evt.msg)) requests_[id] = Request{evt.msg, evt.id_type};
  if (it != marks_.end() && evt.t_ms < it->second.deadline) ++it->second.other_ul;
}

// 기다림 시작 (15_ §4.3-1): tag auth_resp, 기다리는 방향 UL, 마감 t₀ + auth_wait_ms. 앞선 요청을 표시에 복사한다
void AuthStallRule::start(const UeId& id, const UeEvt& evt, const UeRuleCtx& ctx) {
  Mark m;
  m.t_from = evt.t_ms;
  m.deadline = evt.t_ms + cfg_.auth_wait_ms;
  if (auto r = requests_.find(id); r != requests_.end()) m.req = r->second;
  ctx.add_deadline(m.deadline, id.first, id.second, "auth_resp", Dir::UL, m.t_from);
  marks_[id] = std::move(m);
}

// 항목이 닫힘 (15_ §1·§4.3-5, 14_ §2.4): n이 마감 전에 released·reused·stale_setup으로 닫히면 표시를 남기고 닫힐 때
// 상태를 복사한다 — 판정을 마감까지 미루는 것은 닫힌 줄이 든 창의 로스 여부가 그 창 kpm2가 와야 정해지기 때문이다
// (L3-20과 같은 이유). du_reset·evicted·ghost_purge·superseded·session_reset이면 표시를 지운다(ghost_purge는 이슈 #44).
// 앞선 요청·고착 표시는 지운다
void AuthStallRule::on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx&, RuleOutput&) {
  const UeId id{last.key, last.uid};
  requests_.erase(id);
  stalled_.erase(id);
  auto it = marks_.find(id);
  if (it == marks_.end()) return;
  if (reason == CloseReason::Released || reason == CloseReason::Reused || reason == CloseReason::StaleSetup) {
    it->second.closed = last;
    it->second.closed_at = t;
  } else {
    marks_.erase(it);
  }
}

// 마감 처리 (15_ §4.3-6): 표시가 그대로(uid·t_from)이고 마감 전 응답이 없고(있었으면 표시를 지웠다), 대기 구간에 UL 로스가
// 없고(있으면 보류 — 14_ §6.2), n이 mid_join·late가 아니면(14_ §4.3) 고착이다. t_hit = 마감.
// 여기서는 고착을 기록만 하고 셀 단위 성립·RAISE·심각도는 같은 kpm2의 on_cell_tick에서 본다(10/29 이슈 #29) — 그 칸의
// UeCtxMax를 넣은 뒤 심각도를 정해야 RAISE와 심각도 UPDATE가 따로 나지 않는다
void AuthStallRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput&) {
  const UeId id{d.key, d.uid};
  auto it = marks_.find(id);
  if (it == marks_.end() || it->second.t_from != d.t_from) return;
  const Mark m = std::move(it->second);
  marks_.erase(it);
  const int64_t cell = d.key.cell_id;
  CellState& c = cells_[cell];
  if (ctx.deadlines.held(cell, Dir::UL, m.t_from)) {
    ++held_n_;
    c.held_times.push_back(ctx.deadlines.clock(cell).value_or(d.at));
    if (book_.open(cell)) ++c.held_open;
    return;
  }
  const UeState* n = ctx.table.find(d.key);
  const bool open = n && n->uid == d.uid;
  if (!open) n = m.closed ? &*m.closed : nullptr;
  if (!n || n->mid_join || n->late) return;
  ++stalls_n_;
  if (open && !m.responded_late) stalled_.insert(id);

  AlertUe u = alert_ue(*n);
  u.cond = {"auth_no_resp"};
  u.t_hit = d.at;
  u.values["nas"] = m.req ? ojson(m.req->msg) : ojson(nullptr);
  u.values["id_type"] = m.req && m.req->id_type ? ojson(*m.req->id_type) : ojson(nullptr);
  u.values["wait_ms"] = cfg_.auth_wait_ms;
  u.values["closed_ms"] = m.closed_at ? ojson(*m.closed_at - m.t_from) : ojson(nullptr);
  u.values["auth_req_n"] = m.auth_req_n;
  u.values["other_ul"] = m.other_ul;
  c.fresh.push_back(std::move(u));
}

// 셀 kpm2마다 (15_ §4.3 셀 단위·심각도, §4.5):
//  1) input_lost면 진행 중 경보를 END (14_ §1.1·§8.2)
//  2) 심각도 창: 최근 W 안 kpm2의 ext.UeCtxMax 최댓값 Cx를 룰이 들고 있는다(1단계 버퍼는 21칸이라 쓰지 않는다).
//     Cx ≥ 0.9 × max_conn이면 high — 셀 연결 자원이 거의 찼다(1단계 C4와 같은 신호·문턱, 10/29 검수 B6)
//  3) 이번 마감 처리에서 정해진 고착마다 (t_hit − W, t_hit] 안의 고착 수 S_W를 센다. S_W ≥ N이면 성립(t_sat).
//     경보가 없을 때 성립하면 그 창의 고착 UE로 RAISE, 경보 중이면 새 고착 UE를 UPDATE로 모은다(14_ §8.2)
//  4) 경보 중 high가 되면 바로 UPDATE, 모아 둔 UE는 UPDATE 간격에 맞춰 낸다
//  5) t_end_ms − t_sat ≥ clear_quiet_ms면 CLEAR — 성립하지 않는 드문 고착(전파가 끊긴 정상 UE)은 해제를 늦추지 않는다.
//     보류는 고착으로 세지 않으므로 해제를 막지 않는다 (15_ §1)
void AuthStallRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                 RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  CellState& c = cells_[cell];
  note_evictions(c, cell, t, ctx);
  if (input_lost) book_.end(cell, t, "input_lost", out.alerts);

  c.uectx.emplace_back(t, k.ue_ctx_max);
  while (c.uectx.front().first <= t - cfg_.window_ms) c.uectx.pop_front();
  std::optional<int64_t> cx;
  for (const auto& [te, v] : c.uectx)
    if (v && (!cx || *v > *cx)) cx = v;
  const std::optional<int64_t> max_conn = max_conn_for(ctx.hello, cell, cfg_);
  const bool high = max_conn && cx && static_cast<double>(*cx) >= 0.9 * static_cast<double>(*max_conn);
  const Severity sev = high ? Severity::High : Severity::Medium;

  for (AlertUe& u : c.fresh) {
    const int64_t t_hit = u.t_hit;
    c.stalls.push_back(u);
    while (c.stalls.front().t_hit <= t_hit - cfg_.window_ms) c.stalls.pop_front();
    c.t_last_stall = t_hit;
    const bool sat = static_cast<int64_t>(c.stalls.size()) >= cfg_.n_stall;
    if (sat) c.t_sat = t_hit;
    const std::size_t from = out.alerts.size();
    if (book_.open(cell)) {
      std::vector<AlertUe> one;
      one.push_back(std::move(u));
      book_.add(cell, std::move(one), sev, t, ctx.session, ctx.seq, out.alerts);
    } else if (sat) {
      c.held_open = 0;  // 새 경보 — 누적값을 처음부터 센다
      c.evicted_open = 0;
      book_.add(cell, std::vector<AlertUe>(c.stalls.begin(), c.stalls.end()), sev, t, ctx.session, ctx.seq,
                out.alerts);
    }
    decorate(cell, from, cx, max_conn, out);
  }
  c.fresh.clear();

  const std::size_t from = out.alerts.size();
  if (high && book_.severity(cell) == Severity::Medium) book_.update(cell, Severity::High, t, out.alerts);
  book_.flush(cell, t, out.alerts);
  // 6) 직전 clear_quiet_ms 동안 그 셀에 상태표 밀어내기가 있었으면 풀지 않는다 (15_ §4.5, Q-56 해결 — 이슈 #44)
  if (book_.open(cell) && t - c.t_sat >= cfg_.clear_quiet_ms && evicted_window(c, t) == 0)
    book_.clear(cell, t, out.alerts);
  decorate(cell, from, cx, max_conn, out);

  // 창 밖 기록 정리. 경보 중에는 값의 기준이 마지막 고착 시각이고, 경보가 없으면 다음 기준은 앞으로의 고착(> t)이다
  const int64_t bound = (book_.open(cell) && c.t_last_stall ? *c.t_last_stall : t) - cfg_.window_ms;
  while (!c.auth_reqs.empty() && c.auth_reqs.front().first <= bound) c.auth_reqs.pop_front();
  if (!book_.open(cell))
    while (!c.stalls.empty() && c.stalls.front().t_hit <= bound) c.stalls.pop_front();
  held_window(c, t);
}

// L3-01-O 값 채우기 (15_ §4.6): raise·update에 values(stalls_w·auth_req_w는 마지막 고착 시각 기준 창, uectx는 심각도 창,
// held는 L3-20과 같음, stalls_total = ues_total), raise에 cond·candidates·params·로그 필드. UPDATE 로그에는 uectx가 있을
// 때만 붙인다. clear·end는 공통 골격 그대로(14_ §8.3)
void AuthStallRule::decorate(int64_t cell, std::size_t from, std::optional<int64_t> cx,
                             std::optional<int64_t> max_conn, RuleOutput& out) {
  CellState& c = cells_[cell];
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["stalls_w"] = static_cast<int64_t>(c.stalls.size());
    e.values["stalls_total"] = e.ues_total;
    e.values["auth_req_w"] = auth_req_w(c);
    e.values["held"] = raise ? held_window(c, e.t) : c.held_open;
    e.values["evicted"] = raise ? evicted_window(c, e.t) : c.evicted_open;  // 15_ §4.6 (이슈 #44)
    e.values["uectx"] = cx ? ojson(*cx) : ojson(nullptr);
    // 로그의 uectx (15_ §4.6): Cx/max_conn, max_conn이 null이면 Cx. RAISE는 늘 적고(없으면 null) UPDATE는 있을 때만
    const std::string uectx =
        !cx ? "null" : max_conn ? std::to_string(*cx) + "/" + std::to_string(*max_conn) : std::to_string(*cx);
    if (!raise) {
      if (cx) e.log_fields = {{"uectx", uectx}};
      continue;
    }
    e.cond = {"stall_count"};
    // 후보 (15_ §4.6): 같은 모양의 4단계 AN-01(등록·인증 미완료 반복). 실린 UE에 S-TMSI가 있으면 피해자 S-TMSI로 연
    // Blind DoS 공격 연결(L3-20)일 수 있다 (15_ §4.1)
    e.candidates = {"AN-01"};
    if (std::any_of(e.ues.begin(), e.ues.end(), [](const AlertUe& u) { return u.s_tmsi.has_value(); }))
      e.candidates.push_back("L3-20");
    e.params["auth_wait_ms"] = cfg_.auth_wait_ms;
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_stall"] = cfg_.n_stall;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    e.params["max_conn"] = max_conn ? ojson(*max_conn) : ojson(nullptr);
    e.log_fields = {{"stalls_w", std::to_string(c.stalls.size())},
                    {"n_stall", std::to_string(cfg_.n_stall)},
                    {"window_ms", std::to_string(cfg_.window_ms)},
                    {"auth_wait_ms", std::to_string(cfg_.auth_wait_ms)},
                    {"uectx", uectx}};
  }
}

// auth_req_w — 마지막 고착 시각 t 기준 (t − W, t] 안에 AuthenticationRequest를 받은 UE 수. 참고용, 판정에 안 씀 (15_ §4.6)
int64_t AuthStallRule::auth_req_w(const CellState& c) const {
  if (!c.t_last_stall) return 0;
  const int64_t t = *c.t_last_stall;
  std::set<UeId> ues;
  for (const auto& [ta, id] : c.auth_reqs)
    if (ta > t - cfg_.window_ms && ta <= t) ues.insert(id);
  return static_cast<int64_t>(ues.size());
}

// raise의 held — 직전 clear_quiet_ms 동안 보류된 판정 수. 경보가 없을 때도 셀별 이동 창으로 센다 (15_ §4.6, L3-20과 같음)
int64_t AuthStallRule::held_window(CellState& c, int64_t now) const {
  while (!c.held_times.empty() && c.held_times.front() <= now - cfg_.clear_quiet_ms) c.held_times.pop_front();
  return static_cast<int64_t>(c.held_times.size());
}

// 상태표 셀별 누적 evicted(14_ §6.3)의 증가분을 이 칸 시각으로 적는다 — 경보가 열려 있으면 evicted_open도 (이슈 #44)
void AuthStallRule::note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx) {
  const int64_t total = ctx.table.counts(cell).evicted;
  for (; c.evicted_seen < total; ++c.evicted_seen) {
    c.evict_times.push_back(t);
    if (book_.open(cell)) ++c.evicted_open;
  }
}

// 직전 clear_quiet_ms 동안의 밀어내기 수 (이동 창) — raise의 values.evicted와 해제 보류 기준
int64_t AuthStallRule::evicted_window(CellState& c, int64_t now) const {
  while (!c.evict_times.empty() && c.evict_times.front() <= now - cfg_.clear_quiet_ms) c.evict_times.pop_front();
  return static_cast<int64_t>(c.evict_times.size());
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 대기 표시·셀 기록을 모두 버린다
void AuthStallRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  book_.end_all("session_reset", out.alerts);
  marks_.clear();
  requests_.clear();
  stalled_.clear();
  cells_.clear();
}

}  // namespace detect
