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

// 불확실 경보 묶음의 값 (14_ §6.2, 15_ §4.7): 창 W, 문턱 N. raise의 params는 auth_wait_ms·window_ms·n_stall·clear_quiet_ms,
// 로그 줄은 kind=anomaly held_w= 뒤에 n_stall= window_ms= auth_wait_ms=
HeldBook::Spec held_spec(const AuthStallConfig& cfg) {
  HeldBook::Spec s;
  s.rule = AuthStallRule::kId;
  s.stage = 2;
  s.window_ms = cfg.window_ms;
  s.n = cfg.n_stall;
  s.clear_quiet_ms = cfg.clear_quiet_ms;
  s.params["auth_wait_ms"] = cfg.auth_wait_ms;
  s.params["window_ms"] = cfg.window_ms;
  s.params["n_stall"] = cfg.n_stall;
  s.params["clear_quiet_ms"] = cfg.clear_quiet_ms;
  s.log_fields = {{"n_stall", std::to_string(cfg.n_stall)},
                  {"window_ms", std::to_string(cfg.window_ms)},
                  {"auth_wait_ms", std::to_string(cfg.auth_wait_ms)}};
  return s;
}

}  // namespace

// 공격 묶음 (15_ §4.3·§4.5 — R2, 이슈 #96): HitWindow를 2단계 모양으로 — 종류 attack·단계 2, 연결당 한 번은 룰 몫(stalled_ —
// 응답 뒤 새 기다림은 같은 연결이 다시 고착할 수 있다, §4.3-4), CLEAR 기준은 마지막 성립 t_sat(§4.5 — 성립하지 않는 드문 고착은
// 해제를 늦추지 않는다), END 뒤 창 비움은 4단계와 같다(§4.5 — 11/05 Q-77, W-41), 공격 RAISE 직전 불확실 경보 CLEAR는 held_ 고리로
AuthStallRule::AuthStallRule(AuthStallConfig cfg, AlertConfig alert)
    : cfg_(cfg),
      alert_(alert),
      hits_(kId, alert, cfg.window_ms, cfg.n_stall, cfg.clear_quiet_ms, "attack", 2),
      held_(held_spec(cfg), alert) {
  hits_.set_once_per_conn(false);
  hits_.set_clear_on_satisfied(true);
  hits_.set_held(&held_);
}

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
// 앞선 요청·고착 표시는 지운다. 아직 kpm2를 거치지 않은 고착은 헬퍼가 마지막 상태로 둔다
void AuthStallRule::on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx&, RuleOutput&) {
  const UeId id{last.key, last.uid};
  hits_.on_close(last);
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
// 없고(있으면 보류 — 14_ §6.2), n이 mid_join이 아니고 늦은 줄 제외 기간(late_until)이 지났으면(14_ §4.3, 이슈 #46) 고착이다.
// t_hit = 마감.
// 여기서는 고착을 적기만 하고 셀 단위 성립·RAISE·심각도는 같은 kpm2의 on_cell_tick에서 본다(10/29 이슈 #29) — 그 칸의
// UeCtxMax를 넣은 뒤 심각도를 정해야 RAISE와 심각도 UPDATE가 따로 나지 않는다
void AuthStallRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput&) {
  const UeId id{d.key, d.uid};
  auto it = marks_.find(id);
  if (it == marks_.end() || it->second.t_from != d.t_from) return;
  const Mark m = std::move(it->second);
  marks_.erase(it);
  const int64_t cell = d.key.cell_id;
  const UeState* n = ctx.table.find(d.key);
  const bool open = n && n->uid == d.uid;
  if (!open) n = m.closed ? &*m.closed : nullptr;
  if (ctx.deadlines.held(cell, Dir::UL, m.t_from)) {
    // 보류 (14_ §6.2): 공격 경보 중이면 values.held로만, 아니면 불확실 경보용으로 적어 둔다(판정은 held_.tick) — 이슈 #48
    held_.hold(cell, ctx.deadlines.clock(cell).value_or(d.at), hits_.open(cell),
               n ? std::optional<AlertUe>(held_ue(*n, d.at)) : std::nullopt);
    return;
  }
  if (!n || n->mid_join || n->late_blocks(d.at)) return;
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
  hits_.hit(id, std::move(u));
}

// 셀 kpm2마다 (15_ §4.3 셀 단위·심각도, §4.5):
//  1) 심각도 창: 최근 W 안 kpm2의 ext.UeCtxMax 최댓값 Cx를 룰이 들고 있는다(1단계 버퍼는 21칸이라 쓰지 않는다).
//     Cx ≥ 0.9 × max_conn이면 high — 셀 연결 자원이 거의 찼다(1단계 C4와 같은 신호·문턱, 10/29 검수 B6)
//  2) 헬퍼(HitWindow): input_lost면 END(14_ §1.1·§8.2). 이번 마감 처리에서 정해진 고착마다 (t_hit − W, t_hit] 안의 고착 수 S_W를
//     센다. S_W ≥ N이면 성립(t_sat). 경보가 없을 때 성립하면 그 창의 고착 UE로 RAISE(열린 불확실 경보는 먼저 CLEAR), 경보 중이면
//     새 고착 UE를 UPDATE로 모은다(14_ §8.2). 경보 중 high가 되면 바로 UPDATE, 모아 둔 UE는 UPDATE 간격에 맞춰 낸다.
//     t_end_ms − t_sat ≥ clear_quiet_ms면 CLEAR — 성립하지 않는 드문 고착(전파가 끊긴 정상 UE)은 해제를 늦추지 않는다.
//     직전 clear_quiet_ms 동안 그 셀에 상태표 밀어내기가 있었으면 풀지 않는다(15_ §4.5, Q-56 해결 — 이슈 #44). CLEAR 뒤 걸림만
//     싣는다(15_ §4.5 — 11/05 Q-73, 이슈 #94: 창 안 고착 목록을 비워 옛 경보에 실렸던 UE가 새 RAISE에 다시 실리지 않게)
//  3) 보류는 고착으로 세지 않으므로 해제를 막지 않는다 (15_ §1). 불확실 경보는 공격 묶음 뒤에 held_가 본다
void AuthStallRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                 RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  CellState& c = cells_[cell];

  c.uectx.emplace_back(t, k.ue_ctx_max);
  while (c.uectx.front().first <= t - cfg_.window_ms) c.uectx.pop_front();
  std::optional<int64_t> cx;
  for (const auto& [te, v] : c.uectx)
    if (v && (!cx || *v > *cx)) cx = v;
  const std::optional<int64_t> max_conn = max_conn_for(ctx.hello, cell, cfg_);
  const bool high = max_conn && cx && static_cast<double>(*cx) >= 0.9 * static_cast<double>(*max_conn);
  hits_.set_severity(high ? Severity::High : Severity::Medium);

  hits_.tick(cell, t, input_lost, ctx, out.alerts,
             [&](std::size_t from, const AlertUe* hit) { decorate(cell, from, hit, cx, max_conn, out); });

  // 창 밖 기록 정리. 경보 중에는 값의 기준이 마지막 고착 시각이고, 경보가 없으면 다음 기준은 앞으로의 고착(> t)이다
  const int64_t bound = (hits_.open(cell) && c.t_last_stall ? *c.t_last_stall : t) - cfg_.window_ms;
  while (!c.auth_reqs.empty() && c.auth_reqs.front().first <= bound) c.auth_reqs.pop_front();
  held_.tick(cell, t, input_lost, hits_.open(cell), ctx, out.alerts);
}

// 보류된 UE 한 칸 (14_ §6.2 불확실 경보의 ues[]): cond held, t_hit = 마감, uncertain에 loss, 기다린 시간·방향
AlertUe AuthStallRule::held_ue(const UeState& n, int64_t t_hit) const {
  AlertUe u = alert_ue(n);
  u.cond = {"held"};
  u.t_hit = t_hit;
  if (std::find(u.uncertain.begin(), u.uncertain.end(), "loss") == u.uncertain.end()) u.uncertain.emplace_back("loss");
  u.values["wait_ms"] = cfg_.auth_wait_ms;
  u.values["dir"] = "UL";
  return u;
}

// L3-01-O 값 채우기 (15_ §4.6): raise·update에 values(stalls_w·auth_req_w는 마지막 고착 시각 기준 창, uectx는 심각도 창,
// held는 L3-20과 같음, stalls_total = ues_total), raise에 cond·candidates·params·로그 필드. UPDATE 로그에는 uectx가 있을
// 때만 붙인다. clear·end는 공통 골격 그대로(14_ §8.3). hit = 이번에 처리한 고착(헬퍼가 걸림마다 넘긴다) — 마지막 고착 시각의 기준
void AuthStallRule::decorate(int64_t cell, std::size_t from, const AlertUe* hit, std::optional<int64_t> cx,
                             std::optional<int64_t> max_conn, RuleOutput& out) {
  CellState& c = cells_[cell];
  if (hit) c.t_last_stall = hit->t_hit;
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    const int64_t stalls_w = hits_.window(cell);
    e.values["stalls_w"] = stalls_w;
    e.values["stalls_total"] = e.ues_total;
    e.values["auth_req_w"] = auth_req_w(c);
    e.values["held"] = held_.held(cell, raise, e.t);
    e.values["evicted"] = hits_.evicted(cell, raise, e.t);  // 15_ §4.6 (이슈 #44)
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
    e.log_fields = {{"stalls_w", std::to_string(stalls_w)},
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

// 입력 침묵 (14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 진행 중 공격·불확실 경보를 END(input_silent)로 끝낸다 — END t는 각 경보가
// 마지막으로 본 칸. 대기 표시·요청 기록·셀 기록·고착 창은 그대로 — kpm2가 다시 오면 남은 마감이 평소처럼 판정된다(on_session_reset과 다르다)
void AuthStallRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  hits_.end_all("input_silent", out.alerts);
  held_.end_all("input_silent", out.alerts);
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 대기 표시·셀 기록을 모두 버린다
void AuthStallRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  hits_.end_all("session_reset", out.alerts);
  held_.end_all("session_reset", out.alerts);
  marks_.clear();
  requests_.clear();
  stalled_.clear();
  cells_.clear();
  hits_.reset();
  held_.reset();
}

}  // namespace detect
