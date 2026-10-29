#include "detect/rules/blind_dos.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <string>
#include <utility>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

// 망 수락 (15_ §1.1): RegistrationAccept·ServiceAccept로 nas가 REGISTERED, 또는 RRC SecurityModeCommand로 rrc_sec이
// CMD·ON. gNB는 AMF가 보안 키를 내려 준 — 받아들인 — 연결에만 AS 보안 모드를 걸고, RRC SMC는 AS 암호를 켜기 전에 보내므로
// NAS 암호가 켜져도 보인다
bool accepted(const UeState& s) {
  return s.nas == NasState::Registered || s.rrc_sec == RrcSecState::Cmd || s.rrc_sec == RrcSecState::On;
}

// 짝의 확실성 (15_ §2.3, 10/29 검수 B4): 불확실 표시가 없거나, loss뿐이고 마지막 로스 창 뒤에 줄이 있으면 확실하다 —
// 해제 줄을 놓친 유령은 로스 뒤에 줄을 낼 수 없다
bool certain(const UeState& p) {
  if (p.mid_join || p.late) return false;
  return !p.loss || (p.t_loss && p.t_last > *p.t_loss);
}

// n의 NAS 요청 (15_ §2.6 ues[].values.nas): cnt에 있는 것, 여럿이면 이 순서로 하나 (10/29 이슈 #27)
std::optional<std::string> nas_request(const UeState& s) {
  for (const char* m : {"ServiceRequest", "RegistrationRequest", "DeregistrationRequest"})
    if (s.count(Proto::NAS, m) > 0) return std::string(m);
  return std::nullopt;
}

// 후보 (15_ §2.6): 새 연결의 NAS로 정한다. '같은 S-TMSI 두 세션'을 함께 쓰는 3단계 L3-19-Va·L3-23-O와 위조 등록 L3-21
std::vector<std::string> candidates_for(const ojson& nas) {
  if (nas.is_null()) return {"L3-19-Va", "L3-23-O"};
  const std::string& m = nas.get_ref<const std::string&>();
  if (m == "ServiceRequest") return {};
  if (m == "RegistrationRequest") return {"L3-19-Va", "L3-21"};
  return {"L3-23-O", "L3-19-Va"};  // DeregistrationRequest
}

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

std::string hex48(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%012" PRIx64, v);
  return buf;
}

std::vector<std::string> uncertain_reasons(const UeState& s) {
  std::vector<std::string> r;
  if (s.mid_join) r.emplace_back("mid_join");
  if (s.loss) r.emplace_back("loss");
  if (s.late) r.emplace_back("late");
  return r;
}

}  // namespace

BlindDosRule::BlindDosRule(BlindDosConfig cfg, AlertConfig alert) : cfg_(cfg), alert_(alert), book_(kId, alert) {}

// 증거 지평 (14_ §1.1): 수락 대기 + UPDATE 모음 지연 — 마감 전에 닫힌 n이 걸려 UPDATE로 실릴 때까지 recent가 남게
int64_t BlindDosRule::evidence_horizon_ms() const { return cfg_.accept_wait_ms + alert_.update_min_ms; }

// ue_evt 한 줄 (15_ §2.3 '기다리는 동안'·'기다림 시작'):
//  1) 짝에 UEContextReleaseCommand가 왔다 — 그 짝을 가진 표시에 피해 확정
//  2) n이 망 수락을 얻은 줄 — 마감 전이면 대기를 푼다. 마감 이후(늦은 수락)면 그대로 두고 마감 때 판정한다 (14_ §6.1-5)
//  3) n의 s_tmsi가 정해지거나 바뀐 줄이 t₀ — 옛 표시를 버리고 기다림을 (다시) 시작한다
void BlindDosRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                               RuleOutput&) {
  const UeId id{after.key, after.uid};
  if (evt.proto == Proto::F1AP && evt.dir == Dir::DL && evt.msg == "UEContextReleaseCommand") mark_victim(id);
  if (auto it = marks_.find(id);
      it != marks_.end() && accepted(after) && !accepted(before) && evt.t_ms < it->second.deadline)
    drop(id);
  if (after.s_tmsi && after.s_tmsi != before.s_tmsi) {
    drop(id);
    start(after, evt.t_ms, ctx);
  }
}

// 기다림 시작 (15_ §2.3 1~4): n이 mid_join이거나 이미 망 수락이면 시작하지 않는다. 같은 S-TMSI의 다른 열린 연결(짝)이
// 없으면 시작하지 않는다 — IDLE형이거나 피해자의 S-TMSI를 모르는 경우다(15_ §2.1·§2.7). 확실한 짝이 하나라도 있으면
// concurrent, 모두 불확실하면 peer_uncertain — 짝이 해제 줄을 놓친 유령일 수 있어 '동시'를 확정하지 못하기 때문이다
void BlindDosRule::start(const UeState& n, int64_t t0, const UeRuleCtx& ctx) {
  if (n.mid_join || accepted(n)) return;
  Mark m;
  for (const UeState* p : ctx.table.by_s_tmsi(*n.s_tmsi)) {
    if (p->key == n.key && p->uid == n.uid) continue;
    m.peers.emplace_back(p->key, p->uid);
    m.concurrent = m.concurrent || certain(*p);
  }
  if (m.peers.empty()) return;
  m.s_tmsi = *n.s_tmsi;
  m.t_from = t0;
  m.deadline = t0 + cfg_.accept_wait_ms;
  const UeId id{n.key, n.uid};
  for (const UeId& p : m.peers) by_peer_[p].insert(id);
  ctx.add_deadline(m.deadline, n.key, n.uid, "accept", Dir::DL, t0);  // 수락 근거가 모두 DL (15_ §1.1)
  marks_[id] = std::move(m);
}

void BlindDosRule::drop(const UeId& id) {
  auto it = marks_.find(id);
  if (it == marks_.end()) return;
  for (const UeId& p : it->second.peers) {
    auto bp = by_peer_.find(p);
    if (bp == by_peer_.end()) continue;
    bp->second.erase(id);
    if (bp->second.empty()) by_peer_.erase(bp);
  }
  marks_.erase(it);
}

// 피해 확정 (15_ §2.3): 그 짝을 가진 표시에 적는다. 판정한 표시는 이미 지웠으므로 판정 뒤의 해제는 반영되지 않는다
void BlindDosRule::mark_victim(const UeId& peer) {
  auto bp = by_peer_.find(peer);
  if (bp == by_peer_.end()) return;
  for (const UeId& id : bp->second)
    if (auto it = marks_.find(id); it != marks_.end()) it->second.victim_released = true;
}

// 항목이 닫힘 (15_ §1·§2.3, 14_ §2.4):
//  - 짝이 released로 닫히면 피해 확정. 닫힌 짝에는 더 줄이 없으므로 역색인에서 뺀다
//  - n이 마감 전에 released·reused·stale_setup으로 닫히면 표시를 남기고 닫힐 때 상태를 복사한다 — 마감 전에 닫혔다는 것은
//    수락 없이 끝났다는 뜻이고, 판정을 마감까지 미루는 것은 닫힌 줄이 든 창의 로스 여부가 그 창 kpm2가 와야 정해지기 때문이다
//  - du_reset·evicted·superseded·session_reset이면 표시를 지운다
void BlindDosRule::on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx&, RuleOutput&) {
  const UeId id{last.key, last.uid};
  if (reason == CloseReason::Released) mark_victim(id);
  by_peer_.erase(id);
  auto it = marks_.find(id);
  if (it == marks_.end()) return;
  if (reason == CloseReason::Released || reason == CloseReason::Reused || reason == CloseReason::StaleSetup) {
    it->second.closed = last;
    it->second.closed_at = t;
  } else {
    drop(id);
  }
}

// 성립 (15_ §2.3): 마감을 처리하는 그 셀 kpm2에서 — 표시가 그대로(uid·t_from)이고 마감 전 수락이 없고(있었으면 표시를
// 지웠다), 대기 구간에 DL 로스가 없고(있으면 보류 — 14_ §6.2), n이 mid_join·late가 아니면(14_ §4.3) 걸린다
void BlindDosRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) {
  const UeId id{d.key, d.uid};
  auto it = marks_.find(id);
  if (it == marks_.end() || it->second.t_from != d.t_from) return;
  const Mark m = it->second;
  drop(id);
  const int64_t cell = d.key.cell_id;
  const int64_t now = ctx.deadlines.clock(cell).value_or(d.at);
  if (ctx.deadlines.held(cell, Dir::DL, m.t_from)) {
    CellState& c = cells_[cell];
    c.held_times.push_back(now);
    if (book_.open(cell)) ++c.held_open;
    return;
  }
  const UeState* n = ctx.table.find(d.key);
  if (!n || n->uid != d.uid) n = m.closed ? &*m.closed : nullptr;
  if (!n || n->mid_join || n->late) return;
  hit(m, *n, d.at, now, ctx, out);
}

// 걸린 UE (15_ §2.3 표·§2.6): concurrent면 피해 확정일 때 high, 아니면 medium. peer_uncertain은 짝이 유령일 수 있어
// 늘 medium이다. 걸린 n만 ues에 싣고 짝은 peers로만 가리킨다 — 짝의 recent까지 내면 경보당 증거 UE 상한을 두 배로 쓴다.
// 경보의 t는 그 마감을 처리한 kpm2의 t_end_ms, t_hit는 마감이다
void BlindDosRule::hit(const Mark& m, const UeState& n, int64_t t_hit, int64_t now, const UeRuleCtx& ctx,
                       RuleOutput& out) {
  const int64_t cell = n.key.cell_id;
  CellState& c = cells_[cell];
  if (!book_.open(cell)) {  // 새 경보 — 누적값을 처음부터 센다
    c.concurrent = 0;
    c.peer_uncertain = 0;
    c.victims.clear();
    c.held_open = 0;
  }
  ++(m.concurrent ? c.concurrent : c.peer_uncertain);
  const int64_t repeat = ++c.victims[m.s_tmsi];
  c.t_hit_last = t_hit;

  AlertUe u;
  u.cell = cell;
  u.du_ue_id = n.key.du_ue_id;
  u.uid = n.uid;
  u.cu_ue_id = n.cu_ue_id;
  u.crnti = n.crnti;
  u.s_tmsi = m.s_tmsi;
  u.cond = {"same_stmsi", m.concurrent ? "concurrent" : "peer_uncertain", "not_accepted"};
  u.t_hit = t_hit;
  const std::optional<std::string> nas = nas_request(n);
  u.values["peer"] = m.concurrent ? "concurrent" : "peer_uncertain";
  u.values["nas"] = nas ? ojson(*nas) : ojson(nullptr);
  u.values["wait_ms"] = cfg_.accept_wait_ms;
  u.values["closed_ms"] = m.closed_at ? ojson(*m.closed_at - m.t_from) : ojson(nullptr);
  u.values["victim_released"] = m.victim_released;
  u.values["repeat"] = repeat;
  u.uncertain = uncertain_reasons(n);
  for (const UeId& p : m.peers) u.peers.push_back({p.first.cell_id, p.first.du_ue_id, p.second});

  const Severity sev = m.concurrent && m.victim_released ? Severity::High : Severity::Medium;
  const std::size_t from = out.alerts.size();
  std::vector<AlertUe> ues;
  ues.push_back(std::move(u));
  book_.add(cell, std::move(ues), sev, now, ctx.session, ctx.seq, out.alerts);
  decorate(from, out);
}

// L3-20 값 채우기 (15_ §2.6): raise·update에 values(경보가 열린 뒤 누적), raise에 cond(RAISE를 일으킨 UE의 것)·
// candidates(실린 UE들의 후보 합)·params·로그 필드. clear·end는 공통 골격 그대로(14_ §8.3 — values는 raise·update만)
void BlindDosRule::decorate(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    CellState& c = cells_[e.cell_id];
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["concurrent"] = c.concurrent;
    e.values["peer_uncertain"] = c.peer_uncertain;
    e.values["victims"] = static_cast<int64_t>(c.victims.size());
    e.values["held"] = raise ? held_window(c, e.t) : c.held_open;
    if (!raise || e.ues.empty()) continue;

    const AlertUe& u = e.ues.front();
    e.cond = u.cond;
    for (const AlertUe& x : e.ues)
      for (const std::string& cand : candidates_for(x.values.at("nas")))
        if (std::find(e.candidates.begin(), e.candidates.end(), cand) == e.candidates.end())
          e.candidates.push_back(cand);
    e.params["accept_wait_ms"] = cfg_.accept_wait_ms;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (15_ §2.6): ue=·peers=는 cell/du_ue_id/uid, 짝이 여럿이면 ','. nas가 없으면 null, 피해 확정은 1·0
    std::string peers;
    for (const auto& p : u.peers) peers += (peers.empty() ? "" : ",") + ue_name(p[0], p[1], p[2]);
    const ojson& nas = u.values.at("nas");
    e.log_fields = {{"peer", u.values.at("peer").get<std::string>()},
                    {"ue", ue_name(u.cell, u.du_ue_id, u.uid)},
                    {"s_tmsi", hex48(*u.s_tmsi)},
                    {"peers", peers},
                    {"nas", nas.is_null() ? std::string("null") : nas.get<std::string>()},
                    {"wait_ms", std::to_string(cfg_.accept_wait_ms)},
                    {"victim_released", u.values.at("victim_released").get<bool>() ? "1" : "0"}};
  }
}

// raise의 held — 직전 clear_quiet_ms 동안 보류된 판정 수. 경보가 없을 때도 셀별 이동 창으로 센다 (15_ §2.6)
int64_t BlindDosRule::held_window(CellState& c, int64_t now) const {
  while (!c.held_times.empty() && c.held_times.front() <= now - cfg_.clear_quiet_ms) c.held_times.pop_front();
  return static_cast<int64_t>(c.held_times.size());
}

// 셀 kpm2마다 (15_ §2.5): input_lost면 진행 중 경보를 END, 모아 둔 UE를 UPDATE 간격에 맞춰 내고, 마지막 걸림 뒤
// clear_quiet_ms가 지나면 CLEAR — 걸린 연결이 아직 열려 있어도 푼다(해제 줄을 놓친 연결 때문에 경보가 안 풀리는 일을 막는다).
// 보류는 걸림으로 세지 않으므로 해제를 막지 않는다 (15_ §1)
void BlindDosRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx&,
                                RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  const std::size_t from = out.alerts.size();
  if (input_lost) book_.end(cell, t, "input_lost", out.alerts);
  book_.flush(cell, t, out.alerts);
  if (book_.open(cell) && t - cells_[cell].t_hit_last >= cfg_.clear_quiet_ms) book_.clear(cell, t, out.alerts);
  decorate(from, out);
  if (auto it = cells_.find(cell); it != cells_.end()) held_window(it->second, t);
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 대기 표시·누적값을 모두 버린다
void BlindDosRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  book_.end_all("session_reset", out.alerts);
  marks_.clear();
  by_peer_.clear();
  cells_.clear();
}

}  // namespace detect
