#include "detect/ue_hits.h"

#include <algorithm>
#include <utility>

namespace detect {
namespace {

// 식별·uncertain만 상태 항목에서 다시 채우고, 룰이 걸릴 때 채운 값(cond·t_hit·values 등)은 그대로 둔다
void refresh(AlertUe& u, const UeState& s) {
  AlertUe r = alert_ue(s);
  r.cond = std::move(u.cond);
  r.t_hit = u.t_hit;
  r.values = std::move(u.values);
  r.peers = std::move(u.peers);
  r.conditions = std::move(u.conditions);
  u = std::move(r);
}

}  // namespace

HitWindow::HitWindow(std::string rule, AlertConfig alert, int64_t window_ms, int64_t n, int64_t clear_quiet_ms)
    : window_ms_(window_ms), n_(n), clear_quiet_ms_(clear_quiet_ms), book_(std::move(rule), alert, "anomaly", 4) {}

bool HitWindow::hit(const UeId& id, AlertUe u, bool force, std::optional<UeId> ref) {
  if (conns_.count(id)) return false;
  const int64_t cell = id.first.cell_id;
  conns_[id] = Conn{cell, false};
  cells_[cell].fresh.push_back(Hit{id, ref.value_or(id), std::move(u), {}, force});
  return true;
}

bool HitWindow::hit_before(const UeId& id) const { return conns_.count(id) > 0; }

// 회복 전 반복 (21_ §1.1·§6.5·§7.5·§8.5 — 11/04 Q-69 (가), 이슈 #86): 그 키를 실은 경보가 열려 있을 때만 해제 기준을 올린다.
// t_hit_last(기본 해제 기준)와 t_sat(clear_on_satisfied — AN-08) 둘 다 — 어느 기준이든 '그 키가 마지막으로 반복한 시각'이 된다
void HitWindow::touch(const UeId& id, int64_t t) {
  auto it = conns_.find(id);
  if (it == conns_.end() || !it->second.in_alert || !book_.open(it->second.cell)) return;
  Cell& c = cells_[it->second.cell];
  c.t_hit_last = std::max(c.t_hit_last, t);
  c.t_sat = std::max(c.t_sat, t);
}

bool HitWindow::active(const UeId& id) const {
  auto it = conns_.find(id);
  if (it == conns_.end()) return false;
  return !it->second.in_alert || book_.open(it->second.cell);
}

void HitWindow::add(const UeId& id, const std::string& name, int64_t n) {
  auto it = conns_.find(id);
  if (it == conns_.end()) return;
  Cell& c = cells_[it->second.cell];
  if (it->second.in_alert) {
    if (book_.open(it->second.cell)) c.counts[name] += n;
    return;
  }
  for (Hit& h : c.fresh)
    if (h.id == id) h.acc[name] += n;
  for (Hit& h : c.win)
    if (h.id == id) h.acc[name] += n;
}

// 아직 kpm2를 거치지 않은 걸림 가운데 이 연결을 가리키는 것(ref)은 마지막 상태로 식별·uncertain을 채운다. 걸림 키가 연결이면
// 연결 기록도 지운다 — S-TMSI 키(AN-08)는 룰이 회복 때 forget으로 지운다
void HitWindow::on_close(const UeState& last) {
  const UeId id{last.key, last.uid};
  if (auto c = cells_.find(last.key.cell_id); c != cells_.end())
    for (Hit& h : c->second.fresh)
      if (h.ref == id) refresh(h.u, last);
  conns_.erase(id);
}

// 경보에 실림 — 쌓아 둔 누적 수를 경보 값에 더하고, 그 뒤 누적 수는 바로 더하게 표시한다. 해제 기준 시각을 올린다
void HitWindow::include(Cell& c, const Hit& h) {
  for (const auto& [name, n] : h.acc) c.counts[name] += n;
  if (auto it = conns_.find(h.id); it != conns_.end()) it->second.in_alert = true;
  c.t_hit_last = std::max(c.t_hit_last, h.u.t_hit);
}

// 셀 kpm2 (21_ §1.1·§3.3-3·§3.5·§5.3): 이번 걸림마다 창 (t_hit − W, t_hit]을 맞추고 걸린 연결 수 ≥ N이거나 force 걸림이면
// 성립 — 경보가 없으면 창 안 걸림 전부로 RAISE(누적 수는 처음부터), 경보 중이면 새 걸림을 UPDATE로 모은다(alert.update_min_ms).
// 심각도는 4단계 기본 medium(21_ §1). 해제는 경보에 실린 마지막 걸림(clear_on_satisfied면 마지막 성립) 뒤 clear_quiet_ms,
// 직전 clear_quiet_ms 동안 밀어내기가 있으면 풀지 않는다(Q-56)
void HitWindow::tick(int64_t cell, int64_t t, bool input_lost, const UeRuleCtx& ctx, std::vector<AlertEvent>& out,
                     const Decorate& fn) {
  Cell& c = cells_[cell];
  note_evictions(c, cell, t, ctx);
  std::size_t from = out.size();
  const bool ended = input_lost && book_.open(cell);
  if (ended) book_.end(cell, t, "input_lost", out);
  fn(from, nullptr);  // END에도 누적값 (14_ §8.3 — 11/04 Q-69 W-28)
  if (ended) forget_window(c);

  for (Hit& h : c.fresh) {
    if (const UeState* s = ctx.table.find(h.ref.first); s && s->uid == h.ref.second) refresh(h.u, *s);
    c.win.push_back(h);
    while (c.win.front().u.t_hit <= h.u.t_hit - window_ms_) c.win.pop_front();
    const bool sat = h.force || static_cast<int64_t>(c.win.size()) >= n_;
    if (sat) c.t_sat = std::max(c.t_sat, h.u.t_hit);
    from = out.size();
    if (book_.open(cell)) {
      include(c, h);
      book_.add(cell, std::vector<AlertUe>{h.u}, Severity::Medium, t, ctx.session, ctx.seq, out);
    } else if (sat) {
      c.counts.clear();  // 새 경보 — 누적 수를 처음부터 센다
      c.evicted_open = 0;
      std::vector<AlertUe> ues;
      for (const Hit& w : c.win) {
        include(c, w);
        ues.push_back(w.u);
      }
      book_.add(cell, std::move(ues), Severity::Medium, t, ctx.session, ctx.seq, out);
    }
    fn(from, &h.u);  // 이번 걸림 — 식별·uncertain을 다시 채운 뒤 (이슈 #84)
  }
  c.fresh.clear();

  from = out.size();
  book_.flush(cell, t, out);
  const int64_t base = clear_on_satisfied_ ? c.t_sat : c.t_hit_last;
  const bool cleared = book_.open(cell) && t - base >= clear_quiet_ms_ && evicted_window(c, t) == 0;
  if (cleared) book_.clear(cell, t, out);
  fn(from, nullptr);  // 모아 둔 UPDATE·CLEAR — 창을 비우기 전에 채운다(UPDATE의 창 안 수, CLEAR의 누적값 — 14_ §8.3)
  if (cleared) forget_window(c);
}

// CLEAR·END 뒤 (23_ §3.1-2, 이슈 #84): 창과 해제 기준을 비운다 — 새 경보는 그 뒤 걸림만 싣고 창 안 수(window)도 새로 센다. 그전에는 창 W가
// 해제 시간보다 길면(AN-04 기본 300 s > 60 s) CLEAR된 경보의 걸림이 창에 남아 다음 RAISE에 다시 실리고(ues_total 2, 증거 없음) 그 acc도
// 다시 더해졌다. 걸린 연결·키 기록(conns_)은 그대로다 — 연결당·키당 한 번은 유지된다(회복은 룰이 forget으로)
void HitWindow::forget_window(Cell& c) {
  c.win.clear();
  c.t_hit_last = 0;
  c.t_sat = 0;
}

// 모든 셀 END (session_reset·input_silent): 경보가 열려 있던 셀의 창을 비운다 — 경보가 없던 셀의 성립 전 걸림은 그대로 둔다
void HitWindow::end_all(const std::string& reason, std::vector<AlertEvent>& out) {
  for (auto& [cell, c] : cells_)
    if (book_.open(cell)) forget_window(c);
  book_.end_all(reason, out);
}

void HitWindow::reset() {
  cells_.clear();
  conns_.clear();
}

int64_t HitWindow::window(int64_t cell) const {
  auto it = cells_.find(cell);
  return it == cells_.end() ? 0 : static_cast<int64_t>(it->second.win.size());
}

int64_t HitWindow::window_with(int64_t cell, const std::string& cond) const {
  return window_if(cell, [&](const AlertUe& u) { return std::find(u.cond.begin(), u.cond.end(), cond) != u.cond.end(); });
}

int64_t HitWindow::window_if(int64_t cell, const std::function<bool(const AlertUe&)>& pred) const {
  auto it = cells_.find(cell);
  if (it == cells_.end()) return 0;
  return static_cast<int64_t>(
      std::count_if(it->second.win.begin(), it->second.win.end(), [&](const Hit& h) { return pred(h.u); }));
}

int64_t HitWindow::count(int64_t cell, const std::string& name) const {
  auto it = cells_.find(cell);
  if (it == cells_.end()) return 0;
  auto n = it->second.counts.find(name);
  return n == it->second.counts.end() ? 0 : n->second;
}

int64_t HitWindow::evicted(int64_t cell, bool raise, int64_t t) {
  Cell& c = cells_[cell];
  return raise ? evicted_window(c, t) : c.evicted_open;
}

// 상태표 셀별 누적 evicted(14_ §6.3)의 증가분을 이 칸 시각으로 적는다 — 경보가 열려 있으면 evicted_open도
void HitWindow::note_evictions(Cell& c, int64_t cell, int64_t t, const UeRuleCtx& ctx) {
  const int64_t total = ctx.table.counts(cell).evicted;
  for (; c.evicted_seen < total; ++c.evicted_seen) {
    c.evict_times.push_back(t);
    if (book_.open(cell)) ++c.evicted_open;
  }
}

// 직전 clear_quiet_ms 동안의 밀어내기 수 (이동 창) — raise의 values.evicted와 해제 보류 기준
int64_t HitWindow::evicted_window(Cell& c, int64_t now) const {
  while (!c.evict_times.empty() && c.evict_times.front() <= now - clear_quiet_ms_) c.evict_times.pop_front();
  return static_cast<int64_t>(c.evict_times.size());
}

}  // namespace detect
