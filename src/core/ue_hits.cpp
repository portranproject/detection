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

bool HitWindow::hit(const UeId& id, AlertUe u) {
  if (conns_.count(id)) return false;
  const int64_t cell = id.first.cell_id;
  conns_[id] = Conn{cell, false};
  cells_[cell].fresh.push_back(Hit{id, std::move(u), {}});
  return true;
}

bool HitWindow::hit_before(const UeId& id) const { return conns_.count(id) > 0; }

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

void HitWindow::on_close(const UeState& last) {
  const UeId id{last.key, last.uid};
  auto it = conns_.find(id);
  if (it == conns_.end()) return;
  for (Hit& h : cells_[it->second.cell].fresh)
    if (h.id == id) refresh(h.u, last);
  conns_.erase(it);
}

// 경보에 실림 — 쌓아 둔 누적 수를 경보 값에 더하고, 그 뒤 누적 수는 바로 더하게 표시한다. 해제 기준 시각을 올린다
void HitWindow::include(Cell& c, const Hit& h) {
  for (const auto& [name, n] : h.acc) c.counts[name] += n;
  if (auto it = conns_.find(h.id); it != conns_.end()) it->second.in_alert = true;
  c.t_hit_last = std::max(c.t_hit_last, h.u.t_hit);
}

// 셀 kpm2 (21_ §1.1·§3.3-3·§3.5): 이번 걸림마다 창 (t_hit − W, t_hit]을 맞추고 걸린 연결 수 ≥ N이면 성립 — 경보가 없으면 창 안
// 걸림 전부로 RAISE(누적 수는 처음부터), 경보 중이면 새 걸림을 UPDATE로 모은다(alert.update_min_ms). 심각도는 4단계 기본 medium
// (21_ §1). 해제는 경보에 실린 마지막 걸림 뒤 clear_quiet_ms, 직전 clear_quiet_ms 동안 밀어내기가 있으면 풀지 않는다(Q-56)
void HitWindow::tick(int64_t cell, int64_t t, bool input_lost, const UeRuleCtx& ctx, std::vector<AlertEvent>& out,
                     const Decorate& fn) {
  Cell& c = cells_[cell];
  note_evictions(c, cell, t, ctx);
  std::size_t from = out.size();
  if (input_lost) book_.end(cell, t, "input_lost", out);
  fn(from);

  for (Hit& h : c.fresh) {
    if (const UeState* s = ctx.table.find(h.id.first); s && s->uid == h.id.second) refresh(h.u, *s);
    c.win.push_back(h);
    while (c.win.front().u.t_hit <= h.u.t_hit - window_ms_) c.win.pop_front();
    from = out.size();
    if (book_.open(cell)) {
      include(c, h);
      book_.add(cell, std::vector<AlertUe>{h.u}, Severity::Medium, t, ctx.session, ctx.seq, out);
    } else if (static_cast<int64_t>(c.win.size()) >= n_) {
      c.counts.clear();  // 새 경보 — 누적 수를 처음부터 센다
      c.evicted_open = 0;
      std::vector<AlertUe> ues;
      for (const Hit& w : c.win) {
        include(c, w);
        ues.push_back(w.u);
      }
      book_.add(cell, std::move(ues), Severity::Medium, t, ctx.session, ctx.seq, out);
    }
    fn(from);
  }
  c.fresh.clear();

  from = out.size();
  book_.flush(cell, t, out);
  if (book_.open(cell) && t - c.t_hit_last >= clear_quiet_ms_ && evicted_window(c, t) == 0) book_.clear(cell, t, out);
  fn(from);
}

void HitWindow::reset() {
  cells_.clear();
  conns_.clear();
}

int64_t HitWindow::window(int64_t cell) const {
  auto it = cells_.find(cell);
  return it == cells_.end() ? 0 : static_cast<int64_t>(it->second.win.size());
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
