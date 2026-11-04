#include "detect/ue_held.h"

#include <string>
#include <utility>

namespace detect {

// ---- EvictWindow (14_ §6.3, Q-56 해결 — 이슈 #44) ----

void EvictWindow::note(int64_t cell, int64_t t, bool alert_open, const UeRuleCtx& ctx) {
  Cell& c = cells_[cell];
  window(cell, t);
  const int64_t total = ctx.table.counts(cell).evicted;
  for (; c.seen < total; ++c.seen) {
    c.times.push_back(t);
    if (alert_open) ++c.open;
  }
}

int64_t EvictWindow::window(int64_t cell, int64_t now) {
  Cell& c = cells_[cell];
  while (!c.times.empty() && c.times.front() <= now - clear_quiet_ms_) c.times.pop_front();
  return static_cast<int64_t>(c.times.size());
}

int64_t EvictWindow::open(int64_t cell) const {
  auto it = cells_.find(cell);
  return it == cells_.end() ? 0 : it->second.open;
}

void EvictWindow::reset_open(int64_t cell) { cells_[cell].open = 0; }

std::size_t EvictWindow::times_size(int64_t cell) const {
  auto it = cells_.find(cell);
  return it == cells_.end() ? 0 : it->second.times.size();
}

// ---- HeldBook (14_ §6.2) ----

HeldBook::HeldBook(Spec spec, AlertConfig alert)
    : spec_(std::move(spec)), alert_(alert), book_(spec_.rule, alert, "anomaly", spec_.stage) {}

// 보류 (14_ §6.2): 공격 경보 중이면 values.held로만, 아니면 불확실 경보용으로 적어 둔다 — 이슈 #48
void HeldBook::hold(int64_t cell, int64_t now, bool attack_open, std::optional<AlertUe> u) {
  Cell& c = cells_[cell];
  ++total_;
  c.held_times.push_back(now);
  if (attack_open) ++c.held_open;
  else if (alert_.held_alert && u) c.fresh.push_back(std::move(*u));
}

// 불확실 경보 (14_ §6.2 — Q-58 ② 해결, 이슈 #48): 보류 UE마다 창 (t_hit − W, t_hit] 안 보류 수 H_W. 공격 경보가 없으면 H_W ≥ N에서
// 창 안 보류 UE로 RAISE(kind anomaly), 불확실 경보 중이면 그 UE를 UPDATE로 모은다. 공격 경보가 이 칸에서 열렸으면 held_open으로만.
// 마지막 보류 뒤 clear_quiet_ms면 CLEAR, input_lost면 END. 창 밖 정리는 불확실 경보가 없을 때만 — 경보 중에는 값의 기준이 마지막 보류다
void HeldBook::tick(int64_t cell, int64_t t, bool input_lost, bool attack_open, const UeRuleCtx& ctx,
                    std::vector<AlertEvent>& out) {
  Cell& c = cells_[cell];
  window(c, t);
  const std::size_t from = out.size();
  if (input_lost) book_.end(cell, t, "input_lost", out);
  for (AlertUe& u : c.fresh) {
    c.ues.push_back(u);
    while (c.ues.front().t_hit <= u.t_hit - spec_.window_ms) c.ues.pop_front();
    c.t_last = u.t_hit;
    if (attack_open) {
      ++c.held_open;
      continue;
    }
    const bool sat = static_cast<int64_t>(c.ues.size()) >= spec_.n;
    if (book_.open(cell)) {
      std::vector<AlertUe> one;
      one.push_back(std::move(u));
      book_.add(cell, std::move(one), Severity::Medium, t, ctx.session, ctx.seq, out);
    } else if (sat) {
      book_.add(cell, std::vector<AlertUe>(c.ues.begin(), c.ues.end()), Severity::Medium, t, ctx.session, ctx.seq,
                out);
    }
  }
  c.fresh.clear();
  book_.flush(cell, t, out);
  if (book_.open(cell) && t - c.t_last >= spec_.clear_quiet_ms) book_.clear(cell, t, out);
  decorate(from, out);
  if (!book_.open(cell))
    while (!c.ues.empty() && c.ues.front().t_hit <= t - spec_.window_ms) c.ues.pop_front();
}

// 공격 경보가 RAISE되기 직전 — 열린 불확실 경보를 같은 줄에서 먼저 CLEAR한다 (14_ §8.2)
void HeldBook::close(int64_t cell, int64_t t, std::vector<AlertEvent>& out) {
  if (!book_.open(cell)) return;
  const std::size_t from = out.size();
  book_.clear(cell, t, out);
  decorate(from, out);
}

void HeldBook::new_attack_alert(int64_t cell) { cells_[cell].held_open = 0; }

int64_t HeldBook::held(int64_t cell, bool raise, int64_t now) {
  Cell& c = cells_[cell];
  return raise ? window(c, now) : c.held_open;
}

int64_t HeldBook::held_w(int64_t cell) const {
  auto it = cells_.find(cell);
  return it == cells_.end() ? 0 : static_cast<int64_t>(it->second.ues.size());
}

// raise의 held — 직전 clear_quiet_ms 동안 보류된 판정 수. 경보가 없을 때도 셀별 이동 창으로 센다 (15_ §2.6)
int64_t HeldBook::window(Cell& c, int64_t now) const {
  while (!c.held_times.empty() && c.held_times.front() <= now - spec_.clear_quiet_ms) c.held_times.pop_front();
  return static_cast<int64_t>(c.held_times.size());
}

// 불확실 경보 값 채우기 (14_ §6.2): raise·update에 values.held_w(창 안 보류 수), raise에 cond held_count·candidates(이 룰)·
// params·로그 필드(맨 앞 kind=anomaly, held_w, 그 뒤 룰 필드). update 로그에는 kind=anomaly만. conditions·branch는 싣지 않는다 —
// 공격 판정이 아니다(20_ §3.7·§4.7, 15_ §5.7)
void HeldBook::decorate(std::size_t from, std::vector<AlertEvent>& out) {
  for (std::size_t i = from; i < out.size(); ++i) {
    AlertEvent& e = out[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const int64_t held_w = this->held_w(e.cell_id);
    e.values["held_w"] = held_w;
    if (e.kind != AlertEventKind::Raise) {
      e.log_fields = {{"kind", "anomaly"}};
      continue;
    }
    e.cond = {"held_count"};
    e.candidates = {spec_.rule};
    for (const auto& [k, v] : spec_.params.items()) e.params[k] = v;
    e.log_fields = {{"kind", "anomaly"}, {"held_w", std::to_string(held_w)}};
    e.log_fields.insert(e.log_fields.end(), spec_.log_fields.begin(), spec_.log_fields.end());
  }
}

}  // namespace detect
