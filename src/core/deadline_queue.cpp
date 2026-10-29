#include "detect/deadline_queue.h"

#include <utility>

namespace detect {

void DeadlineQueue::add(Deadline d) {
  d.order = next_order_++;
  const int64_t cell = d.key.cell_id;
  cells_[cell].due.push(std::move(d));
}

void DeadlineQueue::set_clock(int64_t cell, int64_t t) { cells_[cell].clock = t; }

std::optional<int64_t> DeadlineQueue::clock(int64_t cell) const {
  auto it = cells_.find(cell);
  return it == cells_.end() ? std::nullopt : it->second.clock;
}

// 시계가 지난 마감 하나 (14_ §6.1-2). 꺼낸 것을 처리하다 새로 넣은 마감도 이미 지났으면 같은 차례에 꺼낸다
std::optional<Deadline> DeadlineQueue::pop_due(int64_t cell) {
  auto it = cells_.find(cell);
  if (it == cells_.end() || !it->second.clock || it->second.due.empty()) return std::nullopt;
  if (it->second.due.top().at > *it->second.clock) return std::nullopt;
  Deadline d = it->second.due.top();
  it->second.due.pop();
  return d;
}

// 로스 기록 (14_ §6.2). 이 kpm2 창이 로스 창이면 그 방향의 loss_end를 창 끝(t_end_ms)으로, 구간이 끊겼으면 양방향을
// 끊김이 끝난 시각(이 줄의 t_start_ms)으로 올린다. 로스 창은 ① ue_evt_lost에 그 방향이 있음 ② ue_evt_lost가 없거나
// null — 알 수 없으므로 양방향 ③ 구간 끊김 — 양방향. 카운터의 null은 1단계용이라 보지 않는다(14_ §0 결정 7) —
// DL 미관측 모드의 FailCause null을 로스로 읽으면 2단계 '없음' 판정이 모두 영원히 보류된다.
// 진단: ue_evt_lost가 없는 칸, "DL"이 든 칸이 한 셀에서 연속 kDiagStreakSlots칸이면 각각 1회 (14_ §6.2)
DeadlineQueue::LossResult DeadlineQueue::record_loss(const Kpm2& k, bool gap, int64_t seq) {
  CellTime& c = cells_[k.cell_id];
  LossResult r;
  const bool known = k.ue_evt_lost.has_value();
  r.loss.ul = !known || k.ue_evt_lost->ul;
  r.loss.dl = !known || k.ue_evt_lost->dl;
  auto raise_to = [](std::optional<int64_t>& end, int64_t t) {
    if (!end || *end < t) end = t;
  };
  if (r.loss.ul) raise_to(c.loss_end_ul, k.t_end_ms);
  if (r.loss.dl) raise_to(c.loss_end_dl, k.t_end_ms);
  if (gap) {
    raise_to(c.loss_end_ul, k.t_start_ms);
    raise_to(c.loss_end_dl, k.t_start_ms);
    r.loss.ul = r.loss.dl = true;
  }

  c.missing_streak = known ? 0 : c.missing_streak + 1;
  if (c.missing_streak == kDiagStreakSlots)
    r.diags.push_back(Diag{DiagKind::UeEvtLostMissing, k.cell_id, seq,
                           "kpm2 without ue_evt_lost for " + std::to_string(kDiagStreakSlots) +
                               " slots: stage 2 no-answer verdicts are all held"});
  c.dl_streak = known && k.ue_evt_lost->dl ? c.dl_streak + 1 : 0;
  if (c.dl_streak == kDiagStreakSlots)
    r.diags.push_back(Diag{DiagKind::DlUnobserved, k.cell_id, seq,
                           "ue_evt_lost has DL for " + std::to_string(kDiagStreakSlots) +
                               " slots: verdicts waiting for DL are all held"});
  return r;
}

bool DeadlineQueue::held(int64_t cell, Dir dir, int64_t t_from) const {
  const std::optional<int64_t> end = loss_end(cell, dir);
  return end && *end > t_from;
}

std::optional<int64_t> DeadlineQueue::loss_end(int64_t cell, Dir dir) const {
  auto it = cells_.find(cell);
  if (it == cells_.end()) return std::nullopt;
  return dir == Dir::UL ? it->second.loss_end_ul : it->second.loss_end_dl;
}

std::size_t DeadlineQueue::size() const {
  std::size_t n = 0;
  for (const auto& [_, c] : cells_) n += c.due.size();
  return n;
}

void DeadlineQueue::clear() {
  cells_.clear();
  next_order_ = 0;
}

}  // namespace detect
