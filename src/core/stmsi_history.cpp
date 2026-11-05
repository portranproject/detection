#include "detect/stmsi_history.h"

#include "detect/deadline_queue.h"

#include <algorithm>
#include <utility>

namespace detect {

StmsiHistory::StmsiHistory(int64_t tomb_ms, std::size_t tomb_max, int64_t alloc_ms, std::size_t alloc_max)
    : tomb_ms_(tomb_ms), tomb_max_(tomb_max), alloc_ms_(alloc_ms), alloc_max_(alloc_max) {}

// 연결 레코드 (14_ §3.2, 11/03 확인 지점 ⑤ 사용자 확정): 연결 1건 = 레코드 1개. S-TMSI(48비트·Part1)를 둘 다 모르면 넣지 않는다 —
// 같은 UE로 이을 수 없다. 불확실(mid_join·loss·late) 연결도 넣되 표시를 남긴다(결정 ④). 색인은 48비트를 알면 48비트·그 하위
// 39비트 Part1 둘 다, Part1만 알면 Part1만이다(§3.1과 같음). 닫힌 시각 + tomb_ms에 표 몫 마감 tomb으로 지우고, tomb_max를 넘으면
// 오래된 것(먼저 넣은 것)부터 버린다
void StmsiHistory::record(const UeState& s, std::optional<uint64_t> p1, CloseReason reason, int64_t t,
                          DeadlineQueue& dq) {
  if (!s.s_tmsi && !p1) return;
  ConnRecord r;
  r.s_tmsi = s.s_tmsi;
  r.part1 = p1;
  r.src_ue = s.s_tmsi_from_ue;
  r.src_net = s.s_tmsi_from_net;
  r.key = s.key;
  r.uid = s.uid;
  r.t_start = s.t_start;
  r.t_end = t;
  r.reason = reason;
  r.connected = s.ever_connected;
  r.rrc_last = s.rrc;
  r.nas_last = s.nas;
  r.accepted = s.ever_accepted;
  r.rejected = s.count(Proto::RRC, "RRCReject") > 0;
  r.est_cause = s.est_cause;
  r.reg_type = s.reg_type;
  r.id_type = s.id_type;
  r.rel_req_cause = s.rel_req_cause;
  r.mid_join = s.mid_join;
  r.loss = s.loss;
  r.late = s.late;
  const uint64_t order = next_record_++;
  // 같은 (키, uid)는 한 번만 닫히지만, 방어로 옛 것을 먼저 지운다
  if (auto old = record_of_.find({s.key, s.uid}); old != record_of_.end()) erase_record(old->second);
  record_of_[{s.key, s.uid}] = order;
  // 색인 — (t_end, 순서)로 정렬해 둔다. 닫힘은 대개 시각순이라 뒤에 붙는다
  auto put = [&](std::vector<uint64_t>& v) {
    auto pos = std::upper_bound(v.begin(), v.end(), order, [&](uint64_t a, uint64_t b) {
      const int64_t ta = a == order ? t : records_.at(a).t_end;
      const int64_t tb = b == order ? t : records_.at(b).t_end;
      return std::make_pair(ta, a) < std::make_pair(tb, b);
    });
    v.insert(pos, order);
  };
  if (r.s_tmsi) put(hist_s_tmsi_[*r.s_tmsi]);
  if (r.part1) put(hist_part1_[*r.part1]);
  records_.emplace(order, std::move(r));
  while (records_.size() > tomb_max_) erase_record(records_.begin()->first);
  Deadline d;
  d.at = t + tomb_ms_;
  d.key = s.key;
  d.uid = s.uid;
  d.owner = DeadlineQueue::kTableOwner;
  d.tag = kTombTag;
  d.t_from = t;  // 닫힌 시각 — 꺼낼 때 레코드의 t_end와 대조
  dq.add(std::move(d));
}

void StmsiHistory::erase_record(uint64_t order) {
  auto it = records_.find(order);
  if (it == records_.end()) return;
  const ConnRecord& r = it->second;
  auto drop = [&](std::map<uint64_t, std::vector<uint64_t>>& index, uint64_t v) {
    auto ix = index.find(v);
    if (ix == index.end()) return;
    ix->second.erase(std::remove(ix->second.begin(), ix->second.end(), order), ix->second.end());
    if (ix->second.empty()) index.erase(ix);
  };
  if (r.s_tmsi) drop(hist_s_tmsi_, *r.s_tmsi);
  if (r.part1) drop(hist_part1_, *r.part1);
  if (auto id = record_of_.find({r.key, r.uid}); id != record_of_.end() && id->second == order) record_of_.erase(id);
  records_.erase(it);
}

// 할당 기억 (14_ §3.2): RegistrationAccept의 f.s_tmsi → 마지막 할당 시각·셀. 같은 값이 다시 할당되면 시각만 갱신한다.
// 할당 시각 + alloc_ms에 표 몫 마감 alloc으로 지우고(그 사이 다시 할당됐으면 그 마감이 지운다), alloc_max를 넘으면 가장 오래 전에
// 할당된 것부터 버린다. NAS 암호 망에서는 RegistrationAccept가 보이지 않아 비어 있다(§11)
void StmsiHistory::allocate(uint64_t s_tmsi, const UeState& s, int64_t t, DeadlineQueue& dq) {
  if (auto old = allocs_.find(s_tmsi); old != allocs_.end()) alloc_order_.erase(old->second.order);
  const uint64_t order = next_alloc_++;
  allocs_[s_tmsi] = Alloc{t, s.key.cell_id, order};
  alloc_order_[order] = s_tmsi;
  while (allocs_.size() > alloc_max_) {
    auto oldest = alloc_order_.begin();
    allocs_.erase(oldest->second);
    alloc_order_.erase(oldest);
  }
  alloc_due_[{s.key, s.uid, t}] = s_tmsi;
  Deadline d;
  d.at = t + alloc_ms_;
  d.key = s.key;
  d.uid = s.uid;
  d.owner = DeadlineQueue::kTableOwner;
  d.tag = kAllocTag;
  d.t_from = t;  // 할당 시각 — 꺼낼 때 그 S-TMSI의 마지막 할당 시각과 대조
  dq.add(std::move(d));
}

// 표 몫 마감 (14_ §3.2·§6.1 표):
//  - tomb: 연결 레코드 보관이 끝났다 — 그 레코드가 아직 있고 같은 것(닫힌 시각)이면 지운다
//  - alloc: 할당 기억 보관이 끝났다 — 그 S-TMSI의 마지막 할당이 이 마감의 할당과 같으면 지운다(다시 할당됐으면 그 마감이 지운다)
bool StmsiHistory::on_deadline(const Deadline& d) {
  if (d.tag == kTombTag) {
    auto r = record_of_.find({d.key, d.uid});
    if (r != record_of_.end() && records_.at(r->second).t_end == d.t_from) erase_record(r->second);
    return true;
  }
  if (d.tag == kAllocTag) {
    auto due = alloc_due_.find({d.key, d.uid, d.t_from});
    if (due == alloc_due_.end()) return true;
    const uint64_t s_tmsi = due->second;
    alloc_due_.erase(due);
    auto a = allocs_.find(s_tmsi);
    if (a != allocs_.end() && a->second.t == d.t_from) {
      alloc_order_.erase(a->second.order);
      allocs_.erase(a);
    }
    return true;
  }
  return false;
}

void StmsiHistory::clear() {
  records_.clear();
  record_of_.clear();
  hist_s_tmsi_.clear();
  hist_part1_.clear();
  next_record_ = 0;
  allocs_.clear();
  alloc_order_.clear();
  alloc_due_.clear();
  next_alloc_ = 0;
}

std::vector<const ConnRecord*> StmsiHistory::select(const std::map<uint64_t, std::vector<uint64_t>>& index,
                                                    uint64_t v, int64_t since) const {
  std::vector<const ConnRecord*> out;
  auto ix = index.find(v);
  if (ix == index.end()) return out;
  for (uint64_t order : ix->second) {
    const ConnRecord& r = records_.at(order);
    if (r.t_end >= since) out.push_back(&r);
  }
  return out;
}

std::vector<const ConnRecord*> StmsiHistory::history(uint64_t s_tmsi, int64_t since) const {
  return select(hist_s_tmsi_, s_tmsi, since);
}

std::vector<const ConnRecord*> StmsiHistory::history_part1(uint64_t part1, int64_t since) const {
  return select(hist_part1_, part1, since);
}

std::optional<int64_t> StmsiHistory::allocated(uint64_t s_tmsi) const {
  auto it = allocs_.find(s_tmsi);
  return it == allocs_.end() ? std::nullopt : std::optional<int64_t>(it->second.t);
}

std::optional<int64_t> StmsiHistory::allocated_part1(uint64_t part1) const {
  std::optional<int64_t> t;
  for (const auto& [s, a] : allocs_)
    if ((s & kStmsiPart1Mask) == part1 && (!t || a.t > *t)) t = a.t;
  return t;
}

}  // namespace detect
