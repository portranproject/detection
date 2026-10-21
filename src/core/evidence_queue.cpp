#include "detect/evidence_queue.h"

#include <utility>

namespace detect {

EvidenceQueue::EvidenceQueue(std::size_t evidence_max) : evidence_max_(evidence_max) {}

// 생산자 측 드롭 (3_ §7.1):
//  - alert·gap은 상한과 관계없이 넣고 버리지 않는다
//  - evidence가 상한에 닿았으면 큐 안 가장 오래된 evidence를 버리고 넣는다
//  - 버릴 evidence가 없으면(상한 0 등) 새로 넣으려는 evidence를 버린다
// 임계구역은 deque 조작뿐이라 짧다 — 스레드 A가 멈추는 일은 사실상 없다 (Q-29)
EvidenceQueue::PushResult EvidenceQueue::push(EvidenceRecord rec) {
  PushResult r;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (rec.kind == RecordKind::Evidence && n_evidence_ >= evidence_max_) {
      bool removed = false;
      for (auto it = q_.begin(); it != q_.end(); ++it) {
        if (it->kind == RecordKind::Evidence) {
          r.dropped_alert = it->alert_id;
          q_.erase(it);
          --n_evidence_;
          removed = true;
          break;
        }
      }
      if (!removed) {
        r.accepted = false;
        r.dropped_alert = rec.alert_id;
        return r;
      }
    }
    if (rec.kind == RecordKind::Evidence) ++n_evidence_;
    q_.push_back(std::move(rec));
  }
  cv_.notify_one();
  return r;
}

bool EvidenceQueue::pop(EvidenceRecord& out) {
  std::unique_lock<std::mutex> lk(mu_);
  cv_.wait(lk, [&] { return !q_.empty() || closed_; });
  if (q_.empty()) return false;
  out = std::move(q_.front());
  q_.pop_front();
  if (out.kind == RecordKind::Evidence) --n_evidence_;
  return true;
}

void EvidenceQueue::close() {
  {
    std::lock_guard<std::mutex> lk(mu_);
    closed_ = true;
  }
  cv_.notify_all();
}

std::size_t EvidenceQueue::size() const {
  std::lock_guard<std::mutex> lk(mu_);
  return q_.size();
}

std::size_t EvidenceQueue::evidence_count() const {
  std::lock_guard<std::mutex> lk(mu_);
  return n_evidence_;
}

}  // namespace detect
