#pragma once
// 증거 전송 큐 — 스레드 A(탐지)와 스레드 B(전달)가 공유하는 유일한 것 (3_ §7.1 동시성 모델, 1_ NFR-6).
// 크기 고정·스레드 안전(락 기반, Q-29). 넘치면 넣는 쪽(A)이 버린다 — A는 B를 기다리지 않는다.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <string>

namespace detect {

enum class RecordKind { Alert, Evidence, Gap };

// 레코드 하나 = 완성된 JSON 한 줄. 만드는 순간 값을 복사해 두므로, 그 뒤 버퍼 칸이 덮어써져도 바뀌지 않는다 (3_ §7.1)
struct EvidenceRecord {
  RecordKind kind = RecordKind::Evidence;
  std::string alert_id;
  std::string line;
};

class EvidenceQueue {
 public:
  // evidence_max = 큐 안 evidence 수 상한 (queue_max). alert·gap은 상한에 세지 않는다 (3_ §7.1)
  explicit EvidenceQueue(std::size_t evidence_max);

  struct PushResult {
    bool accepted = true;                      // 넣은 레코드가 들어갔는지 (새 evidence를 버렸으면 false)
    std::optional<std::string> dropped_alert;  // 버린 evidence의 alert_id (넣은 것을 버렸으면 그 레코드의 것)
  };

  // 스레드 A. 막히지 않는다
  PushResult push(EvidenceRecord rec);
  // 스레드 B. 레코드가 올 때까지 기다린다. close() 뒤 비면 false
  bool pop(EvidenceRecord& out);
  void close();

  std::size_t size() const;
  std::size_t evidence_count() const;

 private:
  const std::size_t evidence_max_;
  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<EvidenceRecord> q_;
  std::size_t n_evidence_ = 0;
  bool closed_ = false;
};

}  // namespace detect
