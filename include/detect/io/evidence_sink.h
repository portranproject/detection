#pragma once
// 증거 전달 스레드 B (3_ §7.1 동시성 모델): 큐에서 꺼내 JSON Lines 파일에 한 줄씩 쓴다.
// 대시보드 전달 방식이 정해지면(Q-19) 이 부분만 바꾼다.

#include "detect/evidence_queue.h"

#include <atomic>
#include <cstddef>
#include <fstream>
#include <string>
#include <thread>

namespace detect {

class EvidenceSink {
 public:
  EvidenceSink(EvidenceQueue& queue, std::string path);
  ~EvidenceSink();

  EvidenceSink(const EvidenceSink&) = delete;
  EvidenceSink& operator=(const EvidenceSink&) = delete;

  // 파일을 이어 쓰기로 열고(결정 F8) 스레드를 띄운다. 열지 못하면 false
  bool start();
  // 큐를 닫고, 남은 레코드를 다 쓴 뒤 스레드를 끝낸다
  void stop();

  std::size_t written() const { return written_.load(); }

 private:
  void run();

  EvidenceQueue& queue_;
  std::string path_;
  std::ofstream out_;
  std::thread th_;
  std::atomic<std::size_t> written_{0};
};

}  // namespace detect
