#pragma once
// 증거 전달 스레드 B (3_ §7.1 동시성 모델): 큐에서 꺼내 JSON Lines 파일에 한 줄씩 쓴다.
// 대시보드 전달 방식이 정해지면(Q-19) 이 부분만 바꾼다.

#include "detect/evidence_queue.h"
#include "detect/io/rotating_file.h"

#include <atomic>
#include <cstddef>
#include <string>
#include <thread>
#include <vector>

namespace detect {

// 11/05 W-33 (이슈 #92, 25_ §3.1-6): ofstream 버퍼 대신 write(2)로 레코드마다 바로 쓴다 — 쓴 수와 쓰기 오류를 정확히 알고,
// 오류(디스크 가득 등)면 그 실행의 전달을 멈추고 그 뒤 레코드를 버린 수로 센다(입력 기록기 io/input_recorder와 같은 방식, 3_ §7.1).
// 그전에는 스트림이 실패 상태가 되어도 '쓴 것'으로 세고 로그가 없었다. 로그는 실행 파일(스레드 A)이 사건을 읽어 낸다.
// 11/08 (이슈 #102, 29_ §2): 파일은 회전 파일(io/rotating_file)로 연다 — evidence.rotate_s·rotate_max_bytes를 켜면 스레드 B가
// 레코드를 쓰기 직전에 회전하고, 쓰기 오류 뒤 60초마다 새 파일로 다시 해 본다(그사이 레코드는 버린 수). 끄면 위 그대로
class EvidenceSink {
 public:
  EvidenceSink(EvidenceQueue& queue, std::string path, RotateOptions rotate = {}, FileOps ops = FileOps::system());
  ~EvidenceSink();

  EvidenceSink(const EvidenceSink&) = delete;
  EvidenceSink& operator=(const EvidenceSink&) = delete;

  // 파일을 이어 쓰기로 열고(결정 F8) 스레드를 띄운다. 열지 못하면 false, 이유는 error()
  bool start();
  // 큐를 닫고, 남은 레코드를 다 쓴 뒤 스레드를 끝낸다
  void stop();

  std::size_t written() const { return written_.load(); }  // 끝까지 쓴 레코드 수
  std::size_t dropped() const { return dropped_.load(); }  // 쓰기 오류로 버린 레코드 수(오류가 난 레코드 포함)
  bool failed() const { return file_.failed(); }           // 쓰기 오류로 전달을 멈춘 상태인지(회전 켬이면 재개 전까지)
  std::string error() const { return file_.error(); }      // 열기·쓰기 오류 문구
  std::size_t rotated() const { return file_.rotated(); }  // 이 실행의 회전 수 (29_ §7 끝 로그)
  bool has_events() const { return file_.has_events(); }
  std::vector<RotateEvent> take_events() { return file_.take_events(); }  // 스레드 A — 회전·오류 사건 (29_ §2.7)

 private:
  void run();

  EvidenceQueue& queue_;
  RotatingFile file_;
  std::thread th_;
  std::atomic<std::size_t> written_{0};
  std::atomic<std::size_t> dropped_{0};
};

}  // namespace detect
