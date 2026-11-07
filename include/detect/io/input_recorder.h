#pragma once
// 입력 원본 기록 — 스레드 C (24_ §3.3): 스레드 A(받기·판정)가 받은 입력 줄을 큐에 넣고, 스레드 C가 꺼내 기록 파일에 이어 쓴다.
// 증거 기록기(스레드 B, evidence_sink)와 같은 방식이지만 큐는 따로 둔다 — 넘칠 때 버리는 규칙이 다르고(여기는 새 줄),
// 기록이 밀려도 증거가 버려지면 안 된다. 큐는 바이트 합으로 상한을 두고, 넘치면 넣으려는 줄을 버린다 — A는 C를 기다리지
// 않는다 (1_ NFR-1·NFR-6). 로그는 내지 않는다 — 결과와 수를 돌려주면 실행 파일(스레드 A)이 낸다(줄이 섞이지 않게, 24_ §3.4).
// 11/08 (이슈 #102, 29_ §2): 파일은 회전 파일(io/rotating_file)로 연다 — input_record.rotate_s·rotate_max_bytes를 켜면 스레드 C가
// 묶음 사이에서 회전하고, 쓰기 오류 뒤에도 큐에서 줄을 꺼내 버린 수로 세며 60초마다 새 파일로 다시 해 본다 (29_ §2.5)

#include "detect/io/rotating_file.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace detect {

class InputRecorder {
 public:
  // push 결과 — 실행 파일이 넘침 로그(input_record_drop·resume)를 가르는 데 쓴다 (24_ §3.4)
  enum class Push {
    Queued,          // 큐에 넣음
    DroppedFull,     // 큐가 넘쳐 버림 (24_ §3.3)
    DroppedStopped,  // 쓰기 오류로 그 실행의 기록을 멈췄거나(회전 끔) 닫힌 뒤라 버림
  };

  InputRecorder(std::string path, std::size_t queue_max_bytes, RotateOptions rotate = {},
                FileOps ops = FileOps::system());
  ~InputRecorder();

  InputRecorder(const InputRecorder&) = delete;
  InputRecorder& operator=(const InputRecorder&) = delete;

  // 파일을 이어 쓰기로 열고 스레드 C를 띄운다. 열지 못하면 false, 이유는 error()
  bool start();
  // 스레드 A. 줄을 복사해 넣는다(막히지 않음). 끝의 \n은 쓸 때 붙인다
  Push push(std::string_view line);
  // 큐를 닫고, 남은 줄을 다 쓴 뒤 스레드를 끝내고 파일을 닫는다. 여러 번 불러도 된다
  void stop();

  std::size_t written() const { return written_.load(); }  // 파일에 다 쓴 줄 수 — 회전한 파일을 모두 합친 실행 전체
  std::size_t dropped() const { return dropped_.load(); }  // 버린 줄 수 — 넘침 + 쓰기 오류 뒤
  bool failed() const { return failed_.load(); }           // 쓰기 오류로 기록을 멈춘 상태인지 (24_ §3.3 — 회전 켬이면 재개 전까지)
  std::size_t queued_bytes() const;                        // 큐에 든(쓰는 중 포함) 바이트 합 — 넘침 로그용
  std::string error() const { return file_.error(); }      // 열기·쓰기 오류 문구
  const std::string& path() const { return file_.path(); }
  std::size_t rotated() const { return file_.rotated(); }  // 이 실행의 회전 수 (29_ §7 끝 로그)
  bool has_events() const { return file_.has_events(); }
  std::vector<RotateEvent> take_events() { return file_.take_events(); }  // 스레드 A — 회전·오류 사건 (29_ §2.7)

 private:
  void run();

  const std::size_t queue_max_bytes_;
  RotatingFile file_;
  std::thread th_;

  mutable std::mutex mu_;
  std::condition_variable cv_;
  std::deque<std::string> q_;
  std::size_t bytes_ = 0;  // 큐 + 스레드 C가 쓰고 있는 줄의 바이트 합(줄 + \n) — 쓴 뒤에 뺀다
  bool closed_ = false;    // stop()이 불림
  bool stopped_ = false;   // 쓰기 오류로 그 실행의 기록을 멈춤(회전 끔·일반 파일 아님) — 그 뒤 push는 버린다

  std::atomic<std::size_t> written_{0};
  std::atomic<std::size_t> dropped_{0};
  std::atomic<bool> failed_{false};
};

}  // namespace detect
