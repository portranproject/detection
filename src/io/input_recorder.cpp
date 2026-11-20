#include "detect/io/input_recorder.h"

#include <utility>

namespace detect {

InputRecorder::InputRecorder(std::string path, std::size_t queue_max_bytes, RotateOptions rotate, FileOps ops)
    : queue_max_bytes_(queue_max_bytes), file_(std::move(path), rotate, std::move(ops)) {}

InputRecorder::~InputRecorder() { stop(); }

// 이어 쓰기로 연다 — 다시 띄워도 이전 기록이 남는다(증거 파일과 같음, 24_ §3.3). 줄 단위 버퍼 없이 write로 바로 쓰므로
// 쓴 줄 수와 쓰기 오류를 정확히 안다 — 쓰기 오류가 flush 때에야 드러나 '쓴 줄'로 셌던 줄이 사라지는 일이 없다.
// 연 파일 끝이 반쪽 줄이면 첫 묶음 전에 회전한다 (29_ §2.4 — 회전 파일이 맡음)
bool InputRecorder::start() {
  if (!file_.open()) return false;
  th_ = std::thread([this] { run(); });
  return true;
}

// 스레드 A (24_ §3.3): 줄을 복사해 넣고 바로 돌아간다. 넣으면 바이트 합이 상한을 넘을 때 그 줄을 버린다 — 이미 든 줄은
// 순서대로 쓰이므로 파일에는 앞부분이 이어서 남는다. 큐가 비어 있으면 상한보다 긴 줄도 받는다(줄 상한 max_line_bytes가
// 큐 하한 65,536과 같아 가장 긴 줄도 남게). 회전을 켜면 쓰기 오류 뒤에도 받는다 — 스레드 C가 꺼내 버린다 (29_ §2.5)
InputRecorder::Push InputRecorder::push(std::string_view line) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (stopped_ || closed_) {
      ++dropped_;
      return Push::DroppedStopped;
    }
    const std::size_t n = line.size() + 1;
    if (bytes_ > 0 && bytes_ + n > queue_max_bytes_) {
      ++dropped_;
      return Push::DroppedFull;
    }
    q_.emplace_back(line);
    bytes_ += n;
  }
  cv_.notify_one();
  return Push::Queued;
}

void InputRecorder::stop() {
  {
    std::lock_guard<std::mutex> lk(mu_);
    closed_ = true;
  }
  cv_.notify_one();
  if (th_.joinable()) th_.join();
  file_.close();
}

std::size_t InputRecorder::queued_bytes() const {
  std::lock_guard<std::mutex> lk(mu_);
  return bytes_;
}

// 스레드 C 본체 (24_ §3.3): 큐에 든 줄을 한꺼번에 꺼내 이어 붙여 쓴다(줄마다 \n). 다 쓴 뒤에 큐 바이트에서 빼므로 쓰는 중인
// 줄도 상한에 든다. 회전은 묶음을 쓰기 직전에만 본다 — 묶음 중간에서 회전하지 않으므로 파일이 상한보다 묶음 하나만큼 커질 수
// 있다 (29_ §2.1). 쓰기 오류(디스크 가득 등)면:
//   - 회전 끔(또는 일반 파일 아님): 그 실행의 기록을 멈춘다 — 다 쓰지 못한 줄과 남은 줄, 그 뒤 들어오는 줄은 버린 수로 센다.
//     다시 시도하지 않는다(디스크가 찬 동안 줄마다 시도하지 않게, 24_ §3.3)
//   - 회전 켬: 큐에서 계속 꺼내 버린 수로 센다 — 그래야 다음 시도(60초 뒤 새 파일, 29_ §2.5)까지 큐가 차지 않는다
// 판정은 어느 쪽이든 계속된다
void InputRecorder::run() {
  std::deque<std::string> batch;
  std::string buf;
  for (;;) {
    {
      std::unique_lock<std::mutex> lk(mu_);
      cv_.wait(lk, [this] { return !q_.empty() || closed_; });
      if (q_.empty()) return;  // 닫혔고 남은 줄이 없음
      batch.swap(q_);
    }
    buf.clear();
    for (const std::string& l : batch) {
      buf += l;
      buf += '\n';
    }
    const RotatingFile::WriteResult r = file_.write(buf);
    // 끝까지 쓴 줄만 written — 오류면 중간에 걸린 줄부터는 버린 수로 (파일에 반쪽 줄이 남을 수 있다 — 전송기는 완성된 줄만 읽는다).
    // 멈춘 상태라 쓰지 않은 묶음(skipped)은 모두 버린 수
    std::size_t done = 0, end = 0;
    if (!r.skipped) {
      for (const std::string& l : batch) {
        end += l.size() + 1;
        if (end > r.bytes) break;
        ++done;
      }
    }
    written_ += done;
    const std::size_t lost = batch.size() - done;
    bool stop_now = false;
    {
      std::lock_guard<std::mutex> lk(mu_);
      bytes_ -= buf.size();
      if (lost > 0 && file_.stopped()) {
        // 회전 끔 — 그 실행의 기록을 멈춤. 남은 줄도 버리고 이 뒤 push는 DroppedStopped
        dropped_ += lost + q_.size();
        q_.clear();
        bytes_ = 0;
        stopped_ = true;
        stop_now = true;
      } else {
        dropped_ += lost;
        file_.note_dropped(lost);
      }
      failed_ = file_.failed();  // push의 DroppedStopped와 같은 잠금 안에서 — 스레드 A가 failed를 본 뒤 넣는 줄은 버려진다
    }
    batch.clear();
    if (stop_now) return;
  }
}

}  // namespace detect
