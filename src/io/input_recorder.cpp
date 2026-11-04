#include "detect/io/input_recorder.h"

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace detect {

InputRecorder::InputRecorder(std::string path, std::size_t queue_max_bytes)
    : path_(std::move(path)), queue_max_bytes_(queue_max_bytes) {}

InputRecorder::~InputRecorder() { stop(); }

// 이어 쓰기로 연다 — 다시 띄워도 이전 기록이 남는다(증거 파일과 같음, 24_ §3.3). 줄 단위 버퍼 없이 write로 바로 쓰므로
// 쓴 줄 수와 쓰기 오류를 정확히 안다 — 쓰기 오류가 flush 때에야 드러나 '쓴 줄'로 셌던 줄이 사라지는 일이 없다
bool InputRecorder::start() {
  fd_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd_ < 0) {
    std::lock_guard<std::mutex> lk(mu_);
    error_ = std::strerror(errno);
    return false;
  }
  th_ = std::thread([this] { run(); });
  return true;
}

// 스레드 A (24_ §3.3): 줄을 복사해 넣고 바로 돌아간다. 넣으면 바이트 합이 상한을 넘을 때 그 줄을 버린다 — 이미 든 줄은
// 순서대로 쓰이므로 파일에는 앞부분이 이어서 남는다. 큐가 비어 있으면 상한보다 긴 줄도 받는다(줄 상한 max_line_bytes가
// 큐 하한 65,536과 같아 가장 긴 줄도 남게)
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
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

std::size_t InputRecorder::queued_bytes() const {
  std::lock_guard<std::mutex> lk(mu_);
  return bytes_;
}

std::string InputRecorder::error() const {
  std::lock_guard<std::mutex> lk(mu_);
  return error_;
}

// 스레드 C 본체 (24_ §3.3): 큐에 든 줄을 한꺼번에 꺼내 이어 붙여 쓴다(줄마다 \n). 다 쓴 뒤에 큐 바이트에서 빼므로 쓰는 중인
// 줄도 상한에 든다. 쓰기 오류(디스크 가득 등)면 그 실행의 기록을 멈춘다 — 다 쓰지 못한 줄과 남은 줄, 그 뒤 들어오는 줄은
// 버린 수로 센다. 다시 시도하지 않는다(디스크가 찬 동안 줄마다 시도하지 않게). 판정은 계속된다
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
    std::size_t off = 0;
    int err = 0;
    while (off < buf.size()) {
      const ssize_t w = ::write(fd_, buf.data() + off, buf.size() - off);
      if (w < 0) {
        if (errno == EINTR) continue;
        err = errno;
        break;
      }
      off += static_cast<std::size_t>(w);
    }
    // 끝까지 쓴 줄만 written — 오류면 중간에 걸린 줄부터는 버린 수로 (파일에 반쪽 줄이 남을 수 있다 — 전송기는 완성된 줄만 읽는다)
    std::size_t done = 0, end = 0;
    for (const std::string& l : batch) {
      end += l.size() + 1;
      if (end > off) break;
      ++done;
    }
    written_ += done;
    {
      std::lock_guard<std::mutex> lk(mu_);
      bytes_ -= buf.size();
      if (err != 0) {
        dropped_ += (batch.size() - done) + q_.size();
        q_.clear();
        bytes_ = 0;
        stopped_ = true;
        error_ = std::strerror(err);
        failed_ = true;
      }
    }
    batch.clear();
    if (err != 0) return;  // 기록을 멈춤 — 이 뒤 push는 DroppedStopped
  }
}

}  // namespace detect
