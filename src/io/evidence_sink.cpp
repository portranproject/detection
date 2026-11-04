#include "detect/io/evidence_sink.h"

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace detect {

EvidenceSink::EvidenceSink(EvidenceQueue& queue, std::string path) : queue_(queue), path_(std::move(path)) {}

EvidenceSink::~EvidenceSink() { stop(); }

bool EvidenceSink::start() {
  // 이어 쓰기 — 다시 기동해도 이전 증거가 지워지지 않게 (결정 F8). 버퍼 없이 write(2)로 쓴다 (11/05 W-33)
  fd_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd_ < 0) {
    err_.store(errno);
    return false;
  }
  th_ = std::thread([this] { run(); });
  return true;
}

void EvidenceSink::stop() {
  queue_.close();
  if (th_.joinable()) th_.join();
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

std::string EvidenceSink::error() const {
  const int e = err_.load();
  return e ? std::strerror(e) : std::string();
}

// 스레드 B 본체: 꺼낸 레코드를 한 줄씩 write(2)로 쓴다. 판정 쪽(스레드 A)과는 큐로만 이어진다 — 쓰기가 느려도 A는 기다리지 않는다
// (1_ NFR-6). 쓰기 오류(디스크 가득 등)면 failed를 표시하고 그 뒤 레코드는 버린 수로 센다 — 다시 시도하지 않는다 (3_ §7.1, 11/05 W-33)
void EvidenceSink::run() {
  EvidenceRecord rec;
  std::string buf;
  while (queue_.pop(rec)) {
    if (failed_.load()) {
      ++dropped_;
      continue;
    }
    buf.assign(rec.line);
    buf += '\n';
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
    if (err != 0) {
      err_.store(err);
      failed_.store(true);
      ++dropped_;
      continue;
    }
    ++written_;
  }
}

}  // namespace detect
