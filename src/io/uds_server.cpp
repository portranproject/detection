#include "detect/io/uds_server.h"

#include <cerrno>
#include <cstring>
#include <utility>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace detect {
namespace {

bool make_addr(const std::string& path, sockaddr_un& addr) {
  std::memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) return false;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  return true;
}

std::string err_str(const char* what) { return std::string(what) + ": " + std::strerror(errno); }

}  // namespace

UdsServer::UdsServer(std::string path, std::size_t max_line_bytes)
    : path_(std::move(path)), max_line_bytes_(max_line_bytes) {}

UdsServer::~UdsServer() { close(); }

// 기동 (2_ §1 '소켓 파일', 결정 G6):
//  - 같은 경로에 소켓 파일이 있으면 접속해 본다. 응답이 있으면 다른 탐지 엔진이 떠 있는 것 → 기동 멈춤
//  - 응답이 없으면 이전 실행이 남긴 것 → 지우고 새로 만든다
//  - 소켓이 아닌 파일이면 지우지 않고 오류. 디렉터리는 만들지 않는다(배포 때 만듦, 4_ §5)
bool UdsServer::open() {
  sockaddr_un addr;
  if (!make_addr(path_, addr)) {
    error_ = "socket path too long: " + path_;
    return false;
  }
  struct stat st;
  if (::lstat(path_.c_str(), &st) == 0) {
    if (!S_ISSOCK(st.st_mode)) {
      error_ = "path exists and is not a socket: " + path_;
      return false;
    }
    int probe = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0) {
      error_ = err_str("socket");
      return false;
    }
    const int rc = ::connect(probe, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    const int saved = errno;
    ::close(probe);
    if (rc == 0) {
      error_ = "another detector is already listening on " + path_;
      return false;
    }
    if (saved != ECONNREFUSED && saved != ENOENT) {
      errno = saved;
      error_ = err_str("probe connect");
      return false;
    }
    ::unlink(path_.c_str());
    events_.push_back("removed stale socket file " + path_);
  }

  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) {
    error_ = err_str("socket");
    return false;
  }
  if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    error_ = err_str(("bind " + path_).c_str());
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (::listen(listen_fd_, 4) < 0) {
    error_ = err_str("listen");
    close();
    return false;
  }
  events_.push_back("listening on " + path_);
  return true;
}

void UdsServer::close_client(const char* why) {
  if (client_fd_ < 0) return;
  ::close(client_fd_);
  client_fd_ = -1;
  // 끊긴 연결의 반쪽 줄은 버린다 — 끊긴 동안의 메시지는 버려도 된다 (2_ §1, 결정 G4)
  if (!buf_.empty()) events_.push_back("discarded partial line (" + std::to_string(buf_.size()) + " bytes)");
  buf_.clear();
  discarding_ = false;
  events_.push_back(std::string("client closed: ") + why);
}

void UdsServer::close() {
  close_client("server shutdown");
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    ::unlink(path_.c_str());
  }
}

std::vector<std::string> UdsServer::take_events() {
  std::vector<std::string> out;
  out.swap(events_);
  return out;
}

// JSON Lines 줄 나누기 (2_ §1): '\n' 하나가 메시지 하나의 끝.
// 줄 길이 상한을 넘으면 그 줄은 다음 '\n'까지 버리고 1회 기록한다 — 연결은 유지 (결정 G5)
void UdsServer::on_data(const char* data, std::size_t n, const LineHandler& on_line) {
  std::size_t i = 0;
  while (i < n) {
    const char* nl = static_cast<const char*>(std::memchr(data + i, '\n', n - i));
    const std::size_t end = nl ? static_cast<std::size_t>(nl - data) : n;
    if (!discarding_) {
      buf_.append(data + i, end - i);
      if (buf_.size() > max_line_bytes_) {
        events_.push_back("line exceeds " + std::to_string(max_line_bytes_) + " bytes, discarded");
        buf_.clear();
        discarding_ = true;
      }
    }
    if (!nl) break;
    if (!discarding_) on_line(buf_);
    buf_.clear();
    discarding_ = false;
    i = end + 1;
  }
}

// 한 번 기다려 처리 (2_ §1):
//  - 듣는 소켓: 새 연결. 이미 연결이 있으면 이전 연결을 닫고 새 연결을 받는다 (분석 엔진 재시작 대비, 결정 G4)
//  - 연결 소켓: 읽어서 줄로 나눠 넘긴다. 0바이트면 끊김
bool UdsServer::poll_once(int timeout_ms, const LineHandler& on_line) {
  if (listen_fd_ < 0) return false;
  pollfd fds[2];
  nfds_t nfds = 0;
  fds[nfds++] = {listen_fd_, POLLIN, 0};
  if (client_fd_ >= 0) fds[nfds++] = {client_fd_, POLLIN, 0};
  const int rc = ::poll(fds, nfds, timeout_ms);
  if (rc < 0) {
    if (errno == EINTR) return true;  // 신호 — 호출 쪽이 종료 여부를 본다
    error_ = err_str("poll");
    return false;
  }
  if (rc == 0) return true;

  if (nfds > 1 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
    char chunk[65536];
    const ssize_t n = ::read(client_fd_, chunk, sizeof(chunk));
    if (n > 0) {
      on_data(chunk, static_cast<std::size_t>(n), on_line);
    } else if (n == 0) {
      close_client("peer closed");
    } else if (errno != EINTR && errno != EAGAIN) {
      close_client(std::strerror(errno));
    }
  }
  if (fds[0].revents & POLLIN) {
    const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd >= 0) {
      if (client_fd_ >= 0) close_client("replaced by new connection");
      client_fd_ = fd;
      events_.push_back("client connected");
    }
  }
  return true;
}

}  // namespace detect
