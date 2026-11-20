#include "detect/io/rotating_file.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace detect {
namespace {

// 60초가 지났는지 — 벽시계가 뒤로 가면(시각 맞춤) 기다림이 길어지지 않게 바로 다시 해 본다
bool retry_due(int64_t since, int64_t now) { return now < since || now - since >= RotatingFile::kRetryMs; }

// 회전 파일 이름의 시각 YYYYMMDD-HHMMSS — 회전한 벽시계 시각, UTC (29_ §2.3 — 박스 시간대 설정과 섞이지 않게)
std::string utc_stamp(int64_t now_ms) {
  const std::time_t s = static_cast<std::time_t>(now_ms / 1000);
  std::tm tm{};
  gmtime_r(&s, &tm);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec);
  return buf;
}

}  // namespace

// 기본 파일 연산 — 시스템 호출과 벽시계
FileOps FileOps::system() {
  FileOps o;
  o.open_append = [](const std::string& p) { return ::open(p.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644); };
  o.rename = [](const std::string& from, const std::string& to) { return ::rename(from.c_str(), to.c_str()); };
  o.write = [](int fd, const void* b, std::size_t n) { return ::write(fd, b, n); };
  o.fstat = [](int fd, struct stat* st) { return ::fstat(fd, st); };
  // 끝 바이트 — 쓰기 핸들(O_WRONLY)로는 읽지 못해 읽기 전용으로 따로 연다 (29_ §2.4)
  o.last_byte = [](const std::string& p, uint64_t size) {
    if (size == 0) return -1;
    const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    unsigned char c = 0;
    const ssize_t r = ::pread(fd, &c, 1, static_cast<off_t>(size - 1));
    ::close(fd);
    return r == 1 ? static_cast<int>(c) : -1;
  };
  // 이름이 있는지 — 심볼릭 링크도 있는 것으로. 확인하지 못하면(권한 등) 있는 것으로 보아 덮어쓰지 않는다
  o.exists = [](const std::string& p) {
    struct stat st;
    return ::lstat(p.c_str(), &st) == 0 || errno != ENOENT;
  };
  o.now_ms = [] {
    using namespace std::chrono;
    return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
  };
  return o;
}

RotatingFile::RotatingFile(std::string path, RotateOptions opt, FileOps ops)
    : path_(std::move(path)), opt_(opt), ops_(std::move(ops)) {}

RotatingFile::~RotatingFile() { close(); }

// 파일을 연 시각에서 다음 주기 경계를 정한다 — 경계는 1970-01-01 00:00:00 UTC부터 rotate_s의 배수(3,600이면 매시 정각) (29_ §2.1)
void RotatingFile::set_opened(int64_t now) {
  if (opt_.rotate_s <= 0) return;
  const int64_t period = opt_.rotate_s * 1000;
  int64_t k = now / period;
  if (now < 0 && now % period != 0) --k;  // 음수 시각은 내림
  next_boundary_ms_ = (k + 1) * period;
}

// 이어 쓰기로 연다 — 다시 기동해도 이전 내용이 남는다(결정 F8, 24_ §3.3). 연 뒤 일반 파일인지 보고(29_ §2.1), 일반 파일이고
// 끝이 \n이 아니면 첫 쓰기 전에 회전하도록 표시한다 — 조각 뒤에 새 줄이 붙어 깨진 줄이 되지 않게 (29_ §2.4). 끝 바이트를
// 읽지 못하면 반쪽 줄로 보지 않는다(지금처럼 이어 쓴다)
bool RotatingFile::open() {
  fd_ = ops_.open_append(path_);
  if (fd_ < 0) {
    set_error(std::strerror(errno));
    return false;
  }
  struct stat st {};
  regular_ = ops_.fstat(fd_, &st) == 0 && S_ISREG(st.st_mode);
  if (regular_) {
    size_ = static_cast<uint64_t>(st.st_size);
    if (size_ > 0) {
      const int b = ops_.last_byte(path_, size_);
      pending_partial_ = b >= 0 && b != '\n';
    }
  } else if (opt_.enabled()) {
    // 일반 파일이 아님 — 회전·반쪽 줄 처리·재개를 끄고 지금처럼 쓴다. 회전을 켠 경우에만 경고 한 번 (29_ §2.1·§7)
    RotateEvent e;
    e.kind = RotateEvent::Kind::NotRegular;
    e.path = path_;
    push_event(std::move(e));
  }
  set_opened(ops_.now_ms());
  return true;
}

void RotatingFile::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

std::string RotatingFile::error() const {
  std::lock_guard<std::mutex> lk(mu_);
  return error_;
}

void RotatingFile::set_error(const std::string& s) {
  std::lock_guard<std::mutex> lk(mu_);
  error_ = s;
}

void RotatingFile::push_event(RotateEvent e) {
  std::lock_guard<std::mutex> lk(mu_);
  events_.push_back(std::move(e));
  has_events_.store(true);
}

std::vector<RotateEvent> RotatingFile::take_events() {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<RotateEvent> out;
  out.swap(events_);
  has_events_.store(false);
  return out;
}

void RotatingFile::note_dropped(std::size_t n) {
  if (state_.load() == State::Paused) dropped_since_pause_ += n;
}

// 회전 순서 (29_ §2.2): ① 이름 정하기 ② rename(path, path.<시각>) — 같은 폴더라 원자적 ③ 같은 이름으로 새 파일 열기 ④ 옛 핸들
// 닫기. 옛 파일의 내용은 ②보다 먼저 다 쓰여 있어 전송기가 옛 파일을 끝까지 읽은 뒤 넘어갈 때 빠지는 줄이 없다(19_ §4.4).
// ②가 실패하면 옛 핸들로 계속 쓴다. ③이 실패하면 이름을 되돌리고 옛 핸들로 계속 쓴다 — 되돌리지 않으면 전송기가 옛 파일을
// 닫은 뒤 쓰인 줄을 잃는다. 실패하면 사건(경고)을 남기고, 60초 동안은 다시 해 보지 않는다(호출자가 시각을 본다).
// 새 핸들로 바꾸면 true — 지금 파일이 없어 새로 연 경우(Missing)도 true다
bool RotatingFile::rotate(const char* reason, int64_t now, bool paused) {
  auto fail = [&](const char* step, std::string detail) {
    if (!paused) rotate_fail_ms_ = now;
    // 11/08 (이슈 #102, 29_ §2.5): 멈춘 동안의 재개 회전 실패는 그 멈춤에 한 번만 알린다 — 디스크가 계속 차 있어도 분마다 경고가
    // 나지 않게
    if (paused && pause_rotate_failed_logged_) return false;
    if (paused) pause_rotate_failed_logged_ = true;
    RotateEvent e;
    e.kind = RotateEvent::Kind::RotateFailed;
    e.step = step;
    e.detail = std::move(detail);
    e.reason = reason;
    e.paused = paused;
    push_event(std::move(e));
    return false;
  };
  // ① 회전 파일 이름 (29_ §2.3): <path>.<YYYYMMDD-HHMMSS>(UTC), 같은 이름이 있으면 .1 … .99 — 99까지 다 있으면 실패(step=name).
  // 이름의 시각 순서 = 쓰인 순서, 같은 시각이면 붙인 번호 순(없는 것이 먼저) — 전송기·정리 도구가 이 순서를 쓴다
  const std::string base = path_ + "." + utc_stamp(now);
  std::string to;
  for (int i = 0; i <= 99 && to.empty(); ++i) {
    std::string cand = i == 0 ? base : base + "." + std::to_string(i);
    if (!ops_.exists(cand)) to = std::move(cand);
  }
  if (to.empty()) return fail("name", "rotated file names taken up to " + base + ".99");
  // ② 이름 바꾸기
  if (ops_.rename(path_, to) != 0) {
    const int err = errno;
    if (err != ENOENT) return fail("rename", std::strerror(err));
    // 지금 파일이 없어짐 (11/08 이슈 #102, 29_ §2.2): 누가 지우거나 옮겨 기준 경로가 비었다 — 회전할 것이 없으므로 같은 이름으로
    // 새 파일을 열어 바꾼다. 옛 핸들을 닫아야 지운 파일의 공간이 풀린다. 회전 수에는 세지 않고 경고 사건만 남긴다
    const int mfd = ops_.open_append(path_);
    if (mfd < 0) return fail("open", std::strerror(errno));
    switch_to(mfd, now);
    RotateEvent e;
    e.kind = RotateEvent::Kind::Missing;
    e.path = path_;
    push_event(std::move(e));
    return true;
  }
  // ③ 새 파일 열기 — 실패하면 이름을 되돌린다
  const int nfd = ops_.open_append(path_);
  if (nfd < 0) {
    std::string detail = std::strerror(errno);
    if (ops_.rename(to, path_) != 0) detail += std::string("; rename back failed: ") + std::strerror(errno);
    return fail("open", std::move(detail));
  }
  // ④ 옛 핸들을 닫고 새 핸들로
  const uint64_t old_size = size_;
  switch_to(nfd, now);
  rotated_.fetch_add(1);
  RotateEvent e;
  e.kind = RotateEvent::Kind::Rotate;
  e.to = to;
  e.reason = reason;
  e.bytes = old_size;
  push_event(std::move(e));
  return true;
}

// 새 핸들로 바꾼다 — 옛 핸들을 닫고, 크기와 주기 경계를 새 파일 기준으로
void RotatingFile::switch_to(int nfd, int64_t now) {
  ::close(fd_);
  fd_ = nfd;
  struct stat st {};
  size_ = ops_.fstat(fd_, &st) == 0 ? static_cast<uint64_t>(st.st_size) : 0;
  set_opened(now);
  rotate_fail_ms_.reset();
}

// 지금 핸들의 파일이 지워졌는지(링크 수 0) — 비어 있어 회전 없이 다시 쓰려 할 때, 지운 파일에 계속 쓰지 않게
bool RotatingFile::unlinked() {
  struct stat st {};
  return ops_.fstat(fd_, &st) == 0 && st.st_nlink == 0;
}

// 쓰기 스레드 본체에서 덩어리마다 (29_ §2.1·§2.4·§2.5): 쓰기 직전에 ① 쓰기 오류 뒤 멈춘 상태면 60초마다 다시 해 보고(지금 파일이
// 비어 있지 않으면 먼저 회전 reason=reopen — 회전이 안 되면 쓰지 않고 돌아감) ② 기동 때 반쪽 줄이면 회전(partial_tail — 실패해도
// 지금 파일에 씀) ③ 회전이 켜져 있고 60초 실패 대기가 아니면 주기 경계(time)·크기 상한(size)을 본다. 그다음 다 쓴다. 쓰기 오류면
// 회전 켬(일반 파일)은 멈춤 — 60초 뒤 재개, 회전 끔·일반 파일 아님은 그 실행 동안 멈춤(지금과 같음, 3_ §7.1·24_ §3.3)
RotatingFile::WriteResult RotatingFile::write(std::string_view data) {
  WriteResult r;
  const State st = state_.load();
  if (st == State::Stopped) {
    r.skipped = true;
    return r;
  }
  const int64_t now = ops_.now_ms();
  bool retrying = false;  // 이번 쓰기가 멈춘 뒤 다시 해 보는 것인지
  if (st == State::Paused) {
    // ① 쓰기 오류 뒤 재개 (29_ §2.5): 오류(또는 마지막 시도) 뒤 60초가 지난 첫 쓰기 때 다시 해 본다. 그사이 줄은 호출자가 버린
    // 수로 센다. 11/08 (이슈 #102): 지금 파일이 비어 있으면 격리할 것이 없으므로 회전하지 않고 같은 핸들로 다시 쓴다 — 비어 있지
    // 않을 때만(오류 때 쓰다 만 반쪽 줄이 있을 수 있음) 회전해(reason=reopen) 새 파일에 쓴다. 그래서 디스크가 계속 차 있어도
    // 회전 파일은 반쪽 줄을 담은 것 하나뿐이다. 비어 있어도 지금 파일이 지워졌으면(링크 수 0) 회전 쪽으로 — 새 파일을 연다
    if (!retry_due(pause_ms_, now)) {
      r.skipped = true;
      return r;
    }
    pause_ms_ = now;
    if ((size_ > 0 || unlinked()) && !rotate("reopen", now, true)) {
      r.skipped = true;
      return r;
    }
    retrying = true;
  } else if (pending_partial_) {
    // ② 기동 때 반쪽 줄 (29_ §2.4): 회전 키와 관계없이 늘. 조각은 옛 파일 끝에 남는다(잘라내지 않음 — 전송기가 잘림으로 보고
    // 처음부터 다시 보내지 않게). 실패해도 지금 파일에 쓴다 — 첫 줄을 쓰고 나면 끝이 반쪽이 아니므로 다시 하지 않는다
    pending_partial_ = false;
    rotate("partial_tail", now, false);
  } else if (opt_.enabled() && regular_ && (!rotate_fail_ms_ || retry_due(*rotate_fail_ms_, now))) {
    // ③ 주기·크기 회전 (29_ §2.1) — 줄(묶음) 중간에서는 하지 않는다. 실패 뒤 60초 동안은 보지 않는다 (29_ §2.2)
    const char* reason = nullptr;
    if (opt_.rotate_s > 0 && now >= next_boundary_ms_) {
      // 11/08 (이슈 #102): 빈 파일은 경계를 넘겨도 회전하지 않고 경계만 다시 센다 — 경보가 몇 시간 없다가 처음 날 때 빈 회전
      // 파일이 생기지 않게. 다만 지워진 파일(링크 수 0)이면 회전 쪽으로 — 새 파일을 연다(29_ §2.5a)
      if (size_ > 0 || unlinked()) reason = "time";
      else set_opened(now);
    }
    if (reason == nullptr && opt_.rotate_max_bytes > 0 && size_ > 0 && size_ + data.size() > opt_.rotate_max_bytes)
      reason = "size";
    if (reason) rotate(reason, now, false);
  }

  // 다 쓴다 — 버퍼 없이 write(2)로(쓴 바이트와 오류를 정확히 알게, 11/05 W-33). 0을 돌려주면 진행이 없으므로 입출력 오류로 본다
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t w = ops_.write(fd_, data.data() + off, data.size() - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      r.err = errno;
      break;
    }
    if (w == 0) {
      r.err = EIO;
      break;
    }
    off += static_cast<std::size_t>(w);
  }
  size_ += off;
  r.bytes = off;
  if (r.err != 0 && retrying) {
    // 다시 해 봤지만 또 오류 (11/08 이슈 #102): 같은 멈춤이 이어진다 — 오류 사건은 멈출 때 이미 남겼으므로 다시 남기지 않는다.
    // 60초 뒤 또 해 본다
    set_error(std::strerror(r.err));
    pause_ms_ = now;
  } else if (r.err != 0) {
    // 쓰기 오류 (29_ §2.5): 회전 켬(일반 파일)이면 멈추고 60초 뒤 재개, 아니면 그 실행 동안 멈춤. 사건은 멈출 때 한 번
    const bool retry = opt_.enabled() && regular_;
    set_error(std::strerror(r.err));
    pause_ms_ = now;
    dropped_since_pause_ = 0;
    pause_rotate_failed_logged_ = false;
    state_.store(retry ? State::Paused : State::Stopped);
    failed_.store(true);
    RotateEvent e;
    e.kind = RotateEvent::Kind::WriteError;
    e.detail = std::strerror(r.err);
    e.retry = retry;
    push_event(std::move(e));
  } else if (retrying) {
    // 멈춘 뒤 실제로 다시 써짐 (29_ §2.5·§7, 11/08 이슈 #102) — 재개 사건은 이때 한 번. to는 다시 쓰기 시작한 곳 = 늘 기준 경로다
    // (재시도가 회전했으면 반쪽 줄이 든 옛 파일 이름은 그 회전 사건의 to에 있다)
    RotateEvent e;
    e.kind = RotateEvent::Kind::Reopen;
    e.to = path_;
    e.dropped = dropped_since_pause_;
    push_event(std::move(e));
    dropped_since_pause_ = 0;
    state_.store(State::Ok);
    failed_.store(false);
  }
  return r;
}

}  // namespace detect
