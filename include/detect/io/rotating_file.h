#pragma once
// 출력 파일 회전 (29_ §2 — 11/08 이슈 #102): 증거(스레드 B, evidence_sink)와 입력 기록(스레드 C, input_recorder)이 함께 쓰는
// '이어 쓰기 + 회전' 파일. 파일 핸들을 가진 쓰기 스레드가 다음 줄(입력 기록은 다음 묶음)을 쓰기 직전에 회전 조건을 보고 스스로
// 회전한다 — 판정 스레드 A는 관여하지 않으므로 'A는 B·C를 기다리지 않는다'(1_ NFR-6)가 그대로다 (29_ §2.1).
//   - 주기(time): 이 파일을 연 뒤의 주기 경계(1970-01-01 UTC부터 rotate_s의 배수)를 벽시계가 넘었다
//   - 크기(size): 파일이 비어 있지 않고 지금 크기 + 쓸 바이트 > rotate_max_bytes
//   - 기동 때 반쪽 줄(partial_tail): 연 파일 끝이 \n이 아니면 첫 쓰기 전에 — 회전 키와 관계없이 늘 (29_ §2.4)
//   - 쓰기 오류 뒤(reopen): 회전이 켜져 있으면 60초마다 다시 해 본다 (29_ §2.5). 꺼져 있으면 그 실행 동안 멈춤(지금과 같음).
//     11/08 (이슈 #102): 지금 파일이 비어 있으면 회전하지 않고 같은 핸들로 다시 쓰고, 비어 있지 않을 때만(반쪽 줄이 있을 수 있음)
//     회전한다. 오류 사건은 멈출 때 한 번, 재개 사건은 실제로 다시 써졌을 때 한 번 — 디스크가 몇 시간 차 있어도 회전 파일은
//     작은 것 하나, 로그는 2~3줄
// 11/08 (이슈 #102, 29_ §2.2): 회전하려는데 지금 파일이 없으면(rename이 ENOENT — 누가 지우거나 옮김) 같은 이름으로 새 파일을 열어
// 바꾸고 옛 핸들을 닫는다(지운 파일의 공간이 풀리게). 회전 수에 세지 않고 경고 사건(Missing)만 남긴다
// 일반 파일이 아니면(/dev/stdout·/dev/full·FIFO 등) 회전·반쪽 줄 처리·재개를 모두 끄고 지금처럼 쓴다 — 장치 파일의 이름을
// 바꾸지 않게 (29_ §2.1). 일어난 일(회전·실패·오류·재개)은 사건으로 남기기만 하고, 로그는 실행 파일(스레드 A)이
// take_events()로 꺼내 낸다 — 두 스레드가 표준 오류에 함께 쓰면 줄이 섞인다 (29_ §2.7).
// 시험에서 시계와 파일 연산(열기·이름 바꾸기·쓰기·fstat)을 주입할 수 있다 — 벽시계를 기다리거나 실제 장치 경로를 회전시키지
// 않고 실패를 만든다 (29_ §8.1)

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

namespace detect {

// 회전 설정 (29_ §6). 둘 다 0이면 회전 끔 — 주기·크기 회전과 오류 뒤 재개를 하지 않는다. 재생 모드는 실행 파일이 0으로 넘긴다
// (29_ §2.6). 범위 검사는 설정 파서가 한다
struct RotateOptions {
  int64_t rotate_s = 0;            // 회전 주기(초). 0 = 끔
  uint64_t rotate_max_bytes = 0;   // 크기 상한(바이트). 0 = 끔
  bool enabled() const { return rotate_s > 0 || rotate_max_bytes > 0; }
};

// 파일 연산과 시계 — 기본은 시스템 호출과 벽시계. 실패는 시스템 호출처럼 -1(또는 false)을 돌려주고 errno를 둔다
struct FileOps {
  std::function<int(const std::string& path)> open_append;                       // O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644
  std::function<int(const std::string& from, const std::string& to)> rename;     // 0 또는 -1
  std::function<ssize_t(int fd, const void* buf, std::size_t n)> write;          // write(2)
  std::function<int(int fd, struct stat* st)> fstat;                             // fstat(2)
  std::function<int(const std::string& path, uint64_t size)> last_byte;          // 끝 바이트(0~255), 읽지 못하면 -1
  std::function<bool(const std::string& path)> exists;                           // 이름이 이미 있는지(회전 파일 이름 충돌)
  std::function<int64_t()> now_ms;                                               // 벽시계(UTC epoch ms)
  static FileOps system();
};

// 쓰기 스레드가 남기는 사건 — 실행 파일이 로그로 바꾼다 (29_ §7)
struct RotateEvent {
  enum class Kind {
    Rotate,        // 회전함: to·reason(time|size|partial_tail|reopen)·bytes(회전된 파일 크기)
    RotateFailed,  // 회전 실패: step(rename|open|name)·detail, paused = 쓰기 오류 뒤 재개 시도였는지(그 멈춤에 한 번만)
    WriteError,    // 쓰기 오류(멈출 때 한 번): detail, retry = 60초마다 다시 해 보는지(회전 켬) / 그 실행 동안 멈춤(회전 끔)
    Reopen,        // 쓰기 오류 뒤 다시 써짐: to(그 멈춤 동안 회전했으면 회전 파일 이름, 아니면 기준 경로)·dropped(멈춘 동안 버린 수)
    NotRegular,    // 일반 파일이 아니라 회전을 끔: path (회전을 켠 경우에만)
    Missing,       // 회전하려는데 지금 파일이 없어 같은 이름으로 새 파일을 엶: path (회전 수에 세지 않음)
  };
  Kind kind = Kind::Rotate;
  std::string to;
  std::string reason;
  std::string step;
  std::string detail;
  std::string path;
  uint64_t bytes = 0;
  std::size_t dropped = 0;
  bool retry = false;
  bool paused = false;
};

class RotatingFile {
 public:
  static constexpr int64_t kRetryMs = 60000;  // 회전 실패·쓰기 오류 뒤 다시 해 보기까지 — 설정 키가 아닌 고정값 (29_ §2.2·§2.5)

  RotatingFile(std::string path, RotateOptions opt, FileOps ops = FileOps::system());
  ~RotatingFile();

  RotatingFile(const RotatingFile&) = delete;
  RotatingFile& operator=(const RotatingFile&) = delete;

  // 이어 쓰기로 연다(스레드를 띄우기 전, 스레드 A). 일반 파일인지·끝이 반쪽 줄인지 본다. 열지 못하면 false, 이유는 error()
  bool open();
  void close();

  struct WriteResult {
    std::size_t bytes = 0;  // 파일에 쓴 바이트 (오류면 그 앞까지)
    int err = 0;            // 이번 쓰기의 errno (0 = 다 씀)
    bool skipped = false;   // 쓰기 오류 뒤 멈춘 상태라 쓰지 않음 — 호출자가 버린 수로 센다
  };
  // 쓰기 스레드: 한 덩어리(증거 레코드 한 줄 또는 입력 기록 묶음)를 쓰기 직전에 회전·재개를 보고 쓴다. 덩어리 중간에서
  // 회전하지 않는다 (29_ §2.1)
  WriteResult write(std::string_view data);
  // 쓰기 스레드: 쓰기 오류 뒤 버린 줄 수를 알린다 — 재개 로그의 dropped (29_ §7)
  void note_dropped(std::size_t n);

  std::vector<RotateEvent> take_events();  // 스레드 A — 쌓인 사건을 꺼낸다
  bool has_events() const { return has_events_.load(); }
  std::size_t rotated() const { return rotated_.load(); }  // 이 실행의 회전 수(모든 이유)
  bool failed() const { return failed_.load(); }           // 쓰기 오류 뒤 멈춘 상태인지(재개 전 또는 그 실행 동안)
  bool stopped() const { return state_.load() == State::Stopped; }  // 그 실행 동안 멈춤(회전 끔·일반 파일 아님)
  std::string error() const;                               // 마지막 열기·쓰기 오류 문구
  const std::string& path() const { return path_; }

 private:
  enum class State { Ok, Paused, Stopped };

  bool rotate(const char* reason, int64_t now, bool paused);
  void switch_to(int nfd, int64_t now);
  bool unlinked();
  void push_event(RotateEvent e);
  void set_error(const std::string& s);
  void set_opened(int64_t now);

  const std::string path_;
  const RotateOptions opt_;
  FileOps ops_;
  int fd_ = -1;

  // 쓰기 스레드만 만진다 (open은 스레드를 띄우기 전)
  bool regular_ = false;          // 일반 파일 — 아니면 회전·반쪽 줄 처리·재개를 모두 끔
  bool pending_partial_ = false;  // 연 파일 끝이 반쪽 줄 — 첫 쓰기 전에 회전
  uint64_t size_ = 0;             // 지금 파일 크기(연 때 fstat + 쓴 바이트)
  int64_t next_boundary_ms_ = 0;  // 이 파일을 연 뒤의 첫 주기 경계
  std::optional<int64_t> rotate_fail_ms_;  // 주기·크기 회전이 마지막으로 실패한 시각 — 60초 동안 다시 하지 않음
  int64_t pause_ms_ = 0;          // 쓰기 오류 또는 마지막 재개 시도 시각
  // 한 번의 멈춤(쓰기 오류 → 다시 써질 때까지)에 관한 것 — 멈출 때 비운다
  std::size_t dropped_since_pause_ = 0;      // 멈춘 동안 버린 수 — 재개 사건의 dropped
  bool pause_rotate_failed_logged_ = false;  // 멈춘 동안 재개 회전 실패를 이미 알렸는지

  std::atomic<State> state_{State::Ok};
  std::atomic<bool> failed_{false};
  std::atomic<std::size_t> rotated_{0};
  std::atomic<bool> has_events_{false};
  mutable std::mutex mu_;  // events_·error_
  std::vector<RotateEvent> events_;
  std::string error_;
};

}  // namespace detect
