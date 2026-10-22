#pragma once
// Unix 도메인 소켓 서버 (2_ §1, 1_ FR-1): 탐지 엔진 = 서버, 분석 엔진 = 클라이언트.
// 한 스레드(스레드 A)에서 poll()로 돈다 — 받은 줄은 바로 엔진으로 넘긴다 (3_ §7.1 동시성 모델).

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace detect {

class UdsServer {
 public:
  using LineHandler = std::function<void(std::string_view line)>;

  UdsServer(std::string path, std::size_t max_line_bytes);
  ~UdsServer();

  UdsServer(const UdsServer&) = delete;
  UdsServer& operator=(const UdsServer&) = delete;

  // 남은 소켓 파일을 확인·정리한 뒤 bind·listen (2_ §1, 결정 G6). 실패하면 false, 이유는 error()
  bool open();
  // timeout_ms 동안 기다려 들어온 연결·데이터를 처리한다. 치명적 오류면 false
  bool poll_once(int timeout_ms, const LineHandler& on_line);
  // 연결을 닫고 소켓 파일을 지운다 (결정 G7)
  void close();

  // 연결·끊김·줄 길이 초과 같은 사건 기록 — 호출 쪽이 로그로 낸다 (core와 같게 직접 찍지 않음)
  std::vector<std::string> take_events();
  const std::string& error() const { return error_; }
  bool client_connected() const { return client_fd_ >= 0; }

 private:
  void close_client(const char* why);
  void on_data(const char* data, std::size_t n, const LineHandler& on_line);

  std::string path_;
  std::size_t max_line_bytes_;
  int listen_fd_ = -1;
  int client_fd_ = -1;
  std::string buf_;          // 아직 줄바꿈이 오지 않은 부분
  bool discarding_ = false;  // 상한을 넘은 줄을 다음 줄바꿈까지 버리는 중 (결정 G5)
  std::vector<std::string> events_;
  std::string error_;
};

}  // namespace detect
