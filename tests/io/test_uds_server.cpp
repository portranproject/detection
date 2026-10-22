// Unix 소켓 서버 테스트 (2_ §1, 결정 G4~G6). 서버는 테스트 스레드에서 poll로 돌리고, 클라이언트는 같은 스레드에서 쓴다
#include "detect/io/uds_server.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace detect;

namespace {

std::string sock_path(const char* name) { return std::string(DETECT_TMP_DIR) + "/" + name; }

int connect_to(const std::string& path) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  std::strncpy(a.sun_path, path.c_str(), sizeof(a.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

void send_all(int fd, const std::string& s) {
  std::size_t off = 0;
  while (off < s.size()) {
    ssize_t n = ::write(fd, s.data() + off, s.size() - off);
    ASSERT_GT(n, 0);
    off += static_cast<std::size_t>(n);
  }
}

// 서버를 몇 번 돌려 들어온 것을 모두 처리
void pump(UdsServer& s, std::vector<std::string>& lines, int rounds = 5) {
  for (int i = 0; i < rounds; ++i) ASSERT_TRUE(s.poll_once(20, [&](std::string_view l) { lines.emplace_back(l); }));
}

bool has_event(const std::vector<std::string>& ev, const std::string& needle) {
  for (const auto& e : ev)
    if (e.find(needle) != std::string::npos) return true;
  return false;
}

}  // namespace

// 줄 나누기: 한 줄이 여러 번에 나뉘어 와도, 여러 줄이 한 번에 와도 (2_ §1 JSON Lines)
TEST(UdsServer, SplitsLines) {
  const auto path = sock_path("t_split.sock");
  ::unlink(path.c_str());
  UdsServer s(path, 65536);
  ASSERT_TRUE(s.open()) << s.error();
  int c = connect_to(path);
  ASSERT_GE(c, 0);
  std::vector<std::string> lines;
  pump(s, lines);
  send_all(c, "{\"a\":1}\n{\"b\"");
  pump(s, lines);
  send_all(c, ":2}\n{\"c\":3}\n");
  pump(s, lines);
  ::close(c);
  pump(s, lines);
  EXPECT_EQ(lines, (std::vector<std::string>{"{\"a\":1}", "{\"b\":2}", "{\"c\":3}"}));
  EXPECT_TRUE(has_event(s.take_events(), "peer closed"));
  s.close();
  EXPECT_NE(::access(path.c_str(), F_OK), 0);  // 닫으면 소켓 파일 삭제 (결정 G7)
}

// 상한을 넘는 줄은 버리고 연결은 유지, 다음 줄은 정상 (결정 G5)
TEST(UdsServer, OverlongLineDiscarded) {
  const auto path = sock_path("t_long.sock");
  ::unlink(path.c_str());
  UdsServer s(path, 16);
  ASSERT_TRUE(s.open());
  int c = connect_to(path);
  std::vector<std::string> lines;
  pump(s, lines);
  send_all(c, std::string(40, 'x') + "\n{\"ok\":1}\n");
  pump(s, lines);
  EXPECT_EQ(lines, (std::vector<std::string>{"{\"ok\":1}"}));
  EXPECT_TRUE(has_event(s.take_events(), "exceeds 16 bytes"));
  EXPECT_TRUE(s.client_connected());
  ::close(c);
}

// 새 연결이 오면 이전 연결을 닫고, 그 연결의 반쪽 줄은 버린다 (결정 G4)
TEST(UdsServer, NewClientReplacesOld) {
  const auto path = sock_path("t_replace.sock");
  ::unlink(path.c_str());
  UdsServer s(path, 65536);
  ASSERT_TRUE(s.open());
  int c1 = connect_to(path);
  std::vector<std::string> lines;
  pump(s, lines);
  send_all(c1, "{\"from\":1}\n{\"half\"");
  pump(s, lines);
  int c2 = connect_to(path);
  pump(s, lines);
  send_all(c2, "{\"from\":2}\n");
  pump(s, lines);
  EXPECT_EQ(lines, (std::vector<std::string>{"{\"from\":1}", "{\"from\":2}"}));
  auto ev = s.take_events();
  EXPECT_TRUE(has_event(ev, "replaced by new connection"));
  EXPECT_TRUE(has_event(ev, "discarded partial line"));
  // 이전 연결은 서버가 닫았으므로 읽으면 EOF
  char b;
  EXPECT_EQ(::read(c1, &b, 1), 0);
  ::close(c1);
  ::close(c2);
}

// 남은 소켓 파일(듣는 쪽 없음)은 지우고 기동, 살아 있는 서버가 있으면 기동 거부 (결정 G6)
TEST(UdsServer, StaleSocketRemovedLiveServerRefused) {
  const auto path = sock_path("t_stale.sock");
  ::unlink(path.c_str());
  {
    // 듣지 않는 소켓 파일을 남긴다
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un a{};
    a.sun_family = AF_UNIX;
    std::strncpy(a.sun_path, path.c_str(), sizeof(a.sun_path) - 1);
    ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)), 0);
    ::close(fd);
  }
  ASSERT_EQ(::access(path.c_str(), F_OK), 0);
  UdsServer s1(path, 65536);
  ASSERT_TRUE(s1.open()) << s1.error();
  EXPECT_TRUE(has_event(s1.take_events(), "removed stale socket"));

  UdsServer s2(path, 65536);
  EXPECT_FALSE(s2.open());
  EXPECT_NE(s2.error().find("another detector"), std::string::npos);
  s1.close();
}

// 소켓이 아닌 파일은 지우지 않고 오류
TEST(UdsServer, RefusesNonSocketFile) {
  const auto path = sock_path("t_regular.sock");
  { FILE* f = std::fopen(path.c_str(), "w"); std::fclose(f); }
  UdsServer s(path, 65536);
  EXPECT_FALSE(s.open());
  EXPECT_EQ(::access(path.c_str(), F_OK), 0);
  ::unlink(path.c_str());
}
