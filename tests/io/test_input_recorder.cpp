// 입력 원본 기록 — 스레드 C 단위 시험 (24_ §3.3, §8.1 IR-T12 등). 큐는 스레드를 띄우기 전에도 받으므로, 띄우기 전에 채워
// 넘침을 결정적으로 만든다. 파일은 시험 폴더(DETECT_TMP_DIR)에 만든다
#include "detect/io/input_recorder.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include <unistd.h>

using namespace detect;

namespace {

std::string tmp_path(const char* name) {
  const std::string p = std::string(DETECT_TMP_DIR) + "/" + name;
  std::remove(p.c_str());
  return p;
}

std::string read_all(const std::string& p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// 조건이 참이 될 때까지 기다린다(최대 2 s) — 스레드 C가 쓰는 것을 기다릴 때
template <typename F>
bool wait_for(F cond) {
  for (int i = 0; i < 200; ++i) {
    if (cond()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return cond();
}

}  // namespace

// IR-T12: 바이트 합이 상한을 넘게 하는 줄은 버리고 센다 — 이미 든 줄은 순서대로 쓰인다
TEST(InputRecorder, QueueOverflowDropsNewLine) {
  const std::string p = tmp_path("ir_overflow.jsonl");
  InputRecorder r(p, 20);  // 줄 "aaaa" + \n = 5바이트 → 4줄까지
  for (int i = 0; i < 4; ++i) EXPECT_EQ(r.push("aaaa"), InputRecorder::Push::Queued);
  EXPECT_EQ(r.queued_bytes(), 20u);
  EXPECT_EQ(r.push("bbbb"), InputRecorder::Push::DroppedFull);
  EXPECT_EQ(r.push("c"), InputRecorder::Push::DroppedFull);  // 2바이트도 넘는다
  EXPECT_EQ(r.dropped(), 2u);
  ASSERT_TRUE(r.start());
  r.stop();
  EXPECT_EQ(r.written(), 4u);
  EXPECT_EQ(r.dropped(), 2u);
  EXPECT_FALSE(r.failed());
  EXPECT_EQ(read_all(p), "aaaa\naaaa\naaaa\naaaa\n");
}

// IR-T12: 큐가 비어 있으면 상한보다 긴 줄도 받는다 — 가장 긴 줄(max_line_bytes)도 남게
TEST(InputRecorder, EmptyQueueAcceptsLongLine) {
  const std::string p = tmp_path("ir_long.jsonl");
  InputRecorder r(p, 10);
  const std::string longline(50, 'x');
  EXPECT_EQ(r.push(longline), InputRecorder::Push::Queued);
  EXPECT_EQ(r.push("y"), InputRecorder::Push::DroppedFull);
  ASSERT_TRUE(r.start());
  r.stop();
  EXPECT_EQ(read_all(p), longline + "\n");
}

// IR-T12: 스레드 C가 쓴 만큼 큐 바이트가 줄어 다시 들어간다
TEST(InputRecorder, AcceptsAgainAfterWrite) {
  const std::string p = tmp_path("ir_again.jsonl");
  InputRecorder r(p, 10);
  ASSERT_TRUE(r.start());
  EXPECT_EQ(r.push("123456789"), InputRecorder::Push::Queued);  // 10바이트 — 상한 꽉 참
  ASSERT_TRUE(wait_for([&] { return r.queued_bytes() == 0; }));
  EXPECT_EQ(r.push("abc"), InputRecorder::Push::Queued);
  r.stop();
  EXPECT_EQ(r.written(), 2u);
  EXPECT_EQ(r.dropped(), 0u);
  EXPECT_EQ(read_all(p), "123456789\nabc\n");
}

// IR-T12·IR-T13: 닫으면 남은 줄을 다 쓰고 끝낸다 — 순서 그대로. 빈 줄도 받은 그대로(\n만) 남는다(24_ §3.2)
TEST(InputRecorder, StopDrainsInOrder) {
  const std::string p = tmp_path("ir_drain.jsonl");
  InputRecorder r(p, 1 << 20);
  std::string expect;
  for (int i = 0; i < 1000; ++i) {
    const std::string l = i == 500 ? std::string() : "line" + std::to_string(i);
    ASSERT_EQ(r.push(l), InputRecorder::Push::Queued);
    expect += l + "\n";
  }
  ASSERT_TRUE(r.start());
  r.stop();
  EXPECT_EQ(r.written(), 1000u);
  EXPECT_EQ(read_all(p), expect);
  EXPECT_EQ(r.push("late"), InputRecorder::Push::DroppedStopped);  // 닫힌 뒤
  r.stop();                                                         // 두 번 불러도 된다
}

// IR-T7: 이어 쓰기 — 있던 내용 뒤에 붙는다
TEST(InputRecorder, AppendsToExistingFile) {
  const std::string p = tmp_path("ir_append.jsonl");
  {
    std::ofstream out(p, std::ios::binary);
    out << "old\n";
  }
  InputRecorder r(p, 1 << 20);
  ASSERT_TRUE(r.start());
  r.push("new");
  r.stop();
  EXPECT_EQ(read_all(p), "old\nnew\n");
}

// IR-T8: 열지 못하면 start가 false, 이유가 남고 파일은 생기지 않는다
TEST(InputRecorder, OpenFailure) {
  const std::string p = std::string(DETECT_TMP_DIR) + "/no_such_dir_ir/input.jsonl";
  InputRecorder r(p, 1 << 20);
  EXPECT_FALSE(r.start());
  EXPECT_FALSE(r.error().empty());
  EXPECT_NE(::access(p.c_str(), F_OK), 0);
  r.stop();
}

// IR-T10: 쓰기 오류(/dev/full — ENOSPC)면 기록을 멈추고, 못 쓴 줄과 그 뒤 줄을 버린 수로 센다
TEST(InputRecorder, WriteErrorStopsRecording) {
  if (::access("/dev/full", W_OK) != 0) GTEST_SKIP() << "/dev/full not available";
  InputRecorder r("/dev/full", 1 << 20);
  for (int i = 0; i < 3; ++i) r.push("x");
  ASSERT_TRUE(r.start());
  ASSERT_TRUE(wait_for([&] { return r.failed(); }));
  EXPECT_FALSE(r.error().empty());
  EXPECT_EQ(r.push("after"), InputRecorder::Push::DroppedStopped);
  r.stop();
  EXPECT_EQ(r.written(), 0u);
  EXPECT_EQ(r.dropped(), 4u);
}
