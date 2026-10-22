// .jsonl 재생 테스트 (1_ FR-2, 결정 G2)
#include "detect/io/file_replay.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using namespace detect;

namespace {

std::string write_tmp(const char* name, const std::vector<std::string>& lines) {
  const std::string p = std::string(DETECT_TMP_DIR) + "/" + name;
  std::ofstream o(p);
  for (const auto& l : lines) o << l << "\n";
  return p;
}

std::string kpm(long long t_end) {
  return "{\"type\":\"kpm2\",\"t_start_ms\":" + std::to_string(t_end - 100) + ",\"t_end_ms\":" + std::to_string(t_end) + "}";
}

}  // namespace

TEST(FileReplay, FindTEnd) {
  EXPECT_EQ(find_t_end_ms(kpm(1792209000200)), 1792209000200LL);
  EXPECT_EQ(find_t_end_ms("{\"type\":\"hello\"}"), -1);
}

// 최대 속도: 줄 순서 그대로, 길이 상한을 넘는 줄은 건너뜀
TEST(FileReplay, MaxSpeedOrderAndSkip) {
  const auto p = write_tmp("r_order.jsonl", {"{\"type\":\"hello\"}", kpm(1000), std::string(200, 'x'), kpm(1100)});
  std::vector<std::string> got;
  ReplayOptions o;
  o.max_line_bytes = 100;
  auto r = replay_file(p, o, [&](std::string_view l) { got.emplace_back(l); });
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.lines, 3u);
  EXPECT_EQ(r.skipped, 1u);
  EXPECT_EQ(got[0], "{\"type\":\"hello\"}");
  EXPECT_EQ(got[2], kpm(1100));
  std::remove(p.c_str());
}

// 배속 재생: 데이터 시각 간격 / 배속만큼 걸린다 (2 s 데이터, 10배속 → 약 0.2 s)
TEST(FileReplay, PacedBySpeed) {
  std::vector<std::string> lines = {"{\"type\":\"hello\"}"};
  for (int i = 0; i <= 20; ++i) lines.push_back(kpm(1000 + i * 100));
  const auto p = write_tmp("r_paced.jsonl", lines);
  ReplayOptions o;
  o.speed = 10;
  const auto t0 = std::chrono::steady_clock::now();
  auto r = replay_file(p, o, [](std::string_view) {});
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
  ASSERT_TRUE(r.ok);
  EXPECT_GE(ms, 190);
  EXPECT_LT(ms, 1500);
  std::remove(p.c_str());
}

TEST(FileReplay, MissingFile) {
  auto r = replay_file(std::string(DETECT_TMP_DIR) + "/nope.jsonl", {}, [](std::string_view) {});
  EXPECT_FALSE(r.ok);
}
