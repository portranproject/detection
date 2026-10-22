// 설정 파일 해석 테스트 (4_ §1.2, 결정 G3)
#include "detect/config.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

using namespace detect;

// 저장소의 config/detector.json이 해석되고 값이 기본값과 같다
TEST(Config, RepoDefaultFileMatchesDefaults) {
  std::ifstream in(std::string(DETECT_SOURCE_DIR) + "/config/detector.json");
  ASSERT_TRUE(in);
  std::stringstream ss;
  ss << in.rdbuf();
  ConfigResult r = parse_config(ss.str());
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_TRUE(r.warnings.empty());
  const DetectorConfig d;
  EXPECT_EQ(r.config.socket_path, d.socket_path);
  EXPECT_EQ(r.config.max_line_bytes, d.max_line_bytes);
  EXPECT_EQ(r.config.bts.window_ms, d.bts.window_ms);
  EXPECT_EQ(r.config.bts.a_min, d.bts.a_min);
  EXPECT_DOUBLE_EQ(r.config.bts.theta, d.bts.theta);
  EXPECT_DOUBLE_EQ(r.config.bts.k, d.bts.k);
  EXPECT_EQ(r.config.bts.h_sat_ms, d.bts.h_sat_ms);
  EXPECT_DOUBLE_EQ(r.config.bts.baseline_tau_s, d.bts.baseline_tau_s);
  EXPECT_FALSE(r.config.bts.max_conn);
  EXPECT_EQ(r.config.evidence.mode, EvidenceMode::Full);
  EXPECT_FALSE(r.config.evidence.pre_slots);
  EXPECT_EQ(r.config.evidence.post_slots, 10u);
  EXPECT_EQ(r.config.evidence.queue_max, 4096u);
  EXPECT_EQ(r.config.evidence.out_path, "evidence.jsonl");
}

// 빠진 키는 기본값, 일부만 덮어쓰기
TEST(Config, PartialOverride) {
  ConfigResult r = parse_config(R"({"rules":{"L3-01-V":{"theta":0.7,"max_conn":96}},"evidence":{"mode":"ref","pre_slots":300}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_DOUBLE_EQ(r.config.bts.theta, 0.7);
  EXPECT_EQ(r.config.bts.max_conn, 96);
  EXPECT_EQ(r.config.bts.a_min, 5);
  EXPECT_EQ(r.config.evidence.mode, EvidenceMode::Ref);
  EXPECT_EQ(r.config.evidence.pre_slots, 300u);
  EXPECT_EQ(r.config.socket_path, "/run/ran-detect/kpm.sock");
  EXPECT_TRUE(parse_config("{}").ok);
}

// 모르는 키는 경고만 (결정 G3)
TEST(Config, UnknownKeysWarn) {
  ConfigResult r = parse_config(R"({"socket_pth":"x","rules":{"L3-01-V":{"thetaa":1},"L9":{}},"evidence":{"moed":"full"}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.warnings.size(), 4u);
}

// 타입·범위가 틀리거나 JSON이 아니면 오류 (결정 G3)
TEST(Config, Errors) {
  EXPECT_FALSE(parse_config("not json").ok);
  EXPECT_FALSE(parse_config("[1]").ok);
  EXPECT_FALSE(parse_config(R"({"max_line_bytes":"big"})").ok);
  EXPECT_FALSE(parse_config(R"({"max_line_bytes":0})").ok);
  EXPECT_FALSE(parse_config(R"({"rules":{"L3-01-V":{"a_min":1.5}}})").ok);
  EXPECT_FALSE(parse_config(R"({"rules":{"L3-01-V":{"theta":0}}})").ok);
  EXPECT_FALSE(parse_config(R"({"rules":{"L3-01-V":{"max_conn":"96"}}})").ok);
  EXPECT_FALSE(parse_config(R"({"evidence":{"mode":"all"}})").ok);
  EXPECT_FALSE(parse_config(R"({"evidence":{"out_path":""}})").ok);
  EXPECT_FALSE(parse_config(R"({"rules":[]})").ok);
  auto r = parse_config(R"({"rules":{"L3-01-V":{"window_ms":-1}}})");
  EXPECT_FALSE(r.ok);
  EXPECT_NE(r.error.find("window_ms"), std::string::npos);
}
