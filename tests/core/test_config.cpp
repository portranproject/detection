// 설정 파일 해석 테스트 (4_ §1.2, 결정 G3·J4)
#include "detect/config.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

using namespace detect;

namespace {

BtsVariantConfigResult bts_of(const std::string& whole_config) {
  ConfigResult r = parse_config(whole_config);
  EXPECT_TRUE(r.ok) << r.error;
  return parse_bts_variant_config(r.config.rules.at("L3-01-V"));
}

}  // namespace

// 저장소의 config/detector.json이 해석되고, max_conn(설정 파일만 96)을 빼면 값이 구조체 기본값과 같다
TEST(Config, RepoConfigFileParses) {
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
  ASSERT_EQ(r.config.rules.size(), 1u);
  ASSERT_TRUE(r.config.rules.count("L3-01-V"));
  BtsVariantConfigResult b = parse_bts_variant_config(r.config.rules.at("L3-01-V"));
  ASSERT_TRUE(b.ok) << b.error;
  EXPECT_TRUE(b.warnings.empty());
  const BtsVariantConfig bd;
  EXPECT_EQ(b.config.window_ms, bd.window_ms);
  EXPECT_EQ(b.config.a_min, bd.a_min);
  EXPECT_DOUBLE_EQ(b.config.theta, bd.theta);
  EXPECT_EQ(b.config.f_abs, bd.f_abs);
  EXPECT_EQ(bd.f_abs, 10);  // 3_ §4 F_abs 기본값 (10/27 Q-41)
  EXPECT_DOUBLE_EQ(b.config.k, bd.k);
  EXPECT_EQ(b.config.h_sat_ms, bd.h_sat_ms);
  EXPECT_DOUBLE_EQ(b.config.baseline_tau_s, bd.baseline_tau_s);
  EXPECT_EQ(b.config.max_conn, 96);  // DU 셀 UE 한도 (4_ §6.1 #1, 10/27 이슈 #13 W-16). 구조체 기본값은 null(C4 끔)
  EXPECT_FALSE(bd.max_conn);
  EXPECT_EQ(r.config.evidence.mode, EvidenceMode::Full);
  EXPECT_FALSE(r.config.evidence.pre_slots);
  EXPECT_EQ(r.config.evidence.post_slots, 10u);
  EXPECT_EQ(r.config.evidence.queue_max, 4096u);
  EXPECT_EQ(r.config.evidence.out_path, "evidence.jsonl");
}

// 빠진 키는 기본값, 일부만 덮어쓰기
TEST(Config, PartialOverride) {
  const std::string text = R"({"rules":{"L3-01-V":{"theta":0.7,"f_abs":20,"max_conn":96}},"evidence":{"mode":"ref","pre_slots":300}})";
  ConfigResult r = parse_config(text);
  ASSERT_TRUE(r.ok) << r.error;
  BtsVariantConfigResult b = bts_of(text);
  ASSERT_TRUE(b.ok) << b.error;
  EXPECT_DOUBLE_EQ(b.config.theta, 0.7);
  EXPECT_EQ(b.config.max_conn, 96);
  EXPECT_EQ(b.config.f_abs, 20);
  EXPECT_EQ(b.config.a_min, 5);
  EXPECT_EQ(r.config.evidence.mode, EvidenceMode::Ref);
  EXPECT_EQ(r.config.evidence.pre_slots, 300u);
  EXPECT_EQ(r.config.socket_path, "/run/ran-detect/kpm.sock");
  EXPECT_TRUE(parse_config("{}").ok);
  EXPECT_TRUE(parse_config("{}").config.rules.empty());  // 룰 설정이 없으면 실행 파일이 기본값을 쓴다
}

// 모르는 키는 경고만 (결정 G3). 룰 안의 모르는 키는 룰별 파서가, 모르는 룰 ID는 실행 파일이 경고한다 (결정 J4)
TEST(Config, UnknownKeysWarn) {
  const std::string text = R"({"socket_pth":"x","rules":{"L3-01-V":{"thetaa":1},"L9":{}},"evidence":{"moed":"full"}})";
  ConfigResult r = parse_config(text);
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.warnings.size(), 2u);  // socket_pth, evidence.moed
  EXPECT_EQ(r.config.rules.size(), 2u);
  EXPECT_TRUE(r.config.rules.count("L9"));  // 넘기기만 한다 — 경고는 등록된 룰을 아는 쪽에서
  BtsVariantConfigResult b = bts_of(text);
  ASSERT_TRUE(b.ok) << b.error;
  EXPECT_EQ(b.warnings.size(), 1u);  // rules.L3-01-V.thetaa
}

// 타입·범위가 틀리거나 JSON이 아니면 오류 (결정 G3)
TEST(Config, Errors) {
  EXPECT_FALSE(parse_config("not json").ok);
  EXPECT_FALSE(parse_config("[1]").ok);
  EXPECT_FALSE(parse_config(R"({"max_line_bytes":"big"})").ok);
  EXPECT_FALSE(parse_config(R"({"max_line_bytes":0})").ok);
  EXPECT_FALSE(parse_config(R"({"evidence":{"mode":"all"}})").ok);
  EXPECT_FALSE(parse_config(R"({"evidence":{"out_path":""}})").ok);
  EXPECT_FALSE(parse_config(R"({"rules":[]})").ok);
  EXPECT_FALSE(parse_config(R"({"rules":{"L3-01-V":5}})").ok);  // 룰 설정은 객체여야 한다
  // 룰 안의 타입·범위 오류는 룰별 파서가 낸다
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"a_min":1.5}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"theta":0}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"max_conn":"96"}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"f_abs":0}}})").ok);    // 1 이상 (결정 I1)
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"f_abs":2.5}}})").ok);  // 정수
  EXPECT_FALSE(parse_bts_variant_config("[1]").ok);
  auto b = bts_of(R"({"rules":{"L3-01-V":{"window_ms":-1}}})");
  EXPECT_FALSE(b.ok);
  EXPECT_NE(b.error.find("window_ms"), std::string::npos);
}
