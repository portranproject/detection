// 설정 파일 해석 테스트 (4_ §1.2, 결정 G3·J4)
#include "detect/config.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

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
  ASSERT_EQ(r.config.rules.size(), 4u);  // L3-01-V + 2단계 L3-20·L3-01-O·L3-21 (10/29 이슈 #33)
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

  // 2단계 키는 모두 구조체 기본값과 같다 — 설정 파일을 더해도 판정은 그대로 (4_ §1.2, 10/29 이슈 #33)
  const UeTableConfig ud;
  EXPECT_EQ(r.config.ue_table.max_ues, ud.max_ues);
  EXPECT_EQ(r.config.ue_table.recent_n, ud.recent_n);
  EXPECT_EQ(r.config.ue_table.stale_setup_ms, ud.stale_setup_ms);
  EXPECT_EQ(r.config.ue_table.closed_recent_max, ud.closed_recent_max);
  // 유령 정리·보호 무리·상수 대체 키 (14_ §9, 10/29 Q-56·W-24 — 이슈 #44)와 최상위 max_cells
  EXPECT_DOUBLE_EQ(r.config.ue_table.ghost_k, ud.ghost_k);
  EXPECT_EQ(r.config.ue_table.ghost_margin, ud.ghost_margin);
  EXPECT_EQ(r.config.ue_table.ghost_hold_ms, ud.ghost_hold_ms);
  EXPECT_EQ(r.config.ue_table.evict_protect_ms, ud.evict_protect_ms);
  EXPECT_EQ(r.config.ue_table.dl_unobserved_ms, ud.dl_unobserved_ms);
  EXPECT_EQ(r.config.ue_table.recent_keep_margin_ms, ud.recent_keep_margin_ms);
  EXPECT_EQ(r.config.max_cells, d.max_cells);
  EXPECT_EQ(ud.ghost_k, 2);
  EXPECT_EQ(ud.evict_protect_ms, 5000);
  EXPECT_EQ(d.max_cells, 64u);
  const AlertConfig ad;
  EXPECT_EQ(r.config.alert.ues_max, ad.ues_max);
  EXPECT_EQ(r.config.alert.update_min_ms, ad.update_min_ms);
  EXPECT_EQ(r.config.alert.ue_evidence_max, ad.ue_evidence_max);
  auto bl = parse_blind_dos_config(r.config.rules.at("L3-20"));
  ASSERT_TRUE(bl.ok) << bl.error;
  EXPECT_TRUE(bl.warnings.empty());
  EXPECT_EQ(bl.config.accept_wait_ms, BlindDosConfig{}.accept_wait_ms);
  EXPECT_EQ(bl.config.clear_quiet_ms, BlindDosConfig{}.clear_quiet_ms);
  auto st = parse_auth_stall_config(r.config.rules.at("L3-01-O"));
  ASSERT_TRUE(st.ok) << st.error;
  EXPECT_TRUE(st.warnings.empty());
  const AuthStallConfig sd;
  EXPECT_EQ(st.config.auth_wait_ms, sd.auth_wait_ms);
  EXPECT_EQ(st.config.window_ms, sd.window_ms);
  EXPECT_EQ(st.config.n_stall, sd.n_stall);
  EXPECT_EQ(st.config.clear_quiet_ms, sd.clear_quiet_ms);
  EXPECT_EQ(st.config.max_conn, sd.max_conn);
  auto up = parse_uplink_dos_config(r.config.rules.at("L3-21"));
  ASSERT_TRUE(up.ok) << up.error;
  EXPECT_TRUE(up.warnings.empty());
  const UplinkDosConfig pd;
  EXPECT_EQ(up.config.window_ms, pd.window_ms);
  EXPECT_EQ(up.config.n_fail, pd.n_fail);
  EXPECT_EQ(up.config.fail_accept_wait_ms, pd.fail_accept_wait_ms);
  EXPECT_EQ(up.config.reg_repeat, pd.reg_repeat);
  EXPECT_EQ(up.config.clear_quiet_ms, pd.clear_quiet_ms);
  EXPECT_EQ(up.config.ignore_causes, pd.ignore_causes);
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

// 2단계 키 (10/29 이슈 #33): 없으면 구조체 기본값, 있으면 그 값 — ue_table·alert는 최상위, 룰은 rules.<룰 ID> (14_ §9, 15_ §1.2)
TEST(Config, Stage2KeysRead) {
  ConfigResult none = parse_config("{}");
  ASSERT_TRUE(none.ok);
  EXPECT_EQ(none.config.ue_table.max_ues, 4096u);
  EXPECT_EQ(none.config.alert.update_min_ms, 1000);
  EXPECT_EQ(parse_uplink_dos_config("{}").config.n_fail, 5);

  ConfigResult r = parse_config(
      R"({"ue_table":{"max_ues":200,"recent_n":8,"stale_setup_ms":20000,"closed_recent_max":0},)"
      R"("alert":{"ues_max":10,"update_min_ms":500,"ue_evidence_max":0}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_TRUE(r.warnings.empty());
  EXPECT_EQ(r.config.ue_table.max_ues, 200u);
  EXPECT_EQ(r.config.ue_table.recent_n, 8u);
  EXPECT_EQ(r.config.ue_table.stale_setup_ms, 20000);
  EXPECT_EQ(r.config.ue_table.closed_recent_max, 0u);
  EXPECT_EQ(r.config.alert.ues_max, 10u);
  EXPECT_EQ(r.config.alert.update_min_ms, 500);
  EXPECT_EQ(r.config.alert.ue_evidence_max, 0u);

  // 이슈 #44 키: ghost_k는 실수, 나머지는 정수. max_cells는 최상위
  ConfigResult g = parse_config(
      R"({"max_cells":8,"ue_table":{"ghost_k":1.5,"ghost_margin":0,"ghost_hold_ms":0,"evict_protect_ms":100,)"
      R"("dl_unobserved_ms":2000,"recent_keep_margin_ms":0}})");
  ASSERT_TRUE(g.ok) << g.error;
  EXPECT_TRUE(g.warnings.empty());
  EXPECT_EQ(g.config.max_cells, 8u);
  EXPECT_DOUBLE_EQ(g.config.ue_table.ghost_k, 1.5);
  EXPECT_EQ(g.config.ue_table.ghost_margin, 0);
  EXPECT_EQ(g.config.ue_table.ghost_hold_ms, 0);
  EXPECT_EQ(g.config.ue_table.evict_protect_ms, 100);
  EXPECT_EQ(g.config.ue_table.dl_unobserved_ms, 2000);
  EXPECT_EQ(g.config.ue_table.recent_keep_margin_ms, 0);
  EXPECT_DOUBLE_EQ(parse_config(R"({"ue_table":{"ghost_k":3}})").config.ue_table.ghost_k, 3.0);  // 정수도 받는다

  auto bl = parse_blind_dos_config(R"({"accept_wait_ms":3000,"clear_quiet_ms":30000})");
  ASSERT_TRUE(bl.ok) << bl.error;
  EXPECT_EQ(bl.config.accept_wait_ms, 3000);
  EXPECT_EQ(bl.config.clear_quiet_ms, 30000);
  auto st = parse_auth_stall_config(R"({"auth_wait_ms":1500,"window_ms":5000,"n_stall":3,"clear_quiet_ms":2000,"max_conn":null})");
  ASSERT_TRUE(st.ok) << st.error;
  EXPECT_EQ(st.config.auth_wait_ms, 1500);
  EXPECT_EQ(st.config.window_ms, 5000);
  EXPECT_EQ(st.config.n_stall, 3);
  EXPECT_EQ(st.config.clear_quiet_ms, 2000);
  EXPECT_FALSE(st.config.max_conn);  // null이면 심각도 high를 쓰지 않는다 (15_ §1.2)
  EXPECT_EQ(parse_auth_stall_config(R"({"max_conn":50})").config.max_conn, 50);
  auto up = parse_uplink_dos_config(
      R"({"window_ms":20000,"n_fail":3,"fail_accept_wait_ms":4000,"reg_repeat":4,"clear_quiet_ms":120000,"ignore_causes":[9,22]})");
  ASSERT_TRUE(up.ok) << up.error;
  EXPECT_EQ(up.config.window_ms, 20000);
  EXPECT_EQ(up.config.n_fail, 3);
  EXPECT_EQ(up.config.fail_accept_wait_ms, 4000);
  EXPECT_EQ(up.config.reg_repeat, 4);
  EXPECT_EQ(up.config.clear_quiet_ms, 120000);
  EXPECT_EQ(up.config.ignore_causes, (std::vector<int64_t>{9, 22}));
}

// 허용 범위 경계 (15_ §1.2 룰 키, 14_ §9 ue_table·alert — 10/29 이슈 #33): 하한·상한은 받고, 하한 − 1·상한 + 1은 오류
TEST(Config, Stage2RangeBoundaries) {
  struct Range {
    std::string section;  // ue_table·alert는 최상위, 그 밖은 룰 ID
    std::string key;
    int64_t lo;
    int64_t hi;
  };
  const std::vector<Range> ranges = {
      {"ue_table", "max_ues", 100, 16384},          {"ue_table", "recent_n", 1, 64},
      {"ue_table", "stale_setup_ms", 2000, 600000}, {"ue_table", "closed_recent_max", 0, 16384},
      {"ue_table", "ghost_margin", 0, 4096},        {"ue_table", "ghost_hold_ms", 0, 600000},
      {"ue_table", "evict_protect_ms", 0, 600000},  {"ue_table", "dl_unobserved_ms", 1000, 600000},
      {"ue_table", "recent_keep_margin_ms", 0, 60000}, {"top", "max_cells", 1, 1024},
      {"alert", "ues_max", 1, 1000},                {"alert", "update_min_ms", 100, 60000},
      {"alert", "ue_evidence_max", 0, 1000},        {"L3-20", "accept_wait_ms", 100, 60000},
      {"L3-20", "clear_quiet_ms", 1000, 3600000},   {"L3-01-O", "auth_wait_ms", 100, 60000},
      {"L3-01-O", "window_ms", 1000, 600000},       {"L3-01-O", "n_stall", 1, 10000},
      {"L3-01-O", "clear_quiet_ms", 1000, 3600000}, {"L3-21", "window_ms", 1000, 600000},
      {"L3-21", "n_fail", 1, 10000},                {"L3-21", "fail_accept_wait_ms", 100, 60000},
      {"L3-21", "reg_repeat", 2, 100},              {"L3-21", "clear_quiet_ms", 1000, 3600000},
  };
  auto accepts = [](const Range& r, int64_t v, std::string* error = nullptr) {
    const std::string obj = "{\"" + r.key + "\":" + std::to_string(v) + "}";
    bool ok = false;
    std::string err;
    if (r.section == "ue_table" || r.section == "alert") {
      ConfigResult c = parse_config("{\"" + r.section + "\":" + obj + "}");
      ok = c.ok;
      err = c.error;
    } else if (r.section == "top") {  // 최상위 키 (max_cells)
      ConfigResult c = parse_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "L3-20") {
      auto c = parse_blind_dos_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "L3-01-O") {
      auto c = parse_auth_stall_config(obj);
      ok = c.ok;
      err = c.error;
    } else {
      auto c = parse_uplink_dos_config(obj);
      ok = c.ok;
      err = c.error;
    }
    if (error) *error = err;
    return ok;
  };
  for (const Range& r : ranges) {
    const std::string name = r.section + "." + r.key;
    EXPECT_TRUE(accepts(r, r.lo)) << name;
    EXPECT_TRUE(accepts(r, r.hi)) << name;
    std::string err;
    EXPECT_FALSE(accepts(r, r.lo - 1, &err)) << name;
    EXPECT_NE(err.find(r.key + ": out of range"), std::string::npos) << name << ": " << err;
    EXPECT_FALSE(accepts(r, r.hi + 1)) << name;
  }
  // ghost_k는 실수 범위 [1, 10] (14_ §9)
  EXPECT_TRUE(parse_config(R"({"ue_table":{"ghost_k":1}})").ok);
  EXPECT_TRUE(parse_config(R"({"ue_table":{"ghost_k":10}})").ok);
  EXPECT_FALSE(parse_config(R"({"ue_table":{"ghost_k":0.99}})").ok);
  EXPECT_FALSE(parse_config(R"({"ue_table":{"ghost_k":10.5}})").ok);
  EXPECT_NE(parse_config(R"({"ue_table":{"ghost_k":0}})").error.find("ghost_k: out of range"), std::string::npos);
}

// 타입 오류 — 정수 자리의 실수·문자열·null, 객체가 아닌 ue_table·alert, max_conn은 1 이상 또는 null
TEST(Config, Stage2TypeErrors) {
  EXPECT_FALSE(parse_config(R"({"ue_table":{"max_ues":4096.5}})").ok);
  EXPECT_FALSE(parse_config(R"({"ue_table":{"recent_n":"16"}})").ok);
  EXPECT_FALSE(parse_config(R"({"alert":{"ues_max":null}})").ok);
  EXPECT_FALSE(parse_config(R"({"ue_table":[1]})").ok);
  EXPECT_FALSE(parse_config(R"({"alert":5})").ok);
  EXPECT_FALSE(parse_config(R"({"ue_table":{"ghost_k":"2"}})").ok);
  EXPECT_FALSE(parse_config(R"({"ue_table":{"ghost_margin":1.5}})").ok);
  EXPECT_FALSE(parse_config(R"({"max_cells":"64"}})").ok);
  EXPECT_FALSE(parse_config(R"({"max_cells":0})").ok);
  EXPECT_FALSE(parse_blind_dos_config(R"({"accept_wait_ms":5000.0})").ok);
  EXPECT_FALSE(parse_auth_stall_config(R"({"max_conn":0})").ok);
  EXPECT_FALSE(parse_auth_stall_config(R"({"max_conn":"96"})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"reg_repeat":true})").ok);
  EXPECT_FALSE(parse_uplink_dos_config("[1]").ok);
  EXPECT_EQ(parse_auth_stall_config("[1]").error, "config: rules.L3-01-O: not an object");
}

// ignore_causes (15_ §1.2): 정수 배열, 각 0~255, 중복 없음, 빈 배열 허용(끔)
TEST(Config, IgnoreCauses) {
  EXPECT_TRUE(parse_uplink_dos_config(R"({"ignore_causes":[]})").ok);
  EXPECT_TRUE(parse_uplink_dos_config(R"({"ignore_causes":[0,255]})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":[9,9]})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":[256]})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":[-1]})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":["9"]})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":[9.5]})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":9})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"ignore_causes":null})").ok);
  EXPECT_NE(parse_uplink_dos_config(R"({"ignore_causes":[9,9]})").error.find("duplicate 9"), std::string::npos);
}

// 모르는 키는 경고만, 예약 키 ue_table.tomb_ms·tomb_max는 '쓰지 않음' 경고만 (14_ §3.2·§9)
TEST(Config, Stage2UnknownAndReservedKeys) {
  ConfigResult r = parse_config(R"({"ue_table":{"tomb_ms":600000,"tomb_max":4096,"max_uess":1},"alert":{"ues_maxx":1}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key ue_table.max_uess (ignored)",
                                                  "reserved key ue_table.tomb_ms (not used)",
                                                  "reserved key ue_table.tomb_max (not used)",
                                                  "unknown key alert.ues_maxx (ignored)"}));
  EXPECT_EQ(r.config.ue_table.max_ues, 4096u);
  auto up = parse_uplink_dos_config(R"({"n_fails":3})");
  ASSERT_TRUE(up.ok);
  EXPECT_EQ(up.warnings, (std::vector<std::string>{"unknown key rules.L3-21.n_fails (ignored)"}));
  EXPECT_EQ(parse_blind_dos_config(R"({"accept_wait":1})").warnings.size(), 1u);
  EXPECT_EQ(parse_auth_stall_config(R"({"n_stal":1})").warnings.size(), 1u);
}
