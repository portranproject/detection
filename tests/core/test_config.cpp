// 설정 파일 해석 테스트 (4_ §1.2, 결정 G3·J4)
#include "detect/config.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace detect;

namespace {

BtsVariantConfigResult bts_of(const std::string& whole_config) {
  ConfigResult r = parse_config(whole_config);
  EXPECT_TRUE(r.ok) << r.error;
  return parse_bts_variant_config(r.config.rules.at("L3-01-V"));
}

}  // namespace

// 저장소의 config/detector.json이 해석되고, max_conn(설정 파일만 96)과 출력 파일 회전·보관 키(설정 파일에서 켬 — 29_ §6)를
// 빼면 값이 구조체 기본값과 같다
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
  EXPECT_EQ(r.config.max_slots, d.max_slots);  // 11/05 W-31 — 저장소 설정 1,024 = 기본값
  // L3-01-V + 2단계 L3-20·L3-01-O·L3-21 (10/29 이슈 #33) + 3단계 L3-24·L3-14 (20_ §1.5) + 3단계로 올린 L3-06 (20_ §5.4)
  // + 4단계 AN-01·AN-06a·AN-02·AN-04·AN-07·AN-08 (21_ §1.2)
  ASSERT_EQ(r.config.rules.size(), 13u);
  ASSERT_TRUE(r.config.rules.count("L3-01-V"));
  BtsVariantConfigResult b = parse_bts_variant_config(r.config.rules.at("L3-01-V"));
  ASSERT_TRUE(b.ok) << b.error;
  EXPECT_TRUE(b.warnings.empty());
  const BtsVariantConfig bd;
  EXPECT_EQ(b.config.window_ms, bd.window_ms);
  EXPECT_EQ(b.config.a_min, bd.a_min);
  EXPECT_DOUBLE_EQ(b.config.theta, bd.theta);
  EXPECT_DOUBLE_EQ(b.config.f_abs_frac, bd.f_abs_frac);
  EXPECT_DOUBLE_EQ(bd.f_abs_frac, 0.1);  // 3_ §4 C2a 문턱 비율 기본값 — 셀 한도의 10% (11/12)
  EXPECT_DOUBLE_EQ(b.config.z, bd.z);
  EXPECT_DOUBLE_EQ(bd.z, 3.0);           // 3_ §4 C3 표준편차 배수 기본값 (11/12)
  EXPECT_EQ(b.config.h_sat_ms, bd.h_sat_ms);
  EXPECT_DOUBLE_EQ(b.config.baseline_tau_s, bd.baseline_tau_s);
  EXPECT_EQ(b.config.max_conn, 96);  // DU 셀 UE 한도 (4_ §6.1 #1, 10/27 이슈 #13 W-16). 구조체 기본값은 null(C4 끔)
  EXPECT_FALSE(bd.max_conn);
  EXPECT_EQ(r.config.evidence.mode, EvidenceMode::Full);
  EXPECT_FALSE(r.config.evidence.pre_slots);
  EXPECT_EQ(r.config.evidence.post_slots, 10u);
  EXPECT_EQ(r.config.evidence.queue_max, 4096u);
  EXPECT_EQ(r.config.evidence.out_path, "evidence.jsonl");
  // 입력 원본 기록은 저장소 설정에서 끔 — 현장 설정에서 켠다 (24_ §3.1)
  EXPECT_FALSE(r.config.input_record.path);
  EXPECT_EQ(r.config.input_record.queue_max_bytes, d.input_record.queue_max_bytes);
  // 출력 파일 회전·보관 (29_ §6, 11/08 이슈 #102): 코드 기본값은 모두 끔(0), 저장소 설정에서 켠다 — max_conn처럼 예외
  EXPECT_EQ(d.evidence.rotate_s, 0);
  EXPECT_EQ(d.evidence.rotate_max_bytes, 0u);
  EXPECT_EQ(d.evidence.keep_s, 0);
  EXPECT_EQ(d.input_record.rotate_s, 0);
  EXPECT_EQ(d.input_record.rotate_max_bytes, 0u);
  EXPECT_EQ(d.input_record.keep_s, 0);
  EXPECT_EQ(d.input_record.min_free_bytes, 0u);
  EXPECT_EQ(r.config.evidence.rotate_s, 3600);                       // 1시간
  EXPECT_EQ(r.config.evidence.rotate_max_bytes, 268435456u);         // 256 MiB
  EXPECT_EQ(r.config.evidence.keep_s, 604800);                       // 7일
  EXPECT_EQ(r.config.input_record.rotate_s, 3600);
  EXPECT_EQ(r.config.input_record.rotate_max_bytes, 268435456u);
  EXPECT_EQ(r.config.input_record.keep_s, 259200);                   // 3일
  EXPECT_EQ(r.config.input_record.min_free_bytes, 2147483648u);      // 2 GiB

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
  EXPECT_EQ(r.config.input_silent_ms, d.input_silent_ms);  // 입력 침묵 (3_ §8, Q-45 — 이슈 #50)
  EXPECT_EQ(d.input_silent_ms, 10000);
  EXPECT_EQ(ud.ghost_k, 2);
  EXPECT_EQ(ud.evict_protect_ms, 5000);
  EXPECT_EQ(d.max_cells, 64u);
  const AlertConfig ad;
  EXPECT_EQ(r.config.alert.ues_max, ad.ues_max);
  EXPECT_EQ(r.config.alert.update_min_ms, ad.update_min_ms);
  EXPECT_EQ(r.config.alert.ue_evidence_max, ad.ue_evidence_max);
  EXPECT_EQ(r.config.alert.held_alert, ad.held_alert);  // 불확실 경보 (14_ §9, 이슈 #48)
  EXPECT_TRUE(ad.held_alert);
  auto bl = parse_blind_dos_config(r.config.rules.at("L3-20"));
  ASSERT_TRUE(bl.ok) << bl.error;
  EXPECT_TRUE(bl.warnings.empty());
  EXPECT_EQ(bl.config.accept_wait_ms, BlindDosConfig{}.accept_wait_ms);
  EXPECT_EQ(BlindDosConfig{}.accept_wait_ms, 3000);  // 15_ §1.2·§2.4 — 11/15 사용자 결정 5,000 → 3,000
  EXPECT_EQ(bl.config.clear_quiet_ms, BlindDosConfig{}.clear_quiet_ms);
  auto st = parse_auth_stall_config(r.config.rules.at("L3-01-O"));
  ASSERT_TRUE(st.ok) << st.error;
  EXPECT_TRUE(st.warnings.empty());
  const AuthStallConfig sd;
  EXPECT_EQ(st.config.auth_wait_ms, sd.auth_wait_ms);
  EXPECT_EQ(st.config.window_ms, sd.window_ms);
  EXPECT_EQ(st.config.n_stall, sd.n_stall);
  EXPECT_DOUBLE_EQ(st.config.n_stall_frac, sd.n_stall_frac);
  EXPECT_DOUBLE_EQ(sd.n_stall_frac, 0.1);  // 15_ §1.2·§4.4 — 11/15 셀 한도 비율 문턱(96이면 N 10)
  EXPECT_EQ(st.config.clear_quiet_ms, sd.clear_quiet_ms);
  EXPECT_EQ(st.config.max_conn, sd.max_conn);
  auto up = parse_uplink_dos_config(r.config.rules.at("L3-21"));
  ASSERT_TRUE(up.ok) << up.error;
  EXPECT_TRUE(up.warnings.empty());
  const UplinkDosConfig pd;
  EXPECT_EQ(up.config.window_ms, pd.window_ms);
  EXPECT_EQ(up.config.n_fail, pd.n_fail);
  EXPECT_DOUBLE_EQ(up.config.n_fail_frac, pd.n_fail_frac);
  EXPECT_DOUBLE_EQ(pd.n_fail_frac, 0.1);  // 15_ §1.2·§5.4 — 11/15
  EXPECT_EQ(up.config.max_conn, pd.max_conn);
  EXPECT_EQ(pd.max_conn, 96);              // 15_ §5.4 — 11/15 추가, L3-01-O와 같은 값
  EXPECT_EQ(up.config.fail_accept_wait_ms, pd.fail_accept_wait_ms);
  EXPECT_EQ(pd.fail_accept_wait_ms, 3000);  // 15_ §1.2·§5.4 — 11/15 사용자 결정 5,000 → 3,000
  EXPECT_EQ(up.config.reg_repeat, pd.reg_repeat);
  EXPECT_EQ(up.config.clear_quiet_ms, pd.clear_quiet_ms);
  EXPECT_EQ(up.config.ignore_causes, pd.ignore_causes);
  // 3단계 키도 구조체 기본값과 같다 (20_ §1.5, 4_ §6.2 #3)
  auto ie = parse_imsi_extractor_config(r.config.rules.at("L3-24"));
  ASSERT_TRUE(ie.ok) << ie.error;
  EXPECT_TRUE(ie.warnings.empty());
  EXPECT_EQ(ie.config.clear_quiet_ms, ImsiExtractorConfig{}.clear_quiet_ms);
  EXPECT_EQ(ImsiExtractorConfig{}.clear_quiet_ms, 60000);
  auto ch = parse_cap_hijack_config(r.config.rules.at("L3-14"));
  ASSERT_TRUE(ch.ok) << ch.error;
  EXPECT_TRUE(ch.warnings.empty());
  EXPECT_EQ(ch.config.clear_quiet_ms, CapHijackConfig{}.clear_quiet_ms);
  EXPECT_EQ(CapHijackConfig{}.clear_quiet_ms, 60000);
  // 3단계로 올린 L3-06 (20_ §5.4)
  auto nd = parse_nas_desync_config(r.config.rules.at("L3-06"));
  ASSERT_TRUE(nd.ok) << nd.error;
  EXPECT_TRUE(nd.warnings.empty());
  EXPECT_EQ(nd.config.clear_quiet_ms, NasDesyncConfig{}.clear_quiet_ms);
  EXPECT_EQ(NasDesyncConfig{}.clear_quiet_ms, 60000);
  // 4단계 AN-01 (21_ §1.2·§3.4)
  auto sf = parse_sync_failure_config(r.config.rules.at("AN-01"));
  ASSERT_TRUE(sf.ok) << sf.error;
  EXPECT_TRUE(sf.warnings.empty());
  const SyncFailureConfig sfd;
  EXPECT_EQ(sf.config.window_ms, sfd.window_ms);
  EXPECT_EQ(sf.config.n_sync, sfd.n_sync);
  EXPECT_EQ(sf.config.clear_quiet_ms, sfd.clear_quiet_ms);
  EXPECT_EQ(sfd.window_ms, 60000);
  EXPECT_EQ(sfd.n_sync, 1);
  EXPECT_EQ(sfd.clear_quiet_ms, 60000);
  auto sr = parse_sec_reauth_config(r.config.rules.at("AN-06a"));  // 21_ §4.4
  ASSERT_TRUE(sr.ok) << sr.error;
  EXPECT_TRUE(sr.warnings.empty());
  EXPECT_EQ(sr.config.n_reauth, SecReauthConfig{}.n_reauth);
  EXPECT_EQ(sr.config.clear_quiet_ms, SecReauthConfig{}.clear_quiet_ms);
  EXPECT_EQ(SecReauthConfig{}.n_reauth, 1);
  EXPECT_EQ(SecReauthConfig{}.clear_quiet_ms, 60000);
  auto ir = parse_identity_request_config(r.config.rules.at("AN-02"));  // 21_ §5.4
  ASSERT_TRUE(ir.ok) << ir.error;
  EXPECT_TRUE(ir.warnings.empty());
  const IdentityRequestConfig ird;
  EXPECT_EQ(ir.config.window_ms, ird.window_ms);
  EXPECT_EQ(ir.config.n_idreq, ird.n_idreq);
  EXPECT_EQ(ir.config.clear_quiet_ms, ird.clear_quiet_ms);
  EXPECT_EQ(ird.window_ms, 60000);
  EXPECT_EQ(ird.n_idreq, 5);
  auto srr = parse_short_repeat_config(r.config.rules.at("AN-04"));  // 21_ §6.4
  ASSERT_TRUE(srr.ok) << srr.error;
  EXPECT_TRUE(srr.warnings.empty());
  const ShortRepeatConfig srd;
  EXPECT_EQ(srr.config.short_ms, srd.short_ms);
  EXPECT_EQ(srr.config.window_ms, srd.window_ms);
  EXPECT_EQ(srr.config.n_short, srd.n_short);
  EXPECT_EQ(srr.config.clear_quiet_ms, srd.clear_quiet_ms);
  EXPECT_EQ(srd.short_ms, 5000);
  EXPECT_EQ(srd.window_ms, 300000);
  EXPECT_EQ(srd.n_short, 3);
  auto spr = parse_setup_repeat_config(r.config.rules.at("AN-07"));  // 21_ §7.4
  ASSERT_TRUE(spr.ok) << spr.error;
  EXPECT_TRUE(spr.warnings.empty());
  const SetupRepeatConfig spd;
  EXPECT_EQ(spr.config.window_ms, spd.window_ms);
  EXPECT_EQ(spr.config.n_fail, spd.n_fail);
  EXPECT_EQ(spr.config.clear_quiet_ms, spd.clear_quiet_ms);
  EXPECT_EQ(spd.window_ms, 60000);
  EXPECT_EQ(spd.n_fail, 3);
  auto krr = parse_known_reg_burst_config(r.config.rules.at("AN-08"));  // 21_ §8.4
  ASSERT_TRUE(krr.ok) << krr.error;
  EXPECT_TRUE(krr.warnings.empty());
  const KnownRegBurstConfig krd;
  EXPECT_EQ(krr.config.window_ms, krd.window_ms);
  EXPECT_EQ(krr.config.n_reg, krd.n_reg);
  EXPECT_EQ(krr.config.known_ms, krd.known_ms);
  EXPECT_EQ(krr.config.clear_quiet_ms, krd.clear_quiet_ms);
  EXPECT_EQ(krd.n_reg, 5);
  EXPECT_EQ(krd.known_ms, 600000);
}

// 빠진 키는 기본값, 일부만 덮어쓰기
TEST(Config, PartialOverride) {
  const std::string text = R"({"rules":{"L3-01-V":{"theta":0.7,"f_abs_frac":0.2,"z":2.5,"max_conn":96}},"evidence":{"mode":"ref","pre_slots":300}})";
  ConfigResult r = parse_config(text);
  ASSERT_TRUE(r.ok) << r.error;
  BtsVariantConfigResult b = bts_of(text);
  ASSERT_TRUE(b.ok) << b.error;
  EXPECT_DOUBLE_EQ(b.config.theta, 0.7);
  EXPECT_EQ(b.config.max_conn, 96);
  EXPECT_DOUBLE_EQ(b.config.f_abs_frac, 0.2);
  EXPECT_DOUBLE_EQ(b.config.z, 2.5);
  EXPECT_EQ(b.config.a_min, 5);
  EXPECT_EQ(r.config.evidence.mode, EvidenceMode::Ref);
  EXPECT_EQ(r.config.evidence.pre_slots, 300u);
  EXPECT_EQ(r.config.socket_path, "/run/ran-detect/kpm.sock");
  EXPECT_EQ(r.config.input_silent_ms, 10000);
  EXPECT_EQ(parse_config(R"({"input_silent_ms":1500})").config.input_silent_ms, 1500);
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
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"f_abs_frac":0}}})").ok);    // (0, 1] (3_ §4, 11/12)
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"f_abs_frac":1.5}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"f_abs_frac":"0.1"}}})").ok);
  EXPECT_TRUE(bts_of(R"({"rules":{"L3-01-V":{"f_abs_frac":1}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"z":-0.5}}})").ok);  // 0 이상 (3_ §4, 11/12)
  EXPECT_TRUE(bts_of(R"({"rules":{"L3-01-V":{"z":0}}})").ok);       // 0이면 문턱이 base 자체
  // 11/12 전 키 f_abs·k는 모르는 키 — 경고만 하고 무시한다 (4_ §1.2)
  auto old = bts_of(R"({"rules":{"L3-01-V":{"f_abs":10,"k":3}}})");
  EXPECT_TRUE(old.ok);
  EXPECT_EQ(old.warnings.size(), 2u);
  EXPECT_FALSE(parse_bts_variant_config("[1]").ok);
  auto b = bts_of(R"({"rules":{"L3-01-V":{"window_ms":-1}}})");
  EXPECT_FALSE(b.ok);
  EXPECT_NE(b.error.find("window_ms"), std::string::npos);
}

// 11/05 W-31 (이슈 #92): 정수 필드 상한 — INT_MAX 초과값이 잘려 들어가지 않게 (m_raise 4294967297이 1이 됐다), 최상위 max_slots 범위
TEST(Config, IntegerBoundsAndMaxSlots) {
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"m_raise":4294967297}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"k_clear":0}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"k_clear":1000001}}})").ok);
  EXPECT_FALSE(bts_of(R"({"rules":{"L3-01-V":{"missing_key_slots":-1}}})").ok);
  auto ok = bts_of(R"({"rules":{"L3-01-V":{"m_raise":1000000,"k_clear":1,"missing_key_slots":0}}})");
  ASSERT_TRUE(ok.ok) << ok.error;
  EXPECT_EQ(ok.config.m_raise, 1000000);
  EXPECT_EQ(parse_config("{}").config.max_slots, 1024u);
  EXPECT_EQ(parse_config(R"({"max_slots":32})").config.max_slots, 32u);
  EXPECT_EQ(parse_config(R"({"max_slots":65536})").config.max_slots, 65536u);
  EXPECT_FALSE(parse_config(R"({"max_slots":31})").ok);
  EXPECT_FALSE(parse_config(R"({"max_slots":65537})").ok);
  EXPECT_FALSE(parse_config(R"({"max_slots":"many"})").ok);
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
  EXPECT_FALSE(parse_config(R"({"alert":{"held_alert":false}})").config.alert.held_alert);
  EXPECT_FALSE(parse_config(R"({"alert":{"held_alert":1}})").ok);  // 불리언만
  EXPECT_FALSE(parse_config(R"({"alert":{"held_alert":"true"}})").ok);

  auto bl = parse_blind_dos_config(R"({"accept_wait_ms":4000,"clear_quiet_ms":30000})");
  ASSERT_TRUE(bl.ok) << bl.error;
  EXPECT_EQ(bl.config.accept_wait_ms, 4000);
  EXPECT_EQ(bl.config.clear_quiet_ms, 30000);
  auto st = parse_auth_stall_config(
      R"({"auth_wait_ms":1500,"window_ms":5000,"n_stall":3,"n_stall_frac":0.25,"clear_quiet_ms":2000,"max_conn":null})");
  ASSERT_TRUE(st.ok) << st.error;
  EXPECT_TRUE(st.warnings.empty());
  EXPECT_EQ(st.config.auth_wait_ms, 1500);
  EXPECT_EQ(st.config.window_ms, 5000);
  EXPECT_EQ(st.config.n_stall, 3);
  EXPECT_DOUBLE_EQ(st.config.n_stall_frac, 0.25);
  EXPECT_EQ(st.config.clear_quiet_ms, 2000);
  EXPECT_FALSE(st.config.max_conn);  // null이면 심각도 high를 쓰지 않고 문턱 N = n_stall (15_ §1.2)
  EXPECT_EQ(parse_auth_stall_config(R"({"max_conn":50})").config.max_conn, 50);
  auto up = parse_uplink_dos_config(
      R"({"window_ms":20000,"n_fail":3,"n_fail_frac":0.2,"max_conn":null,"fail_accept_wait_ms":4000,"reg_repeat":4,)"
      R"("clear_quiet_ms":120000,"ignore_causes":[9,22]})");
  ASSERT_TRUE(up.ok) << up.error;
  EXPECT_TRUE(up.warnings.empty());
  EXPECT_EQ(up.config.window_ms, 20000);
  EXPECT_EQ(up.config.n_fail, 3);
  EXPECT_DOUBLE_EQ(up.config.n_fail_frac, 0.2);
  EXPECT_FALSE(up.config.max_conn);  // null이면 문턱 N = n_fail (15_ §1.2)
  EXPECT_EQ(parse_uplink_dos_config(R"({"max_conn":256})").config.max_conn, 256);
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
      {"ue_table", "tomb_ms", 60000, 86400000},     {"ue_table", "tomb_max", 100, 65536},  // S-TMSI 이력 표 (14_ §9)
      {"ue_table", "alloc_ms", 60000, 86400000},    {"ue_table", "alloc_max", 100, 65536},
      {"top", "input_silent_ms", 1000, 600000},
      {"alert", "ues_max", 1, 1000},                {"alert", "update_min_ms", 100, 60000},
      {"alert", "ue_evidence_max", 0, 1000},        {"L3-20", "accept_wait_ms", 100, 60000},
      {"L3-20", "clear_quiet_ms", 1000, 3600000},   {"L3-01-O", "auth_wait_ms", 100, 60000},
      {"L3-01-O", "window_ms", 1000, 600000},       {"L3-01-O", "n_stall", 1, 10000},
      {"L3-01-O", "clear_quiet_ms", 1000, 3600000}, {"L3-21", "window_ms", 1000, 600000},
      {"L3-21", "n_fail", 1, 10000},                {"L3-21", "fail_accept_wait_ms", 100, 60000},
      {"L3-21", "reg_repeat", 2, 100},              {"L3-21", "clear_quiet_ms", 1000, 3600000},
      {"L3-24", "clear_quiet_ms", 1000, 3600000},  // 3단계 (20_ §1.5, L24-T25)
      {"L3-14", "clear_quiet_ms", 1000, 3600000},  // 3단계 (20_ §1.5, L14-T20)
      {"L3-06", "clear_quiet_ms", 1000, 3600000},  // 3단계로 올린 L3-06 (20_ §5.4, L06-T20)
      {"AN-01", "window_ms", 1000, 600000},        // 4단계 (21_ §1.2, AN01-T11)
      {"AN-01", "n_sync", 1, 10000},               {"AN-01", "clear_quiet_ms", 1000, 3600000},
      {"AN-06a", "n_reauth", 1, 100},              {"AN-06a", "clear_quiet_ms", 1000, 3600000},  // AN06a-T10
      {"AN-02", "window_ms", 1000, 600000},        {"AN-02", "n_idreq", 1, 10000},  // AN02-T8
      {"AN-02", "clear_quiet_ms", 1000, 3600000},
      {"AN-04", "short_ms", 100, 600000},          {"AN-04", "window_ms", 1000, 600000},  // AN04-T8
      {"AN-04", "n_short", 2, 10000},              {"AN-04", "clear_quiet_ms", 1000, 3600000},
      {"AN-07", "window_ms", 1000, 600000},        {"AN-07", "n_fail", 2, 10000},  // AN07-T7
      {"AN-07", "clear_quiet_ms", 1000, 3600000},
      {"AN-08", "window_ms", 1000, 600000},        {"AN-08", "n_reg", 1, 10000},  // AN08-T7
      {"AN-08", "known_ms", 1000, 86400000},       {"AN-08", "clear_quiet_ms", 1000, 3600000},
  };
  auto accepts = [](const Range& r, int64_t v, std::string* error = nullptr) {
    const std::string obj = "{\"" + r.key + "\":" + std::to_string(v) + "}";
    bool ok = false;
    std::string err;
    if (r.section == "ue_table" || r.section == "alert") {
      ConfigResult c = parse_config("{\"" + r.section + "\":" + obj + "}");
      ok = c.ok;
      err = c.error;
    } else if (r.section == "top") {  // 최상위 키 (max_cells·input_silent_ms)
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
    } else if (r.section == "L3-24") {
      auto c = parse_imsi_extractor_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "L3-14") {
      auto c = parse_cap_hijack_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "L3-06") {
      auto c = parse_nas_desync_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "AN-01") {
      auto c = parse_sync_failure_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "AN-06a") {
      auto c = parse_sec_reauth_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "AN-02") {
      auto c = parse_identity_request_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "AN-04") {
      auto c = parse_short_repeat_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "AN-07") {
      auto c = parse_setup_repeat_config(obj);
      ok = c.ok;
      err = c.error;
    } else if (r.section == "AN-08") {
      auto c = parse_known_reg_burst_config(obj);
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
  EXPECT_FALSE(parse_config(R"({"input_silent_ms":"10000"})").ok);
  EXPECT_FALSE(parse_config(R"({"input_silent_ms":10000.0})").ok);
  EXPECT_FALSE(parse_config(R"({"input_silent_ms":null})").ok);
  EXPECT_FALSE(parse_blind_dos_config(R"({"accept_wait_ms":5000.0})").ok);
  EXPECT_FALSE(parse_auth_stall_config(R"({"max_conn":0})").ok);
  EXPECT_FALSE(parse_auth_stall_config(R"({"max_conn":"96"})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"reg_repeat":true})").ok);
  EXPECT_FALSE(parse_uplink_dos_config("[1]").ok);
  EXPECT_EQ(parse_auth_stall_config("[1]").error, "config: rules.L3-01-O: not an object");
}

// 셀 한도 비율 문턱 키 (15_ §1.2 — 11/15 사용자 결정, L01-T25·L21-T28): n_stall_frac·n_fail_frac은 실수 [0, 1](0은 비율을 쓰지
// 않음 — 1단계 f_abs_frac (0, 1]과 다름), L3-21 max_conn은 1 이상 또는 null(L3-01-O와 같음). 범위 밖·문자열은 오류(종료 코드 1)
TEST(Config, Stage2CellRatioKeys) {
  for (const char* v : {"0", "1", "0.0", "1.0", "0.25"}) {
    const std::string s = std::string("{\"n_stall_frac\":") + v + "}";
    const std::string f = std::string("{\"n_fail_frac\":") + v + "}";
    EXPECT_TRUE(parse_auth_stall_config(s).ok) << s;
    EXPECT_TRUE(parse_uplink_dos_config(f).ok) << f;
  }
  EXPECT_DOUBLE_EQ(parse_auth_stall_config(R"({"n_stall_frac":0})").config.n_stall_frac, 0.0);
  EXPECT_DOUBLE_EQ(parse_uplink_dos_config(R"({"n_fail_frac":1})").config.n_fail_frac, 1.0);
  for (const char* v : {"-0.1", "1.5", "-1", "2"}) {
    const std::string s = std::string("{\"n_stall_frac\":") + v + "}";
    const std::string f = std::string("{\"n_fail_frac\":") + v + "}";
    const auto st = parse_auth_stall_config(s);
    const auto up = parse_uplink_dos_config(f);
    EXPECT_FALSE(st.ok) << s;
    EXPECT_FALSE(up.ok) << f;
    EXPECT_EQ(st.error, "config: rules.L3-01-O.n_stall_frac: out of range [0, 1]") << s;
    EXPECT_EQ(up.error, "config: rules.L3-21.n_fail_frac: out of range [0, 1]") << f;
  }
  for (const char* v : {R"("0.1")", "null", "true", "[0.1]"}) {
    const std::string s = std::string("{\"n_stall_frac\":") + v + "}";
    const std::string f = std::string("{\"n_fail_frac\":") + v + "}";
    EXPECT_EQ(parse_auth_stall_config(s).error, "config: rules.L3-01-O.n_stall_frac: not a number") << s;
    EXPECT_EQ(parse_uplink_dos_config(f).error, "config: rules.L3-21.n_fail_frac: not a number") << f;
  }
  // L3-21 max_conn (11/15 추가) — 1 이상 정수 또는 null. 상한은 없다
  EXPECT_TRUE(parse_uplink_dos_config(R"({"max_conn":1})").ok);
  EXPECT_EQ(parse_uplink_dos_config(R"({"max_conn":1000000})").config.max_conn, 1000000);
  const auto nul = parse_uplink_dos_config(R"({"max_conn":null})");
  ASSERT_TRUE(nul.ok) << nul.error;
  EXPECT_FALSE(nul.config.max_conn);
  EXPECT_NE(parse_uplink_dos_config(R"({"max_conn":0})").error.find("max_conn: out of range"), std::string::npos);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"max_conn":-5})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"max_conn":"96"})").ok);
  EXPECT_FALSE(parse_uplink_dos_config(R"({"max_conn":96.5})").ok);
  EXPECT_FALSE(parse_auth_stall_config(R"({"max_conn":-1})").ok);
  // 최상위 해석은 룰 절을 JSON 그대로 넘기고(Q-46), 룰을 만들 때 키 표로 읽어 이 오류가 난다 — main은 이 오류로 종료 코드 1
  const ConfigResult r = parse_config(R"({"rules":{"L3-21":{"n_fail_frac":1.5}}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(parse_uplink_dos_config(r.config.rules.at("L3-21")).error,
            "config: rules.L3-21.n_fail_frac: out of range [0, 1]");
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

// 모르는 키는 경고만. ue_table.tomb_ms·tomb_max는 10/29까지 예약 키('쓰지 않음' 경고)였으나 11/03 S-TMSI 이력 표 키가 되어
// 경고 없이 읽는다(alloc_*와 함께 — 14_ §3.2·§9, 11/04 이슈 #74)
TEST(Config, Stage2UnknownAndReservedKeys) {
  ConfigResult r = parse_config(
      R"({"ue_table":{"tomb_ms":120000,"tomb_max":200,"alloc_ms":7200000,"alloc_max":300,"max_uess":1},"alert":{"ues_maxx":1}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key ue_table.max_uess (ignored)",
                                                  "unknown key alert.ues_maxx (ignored)"}));
  EXPECT_EQ(r.config.ue_table.max_ues, 4096u);
  EXPECT_EQ(r.config.ue_table.tomb_ms, 120000);
  EXPECT_EQ(r.config.ue_table.tomb_max, 200u);
  EXPECT_EQ(r.config.ue_table.alloc_ms, 7200000);
  EXPECT_EQ(r.config.ue_table.alloc_max, 300u);
  auto up = parse_uplink_dos_config(R"({"n_fails":3})");
  ASSERT_TRUE(up.ok);
  EXPECT_EQ(up.warnings, (std::vector<std::string>{"unknown key rules.L3-21.n_fails (ignored)"}));
  EXPECT_EQ(parse_blind_dos_config(R"({"accept_wait":1})").warnings.size(), 1u);
  EXPECT_EQ(parse_auth_stall_config(R"({"n_stal":1})").warnings.size(), 1u);
}

// L24-T25 (20_ §3.8·§1.5): rules.L3-24.clear_quiet_ms — 999·3,600,001·문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage3ImsiExtractor) {
  EXPECT_TRUE(parse_imsi_extractor_config(R"({"clear_quiet_ms":1000})").ok);
  EXPECT_TRUE(parse_imsi_extractor_config(R"({"clear_quiet_ms":3600000})").ok);
  EXPECT_FALSE(parse_imsi_extractor_config(R"({"clear_quiet_ms":999})").ok);
  EXPECT_FALSE(parse_imsi_extractor_config(R"({"clear_quiet_ms":3600001})").ok);
  EXPECT_FALSE(parse_imsi_extractor_config(R"({"clear_quiet_ms":"60000"})").ok);
  EXPECT_FALSE(parse_imsi_extractor_config(R"({"clear_quiet_ms":60000.5})").ok);
  auto r = parse_imsi_extractor_config(R"({"clear_quiet":1})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.L3-24.clear_quiet (ignored)"}));
  EXPECT_EQ(r.config.clear_quiet_ms, 60000);
}

// L14-T20 (20_ §4.8·§1.5): rules.L3-14.clear_quiet_ms — 범위 밖·문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage3CapHijack) {
  EXPECT_TRUE(parse_cap_hijack_config(R"({"clear_quiet_ms":1000})").ok);
  EXPECT_TRUE(parse_cap_hijack_config(R"({"clear_quiet_ms":3600000})").ok);
  EXPECT_FALSE(parse_cap_hijack_config(R"({"clear_quiet_ms":999})").ok);
  EXPECT_FALSE(parse_cap_hijack_config(R"({"clear_quiet_ms":3600001})").ok);
  EXPECT_FALSE(parse_cap_hijack_config(R"({"clear_quiet_ms":"60000"})").ok);
  auto r = parse_cap_hijack_config(R"({"branch2":true})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.L3-14.branch2 (ignored)"}));
}

// L06-T20 (20_ §5.8·§5.4): rules.L3-06.clear_quiet_ms — 범위 밖·문자열·실수는 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage3NasDesync) {
  EXPECT_TRUE(parse_nas_desync_config(R"({"clear_quiet_ms":1000})").ok);
  EXPECT_TRUE(parse_nas_desync_config(R"({"clear_quiet_ms":3600000})").ok);
  EXPECT_FALSE(parse_nas_desync_config(R"({"clear_quiet_ms":999})").ok);
  EXPECT_FALSE(parse_nas_desync_config(R"({"clear_quiet_ms":3600001})").ok);
  EXPECT_FALSE(parse_nas_desync_config(R"({"clear_quiet_ms":"60000"})").ok);
  EXPECT_FALSE(parse_nas_desync_config(R"({"clear_quiet_ms":60000.5})").ok);
  auto r = parse_nas_desync_config(R"({"wait_ms":1})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.L3-06.wait_ms (ignored)"}));
  EXPECT_EQ(r.config.clear_quiet_ms, 60000);
}

// AN01-T11 (21_ §3.8·§1.2): rules.AN-01 — window_ms 999·n_sync 0·clear_quiet_ms 문자열은 오류(실행 파일은 종료 코드 1),
// 모르는 키는 경고만
TEST(Config, Stage4SyncFailure) {
  EXPECT_FALSE(parse_sync_failure_config(R"({"window_ms":999})").ok);
  EXPECT_FALSE(parse_sync_failure_config(R"({"n_sync":0})").ok);
  EXPECT_FALSE(parse_sync_failure_config(R"({"clear_quiet_ms":"60000"})").ok);
  EXPECT_FALSE(parse_sync_failure_config(R"({"n_sync":1.5})").ok);
  auto ok = parse_sync_failure_config(R"({"window_ms":1000,"n_sync":10000,"clear_quiet_ms":3600000})");
  ASSERT_TRUE(ok.ok) << ok.error;
  EXPECT_EQ(ok.config.n_sync, 10000);
  auto r = parse_sync_failure_config(R"({"n_reauth":1})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.AN-01.n_reauth (ignored)"}));
}

// AN06a-T10 (21_ §4.8·§1.2): rules.AN-06a — n_reauth 0·101·clear_quiet_ms 문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage4SecReauth) {
  EXPECT_FALSE(parse_sec_reauth_config(R"({"n_reauth":0})").ok);
  EXPECT_FALSE(parse_sec_reauth_config(R"({"n_reauth":101})").ok);
  EXPECT_FALSE(parse_sec_reauth_config(R"({"clear_quiet_ms":"60000"})").ok);
  auto ok = parse_sec_reauth_config(R"({"n_reauth":100,"clear_quiet_ms":1000})");
  ASSERT_TRUE(ok.ok) << ok.error;
  EXPECT_EQ(ok.config.n_reauth, 100);
  auto r = parse_sec_reauth_config(R"({"window_ms":1})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.AN-06a.window_ms (ignored)"}));
}

// AN02-T8 (21_ §5.8·§1.2): rules.AN-02 — 범위 밖·문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage4IdentityRequest) {
  EXPECT_FALSE(parse_identity_request_config(R"({"window_ms":999})").ok);
  EXPECT_FALSE(parse_identity_request_config(R"({"n_idreq":0})").ok);
  EXPECT_FALSE(parse_identity_request_config(R"({"clear_quiet_ms":"60000"})").ok);
  auto r = parse_identity_request_config(R"({"n_sync":1})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.AN-02.n_sync (ignored)"}));
}

// AN04-T8 (21_ §6.8·§1.2): rules.AN-04 — n_short 1(하한 2)·범위 밖·문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage4ShortRepeat) {
  EXPECT_FALSE(parse_short_repeat_config(R"({"n_short":1})").ok);
  EXPECT_FALSE(parse_short_repeat_config(R"({"short_ms":99})").ok);
  EXPECT_FALSE(parse_short_repeat_config(R"({"window_ms":"300000"})").ok);
  auto r = parse_short_repeat_config(R"({"n_fail":3})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.AN-04.n_fail (ignored)"}));
}

// AN07-T7 (21_ §7.8·§1.2): rules.AN-07 — n_fail 1(하한 2)·범위 밖·문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage4SetupRepeat) {
  EXPECT_FALSE(parse_setup_repeat_config(R"({"n_fail":1})").ok);
  EXPECT_FALSE(parse_setup_repeat_config(R"({"window_ms":999})").ok);
  EXPECT_FALSE(parse_setup_repeat_config(R"({"clear_quiet_ms":"60000"})").ok);
  auto r = parse_setup_repeat_config(R"({"n_short":3})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.AN-07.n_short (ignored)"}));
}

// AN08-T7 (21_ §8.8·§1.2): rules.AN-08 — n_reg 0·범위 밖·문자열은 오류(실행 파일은 종료 코드 1), 모르는 키는 경고만
TEST(Config, Stage4KnownRegBurst) {
  EXPECT_FALSE(parse_known_reg_burst_config(R"({"n_reg":0})").ok);
  EXPECT_FALSE(parse_known_reg_burst_config(R"({"known_ms":999})").ok);
  EXPECT_FALSE(parse_known_reg_burst_config(R"({"window_ms":"60000"})").ok);
  auto r = parse_known_reg_burst_config(R"({"n_fail":3})");
  ASSERT_TRUE(r.ok);
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key rules.AN-08.n_fail (ignored)"}));
}

// IR-T9 설정 부분 (24_ §3.1·§8.1): input_record — 기본은 끔·8 MiB, path는 null 또는 빈 문자열이 아닌 문자열,
// queue_max_bytes는 65,536~67,108,864, 모르는 키는 경고만. 증거 파일과 같은 경로인지는 실행 파일이 본다(통합 시험)
TEST(Config, InputRecord) {
  const InputRecordConfig d;
  EXPECT_FALSE(d.path);
  EXPECT_EQ(d.queue_max_bytes, 8388608u);

  auto r = parse_config(R"({"input_record":{"path":"input.jsonl","queue_max_bytes":65536}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_TRUE(r.warnings.empty());
  ASSERT_TRUE(r.config.input_record.path);
  EXPECT_EQ(*r.config.input_record.path, "input.jsonl");
  EXPECT_EQ(r.config.input_record.queue_max_bytes, 65536u);

  r = parse_config(R"({"input_record":{"path":null,"queue_max_bytes":67108864}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_FALSE(r.config.input_record.path);
  EXPECT_EQ(r.config.input_record.queue_max_bytes, 67108864u);

  r = parse_config(R"({"input_record":{"path":"input.jsonl","patth":1}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key input_record.patth (ignored)"}));

  EXPECT_FALSE(parse_config(R"({"input_record":{"path":""}})").ok);
  EXPECT_FALSE(parse_config(R"({"input_record":{"path":5}})").ok);
  EXPECT_FALSE(parse_config(R"({"input_record":{"queue_max_bytes":65535}})").ok);
  EXPECT_FALSE(parse_config(R"({"input_record":{"queue_max_bytes":67108865}})").ok);
  EXPECT_FALSE(parse_config(R"({"input_record":{"queue_max_bytes":"8M"}})").ok);
  EXPECT_FALSE(parse_config(R"({"input_record":"input.jsonl"})").ok);
  auto e = parse_config(R"({"input_record":{"queue_max_bytes":1}})");
  EXPECT_NE(e.error.find("input_record.queue_max_bytes"), std::string::npos) << e.error;
}

// RT-T11 (29_ §6·§8.1, 11/08 이슈 #102): 출력 파일 회전·보관 키 — 0(끔) 또는 범위 안. 범위 밖·타입 틀림은 오류, keep_s·min_free_bytes도
// 받아들이고(탐지 엔진은 검사만) 모르는 키 경고가 나지 않는다
TEST(Config, RotationKeys) {
  auto r = parse_config(R"({"evidence":{"rotate_s":60,"rotate_max_bytes":1048576,"keep_s":3600},
                            "input_record":{"path":"input.jsonl","rotate_s":86400,"rotate_max_bytes":4294967296,
                                            "keep_s":31536000,"min_free_bytes":1099511627776}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_TRUE(r.warnings.empty());
  EXPECT_EQ(r.config.evidence.rotate_s, 60);
  EXPECT_EQ(r.config.evidence.rotate_max_bytes, 1048576u);
  EXPECT_EQ(r.config.evidence.keep_s, 3600);
  EXPECT_EQ(r.config.input_record.rotate_s, 86400);
  EXPECT_EQ(r.config.input_record.rotate_max_bytes, 4294967296u);
  EXPECT_EQ(r.config.input_record.keep_s, 31536000);
  EXPECT_EQ(r.config.input_record.min_free_bytes, 1099511627776u);

  r = parse_config(R"({"evidence":{"rotate_s":0,"rotate_max_bytes":0,"keep_s":0},
                       "input_record":{"rotate_s":0,"rotate_max_bytes":0,"keep_s":0,"min_free_bytes":104857600}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_TRUE(r.warnings.empty());
  EXPECT_EQ(r.config.evidence.rotate_s, 0);
  EXPECT_EQ(r.config.input_record.min_free_bytes, 104857600u);

  for (const char* sec : {"evidence", "input_record"}) {
    const std::string s = sec;
    for (const auto& [kv, key] : std::vector<std::pair<std::string, std::string>>{
             {R"("rotate_s":59)", "rotate_s"},
             {R"("rotate_s":86401)", "rotate_s"},
             {R"("rotate_s":-1)", "rotate_s"},
             {R"("rotate_s":"3600")", "rotate_s"},
             {R"("rotate_s":3600.5)", "rotate_s"},
             {R"("rotate_max_bytes":1048575)", "rotate_max_bytes"},
             {R"("rotate_max_bytes":4294967297)", "rotate_max_bytes"},
             {R"("rotate_max_bytes":null)", "rotate_max_bytes"},
             {R"("keep_s":3599)", "keep_s"},
             {R"("keep_s":31536001)", "keep_s"},
             {R"("keep_s":true)", "keep_s"},
         }) {
      auto e = parse_config("{\"" + s + "\":{" + kv + "}}");
      EXPECT_FALSE(e.ok) << s << " " << kv;
      EXPECT_NE(e.error.find(s + "." + key), std::string::npos) << e.error;
    }
  }
  for (const char* kv : {R"("min_free_bytes":104857599)", R"("min_free_bytes":1099511627777)", R"("min_free_bytes":"2G")"}) {
    auto e = parse_config(std::string(R"({"input_record":{)") + kv + "}}");
    EXPECT_FALSE(e.ok) << kv;
    EXPECT_NE(e.error.find("input_record.min_free_bytes"), std::string::npos) << e.error;
  }
  // min_free_bytes는 입력 기록에만 — 증거에 두면 모르는 키 경고
  r = parse_config(R"({"evidence":{"min_free_bytes":2147483648}})");
  ASSERT_TRUE(r.ok) << r.error;
  EXPECT_EQ(r.warnings, (std::vector<std::string>{"unknown key evidence.min_free_bytes (ignored)"}));
}
