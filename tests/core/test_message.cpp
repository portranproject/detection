// message 파서 단위 테스트 (4_ §4-1) — 2_ §1~§6의 형식 규칙
#include "detect/message.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace detect;

namespace {

// 2_ §3 예시 그대로
const std::string kHello =
    R"({"type":"hello","ver":1,"session":"20261017T034950Z","seq":1,"producer":"ebpf-analyzer 0.1","node_id":"cu-p4","cells":[{"cell_id":1,"max_conn":null}],"period_ms":100,"noreply_timeout_ms":1000,"si_sample_ms":10,"clock":"realtime"})";

// 2_ §4 예시 그대로
const std::string kKpm2 =
    R"({"type":"kpm2","ver":1,"session":"20261017T034950Z","seq":102,"cell_id":1,"t_start_ms":1792209000100,"t_end_ms":1792209000200,"cc":{"RRC.ConnEstabAtt":{"total":9,"mo-Signalling":9},"RRC.ConnEstabSucc":{"total":2,"mo-Signalling":2},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":5,"Other":0},"RRC.RelWithoutSuspendConfig":1,"UECNTX.ConnEstabAtt":{"total":2},"UECNTX.ConnEstabSucc":{"total":2},"RRC.ReEstabAtt":0,"RRC.ReEstabSuccWithUeContext":0,"RRC.ResumeAtt":{"total":0},"RRC.ResumeSucc":{"total":0}},"si":{"RRC.ConnMean":7.4,"RRC.ConnMax":9,"RRC.InactiveConnMean":0,"RRC.InactiveConnMax":0},"ext":{"CrntiAlloc":9}})";

// 공통 머리 + 본문으로 kpm2 줄을 만든다
std::string kpm2_with(const std::string& body) {
  return R"({"type":"kpm2","ver":1,"session":"s","seq":2,"cell_id":1,"t_start_ms":0,"t_end_ms":100)" +
         (body.empty() ? "" : "," + body) + "}";
}

std::string hello_with(const std::string& body) {
  return R"({"type":"hello","ver":1,"session":"s","seq":1)" + (body.empty() ? "" : "," + body) + "}";
}

const Kpm2& kpm(const ParseResult& r) { return std::get<Kpm2>(r.msg); }

}  // namespace

// ---- 정상 ----

TEST(Message, HelloExample) {
  auto r = parse_line(kHello);
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  ASSERT_TRUE(r.common);
  EXPECT_EQ(r.common->type, "hello");
  EXPECT_EQ(r.common->session, "20261017T034950Z");
  EXPECT_EQ(r.common->seq, 1);
  const auto& h = std::get<Hello>(r.msg);
  EXPECT_EQ(h.producer, "ebpf-analyzer 0.1");
  EXPECT_EQ(h.node_id, "cu-p4");
  ASSERT_EQ(h.cells.size(), 1u);
  EXPECT_EQ(h.cells[0].cell_id, 1);
  EXPECT_FALSE(h.cells[0].max_conn);
  EXPECT_EQ(h.period_ms, 100);
  EXPECT_EQ(h.noreply_timeout_ms, 1000);
  EXPECT_EQ(h.si_sample_ms, 10);
  EXPECT_EQ(h.clock, "realtime");
  EXPECT_TRUE(r.warnings.empty());
}

TEST(Message, Kpm2Example) {
  auto r = parse_line(kKpm2);
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  const auto& k = kpm(r);
  EXPECT_EQ(r.common->seq, 102);
  EXPECT_EQ(k.cell_id, 1);
  EXPECT_EQ(k.t_start_ms, 1792209000100);
  EXPECT_EQ(k.t_end_ms, 1792209000200);
  EXPECT_EQ(k.conn_estab_att.total, 9);
  EXPECT_EQ(k.conn_estab_att.causes.at("mo-Signalling"), 9);
  EXPECT_EQ(k.conn_estab_succ.total, 2);
  EXPECT_EQ(k.fail_no_reply, 5);
  EXPECT_EQ(k.fail_network_reject, 0);
  EXPECT_EQ(k.fail_other, 0);
  EXPECT_EQ(k.rel_without_suspend_config, 1);
  EXPECT_EQ(k.uecntx_estab_att.total, 2);
  EXPECT_EQ(k.uecntx_estab_succ.total, 2);
  EXPECT_EQ(k.reestab_att, 0);
  EXPECT_EQ(k.reestab_succ_with_ue_context, 0);
  EXPECT_EQ(k.resume_att.total, 0);
  EXPECT_EQ(k.resume_succ.total, 0);
  EXPECT_DOUBLE_EQ(*k.conn_mean, 7.4);
  EXPECT_EQ(k.conn_max, 9);
  EXPECT_DOUBLE_EQ(*k.inactive_conn_mean, 0.0);
  EXPECT_EQ(k.inactive_conn_max, 0);
  EXPECT_EQ(k.crnti_alloc, 9);
  EXPECT_FALSE(k.ue_ctx_max);
  EXPECT_FALSE(k.du_cannot_serve);
  EXPECT_TRUE(r.warnings.empty());
}

// 3_ §7.1: raw는 받은 문자열 그대로(키 순서·숫자 표기 유지)
TEST(Message, Kpm2RawIsByteExact) {
  auto r = parse_line(kKpm2);
  ASSERT_EQ(r.status, ParseStatus::Ok);
  EXPECT_EQ(kpm(r).raw, kKpm2);
}

// 2_ §2: 모르는 필드는 무시
TEST(Message, UnknownFieldsIgnored) {
  auto r = parse_line(kpm2_with(R"("future":{"x":1},"cc":{"RRC.ConnEstabAtt":{"total":1},"New.Counter":3})"));
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  EXPECT_EQ(kpm(r).conn_estab_att.total, 1);
}

// ---- 오류 ----

TEST(Message, InvalidJson) {
  EXPECT_EQ(parse_line("not json").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1)").status, ParseStatus::FormatError);  // 잘린 줄
  EXPECT_EQ(parse_line("").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"a":1} {"b":2})").status, ParseStatus::FormatError);  // 한 줄에 객체 2개
}

TEST(Message, NotAnObject) {
  EXPECT_EQ(parse_line("[1,2]").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line("42").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"("hello")").status, ParseStatus::FormatError);
}

TEST(Message, CommonFieldsMissingOrWrongType) {
  EXPECT_EQ(parse_line(R"({"ver":1,"session":"s","seq":1})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","session":"s","seq":1})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"seq":1})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s"})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":7,"ver":1,"session":"s","seq":1})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":"1","session":"s","seq":1})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"","seq":1})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":"1"})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":0})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":1.5})").status, ParseStatus::FormatError);
}

// 2_ §3: ver를 모르면 그 줄을 버린다
TEST(Message, UnsupportedVersion) {
  auto r = parse_line(R"({"type":"kpm2","ver":2,"session":"s","seq":5,"cell_id":1})");
  EXPECT_EQ(r.status, ParseStatus::UnsupportedVersion);
  ASSERT_TRUE(r.common);
  EXPECT_EQ(r.common->seq, 5);
  EXPECT_EQ(parse_line(R"({"type":"hello","ver":2,"session":"s","seq":1})").status,
            ParseStatus::UnsupportedVersion);
}

// 2_ §2: 모르는 type은 무시
TEST(Message, UnknownType) {
  auto r = parse_line(R"({"type":"future_msg","ver":1,"session":"s","seq":3})");
  EXPECT_EQ(r.status, ParseStatus::UnknownType);
  ASSERT_TRUE(r.common);
  EXPECT_EQ(r.common->seq, 3);
}

// 2_ §1: 줄 길이 상한 64 KiB
TEST(Message, LineTooLong) {
  std::string pad(kDefaultMaxLineBytes, ' ');
  std::string line = kpm2_with(R"("pad":")" + pad + "\"");
  EXPECT_EQ(parse_line(line).status, ParseStatus::LineTooLong);
  EXPECT_EQ(parse_line(kKpm2, 10).status, ParseStatus::LineTooLong);
  EXPECT_EQ(parse_line(kKpm2, kKpm2.size()).status, ParseStatus::Ok);  // 상한과 같으면 통과
}

// 2_ §4.1: 시간 필드 필수, t_end > t_start
TEST(Message, Kpm2TimeFields) {
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":2,"t_start_ms":0,"t_end_ms":100})").status,
            ParseStatus::FormatError);  // cell_id 없음
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":2,"cell_id":1,"t_end_ms":100})").status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":2,"cell_id":1,"t_start_ms":0})").status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":2,"cell_id":1,"t_start_ms":100,"t_end_ms":100})").status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(R"({"type":"kpm2","ver":1,"session":"s","seq":2,"cell_id":1,"t_start_ms":200,"t_end_ms":100})").status,
            ParseStatus::FormatError);
}

// ---- 누락·null·0 (2_ §4.5) ----

TEST(Message, AbsentNullZeroAreDistinct) {
  auto absent = parse_line(kpm2_with(R"("cc":{})"));
  ASSERT_EQ(absent.status, ParseStatus::Ok);
  EXPECT_FALSE(kpm(absent).conn_estab_att.total);

  auto null_v = parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":null})"));
  ASSERT_EQ(null_v.status, ParseStatus::Ok);
  EXPECT_FALSE(kpm(null_v).conn_estab_att.total);

  auto zero = parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":{"total":0}})"));
  ASSERT_EQ(zero.status, ParseStatus::Ok);
  ASSERT_TRUE(kpm(zero).conn_estab_att.total);
  EXPECT_EQ(*kpm(zero).conn_estab_att.total, 0);

  // cc·si·ext 자체가 없거나 null이어도 Ok — 모두 값 없음
  auto no_sections = parse_line(kpm2_with(R"("si":null)"));
  ASSERT_EQ(no_sections.status, ParseStatus::Ok);
  EXPECT_FALSE(kpm(no_sections).conn_estab_succ.total);
  EXPECT_FALSE(kpm(no_sections).conn_max);
  EXPECT_FALSE(kpm(no_sections).crnti_alloc);
}

// 2_ §4.2: DL을 못 보면 FailCause가 null — F·R·Other 모두 값 없음 (3_ §4.1 DL 미관측 모드의 입력)
TEST(Message, FailCauseNull) {
  auto r = parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabFailCause":null})"));
  ASSERT_EQ(r.status, ParseStatus::Ok);
  EXPECT_FALSE(kpm(r).fail_no_reply);
  EXPECT_FALSE(kpm(r).fail_network_reject);
  EXPECT_FALSE(kpm(r).fail_other);
}

TEST(Message, FailCausePartial) {
  auto r = parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabFailCause":{"NoReply":3,"NetworkReject":null}})"));
  ASSERT_EQ(r.status, ParseStatus::Ok);
  EXPECT_EQ(kpm(r).fail_no_reply, 3);
  EXPECT_FALSE(kpm(r).fail_network_reject);
  EXPECT_FALSE(kpm(r).fail_other);
}

// 2_ §4.2 total 불변식: 합이 다르면 total을 쓰고 경고
TEST(Message, TotalMismatchUsesTotal) {
  auto r = parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":{"total":5,"mo-Signalling":2,"mo-Data":1}})"));
  ASSERT_EQ(r.status, ParseStatus::Ok);
  EXPECT_EQ(kpm(r).conn_estab_att.total, 5);
  ASSERT_EQ(r.warnings.size(), 1u);
  EXPECT_NE(r.warnings[0].find("RRC.ConnEstabAtt"), std::string::npos);
}

// 결정 D3: 원인만 있고 total이 없으면 값 없음 + 경고 (원인 합으로 대신하지 않음)
TEST(Message, CausesWithoutTotal) {
  auto r = parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabSucc":{"mo-Signalling":2}})"));
  ASSERT_EQ(r.status, ParseStatus::Ok);
  EXPECT_FALSE(kpm(r).conn_estab_succ.total);
  EXPECT_EQ(r.warnings.size(), 1u);
}

// 결정 D2: 카운터 음수·타입 틀림은 줄 전체 형식 오류
TEST(Message, BadCounterIsFormatError) {
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":{"total":-1}})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":{"total":"9"}})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":{"total":1.5}})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabAtt":9})")).status, ParseStatus::FormatError);  // 객체여야 함
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":{"RRC.ReEstabAtt":-2})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":{"RRC.ConnEstabFailCause":{"NoReply":-1}})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(kpm2_with(R"("cc":[])")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(kpm2_with(R"("si":{"RRC.ConnMax":9.5})")).status, ParseStatus::FormatError);  // Max는 정수
}

// 2_ §4.3·§4.4: ConnMean은 실수(정수도 허용), ext는 선택
TEST(Message, SiAndExt) {
  auto r = parse_line(kpm2_with(R"("si":{"RRC.ConnMean":3},"ext":{"UeCtxMax":93,"DuCannotServe":4})"));
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  EXPECT_DOUBLE_EQ(*kpm(r).conn_mean, 3.0);
  EXPECT_FALSE(kpm(r).conn_max);
  EXPECT_EQ(kpm(r).ue_ctx_max, 93);
  EXPECT_EQ(kpm(r).du_cannot_serve, 4);
  EXPECT_FALSE(kpm(r).crnti_alloc);
}

// ---- hello (2_ §3, 결정 D1) ----

TEST(Message, HelloMaxConnNullVsInt) {
  auto r = parse_line(hello_with(
      R"("period_ms":100,"noreply_timeout_ms":1000,"clock":"realtime","cells":[{"cell_id":1,"max_conn":96},{"cell_id":2,"max_conn":null},{"cell_id":3}])"));
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  const auto& h = std::get<Hello>(r.msg);
  ASSERT_EQ(h.cells.size(), 3u);
  EXPECT_EQ(h.cells[0].max_conn, 96);
  EXPECT_FALSE(h.cells[1].max_conn);
  EXPECT_FALSE(h.cells[2].max_conn);
}

TEST(Message, HelloRequiredFields) {
  EXPECT_EQ(parse_line(hello_with(R"("noreply_timeout_ms":1000)")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(hello_with(R"("period_ms":100)")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(hello_with(R"("period_ms":0,"noreply_timeout_ms":1000)")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(hello_with(R"("period_ms":100,"noreply_timeout_ms":-1)")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(hello_with(R"("period_ms":100,"noreply_timeout_ms":1000,"cells":{})")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(hello_with(R"("period_ms":100,"noreply_timeout_ms":1000,"cells":[{"max_conn":1}])")).status,
            ParseStatus::FormatError);
}

// 결정 D1: si_sample_ms가 없으면 period_ms, clock이 realtime이 아니면 경고만
TEST(Message, HelloDefaultsAndClockWarning) {
  auto r = parse_line(hello_with(R"("period_ms":100,"noreply_timeout_ms":1000)"));
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  const auto& h = std::get<Hello>(r.msg);
  EXPECT_EQ(h.si_sample_ms, 100);
  EXPECT_TRUE(h.cells.empty());
  EXPECT_EQ(r.warnings.size(), 1u);  // clock 없음

  auto m = parse_line(hello_with(R"("period_ms":100,"noreply_timeout_ms":1000,"clock":"monotonic")"));
  ASSERT_EQ(m.status, ParseStatus::Ok);
  EXPECT_EQ(m.warnings.size(), 1u);
}

// ---- ue_evt (2_ §6) ----

namespace {

// 2_ §6.4 예시 8줄 그대로 (정상 첫 등록, 같은 UE)
const std::vector<std::string> kUeEvtExample = {
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2001,"t_ms":1793005200000,"cell_id":1,"du_ue_id":3,"crnti":17922,"dir":"UL","proto":"RRC","msg":"RRCSetupRequest","f":{"est_cause":"mo-Signalling","ue_identity":{"type":"randomValue"}}})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2002,"t_ms":1793005200000,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"DL","proto":"RRC","msg":"RRCSetup"})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2004,"t_ms":1793005200091,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"UL","proto":"RRC","msg":"RRCSetupComplete","f":{}})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2005,"t_ms":1793005200091,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"UL","proto":"NAS","msg":"RegistrationRequest","via":"F1","sht":0,"f":{"reg_type":"initial","id_type":"SUCI"}})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2007,"t_ms":1793005200105,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"DL","proto":"NAS","msg":"AuthenticationRequest","via":"F1","sht":0})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2008,"t_ms":1793005200118,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"UL","proto":"NAS","msg":"AuthenticationResponse","via":"F1","sht":0})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2009,"t_ms":1793005200125,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"DL","proto":"NAS","msg":"SecurityModeCommand","via":"F1","sht":3,"f":{"cipher":"5G-EA0","integrity":"5G-IA2"}})",
    R"({"type":"ue_evt","ver":1,"session":"20261026T090000Z","seq":2011,"t_ms":1793005200140,"cell_id":1,"du_ue_id":3,"cu_ue_id":3,"crnti":17922,"dir":"DL","proto":"RRC","msg":"SecurityModeCommand","f":{"cipher":"nea0","integrity":"nia2"}})",
};

// ue_evt 줄 만들기: 공통 머리(t_ms·cell_id 포함) + fields. kRrcUl·kNasUl은 나머지 필수 필드 묶음
std::string ue_line(const std::string& fields) {
  return R"({"type":"ue_evt","ver":1,"session":"s","seq":7,"t_ms":1000,"cell_id":1,)" + fields + "}";
}
const std::string kRrcUl = R"("du_ue_id":3,"crnti":17922,"dir":"UL","proto":"RRC","msg":"RRCSetupRequest")";
const std::string kNasUl = R"("du_ue_id":3,"crnti":17922,"dir":"UL","proto":"NAS","via":"F1","sht":0)";

const UeEvt& ue(const ParseResult& r) { return std::get<UeEvt>(r.msg); }

}  // namespace

// 2_ §6.4 예시 8줄이 모두 해석되고, 꺼낸 값이 맞다
TEST(Message, UeEvtExampleLines) {
  for (const auto& line : kUeEvtExample) {
    auto r = parse_line(line);
    ASSERT_EQ(r.status, ParseStatus::Ok) << r.error << "\n" << line;
    ASSERT_TRUE(std::holds_alternative<UeEvt>(r.msg));
    EXPECT_EQ(ue(r).raw, line);  // 원본 줄 그대로 (14_ §2.3 recent)
    EXPECT_TRUE(r.warnings.empty());
  }
  const UeEvt a = ue(parse_line(kUeEvtExample[0]));
  EXPECT_EQ(a.t_ms, 1793005200000);
  EXPECT_EQ(a.cell_id, 1);
  EXPECT_EQ(a.du_ue_id, 3);
  EXPECT_FALSE(a.cu_ue_id);
  EXPECT_EQ(a.crnti, 17922);
  EXPECT_EQ(a.dir, Dir::UL);
  EXPECT_EQ(a.proto, Proto::RRC);
  EXPECT_EQ(a.msg, "RRCSetupRequest");
  EXPECT_EQ(a.est_cause, "mo-Signalling");
  EXPECT_EQ(a.ue_identity, UeIdentityType::RandomValue);
  EXPECT_FALSE(a.s_tmsi_part1);
  EXPECT_FALSE(a.sht);

  const UeEvt reg = ue(parse_line(kUeEvtExample[3]));
  EXPECT_EQ(reg.proto, Proto::NAS);
  EXPECT_EQ(reg.via, "F1");
  EXPECT_EQ(reg.sht, 0);
  EXPECT_EQ(reg.reg_type, "initial");
  EXPECT_EQ(reg.id_type, "SUCI");
  EXPECT_FALSE(reg.s_tmsi);

  const UeEvt smc = ue(parse_line(kUeEvtExample[7]));
  EXPECT_EQ(smc.dir, Dir::DL);
  EXPECT_EQ(smc.cipher, "nea0");
  EXPECT_EQ(smc.integrity, "nia2");
}

// S-TMSI 값 (2_ §6.3, 14_ §3.1): 대소문자·앞자리 0과 무관하게 같은 정수. 48·39·9비트를 넘으면 형식 오류
TEST(Message, UeEvtStmsiHex) {
  auto lower = parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":"0x0123456789ab"})"));
  auto upper = parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":"0X123456789AB"})"));
  ASSERT_EQ(lower.status, ParseStatus::Ok) << lower.error;
  ASSERT_EQ(upper.status, ParseStatus::Ok) << upper.error;
  EXPECT_EQ(ue(lower).s_tmsi, uint64_t{0x0123456789ab});
  EXPECT_EQ(ue(upper).s_tmsi, ue(lower).s_tmsi);

  EXPECT_EQ(ue(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":"0xffffffffffff"})"))).s_tmsi, uint64_t{0xffffffffffff});
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":"0x1000000000000"})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":"0x12g4"})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":"1234"})")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":1234})")).status, ParseStatus::FormatError);
  EXPECT_FALSE(ue(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi":null})"))).s_tmsi);  // 꺼내지 못한 값

  // Part1(39비트, RRCSetupRequest ue_identity)과 Part2(9비트 폴백)
  auto p1 = parse_line(ue_line(kRrcUl + R"(,"f":{"ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":"0x7fffffffff"}})"));
  ASSERT_EQ(p1.status, ParseStatus::Ok) << p1.error;
  EXPECT_EQ(ue(p1).ue_identity, UeIdentityType::Part1);
  EXPECT_EQ(ue(p1).s_tmsi_part1, uint64_t{0x7fffffffff});
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"ue_identity":{"type":"ng-5G-S-TMSI-Part1","value":"0x8000000000"}})")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"ue_identity":{"type":"ng-5G-S-TMSI-Part1"}})")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"ue_identity":{"type":"imsi"}})")).status, ParseStatus::FormatError);
  EXPECT_EQ(ue(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi_part2":"0x1ff"})"))).s_tmsi_part2, uint64_t{0x1ff});
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"s_tmsi_part2":"0x200"})")).status, ParseStatus::FormatError);
}

// 필수 필드·타입 (2_ §6.2·§6.5): 없거나 틀리면 줄 전체가 형식 오류
TEST(Message, UeEvtRequiredFields) {
  EXPECT_EQ(parse_line(ue_line(kRrcUl)).status, ParseStatus::Ok);
  EXPECT_EQ(parse_line(R"({"type":"ue_evt","ver":1,"session":"s","seq":7,"cell_id":1,)" + kRrcUl + "}").status,
            ParseStatus::FormatError);  // t_ms 없음
  EXPECT_EQ(parse_line(ue_line(R"("crnti":1,"dir":"UL","proto":"RRC","msg":"X")")).status,
            ParseStatus::FormatError);  // du_ue_id 키 없음
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"dir":"UL","proto":"RRC","msg":"X")")).status,
            ParseStatus::FormatError);  // crnti 키 없음
  EXPECT_FALSE(ue(parse_line(ue_line(R"("du_ue_id":3,"crnti":null,"dir":"UL","proto":"RRC","msg":"X")"))).crnti);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":-1,"crnti":1,"dir":"UL","proto":"RRC","msg":"X")")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"up","proto":"RRC","msg":"X")")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"UL","proto":"PDCP","msg":"X")")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"UL","proto":"RRC","msg":"")")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":[])")).status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(kRrcUl + R"(,"f":{"suspend":"yes"})")).status, ParseStatus::FormatError);

  // 모르는 메시지 이름·모르는 f 키는 받는다 — 이력에만 남고 판정에는 안 쓰임 (2_ §6.2)
  auto unknown = parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"RRC","msg":"UECapabilityEnquiry","f":{"x":1})"));
  ASSERT_EQ(unknown.status, ParseStatus::Ok) << unknown.error;
  EXPECT_EQ(ue(unknown).msg, "UECapabilityEnquiry");
}

// NAS 줄은 via·sht가 필수, du_ue_id: null은 NGAP에서만 본 NAS 줄에만 (2_ §6.2·§6.5·§6.6)
TEST(Message, UeEvtNasViaShtAndNullDuUeId) {
  auto nas = parse_line(ue_line(kNasUl + R"(,"msg":"ServiceRequest","f":{"s_tmsi":"0x0000000000ab"})"));
  ASSERT_EQ(nas.status, ParseStatus::Ok) << nas.error;
  EXPECT_EQ(ue(nas).s_tmsi, uint64_t{0xab});

  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"UL","proto":"NAS","sht":0,"msg":"X")")).status,
            ParseStatus::FormatError);  // via 없음
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"UL","proto":"NAS","via":"F1","msg":"X")")).status,
            ParseStatus::FormatError);  // sht 없음
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"UL","proto":"NAS","via":"S1","sht":0,"msg":"X")")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"UL","proto":"NAS","via":"F1","sht":5,"msg":"X")")).status,
            ParseStatus::FormatError);

  // 암호라 종류를 모르는 NAS (2_ §6.2)
  auto prot = parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"NAS","via":"F1","sht":2,"msg":"ProtectedNAS")"));
  ASSERT_EQ(prot.status, ParseStatus::Ok) << prot.error;
  EXPECT_EQ(ue(prot).sht, 2);

  auto ngap = parse_line(ue_line(R"("du_ue_id":null,"crnti":null,"dir":"DL","proto":"NAS","via":"NGAP","sht":0,"msg":"ServiceAccept")"));
  ASSERT_EQ(ngap.status, ParseStatus::Ok) << ngap.error;
  EXPECT_FALSE(ue(ngap).du_ue_id);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":null,"crnti":null,"dir":"DL","proto":"NAS","via":"F1","sht":0,"msg":"X")")).status,
            ParseStatus::FormatError);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":null,"crnti":1,"dir":"UL","proto":"RRC","msg":"X")")).status,
            ParseStatus::FormatError);
}

// cause: NAS는 5GMM 원인값 숫자, F1AP는 문자열 (2_ §6.3). RRCRelease suspend, RRCReject wait_time
TEST(Message, UeEvtCauseAndFlags) {
  auto rej = parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"NAS","via":"F1","sht":0,"msg":"RegistrationReject","f":{"cause":9})"));
  ASSERT_EQ(rej.status, ParseStatus::Ok) << rej.error;
  EXPECT_EQ(ue(rej).cause, 9);
  EXPECT_FALSE(ue(rej).f1ap_cause);
  EXPECT_EQ(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"NAS","via":"F1","sht":0,"msg":"RegistrationReject","f":{"cause":"9"})")).status,
            ParseStatus::FormatError);

  auto rel = parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"F1AP","msg":"UEContextReleaseCommand","f":{"cause":"radioNetwork:normal-release"})"));
  ASSERT_EQ(rel.status, ParseStatus::Ok) << rel.error;
  EXPECT_EQ(ue(rel).proto, Proto::F1AP);
  EXPECT_EQ(ue(rel).f1ap_cause, "radioNetwork:normal-release");
  EXPECT_FALSE(ue(rel).cause);

  EXPECT_EQ(ue(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"RRC","msg":"RRCRelease","f":{"suspend":true})"))).suspend, true);
  EXPECT_EQ(ue(parse_line(ue_line(R"("du_ue_id":3,"crnti":1,"dir":"DL","proto":"RRC","msg":"RRCReject","f":{"wait_time":16})"))).wait_time, 16);
  EXPECT_EQ(ue(parse_line(ue_line(kNasUl + R"(,"msg":"DeregistrationRequest","f":{"switch_off":false})"))).switch_off, false);
}

// ---- f1_evt (2_ §6.7) ----

TEST(Message, F1EvtExampleAndFields) {
  // 2_ §6.7 예시 그대로
  auto r = parse_line(R"({"type":"f1_evt","ver":1,"session":"20261026T090000Z","seq":3001,"t_ms":1793005300000,"msg":"F1SetupRequest","cells":[1]})");
  ASSERT_EQ(r.status, ParseStatus::Ok) << r.error;
  const F1Evt& e = std::get<F1Evt>(r.msg);
  EXPECT_EQ(e.t_ms, 1793005300000);
  EXPECT_EQ(e.msg, "F1SetupRequest");
  EXPECT_EQ(e.cells, (std::vector<int64_t>{1}));
  EXPECT_FALSE(e.du_ue_ids);

  const std::string head = R"({"type":"f1_evt","ver":1,"session":"s","seq":9,"t_ms":5,)";
  auto all = parse_line(head + R"("msg":"F1Reset","cells":null,"du_ue_ids":[3,7]})");
  ASSERT_EQ(all.status, ParseStatus::Ok) << all.error;
  EXPECT_FALSE(std::get<F1Evt>(all.msg).cells);  // null = 모든 셀
  EXPECT_EQ(std::get<F1Evt>(all.msg).du_ue_ids, (std::vector<int64_t>{3, 7}));

  EXPECT_EQ(parse_line(head + R"("msg":"F1Reset"})").status, ParseStatus::FormatError);  // cells 키 없음
  EXPECT_EQ(parse_line(head + R"("msg":"F1RemovalRequest","cells":[1]})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(head + R"("msg":"F1Reset","cells":[1,"2"]})").status, ParseStatus::FormatError);
  EXPECT_EQ(parse_line(head + R"("msg":"F1Reset","cells":[1],"du_ue_ids":3})").status, ParseStatus::FormatError);
}

// ---- 2단계 표시 필드: hello.ue_evt (2_ §6.5), kpm2.ue_evt_lost (2_ §4.6) ----

// 틀린 값이어도 줄은 버리지 않고 경고 — 2단계 필드 때문에 1단계가 멈추지 않게 (2_ §4.6)
TEST(Message, HelloUeEvtFlag) {
  const std::string base = R"("period_ms":100,"noreply_timeout_ms":1000,"clock":"realtime")";
  EXPECT_FALSE(std::get<Hello>(parse_line(hello_with(base)).msg).ue_evt);
  EXPECT_TRUE(std::get<Hello>(parse_line(hello_with(base + R"(,"ue_evt":true)")).msg).ue_evt);
  EXPECT_FALSE(std::get<Hello>(parse_line(hello_with(base + R"(,"ue_evt":false)")).msg).ue_evt);
  auto bad = parse_line(hello_with(base + R"(,"ue_evt":"yes")"));
  ASSERT_EQ(bad.status, ParseStatus::Ok);
  EXPECT_FALSE(std::get<Hello>(bad.msg).ue_evt);
  EXPECT_EQ(bad.warnings.size(), 1u);
}

TEST(Message, Kpm2UeEvtLost) {
  const std::string cc = R"("cc":{"RRC.ConnEstabAtt":{"total":3}})";
  EXPECT_FALSE(kpm(parse_line(kpm2_with(cc))).ue_evt_lost);  // 없음 = 알 수 없음
  EXPECT_FALSE(kpm(parse_line(kpm2_with(cc + R"(,"ue_evt_lost":null)"))).ue_evt_lost);
  EXPECT_EQ(kpm(parse_line(kpm2_with(cc + R"(,"ue_evt_lost":[])"))).ue_evt_lost, (UeEvtLost{false, false}));
  EXPECT_EQ(kpm(parse_line(kpm2_with(cc + R"(,"ue_evt_lost":["UL"])"))).ue_evt_lost, (UeEvtLost{true, false}));
  EXPECT_EQ(kpm(parse_line(kpm2_with(cc + R"(,"ue_evt_lost":["DL"])"))).ue_evt_lost, (UeEvtLost{false, true}));
  EXPECT_EQ(kpm(parse_line(kpm2_with(cc + R"(,"ue_evt_lost":["UL","DL"])"))).ue_evt_lost, (UeEvtLost{true, true}));
  for (const char* bad : {R"("ue_evt_lost":["up"])", R"("ue_evt_lost":"UL")", R"("ue_evt_lost":[1])"}) {
    auto r = parse_line(kpm2_with(cc + "," + bad));
    ASSERT_EQ(r.status, ParseStatus::Ok) << bad;
    EXPECT_FALSE(kpm(r).ue_evt_lost) << bad;            // 알 수 없음으로
    EXPECT_EQ(kpm(r).conn_estab_att.total, 3) << bad;   // 1단계 값은 그대로
    EXPECT_EQ(r.warnings.size(), 1u) << bad;
  }
}
