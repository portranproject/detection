// message 파서 단위 테스트 (4_ §4-1) — 2_ §1~§6의 형식 규칙
#include "detect/message.h"

#include <gtest/gtest.h>

#include <string>

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

// 2단계 룰 명세 전이라 종류만 인식하고 본문은 해석하지 않는다
TEST(Message, UeEvtRecognized) {
  auto r = parse_line(
      R"({"type":"ue_evt","ver":1,"session":"s","seq":5310,"t_ms":1792209000153,"cell_id":1,"crnti":17921,"layer":"RRC","dir":"UL","msg":"RRCSetupRequest","ue":{"rrc_state":"IDLE","sec_state":"OFF"}})");
  ASSERT_EQ(r.status, ParseStatus::Ok);
  EXPECT_TRUE(std::holds_alternative<UeEvt>(r.msg));
  EXPECT_EQ(r.common->seq, 5310);
}
