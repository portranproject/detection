// 3단계 되돌아보는 판정 공통 헬퍼 테스트 (20_ §1.2) — AS 무결성(§1.2-1), '요청 없는 응답' 횟수 맞추기(§1.2-1·2),
// 표시의 생애(§1.2 — 연결당 한 번·닫힘 이유별·late·복사본 판정). 열린 항목이 필요한 경로(보류·결정됨 뒤 닫힘)는
// 룰 테스트(test_imsi_extractor.cpp)가 엔진으로 본다
#include "detect/ue_lookback.h"

#include <gtest/gtest.h>

#include <string>

using namespace detect;

namespace {

UeState with_sec(RrcSecState sec, const char* integrity = nullptr) {
  UeState s;
  s.rrc_sec = sec;
  if (integrity) s.rrc_alg = SecAlg{"nea0", integrity};
  return s;
}

UeState counts(int64_t req, int64_t resp) {
  UeState s;
  if (req) s.cnt[{Proto::NAS, "IdentityRequest"}] = req;
  if (resp) s.cnt[{Proto::NAS, "IdentityResponse"}] = resp;
  return s;
}

bool unsol(const UeState& s) { return unsolicited(s, Proto::NAS, "IdentityRequest", "IdentityResponse"); }

// 마감 목록·상태표를 직접 쥔 문맥 — 상태표는 비어 있어 항목은 닫힌 복사본으로만 판정된다
struct Ctx {
  UeTable table;
  DeadlineQueue dq;
  Hello hello;
  std::string session = "S";
  UeRuleCtx ctx() { return UeRuleCtx(table, dq, hello, session, 1, 0); }
  std::optional<Deadline> due(int64_t cell, int64_t t) {
    dq.set_clock(cell, t);
    return dq.pop_due(cell);
  }
};

UeState ue(int64_t du, int64_t uid, int64_t t_start) {
  UeState s;
  s.key = UeKey{1, du};
  s.uid = uid;
  s.t_start = t_start;
  return s;
}

}  // namespace

// §1.2-1: ON이고 무결성이 nia0이 아니면 AS 무결성 뒤. CMD·FAILED·OFF·UNKNOWN은 아님. nia0은 대소문자를 가리지 않고,
// 무결성 값이 없거나 모르는 값이면 nia0이 아닌 것으로 본다(보수적 — 판정하지 않음)
TEST(UeLookback, AsIntegrityOn) {
  EXPECT_FALSE(as_integrity_on(with_sec(RrcSecState::Off)));
  EXPECT_FALSE(as_integrity_on(with_sec(RrcSecState::Unknown)));
  EXPECT_FALSE(as_integrity_on(with_sec(RrcSecState::Cmd, "nia2")));
  EXPECT_FALSE(as_integrity_on(with_sec(RrcSecState::Failed, "nia2")));
  EXPECT_TRUE(as_integrity_on(with_sec(RrcSecState::On, "nia2")));
  EXPECT_FALSE(as_integrity_on(with_sec(RrcSecState::On, "nia0")));
  EXPECT_FALSE(as_integrity_on(with_sec(RrcSecState::On, "NIA0")));
  EXPECT_TRUE(as_integrity_on(with_sec(RrcSecState::On, "")));        // f 누락
  EXPECT_TRUE(as_integrity_on(with_sec(RrcSecState::On, "nia9")));    // 모르는 값
  EXPECT_TRUE(as_integrity_on(with_sec(RrcSecState::On)));            // rrc_alg 없음
}

// §1.2-1·2: 갱신 전 R ≤ A면 요청 없는 응답. 정상 식별(R 1, A 0)·재전송에 두 번 답함(R 2, A 1)은 아니고, 정상 뒤 주입(R 1, A 1)은
// 맞다. mid_join·AS 무결성 뒤는 후보가 아니다. proto가 다르면 섞지 않는다
TEST(UeLookback, UnsolicitedCountsByProto) {
  EXPECT_TRUE(unsol(counts(0, 0)));
  EXPECT_FALSE(unsol(counts(1, 0)));
  EXPECT_TRUE(unsol(counts(1, 1)));
  EXPECT_FALSE(unsol(counts(2, 1)));
  EXPECT_TRUE(unsol(counts(2, 2)));
  UeState mid = counts(0, 0);
  mid.mid_join = true;
  EXPECT_FALSE(unsol(mid));
  UeState on = counts(0, 0);
  on.rrc_sec = RrcSecState::On;
  on.rrc_alg = SecAlg{"nea0", "nia2"};
  EXPECT_FALSE(unsol(on));
  on.rrc_alg = SecAlg{"nea0", "nia0"};
  EXPECT_TRUE(unsol(on));
  UeState rrc;
  rrc.cnt[{Proto::RRC, "IdentityRequest"}] = 1;  // 다른 proto의 같은 이름은 세지 않는다
  EXPECT_TRUE(unsol(rrc));
}

// 응답 집합 (20_ §1.2 m/q 표·§5.3 — L3-06): A = Complete + Reject. 정상 명령 → Complete(R 1, A 1) 뒤 Reject는 요청 없는 응답,
// 정상 명령 → UE 거부(R 1, A 0)는 아니다. RRC의 SecurityModeComplete는 NAS 집합에 들지 않는다
TEST(UeLookback, UnsolicitedResponseSet) {
  const std::vector<std::string> set = {"SecurityModeComplete", "SecurityModeReject"};
  auto smc = [&](int64_t cmd, int64_t cpl, int64_t rej) {
    UeState s;
    if (cmd) s.cnt[{Proto::NAS, "SecurityModeCommand"}] = cmd;
    if (cpl) s.cnt[{Proto::NAS, "SecurityModeComplete"}] = cpl;
    if (rej) s.cnt[{Proto::NAS, "SecurityModeReject"}] = rej;
    return s;
  };
  EXPECT_TRUE(unsolicited(smc(0, 0, 0), Proto::NAS, "SecurityModeCommand", set));   // 보안 전 주입 (J1)
  EXPECT_FALSE(unsolicited(smc(1, 0, 0), Proto::NAS, "SecurityModeCommand", set));  // 정상 거부
  EXPECT_TRUE(unsolicited(smc(1, 1, 0), Proto::NAS, "SecurityModeCommand", set));   // 정상 완료 뒤 주입 (J2)
  EXPECT_FALSE(unsolicited(smc(2, 0, 1), Proto::NAS, "SecurityModeCommand", set));  // 재전송마다 거부
  EXPECT_EQ(count_any(smc(1, 1, 2), Proto::NAS, set), 3);
  UeState rrc = smc(1, 0, 0);
  rrc.cnt[{Proto::RRC, "SecurityModeComplete"}] = 1;
  EXPECT_FALSE(unsolicited(rrc, Proto::NAS, "SecurityModeCommand", set));
  // 응답 하나짜리 함수는 집합 {resp}와 같다
  EXPECT_EQ(unsol(counts(1, 1)), unsolicited(counts(1, 1), Proto::NAS, "IdentityRequest",
                                             std::vector<std::string>{"IdentityResponse"}));
}

// §1.2-2·3: 표시가 없으면 대기 표시 + 마감 t + 1(DL). 같은 (키, uid, tag)에 또 오면 extra만 — 연결당 한 번. tag(갈래)는 따로
TEST(UeLookback, StartOncePerConnectionAndTag) {
  Ctx c;
  const UeState n = ue(3, 7, 1000);
  LookbackMarks m;
  EXPECT_TRUE(m.start(n, "unsolicited", 1098, {{"req", 0}}, c.ctx()));
  EXPECT_EQ(c.dq.size(), 1u);
  EXPECT_FALSE(m.start(n, "unsolicited", 1099, {}, c.ctx()));
  EXPECT_EQ(c.dq.size(), 1u);  // 새 마감 없음
  const LookbackMarks::Mark* k = m.find(n.key, n.uid, "unsolicited");
  ASSERT_NE(k, nullptr);
  EXPECT_EQ(k->extra, 1);
  EXPECT_EQ(k->t_from, 1098);
  EXPECT_EQ(k->phase, LookbackMarks::Phase::Waiting);
  EXPECT_TRUE(m.start(n, "pre_sec_enquiry", 1120, {}, c.ctx()));  // 다른 갈래
  EXPECT_TRUE(m.start(ue(3, 8, 2000), "unsolicited", 2010, {}, c.ctx()));  // 같은 키의 다른 항목(uid)
  EXPECT_EQ(m.size(), 3u);
  std::optional<Deadline> d = c.due(1, 1100);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->at, 1099);  // t + 1 — t를 품은 창(t_end 1100)에서 꺼낸다
  EXPECT_EQ(d->dir, Dir::DL);
  EXPECT_EQ(d->tag, "unsolicited");
}

// §1.2-5: 대기 중 released·reused·stale_setup으로 닫히면 복사본으로 마감 때 판정하고, 판정 뒤 표시를 지운다(더 올 줄이 없음).
// 그 밖의 이유(evicted 등)면 지운다 — 마감은 Stale
TEST(UeLookback, ClosedBeforeDeadline) {
  for (CloseReason r : {CloseReason::Released, CloseReason::Reused, CloseReason::StaleSetup}) {
    Ctx c;
    LookbackMarks m;
    const UeState n = ue(3, 7, 1000);
    m.start(n, "unsolicited", 1098, {{"req", 0}}, c.ctx());
    m.start(n, "unsolicited", 1098, {}, c.ctx());
    m.on_close(n, r);
    EXPECT_EQ(m.size(), 1u) << to_string(r);
    const std::optional<Deadline> d = c.due(1, 1100);
    ASSERT_TRUE(d);
    const LookbackMarks::Decision dc = m.on_deadline(*d, c.ctx());
    EXPECT_EQ(dc.verdict, LookbackMarks::Verdict::Hit) << to_string(r);
    EXPECT_EQ(dc.n.uid, 7);
    EXPECT_EQ(dc.mark.extra, 1);
    EXPECT_EQ(dc.mark.snap.dump(), R"({"req":0})");
    EXPECT_EQ(m.size(), 0u);
  }
  for (CloseReason r : {CloseReason::Evicted, CloseReason::DuReset, CloseReason::GhostPurge, CloseReason::Superseded,
                        CloseReason::SessionReset}) {
    Ctx c;
    LookbackMarks m;
    const UeState n = ue(3, 7, 1000);
    m.start(n, "unsolicited", 1098, {}, c.ctx());
    m.on_close(n, r);
    EXPECT_EQ(m.size(), 0u) << to_string(r);
    const std::optional<Deadline> d = c.due(1, 1100);
    ASSERT_TRUE(d);
    EXPECT_EQ(m.on_deadline(*d, c.ctx()).verdict, LookbackMarks::Verdict::Stale) << to_string(r);
  }
  // 다른 항목의 닫힘은 건드리지 않는다
  Ctx c;
  LookbackMarks m;
  m.start(ue(3, 7, 1000), "unsolicited", 1098, {}, c.ctx());
  m.on_close(ue(3, 6, 900), CloseReason::Evicted);
  m.on_close(ue(4, 7, 900), CloseReason::Evicted);
  EXPECT_EQ(m.size(), 1u);
}

// §1.2-4 late: 늦은 줄 제외 기간이 마감을 덮으면 판정하지 않고 표시를 지운다(Skip). 마감이 late_until 이상이면 판정한다
TEST(UeLookback, LateSkipErasesMark) {
  {
    Ctx c;
    LookbackMarks m;
    UeState n = ue(3, 7, 1000);
    n.late = true;
    n.late_until = 3098;
    m.start(n, "unsolicited", 1098, {}, c.ctx());
    m.on_close(n, CloseReason::Released);
    const LookbackMarks::Decision dc = m.on_deadline(*c.due(1, 1100), c.ctx());
    EXPECT_EQ(dc.verdict, LookbackMarks::Verdict::Skip);
    EXPECT_EQ(m.size(), 0u);
  }
  {
    Ctx c;
    LookbackMarks m;
    UeState n = ue(3, 7, 1000);
    n.late = true;
    n.late_until = 1099;  // 마감 1099 ≥ late_until → 판정
    m.start(n, "unsolicited", 1098, {}, c.ctx());
    m.on_close(n, CloseReason::Released);
    EXPECT_EQ(m.on_deadline(*c.due(1, 1100), c.ctx()).verdict, LookbackMarks::Verdict::Hit);
  }
}

// 표시와 다른 마감(t_from이 다름)은 Stale — 표시는 그대로
TEST(UeLookback, StaleDeadline) {
  Ctx c;
  LookbackMarks m;
  const UeState n = ue(3, 7, 1000);
  m.start(n, "unsolicited", 1098, {}, c.ctx());
  Deadline d;
  d.at = 1099;
  d.key = n.key;
  d.uid = n.uid;
  d.tag = "unsolicited";
  d.t_from = 1050;
  EXPECT_EQ(m.on_deadline(d, c.ctx()).verdict, LookbackMarks::Verdict::Stale);
  d.t_from = 1098;
  d.tag = "pre_sec_enquiry";
  EXPECT_EQ(m.on_deadline(d, c.ctx()).verdict, LookbackMarks::Verdict::Stale);
  EXPECT_EQ(m.size(), 1u);
  m.clear();
  EXPECT_EQ(m.size(), 0u);
}
