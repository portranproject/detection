// 경보 상태기계·로그 한 줄 단위 테스트 (3_ §4·§6.1 가·§7·§8)
#include "detect/alert.h"

#include <gtest/gtest.h>

using namespace detect;
using Step = AlertMachine::Step;

// M = 3칸 연속 성립에서 RAISE, 중간에 불성립이 끼면 처음부터
TEST(AlertMachine, RaiseAfterMConsecutive) {
  AlertMachine m(3, 10, 3000);
  EXPECT_EQ(m.on_slot(true, 100), Step::None);
  EXPECT_EQ(m.on_slot(true, 200), Step::None);
  EXPECT_EQ(m.on_slot(false, 300), Step::None);
  EXPECT_EQ(m.on_slot(true, 400), Step::None);
  EXPECT_EQ(m.on_slot(true, 500), Step::None);
  EXPECT_EQ(m.on_slot(true, 600), Step::Raise);
  EXPECT_TRUE(m.active());
  EXPECT_EQ(m.raised_at(), 600);
}

// CLEAR = K칸 연속 불성립 ∧ t − t_last ≥ H_sat — K만 채워서는 풀리지 않는다 (3_ §6.1 가)
TEST(AlertMachine, ClearNeedsKAndHsat) {
  AlertMachine m(1, 10, 3000);
  ASSERT_EQ(m.on_slot(true, 1000), Step::Raise);
  for (int i = 1; i <= 29; ++i) EXPECT_EQ(m.on_slot(false, 1000 + i * 100), Step::None) << i;  // K 충족, H_sat 미달
  EXPECT_EQ(m.on_slot(false, 4000), Step::Clear);
  EXPECT_FALSE(m.active());
}

// H_sat가 지났어도 불성립이 K칸 안 되면 CLEAR하지 않는다
TEST(AlertMachine, ClearNeedsK) {
  AlertMachine m(1, 10, 300);
  ASSERT_EQ(m.on_slot(true, 1000), Step::Raise);
  for (int i = 1; i <= 9; ++i) EXPECT_EQ(m.on_slot(false, 1000 + i * 100), Step::None);
  EXPECT_EQ(m.on_slot(false, 2000), Step::Clear);
}

// 경보 중 성립하면 불성립 연속과 t_last가 다시 시작된다
TEST(AlertMachine, SatisfiedResetsClearCountdown) {
  AlertMachine m(1, 2, 0);
  ASSERT_EQ(m.on_slot(true, 100), Step::Raise);
  EXPECT_EQ(m.on_slot(false, 200), Step::None);
  EXPECT_EQ(m.on_slot(true, 300), Step::None);
  EXPECT_EQ(*m.t_last(), 300);
  EXPECT_EQ(m.on_slot(false, 400), Step::None);
  EXPECT_EQ(m.on_slot(false, 500), Step::Clear);
}

// 강제 종료 뒤에는 다시 M칸이 필요하다
TEST(AlertMachine, ResetClearsCounters) {
  AlertMachine m(2, 10, 3000);
  m.on_slot(true, 100);
  ASSERT_EQ(m.on_slot(true, 200), Step::Raise);
  m.reset();
  EXPECT_FALSE(m.active());
  EXPECT_EQ(m.on_slot(true, 300), Step::None);
  EXPECT_EQ(m.on_slot(true, 400), Step::Raise);
}

// 3_ §7 예시와 같은 형식
TEST(AlertLog, RaiseLineMatchesSpecExample) {
  AlertEvent e;
  e.kind = AlertEventKind::Raise;
  e.rule = "L3-01-V";
  e.cell_id = 1;
  e.t = 1792209001200;
  e.a_w = 48;
  e.f_w = 45;
  e.ratio = 45.0 / 48.0;
  e.base = 3.1;
  e.k = 3;
  e.theta = 0.5;
  e.uectx = 93;
  e.max_conn = 96;
  e.severity = Severity::High;
  e.mode = AlertMode::Normal;
  e.candidates = {"L3-11"};
  EXPECT_EQ(format_log_line(e),
            "ALERT RAISE rule=L3-01-V cell=1 t=1792209001200 A_w=48 F_w=45 ratio=0.94 base=3.1 k=3 theta=0.5 "
            "uectx=93/96 severity=high mode=normal candidates=L3-11");
}

TEST(AlertLog, ClearEndUpdateAndDlMissing) {
  AlertEvent e;
  e.rule = "L3-01-V";
  e.cell_id = 1;
  e.t = 1792209009200;
  e.kind = AlertEventKind::Clear;
  e.duration_ms = 8000;
  EXPECT_EQ(format_log_line(e), "ALERT CLEAR rule=L3-01-V cell=1 t=1792209009200 duration_ms=8000");

  e.kind = AlertEventKind::End;
  e.reason = "session_reset";
  EXPECT_EQ(format_log_line(e),
            "ALERT END rule=L3-01-V cell=1 t=1792209009200 duration_ms=8000 reason=session_reset");

  e.kind = AlertEventKind::Update;
  e.severity = Severity::High;
  e.uectx = 90;
  e.max_conn = 96;
  EXPECT_EQ(format_log_line(e), "ALERT UPDATE rule=L3-01-V cell=1 t=1792209009200 severity=high uectx=90/96");

  AlertEvent d;
  d.kind = AlertEventKind::Raise;
  d.rule = "L3-01-V";
  d.cell_id = 2;
  d.t = 5;
  d.a_w = 7;
  d.u = 6.0 / 7.0;
  d.base = 0;
  d.k = 3;
  d.theta = 0.5;
  d.mode = AlertMode::DlMissing;
  d.candidates = {"L3-11"};
  EXPECT_EQ(format_log_line(d),
            "ALERT RAISE rule=L3-01-V cell=2 t=5 A_w=7 U=0.86 base=0.0 k=3 theta=0.5 severity=medium "
            "mode=dl_missing candidates=L3-11");
}
