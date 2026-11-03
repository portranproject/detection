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

// 3_ §7 예시와 같은 형식 — 룰별 필드(log_fields)는 severity 앞에, 골격은 공통 (4_ §6.1 #5)
TEST(AlertLog, RaiseLineMatchesSpecExample) {
  AlertEvent e;
  e.kind = AlertEventKind::Raise;
  e.rule = "L3-01-V";
  e.cell_id = 1;
  e.t = 1792209001200;
  e.log_fields = {{"A_w", "48"}, {"F_w", "45"}, {"ratio", "0.94"}, {"base", "3.1"}, {"k", "3"},
                  {"theta", "0.5"}, {"f_abs", "10"}, {"uectx", "93/96"}};
  e.severity = Severity::High;
  e.mode = AlertMode::Normal;
  e.candidates = {"L3-11"};
  EXPECT_EQ(format_log_line(e),
            "ALERT RAISE rule=L3-01-V cell=1 t=1792209001200 A_w=48 F_w=45 ratio=0.94 base=3.1 k=3 theta=0.5 f_abs=10 "
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
  e.log_fields = {{"uectx", "90/96"}};  // UPDATE의 룰별 필드는 severity 뒤 (결정 E2)
  EXPECT_EQ(format_log_line(e), "ALERT UPDATE rule=L3-01-V cell=1 t=1792209009200 severity=high uectx=90/96");

  AlertEvent d;
  d.kind = AlertEventKind::Raise;
  d.rule = "L3-01-V";
  d.cell_id = 2;
  d.t = 5;
  d.log_fields = {{"A_w", "7"}, {"U", "0.86"}, {"base", "0.0"}, {"k", "3"}, {"theta", "0.5"}};
  d.mode = AlertMode::DlMissing;
  d.candidates = {"L3-11"};
  EXPECT_EQ(format_log_line(d),
            "ALERT RAISE rule=L3-01-V cell=2 t=5 A_w=7 U=0.86 base=0.0 k=3 theta=0.5 severity=medium "
            "mode=dl_missing candidates=L3-11");
}

// UE 단위 경보(unit = "ue")의 줄 모양 — 15_ §2.6 L3-20 예. candidates가 비어도 'candidates='를 찍는다
TEST(AlertLog, UeUnitLinesMatchStage2Examples) {
  AlertEvent e;
  e.rule = "L3-20";
  e.stage = 2;
  e.unit = "ue";
  e.cell_id = 1;
  e.t = 1793005265500;
  e.kind = AlertEventKind::Raise;
  e.severity = Severity::High;
  e.log_fields = {{"peer", "concurrent"}, {"ue", "1/7/58"}, {"s_tmsi", "0x0123456789ab"}, {"peers", "1/3/41"},
                  {"nas", "ServiceRequest"}, {"wait_ms", "5000"}, {"victim_released", "1"}};
  EXPECT_EQ(format_log_line(e),
            "ALERT RAISE rule=L3-20 cell=1 t=1793005265500 peer=concurrent ue=1/7/58 s_tmsi=0x0123456789ab "
            "peers=1/3/41 nas=ServiceRequest wait_ms=5000 victim_released=1 severity=high mode=normal candidates=");

  // UPDATE: 새로 걸린 UE 수(ues 크기)와 누적 수 (14_ §8.2)
  e.kind = AlertEventKind::Update;
  e.log_fields.clear();
  e.ues.resize(2);
  e.ues_total = 3;
  EXPECT_EQ(format_log_line(e), "ALERT UPDATE rule=L3-20 cell=1 t=1793005265500 ues_new=2 ues_total=3 severity=high");

  e.kind = AlertEventKind::Clear;
  e.duration_ms = 60000;
  EXPECT_EQ(format_log_line(e), "ALERT CLEAR rule=L3-20 cell=1 t=1793005265500 duration_ms=60000 ues_total=3");

  // 갈래가 있는 룰은 UPDATE에 branch (15_ §5.6 L3-21 예)
  AlertEvent b = e;
  b.rule = "L3-21";
  b.kind = AlertEventKind::Update;
  b.branch = "1";
  b.ues_total = 7;
  EXPECT_EQ(format_log_line(b), "ALERT UPDATE rule=L3-21 cell=1 t=1793005265500 ues_new=2 ues_total=7 branch=1 severity=high");

  // 룰별 필드는 UPDATE에서 severity 뒤 (15_ §4.6 L3-01-O 예)
  AlertEvent o = e;
  o.rule = "L3-01-O";
  o.kind = AlertEventKind::Update;
  o.ues.resize(4);
  o.ues_total = 10;
  o.log_fields = {{"uectx", "96/96"}};
  EXPECT_EQ(format_log_line(o),
            "ALERT UPDATE rule=L3-01-O cell=1 t=1793005265500 ues_new=4 ues_total=10 severity=high uectx=96/96");
}

// 3단계 conditions (20_ §1.3·§3.6·§4.6, 4_ §6.2 #2): 공통 골격이 RAISE는 mode= 뒤·candidates= 앞, UPDATE는 severity= 뒤에
// 찍는다. 비어 있어도 'conditions='. 값이 없으면(nullopt) 찍지 않는다 — 1·2단계 줄은 그대로
TEST(AlertLog, ConditionsLinesMatchStage3Examples) {
  AlertEvent e;
  e.rule = "L3-24";
  e.stage = 3;
  e.unit = "ue";
  e.cell_id = 1;
  e.t = 1793005200100;
  e.kind = AlertEventKind::Raise;
  e.conditions = std::vector<std::string>{"mitm_ul_relay"};
  e.log_fields = {{"ue", "1/3/12"}, {"req", "0"}, {"resp", "1"}, {"rrc_sec", "OFF"}, {"nas_sec", "NONE"}};
  EXPECT_EQ(format_log_line(e),
            "ALERT RAISE rule=L3-24 cell=1 t=1793005200100 ue=1/3/12 req=0 resp=1 rrc_sec=OFF nas_sec=NONE "
            "severity=medium mode=normal conditions=mitm_ul_relay candidates=");

  // L3-24 UPDATE에는 conditions를 싣지 않는다 (20_ §3.6)
  e.kind = AlertEventKind::Update;
  e.conditions.reset();
  e.log_fields.clear();
  e.ues.resize(1);
  e.ues_total = 2;
  e.t = 1793005201000;
  EXPECT_EQ(format_log_line(e), "ALERT UPDATE rule=L3-24 cell=1 t=1793005201000 ues_new=1 ues_total=2 severity=medium");

  // L3-14 갈래 ② RAISE — 전제 없음은 'conditions=' (20_ §4.6)
  AlertEvent b;
  b.rule = "L3-14";
  b.stage = 3;
  b.unit = "ue";
  b.cell_id = 1;
  b.t = 1793005200200;
  b.kind = AlertEventKind::Raise;
  b.severity = Severity::High;
  b.branch = "2";
  b.conditions = std::vector<std::string>{};
  b.log_fields = {{"branch", "2"}, {"ue", "1/3/12"}, {"req", "1"}, {"resp", "0"}, {"rrc_sec", "OFF"}};
  EXPECT_EQ(format_log_line(b),
            "ALERT RAISE rule=L3-14 cell=1 t=1793005200200 branch=2 ue=1/3/12 req=1 resp=0 rrc_sec=OFF severity=high "
            "mode=normal conditions= candidates=");

  // L3-14 UPDATE — 전제가 바뀌면 severity= 뒤에 (20_ §4.6)
  b.kind = AlertEventKind::Update;
  b.log_fields.clear();
  b.conditions = std::vector<std::string>{"mitm_ul_relay"};
  b.ues.resize(1);
  b.ues_total = 2;
  b.t = 1793005201200;
  EXPECT_EQ(format_log_line(b),
            "ALERT UPDATE rule=L3-14 cell=1 t=1793005201200 ues_new=1 ues_total=2 branch=2 severity=high "
            "conditions=mitm_ul_relay");

  // CLEAR·END는 conditions가 있어도 골격 그대로
  b.kind = AlertEventKind::Clear;
  b.duration_ms = 60000;
  EXPECT_EQ(format_log_line(b), "ALERT CLEAR rule=L3-14 cell=1 t=1793005201200 duration_ms=60000 ues_total=2");
}
