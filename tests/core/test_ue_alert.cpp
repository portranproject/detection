// UE 경보 묶음 단위 테스트 (14_ §8.2·§8.3) — RAISE, UPDATE 간격(alert.update_min_ms)·심각도 상승, ues_max, CLEAR·END
#include "detect/ue_alert.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace detect;

namespace {

AlertUe ue(int64_t du) {
  AlertUe u;
  u.cell = 1;
  u.du_ue_id = du;
  u.uid = du;
  return u;
}

std::vector<AlertUe> ues(std::initializer_list<int64_t> dus) {
  std::vector<AlertUe> v;
  for (int64_t d : dus) v.push_back(ue(d));
  return v;
}

std::vector<int64_t> dus(const AlertEvent& e) {
  std::vector<int64_t> v;
  for (const auto& u : e.ues) v.push_back(u.du_ue_id);
  return v;
}

}  // namespace

// 첫 걸림은 RAISE(alert_id = session-룰-셀-seq). 그 뒤 걸린 UE는 RAISE·UPDATE 뒤 update_min_ms가 지나야 UPDATE로 모아 낸다
TEST(UeAlertBook, RaiseThenUpdatesAtMostOncePerInterval) {
  UeAlertBook b("R", AlertConfig{});
  std::vector<AlertEvent> out;
  b.add(1, ues({1}), Severity::Medium, 0, "S", 10, out);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(out[0].alert_id, "S-R-1-10");
  EXPECT_EQ(out[0].stage, 2);
  EXPECT_EQ(out[0].unit, "ue");
  EXPECT_EQ(out[0].ues_total, 1);
  EXPECT_EQ(dus(out[0]), (std::vector<int64_t>{1}));

  b.add(1, ues({2}), Severity::Medium, 500, "S", 11, out);
  b.add(1, ues({3}), Severity::Medium, 700, "S", 12, out);
  b.flush(1, 900, out);
  EXPECT_EQ(out.size(), 1u);  // 아직 1 s 안
  b.flush(1, 1000, out);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[1].kind, AlertEventKind::Update);
  EXPECT_EQ(out[1].alert_id, "S-R-1-10");
  EXPECT_EQ(dus(out[1]), (std::vector<int64_t>{2, 3}));
  EXPECT_EQ(out[1].ues_total, 3);

  b.add(1, ues({4}), Severity::Medium, 2000, "S", 13, out);  // 간격이 지났으면 바로
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(dus(out[2]), (std::vector<int64_t>{4}));
  b.flush(1, 5000, out);  // 모아 둔 것이 없으면 내지 않는다
  EXPECT_EQ(out.size(), 3u);
}

// 심각도가 오르면 간격과 관계없이 바로 UPDATE — 모아 둔 UE도 함께. 오르지 않는 걸림은 다시 모은다
TEST(UeAlertBook, SeverityRiseUpdatesImmediately) {
  UeAlertBook b("R", AlertConfig{});
  std::vector<AlertEvent> out;
  b.add(1, ues({1}), Severity::Medium, 0, "S", 1, out);
  b.add(1, ues({2}), Severity::Medium, 100, "S", 2, out);
  b.add(1, ues({3}), Severity::High, 200, "S", 3, out);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[1].severity, Severity::High);
  EXPECT_EQ(dus(out[1]), (std::vector<int64_t>{2, 3}));
  b.add(1, ues({4}), Severity::High, 300, "S", 4, out);
  EXPECT_EQ(out.size(), 2u);
  EXPECT_EQ(b.severity(1), Severity::High);

  b.update(1, Severity::High, 400, out);  // 강제 UPDATE (갈래 변경 등)
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(dus(out[2]), (std::vector<int64_t>{4}));
}

// 한 레코드의 ues는 ues_max칸까지 — 넘는 UE는 싣지 않고 ues_total로만 센다 (14_ §8.3)
TEST(UeAlertBook, UesMaxCapsEachRecord) {
  AlertConfig cfg;
  cfg.ues_max = 2;
  UeAlertBook b("R", cfg);
  std::vector<AlertEvent> out;
  b.add(1, ues({1, 2, 3}), Severity::Medium, 0, "S", 1, out);
  EXPECT_EQ(dus(out[0]), (std::vector<int64_t>{1, 2}));
  EXPECT_EQ(out[0].ues_total, 3);
  b.add(1, ues({4, 5, 6}), Severity::Medium, 1000, "S", 2, out);
  EXPECT_EQ(dus(out[1]), (std::vector<int64_t>{4, 5}));
  EXPECT_EQ(out[1].ues_total, 6);
}

// CLEAR: 모아 둔 UE가 있으면 먼저 UPDATE. CLEAR 뒤 다시 걸리면 새 경보(새 alert_id)다 (15_ §2.5)
TEST(UeAlertBook, ClearFlushesPendingAndNextHitRaisesAgain) {
  UeAlertBook b("R", AlertConfig{});
  std::vector<AlertEvent> out;
  b.add(1, ues({1}), Severity::Medium, 0, "S", 1, out);
  b.add(1, ues({2}), Severity::Medium, 100, "S", 2, out);
  b.clear(1, 200, out);
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[1].kind, AlertEventKind::Update);
  EXPECT_EQ(out[2].kind, AlertEventKind::Clear);
  EXPECT_EQ(out[2].duration_ms, 200);
  EXPECT_EQ(out[2].ues_total, 2);
  EXPECT_FALSE(b.open(1));
  b.add(1, ues({3}), Severity::Medium, 300, "S", 9, out);
  EXPECT_EQ(out[3].kind, AlertEventKind::Raise);
  EXPECT_EQ(out[3].alert_id, "S-R-1-9");
}

// END (14_ §8.2): input_lost는 그 셀만, session_reset은 모든 셀 — 각 경보가 마지막으로 본 시각으로
TEST(UeAlertBook, EndInputLostAndSessionReset) {
  UeAlertBook b("R", AlertConfig{});
  std::vector<AlertEvent> out;
  b.add(1, ues({1}), Severity::Medium, 0, "S", 1, out);
  b.add(2, ues({1}), Severity::Medium, 50, "S", 2, out);
  b.flush(2, 700, out);
  b.end(1, 500, "input_lost", out);
  ASSERT_EQ(out.size(), 3u);
  EXPECT_EQ(out[2].kind, AlertEventKind::End);
  EXPECT_EQ(out[2].reason, "input_lost");
  EXPECT_EQ(out[2].duration_ms, 500);
  b.end_all("session_reset", out);
  ASSERT_EQ(out.size(), 4u);
  EXPECT_EQ(out[3].cell_id, 2);
  EXPECT_EQ(out[3].t, 700);
  EXPECT_EQ(out[3].duration_ms, 650);
  EXPECT_EQ(out[3].reason, "session_reset");
  EXPECT_FALSE(b.open(2));
}

// 단계 (4_ §6.2 #1, 14_ §8.3): 생성자에서 받은 stage를 모든 이벤트에 — 3단계 룰은 3. 기본값은 2(2단계 룰)
TEST(UeAlertBook, StageFromConstructor) {
  for (const char* kind : {"attack", "anomaly"}) {
    UeAlertBook b("R", AlertConfig{}, kind, 3);
    std::vector<AlertEvent> out;
    b.add(1, ues({1}), Severity::Medium, 0, "S", 1, out);
    b.add(1, ues({2}), Severity::High, 100, "S", 2, out);  // 심각도 상승 → 바로 UPDATE
    b.add(2, ues({1}), Severity::Medium, 100, "S", 3, out);
    b.clear(1, 200, out);
    b.end_all("session_reset", out);
    ASSERT_EQ(out.size(), 5u);
    EXPECT_EQ(out[0].kind, AlertEventKind::Raise);
    EXPECT_EQ(out[1].kind, AlertEventKind::Update);
    EXPECT_EQ(out[2].kind, AlertEventKind::Raise);
    EXPECT_EQ(out[3].kind, AlertEventKind::Clear);
    EXPECT_EQ(out[4].kind, AlertEventKind::End);
    for (const AlertEvent& e : out) {
      EXPECT_EQ(e.stage, 3);
      EXPECT_EQ(e.alert_kind, kind);
      EXPECT_FALSE(e.conditions.has_value());  // 묶음은 conditions를 채우지 않는다 — 룰 몫 (20_ §1.3)
    }
  }
  UeAlertBook d("R", AlertConfig{});
  std::vector<AlertEvent> out;
  d.add(1, ues({1}), Severity::Medium, 0, "S", 1, out);
  d.end(1, 50, "input_lost", out);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].stage, 2);
  EXPECT_EQ(out[1].stage, 2);
}
