// 마감 목록·셀 시계·로스 기록 단위 테스트 (14_ §6)
#include "detect/deadline_queue.h"

#include <gtest/gtest.h>

#include <string>

using namespace detect;

namespace {

Deadline at(int64_t t, int64_t cell, const std::string& tag) {
  Deadline d;
  d.at = t;
  d.key = UeKey{cell, 1};
  d.tag = tag;
  return d;
}

Kpm2 window(int64_t t_start, std::optional<UeEvtLost> lost) {
  Kpm2 k;
  k.cell_id = 1;
  k.t_start_ms = t_start;
  k.t_end_ms = t_start + 100;
  k.ue_evt_lost = lost;
  return k;
}

}  // namespace

// 셀 시계가 마감을 지난 것만, 마감 시각 → 넣은 순서로 꺼낸다. 셀마다 따로 (14_ §6.1-2·4)
TEST(DeadlineQueue, PopsDueByTimeThenInsertionPerCell) {
  DeadlineQueue q;
  q.add(at(200, 1, "a"));
  q.add(at(100, 1, "b"));
  q.add(at(200, 1, "c"));
  q.add(at(50, 2, "d"));
  EXPECT_EQ(q.size(), 4u);
  EXPECT_FALSE(q.pop_due(1));  // 시계 없음

  q.set_clock(1, 150);
  EXPECT_EQ(q.pop_due(1)->tag, "b");
  EXPECT_FALSE(q.pop_due(1));
  q.set_clock(1, 200);  // 마감 = 시계도 꺼낸다
  EXPECT_EQ(q.pop_due(1)->tag, "a");
  EXPECT_EQ(q.pop_due(1)->tag, "c");
  EXPECT_FALSE(q.pop_due(1));

  EXPECT_FALSE(q.pop_due(2));  // 셀 2 시계는 아직 없다
  q.set_clock(2, 50);
  EXPECT_EQ(q.pop_due(2)->tag, "d");
  EXPECT_EQ(q.size(), 0u);
}

// 로스 기록 (14_ §6.2): ue_evt_lost의 방향만, 키 없음은 양방향, 끊김은 양방향을 끊김 끝(t_start)까지.
// 보류 = loss_end[dir] > t_from
TEST(DeadlineQueue, LossRecordAndHeld) {
  DeadlineQueue q;
  auto r = q.record_loss(window(0, UeEvtLost{true, false}), false, 1);
  EXPECT_TRUE(r.loss.ul);
  EXPECT_FALSE(r.loss.dl);
  EXPECT_TRUE(q.held(1, Dir::UL, 99));
  EXPECT_FALSE(q.held(1, Dir::UL, 100));  // 로스가 대기 시작 전에 끝남
  EXPECT_FALSE(q.held(1, Dir::DL, 0));

  r = q.record_loss(window(100, std::nullopt), false, 2);  // 알 수 없음 → 양방향
  EXPECT_TRUE(r.loss.ul && r.loss.dl);
  EXPECT_EQ(q.loss_end(1, Dir::DL), 200);

  r = q.record_loss(window(500, UeEvtLost{false, false}), true, 3);  // 끊김 [200, 500)
  EXPECT_TRUE(r.loss.ul && r.loss.dl);
  EXPECT_EQ(q.loss_end(1, Dir::UL), 500);
  EXPECT_TRUE(q.held(1, Dir::DL, 499));
  EXPECT_FALSE(q.held(1, Dir::DL, 500));

  r = q.record_loss(window(600, UeEvtLost{false, false}), false, 4);  // 로스 없는 창 — 기록은 그대로
  EXPECT_FALSE(r.loss.any());
  EXPECT_EQ(q.loss_end(1, Dir::UL), 500);
  EXPECT_FALSE(q.loss_end(2, Dir::UL));
}

// 룰 몫 마감 색인 (14_ §4.4·§4.2 — 이슈 #44): 룰 몫 마감이 걸린 (키, uid)만 참, 꺼내면 거짓. 표 몫(kTableOwner)은 세지 않는다.
// 같은 (키, uid)에 둘이 걸리면 둘 다 꺼내야 거짓
TEST(DeadlineQueue, RuleDeadlineIndex) {
  DeadlineQueue q;
  Deadline table = at(100, 1, "stale_setup");
  table.owner = DeadlineQueue::kTableOwner;
  q.add(table);
  EXPECT_FALSE(q.has_rule_deadline(UeKey{1, 1}, 0));
  q.add(at(200, 1, "auth_resp"));  // owner 0 = 룰, uid 0
  q.add(at(300, 1, "accept"));
  EXPECT_TRUE(q.has_rule_deadline(UeKey{1, 1}, 0));
  EXPECT_FALSE(q.has_rule_deadline(UeKey{1, 1}, 1));  // 다른 uid
  EXPECT_FALSE(q.has_rule_deadline(UeKey{1, 2}, 0));
  q.set_clock(1, 200);
  EXPECT_EQ(q.pop_due(1)->tag, "stale_setup");
  EXPECT_EQ(q.pop_due(1)->tag, "auth_resp");
  EXPECT_TRUE(q.has_rule_deadline(UeKey{1, 1}, 0));  // accept가 남았다
  q.set_clock(1, 300);
  EXPECT_EQ(q.pop_due(1)->tag, "accept");
  EXPECT_FALSE(q.has_rule_deadline(UeKey{1, 1}, 0));
  q.add(at(400, 1, "x"));
  q.clear();
  EXPECT_FALSE(q.has_rule_deadline(UeKey{1, 1}, 0));
}

TEST(DeadlineQueue, ClearEmptiesEverything) {
  DeadlineQueue q;
  q.add(at(100, 1, "a"));
  q.set_clock(1, 50);
  q.record_loss(window(0, std::nullopt), false, 1);
  q.clear();
  EXPECT_EQ(q.size(), 0u);
  EXPECT_FALSE(q.clock(1));
  EXPECT_FALSE(q.loss_end(1, Dir::UL));
}
