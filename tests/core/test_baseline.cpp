// 기준선 단위 테스트 (3_ §5)
#include "detect/baseline.h"

#include <gtest/gtest.h>

using namespace detect;

// 웜업 동안은 단순 평균
TEST(Baseline, WarmupIsSimpleMean) {
  Baseline b(30000, 300, 100);
  b.add(1000, 2);
  b.add(1100, 4);
  b.add(1200, 6);
  EXPECT_DOUBLE_EQ(b.value(), 4.0);
  EXPECT_TRUE(b.in_warmup(1200));
  EXPECT_TRUE(b.in_warmup(30999));
  EXPECT_FALSE(b.in_warmup(31000));  // 첫 칸부터 30 s (데이터 시각)
}

// 웜업 뒤에는 α = P / τ로 EWMA — τ 300 s, P 100 ms면 α = 1/3000
TEST(Baseline, EwmaAfterWarmup) {
  Baseline b(1000, 300, 100);
  b.add(0, 3);
  b.add(1000, 3003);
  EXPECT_NEAR(b.value(), 3.0 + 3000.0 / 3000.0, 1e-9);
}

// tick만 하고 add하지 않은 칸(갱신 제외 칸)도 웜업 시간은 흐른다
TEST(Baseline, TickStartsWarmupClock) {
  Baseline b(1000, 300, 100);
  b.tick(500);
  EXPECT_TRUE(b.in_warmup(1499));
  EXPECT_FALSE(b.in_warmup(1500));
  EXPECT_DOUBLE_EQ(b.value(), 0.0);
}

// 공격처럼 큰 값이 한 번 들어와도 기준선은 거의 움직이지 않는다 (3_ §5 — 10/21 전 α 0.05의 문제)
TEST(Baseline, LongTimeConstantResistsSpike) {
  Baseline b(0, 300, 100);
  b.tick(0);
  for (int i = 0; i < 30; ++i) b.add(100 * (i + 1), 2);
  const double before = b.value();
  for (int i = 0; i < 20; ++i) b.add(3100 + 100 * i, 300);  // 2 s 동안 큰 값
  EXPECT_LT(b.value() - before, 3.0);
}
