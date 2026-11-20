// 기준선 단위 테스트 (3_ §5)
#include "detect/baseline.h"

#include <gtest/gtest.h>

#include <cmath>

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

// 웜업 표본 0개 (3_ §5 — 11/05 Q-76 해결, 이슈 #94): 웜업 동안 갱신 표본이 없었으면 웜업 뒤 첫 표본으로 시드하고 그 뒤 EWMA.
// 0에서 EWMA를 시작하면 τ 동안 C3가 늘 참이었다(25_ §3.2-7)
TEST(Baseline, SeedWhenNoWarmupSamples) {
  Baseline b(1000, 300, 100);
  b.tick(0);
  b.tick(900);
  EXPECT_DOUBLE_EQ(b.value(), 0.0);
  b.add(1000, 6);  // 웜업(1 s) 뒤 첫 표본 → 시드
  EXPECT_DOUBLE_EQ(b.value(), 6.0);
  EXPECT_DOUBLE_EQ(b.sigma(), 0.0);  // 표본 하나로는 분산을 모름 — σ는 0으로 시드 (3_ §5, 11/12)
  b.add(1100, 3006);  // 그 뒤 EWMA (α = 1/3000)
  EXPECT_NEAR(b.value(), 6.0 + 3000.0 / 3000.0, 1e-9);
  EXPECT_NEAR(b.sigma(), std::sqrt((1.0 - 1.0 / 3000) * (3000.0 * 3000.0 / 3000)), 1e-9);
}

// σ (3_ §5 — 11/12 사용자 결정, Q-44 C3 부분 해결): 웜업 중에는 모분산(n으로 나눔)
TEST(Baseline, WarmupSigmaIsPopulationStd) {
  Baseline b(30000, 300, 100);
  EXPECT_DOUBLE_EQ(b.sigma(), 0.0);
  b.add(1000, 2);
  b.add(1100, 4);
  b.add(1200, 6);
  EXPECT_NEAR(b.sigma(), std::sqrt(8.0 / 3.0), 1e-12);
}

// 일정한 입력이면 σ는 정확히 0 — 웜업 중에도 뒤에도 (반올림 잔차가 있으면 A_w = base인 칸의 C3가 흔들린다)
TEST(Baseline, ConstantInputGivesExactZeroSigma) {
  Baseline b(1000, 300, 100);
  for (int i = 0; i < 30; ++i) b.add(100 * i, 7);
  EXPECT_FALSE(b.in_warmup(2900));
  EXPECT_EQ(b.sigma(), 0.0);
  EXPECT_EQ(b.value(), 7.0);
}

// 웜업 뒤에는 같은 α의 지수 이동 분산: d = x − base, var ← (1 − α)·(var + α·d²), 웜업 분산에서 이어 간다
TEST(Baseline, EwmaVarianceAfterWarmup) {
  Baseline b(1000, 300, 100);
  b.add(0, 2);
  b.add(100, 4);  // 웜업: base 3, var 1
  EXPECT_DOUBLE_EQ(b.sigma(), 1.0);
  b.add(1000, 33);  // d = 30, α = 1/3000
  const double a = 1.0 / 3000;
  EXPECT_NEAR(b.value(), 3.0 + a * 30, 1e-12);
  EXPECT_NEAR(b.sigma(), std::sqrt((1 - a) * (1.0 + a * 900)), 1e-12);
}
