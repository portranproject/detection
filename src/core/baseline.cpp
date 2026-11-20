#include "detect/baseline.h"

#include <algorithm>
#include <cmath>

namespace detect {

// α = P / τ (3_ §5). τ = 300 s, P = 100 ms면 α ≈ 0.00033 — 기준선이 공격을 따라 올라가지 않게 길게 잡는다
Baseline::Baseline(int64_t warmup_ms, double tau_s, int64_t period_ms)
    : warmup_ms_(warmup_ms), alpha_(static_cast<double>(period_ms) / (tau_s * 1000.0)) {}

void Baseline::tick(int64_t t) {
  if (!t0_) t0_ = t;
}

// 웜업 중에는 단순 평균, 웜업 뒤에는 그 평균에서 시작해 EWMA로 갱신한다 (3_ §5).
// 분산도 같은 칸으로 함께 잰다 (3_ §5 'σ' — 11/12 사용자 결정, Q-44 C3 부분 해결): 웜업 중 모분산(n으로 나눔), 웜업 뒤
// d = x − base, base ← base + α·d, var ← (1 − α)·(var + α·d²). 분산도 웜업 값에서 이어 간다
void Baseline::add(int64_t t, double x) {
  tick(t);
  if (in_warmup(t)) {
    sum_ += x;
    sumsq_ += x * x;
    ++n_;
    const double n = static_cast<double>(n_);
    value_ = sum_ / n;
    // 모분산 = (n·Σx² − (Σx)²) / n². A_w는 정수라 분자가 정확히 계산되어, 일정한 입력이면 σ가 정확히 0이다
    // (σ에 반올림 잔차가 남으면 A_w = base인 칸의 C3가 흔들린다). 음수 잔차는 0으로
    var_ = std::max(0.0, (n * sumsq_ - sum_ * sum_) / (n * n));
  } else if (n_ == 0) {
    // 웜업 표본 0개 (3_ §5 — 11/05 Q-76, 이슈 #94): DL 미관측 웜업·공격 중 세션 변경으로 웜업 동안 갱신 표본이 없었으면 첫 표본으로
    // 시드한다 — 0에서 EWMA를 시작하면 τ 동안 C3가 늘 참이었다(25_ §3.2-7). 표본 하나로는 분산을 알 수 없어 σ는 0에서 시작한다
    // (3_ §5 — 11/12, 약 τ에 걸쳐 실제 값으로 자람)
    value_ = x;
    var_ = 0;
    n_ = 1;
  } else {
    const double d = x - value_;
    value_ += alpha_ * d;
    var_ = (1.0 - alpha_) * (var_ + alpha_ * d * d);
  }
}

double Baseline::sigma() const { return std::sqrt(var_); }

}  // namespace detect
