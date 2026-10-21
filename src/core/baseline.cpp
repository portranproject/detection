#include "detect/baseline.h"

namespace detect {

// α = P / τ (3_ §5). τ = 300 s, P = 100 ms면 α ≈ 0.00033 — 기준선이 공격을 따라 올라가지 않게 길게 잡는다
Baseline::Baseline(int64_t warmup_ms, double tau_s, int64_t period_ms)
    : warmup_ms_(warmup_ms), alpha_(static_cast<double>(period_ms) / (tau_s * 1000.0)) {}

void Baseline::tick(int64_t t) {
  if (!t0_) t0_ = t;
}

// 웜업 중에는 단순 평균, 웜업 뒤에는 그 평균에서 시작해 EWMA로 갱신한다 (3_ §5)
void Baseline::add(int64_t t, double x) {
  tick(t);
  if (in_warmup(t)) {
    sum_ += x;
    ++n_;
    value_ = sum_ / static_cast<double>(n_);
  } else {
    value_ += alpha_ * (x - value_);
  }
}

}  // namespace detect
