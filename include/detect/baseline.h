#pragma once
// 기준선 base와 표준편차 σ (3_ §5): 웜업 동안 단순 평균·모분산, 그 뒤 EWMA(α = P / τ)와 같은 α의 지수 이동 분산.
// 어떤 칸을 갱신에서 뺄지(경보 중·의심 칸)는 룰이 정하고, 여기서는 받은 값만 반영한다.

#include <cstdint>
#include <optional>

namespace detect {

class Baseline {
 public:
  Baseline(int64_t warmup_ms, double tau_s, int64_t period_ms);

  // 판정한 칸마다 부른다(갱신에서 뺀 칸도). 첫 호출 시각이 웜업 시작이다 — 웜업은 데이터 시각으로 잰다
  void tick(int64_t t);
  bool in_warmup(int64_t t) const { return !t0_ || t - *t0_ < warmup_ms_; }

  // 갱신에 쓸 칸의 값 x (= A_w 또는 A′_w)
  void add(int64_t t, double x);
  double value() const { return value_; }
  // 표준편차 σ (3_ §5 — 11/12): C3 문턱 base + z·σ에 쓴다
  double sigma() const;

 private:
  int64_t warmup_ms_;
  double alpha_;
  std::optional<int64_t> t0_;
  double sum_ = 0;
  double sumsq_ = 0;  // 웜업 중 x² 합 — 모분산용 (11/12)
  int64_t n_ = 0;
  double value_ = 0;
  double var_ = 0;    // 분산 σ² (11/12)
};

}  // namespace detect
