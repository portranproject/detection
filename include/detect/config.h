#pragma once
// 룰 파라미터 (3_ §4 파라미터 표·§5·§8). 키 이름과 기본값은 4_ §1.2 설정 파일과 같다.
// 설정 파일 읽기는 실행 파일 이슈(M4)에서 붙인다 — 지금은 구조체 기본값만 둔다 (결정 E10).

#include <cstdint>
#include <optional>

namespace detect {

struct BtsVariantConfig {
  int64_t window_ms = 1000;            // window_ms — W
  int64_t a_min = 5;                   // a_min — A_min
  double theta = 0.5;                  // theta — θ
  double k = 3;                        // k — 기준선 배수
  int m_raise = 3;                     // m_raise — M (연속 성립)
  int k_clear = 10;                    // k_clear — K (연속 불성립)
  int64_t h_sat_ms = 3000;             // h_sat_ms — 해제 유지 창 (3_ §6.1 가)
  int64_t warmup_ms = 30000;           // warmup_ms — 웜업 (3_ §5)
  double baseline_tau_s = 300;         // baseline_tau_s — τ, α = P / τ (3_ §5)
  int64_t h_hold_ms = 10000;           // h_hold_ms — 보류 상한 (3_ §8)
  int missing_key_slots = 10;          // missing_key_slots — A·S 누락 연속 칸 상한 (3_ §8)
  std::optional<int64_t> max_conn;     // max_conn — C4. null이면 끔, hello cells[].max_conn이 우선 (3_ §4)
};

}  // namespace detect
