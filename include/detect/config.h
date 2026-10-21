#pragma once
// 룰 파라미터 (3_ §4 파라미터 표·§5·§8). 키 이름과 기본값은 4_ §1.2 설정 파일과 같다.
// 설정 파일 읽기는 실행 파일 이슈(M4)에서 붙인다 — 지금은 구조체 기본값만 둔다 (결정 E10).

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

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

// 증거 내보내기 설정 (3_ §7.1 파라미터 표, 4_ §1.2 "evidence")
enum class EvidenceMode {
  Full,  // alert + evidence + gap
  Ref,   // alert만 (seq 범위 포함) — 대시보드가 KPM을 직접 받을 때
  Off,   // 내지 않음
};

struct EvidenceConfig {
  EvidenceMode mode = EvidenceMode::Full;  // mode
  std::optional<std::size_t> pre_slots;    // pre_slots — null이면 버퍼 크기(W/P + D + 1). 버퍼도 이 값 이상으로 잡아야 한다
  std::size_t post_slots = 10;             // post_slots — CLEAR 뒤 더 낼 칸 수
  std::size_t queue_max = 4096;            // queue_max — 큐 안 evidence 수 상한
  std::string out_path = "evidence.jsonl"; // out_path — 대시보드 전달 방식이 정해지기 전까지 쓰는 파일 (Q-19)
};

}  // namespace detect
