#pragma once
// 설정 (4_ §1.2 config/detector.json, 1_ FR-7). 키 이름과 기본값은 설정 파일과 같다.
// parse_config는 JSON 문자열만 받는다 — 파일 읽기는 실행 파일이 한다 (core는 I/O 없음, 4_ §2).

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace detect {

struct BtsVariantConfig {
  int64_t window_ms = 1000;            // window_ms — W
  int64_t a_min = 5;                   // a_min — A_min
  double theta = 0.5;                  // theta — θ
  int64_t f_abs = 10;                  // f_abs — F_abs: C2a 절대 실패 수 문턱(건/W), 1 이상 (3_ §4, 10/27 Q-41)
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

// UE 상태표 (14_ §9 ue_table.*). 설정 파일 키는 아직 읽지 않고 이 기본값을 쓴다 (4_ §1.2)
struct UeTableConfig {
  std::size_t max_ues = 4096;      // ue_table.max_ues — 열린 항목 상한 (14_ §4.4)
  std::size_t recent_n = 16;       // ue_table.recent_n — UE당 최근 메시지 수, 증거용 (14_ §2.3)
  int64_t stale_setup_ms = 30000;  // ue_table.stale_setup_ms — CONNECTED 전 항목 정리 (14_ §4.2)
};

// 설정 파일 전체 (4_ §1.2). rules는 룰 ID → 그 룰의 설정 객체(JSON 문자열)다 — 공통 파서는 넘기기만 하고
// 룰별 파서(parse_bts_variant_config 등)가 키·범위를 검사한다 (Q-46, 결정 J4)
struct DetectorConfig {
  std::string socket_path = "/run/ran-detect/kpm.sock";  // socket_path (2_ §1)
  std::size_t max_line_bytes = 65536;                     // max_line_bytes (2_ §1 줄 길이 상한)
  std::map<std::string, std::string> rules;               // rules.<룰 ID> — 설정 객체를 JSON 문자열 그대로
  EvidenceConfig evidence;                                // evidence
};

struct ConfigResult {
  bool ok = false;
  DetectorConfig config;
  std::string error;                  // ok가 아니면 이유
  std::vector<std::string> warnings;  // 모르는 키 등 (결정 G3)
};

// 빠진 키는 기본값, 모르는 키는 경고, 타입·범위가 틀리면 오류 (결정 G3). rules의 값은 객체여야 하고 내용은 검사하지 않는다
ConfigResult parse_config(std::string_view json_text);

// 룰 L3-01-V의 설정 객체 해석 (3_ §4 파라미터 표 · §5 · §8). 모르는 키는 경고, 타입·범위 오류는 ok = false
struct BtsVariantConfigResult {
  bool ok = false;
  BtsVariantConfig config;
  std::string error;
  std::vector<std::string> warnings;
};
BtsVariantConfigResult parse_bts_variant_config(std::string_view json_text);

}  // namespace detect
