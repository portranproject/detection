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

// UE 상태표 (14_ §9 ue_table.*). 설정 파일에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct UeTableConfig {
  std::size_t max_ues = 4096;      // ue_table.max_ues — 열린 항목 상한 (14_ §4.4)
  std::size_t recent_n = 16;       // ue_table.recent_n — UE당 최근 메시지 수, 증거용 (14_ §2.3)
  int64_t stale_setup_ms = 30000;  // ue_table.stale_setup_ms — CONNECTED 전 항목 정리 (14_ §4.2)
  std::size_t closed_recent_max = 1024;  // ue_table.closed_recent_max — 닫힌 항목 recent 보관 상한 (14_ §2.3)
  // 유령 정리·밀어내기 보호 무리 (14_ §4.2·§4.4·§9 — 10/29 Q-56 해결, 이슈 #44). 값은 제안값(16_ W-27 실측 뒤 조정)
  double ghost_k = 2;               // ue_table.ghost_k — CONNECTED 수 > k × ConnMax + margin이면 유령 정리
  int64_t ghost_margin = 16;        // ue_table.ghost_margin — 유령 정리 여유(ConnMax 표본 뒤 붙은 UE·해제 대기)
  int64_t ghost_hold_ms = 5000;     // ue_table.ghost_hold_ms — 초과가 이만큼 이어져야 정리. 0이면 바로
  int64_t evict_protect_ms = 5000;  // ue_table.evict_protect_ms — 마지막 줄이 이 안인 항목은 밀어내기 맨 뒤
  // 상수에서 설정 키로 (16_ §3.2-1 W-24, 이슈 #44)
  int64_t dl_unobserved_ms = 5000;       // ue_table.dl_unobserved_ms — 진단 dl_unobserved·ue_evt_lost_missing 연속 시간 (14_ §6.2)
  int64_t recent_keep_margin_ms = 1000;  // ue_table.recent_keep_margin_ms — 닫힌 항목 recent 보관 여유 (14_ §2.3·§1.1)
  // S-TMSI 이력 표 (14_ §3.2·§9 — 11/03 확인 지점 ⑤ 사용자 확정, 11/04 이슈 #74)
  int64_t tomb_ms = 600000;        // ue_table.tomb_ms — 연결 레코드 보관 시간. 4단계 룰의 창(최대 5분)보다 길게
  std::size_t tomb_max = 4096;     // ue_table.tomb_max — 연결 레코드 상한, 넘치면 오래된 것부터
  int64_t alloc_ms = 3600000;      // ue_table.alloc_ms — 할당 기억 보관 시간. 단말은 받은 5G-GUTI를 다음 등록까지 쓴다
  std::size_t alloc_max = 4096;    // ue_table.alloc_max — 할당 기억 상한
};

// UE 단위 경보 (14_ §9 alert.*). 설정 파일에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct AlertConfig {
  std::size_t ues_max = 50;          // alert.ues_max — 레코드 하나의 ues 칸 수 (14_ §8.3)
  int64_t update_min_ms = 1000;      // alert.update_min_ms — 새 UE로 내는 update 최소 간격 (14_ §8.2)
  std::size_t ue_evidence_max = 50;  // alert.ue_evidence_max — 경보 하나에서 증거를 내는 UE 수 상한 (14_ §8.3)
  bool held_alert = true;            // alert.held_alert — 보류가 개수 문턱만큼 쌓이면 불확실 경보(kind anomaly) (14_ §6.2, Q-58 해결 — 이슈 #48)
};

// 룰 L3-20 Blind DoS (15_ §2.4·§1.2). 설정 파일 rules.L3-20에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct BlindDosConfig {
  int64_t accept_wait_ms = 5000;   // accept_wait_ms — T_acc, 망 수락 대기 (15_ §2.3)
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림 뒤 이만큼 새로 걸린 UE가 없으면 해제 (15_ §2.5)
};

// 룰 L3-01-O 인증 단계 고착 (15_ §4.4·§1.2). 설정 파일 rules.L3-01-O에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct AuthStallConfig {
  int64_t auth_wait_ms = 2000;           // auth_wait_ms — T_auth, AuthenticationRequest 응답 대기 (15_ §4.3)
  int64_t window_ms = 10000;             // window_ms — W, 셀 고착 수를 세는 창
  int64_t n_stall = 5;                   // n_stall — N, 창 안 고착 수 문턱
  int64_t clear_quiet_ms = 60000;        // clear_quiet_ms — 마지막 성립 뒤 이만큼 성립이 없으면 해제 (15_ §4.5)
  std::optional<int64_t> max_conn = 96;  // max_conn — 심각도 high 문턱 0.9 × max_conn. null이면 high를 쓰지 않음,
                                         // hello cells[].max_conn이 우선 (15_ §4.3, 1단계 3_ §4와 같음)
};

// 룰 L3-21 상향 DoS (15_ §5.4·§1.2). 설정 파일 rules.L3-21에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct UplinkDosConfig {
  int64_t window_ms = 10000;            // window_ms — W, 셀 실패 UE 수를 세는 창 (갈래 ①)
  int64_t n_fail = 5;                   // n_fail — N, 창 안 실패 UE 수 문턱 (갈래 ①)
  int64_t fail_accept_wait_ms = 5000;   // fail_accept_wait_ms — T_fa, 실패 뒤 망 수락 대기 (15_ §5.3)
  int64_t reg_repeat = 3;               // reg_repeat — R, 한 연결 안 RegistrationRequest 수 문턱 (갈래 ②)
  int64_t clear_quiet_ms = 60000;       // clear_quiet_ms — 마지막 성립·걸림 뒤 이만큼 조용하면 해제 (15_ §5.5)
  std::vector<int64_t> ignore_causes;   // ignore_causes — 실패로 세지 않을 Reject의 5GMM 원인값. 기본 끔 (15_ §5.2)
};

// 룰 L3-24 하향 IMSI 추출 (20_ §3.4·§1.5). 설정 파일 rules.L3-24에 키가 없으면 이 기본값을 쓴다 (4_ §1.2).
// 대기 시간 키는 없다 — 마감 = 응답 시각 + 1 ms는 입력 순서에서 나온 값이라 바꾸면 판정이 틀어진다(20_ §1.2-3)
struct ImsiExtractorConfig {
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림 뒤 이만큼 새로 걸린 UE가 없으면 해제 (20_ §3.5)
};

// 룰 L3-14 UE 능력 탈취 (20_ §4.4·§1.5). 설정 파일 rules.L3-14에 키가 없으면 이 기본값을 쓴다 (4_ §1.2). 대기 시간 키는 없다(§3.4와 같은 이유)
struct CapHijackConfig {
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림(두 갈래 중 늦은 것) 뒤 이만큼 새로 걸린 UE가 없으면 해제 (20_ §4.5)
};

// 룰 L3-06 NAS 카운터 비동기화 — 요청 없는 Security Mode Reject (20_ §5.4·§1.5). 설정 파일 rules.L3-06에 키가 없으면 이 기본값을
// 쓴다 (4_ §1.2). 대기 시간 키는 없다(§3.4와 같은 이유)
struct NasDesyncConfig {
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림 뒤 이만큼 새로 걸린 UE가 없으면 해제 (20_ §5.5)
};

// 4단계 룰 AN-01 인증 동기 실패 재인증 (21_ §3.4·§1.2). 설정 파일 rules.AN-01에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct SyncFailureConfig {
  int64_t window_ms = 60000;       // window_ms — W, 셀 창. N = 1이면 쓰이지 않고 N > 1일 때 '반복'을 재는 폭 (21_ §3.4)
  int64_t n_sync = 1;              // n_sync — N, 창 안 동기 실패 연결 수 문턱. 표적 공격은 피해자 한 명 (21_ §3.3-3)
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림 뒤 이만큼 새로 걸린 UE가 없으면 해제 (21_ §3.5)
};

// 4단계 룰 AN-06a 보안 수립 뒤 재인증·SMC 재등장 (21_ §4.4·§1.2). 설정 파일 rules.AN-06a에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct SecReauthConfig {
  int64_t n_reauth = 1;            // n_reauth — N, 연결당 보안 뒤 재등장 수 문턱. 이 AMF는 정상에서 0회 (21_ §4.4, 5_ §16)
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림 뒤 이만큼 새로 걸린 UE가 없으면 해제 (21_ §4.5)
};

// 4단계 룰 AN-02 식별 요청 증가 (21_ §5.4·§1.2). 설정 파일 rules.AN-02에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct IdentityRequestConfig {
  int64_t window_ms = 60000;       // window_ms — W, 갈래 ② 셀 창. 식별 요청은 등록마다 많아야 하나 (21_ §5.4)
  int64_t n_idreq = 5;             // n_idreq — N, 창 안 식별 요청 연결 수 문턱. 2단계 셀 문턱과 같은 규모 (21_ §5.4)
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 성립 뒤 이만큼 새 성립이 없으면 해제 (21_ §5.5)
};

// 4단계 룰 AN-04 같은 UE의 짧은 연결 반복 (21_ §6.4·§1.2). 설정 파일 rules.AN-04에 키가 없으면 이 기본값을 쓴다 (4_ §1.2)
struct ShortRepeatConfig {
  int64_t short_ms = 5000;         // short_ms — S, 짧은 연결 기준. 페이징에 답한 뒤 할 일 없는 접속은 곧 해제 (21_ §6.4)
  int64_t window_ms = 300000;      // window_ms — W, 같은 S-TMSI의 짧은 연결을 세는 창. 이력 표 보관(10분)보다 짧게
  int64_t n_short = 3;             // n_short — N, 창 안 짧은 연결 수 문턱. 2번은 정상에서도 흔하다
  int64_t clear_quiet_ms = 60000;  // clear_quiet_ms — 마지막 걸림 뒤 이만큼 새로 걸린 UE가 없으면 해제 (21_ §6.5)
};

// 설정 파일 전체 (4_ §1.2). rules는 룰 ID → 그 룰의 설정 객체(JSON 문자열)다 — 공통 파서는 넘기기만 하고
// 룰별 파서(parse_bts_variant_config 등)가 키·범위를 검사한다 (Q-46, 결정 J4)
struct DetectorConfig {
  std::string socket_path = "/run/ran-detect/kpm.sock";  // socket_path (2_ §1)
  std::size_t max_line_bytes = 65536;                     // max_line_bytes (2_ §1 줄 길이 상한)
  std::size_t max_cells = 64;                             // max_cells — 셀 수 상한 (결정 D7, 16_ W-24로 설정 키)
  // input_silent_ms — 벽시계로 마지막 kpm2 뒤 이만큼 kpm2가 없으면 진단 input_silent 1회 + 진행 중 경보 전부 END(reason=input_silent).
  // 기본 10,000 = H_hold와 같은 값(제안값), 1,000~600,000. 소켓 모드만 (3_ §8, 14_ §6.2 — 10/29 Q-45 해결, 이슈 #50)
  int64_t input_silent_ms = 10000;
  std::map<std::string, std::string> rules;               // rules.<룰 ID> — 설정 객체를 JSON 문자열 그대로
  EvidenceConfig evidence;                                // evidence
  UeTableConfig ue_table;                                 // ue_table — 2단계 UE 상태표 (14_ §9)
  AlertConfig alert;                                      // alert — 2단계 UE 경보 (14_ §9)
};

struct ConfigResult {
  bool ok = false;
  DetectorConfig config;
  std::string error;                  // ok가 아니면 이유
  std::vector<std::string> warnings;  // 모르는 키 등 (결정 G3)
};

// 빠진 키는 기본값, 모르는 키는 경고, 타입·범위가 틀리면 오류 (결정 G3). rules의 값은 객체여야 하고 내용은 검사하지 않는다
ConfigResult parse_config(std::string_view json_text);

// 룰별 설정 객체 해석 결과 (Q-46, 결정 J4). 모르는 키는 경고, 타입·범위 오류는 ok = false
template <typename T>
struct RuleConfigResult {
  bool ok = false;
  T config;
  std::string error;
  std::vector<std::string> warnings;
};

// 룰 L3-01-V (3_ §4 파라미터 표 · §5 · §8)
using BtsVariantConfigResult = RuleConfigResult<BtsVariantConfig>;
BtsVariantConfigResult parse_bts_variant_config(std::string_view json_text);
// 2단계 룰 L3-20·L3-01-O·L3-21 (15_ §1.2 표 — 타입·허용 범위)
RuleConfigResult<BlindDosConfig> parse_blind_dos_config(std::string_view json_text);
RuleConfigResult<AuthStallConfig> parse_auth_stall_config(std::string_view json_text);
RuleConfigResult<UplinkDosConfig> parse_uplink_dos_config(std::string_view json_text);
// 3단계 룰 L3-24·L3-14 (20_ §1.5 표 — 타입·허용 범위)
RuleConfigResult<ImsiExtractorConfig> parse_imsi_extractor_config(std::string_view json_text);
RuleConfigResult<CapHijackConfig> parse_cap_hijack_config(std::string_view json_text);
// 3단계로 올린 룰 L3-06 (20_ §5.4 — 4단계 AN-06b였음)
RuleConfigResult<NasDesyncConfig> parse_nas_desync_config(std::string_view json_text);
// 4단계 룰 (21_ §1.2 표 — 타입·허용 범위)
RuleConfigResult<SyncFailureConfig> parse_sync_failure_config(std::string_view json_text);
RuleConfigResult<SecReauthConfig> parse_sec_reauth_config(std::string_view json_text);
RuleConfigResult<IdentityRequestConfig> parse_identity_request_config(std::string_view json_text);
RuleConfigResult<ShortRepeatConfig> parse_short_repeat_config(std::string_view json_text);

}  // namespace detect
