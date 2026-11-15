#include "detect/config.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <set>
#include <stdexcept>

namespace detect {
namespace {

using json = nlohmann::json;

struct ConfigErr : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// 객체 안의 모르는 키를 경고로 모은다 (결정 G3 — 오타를 알아채게)
void warn_unknown(const json& obj, const std::set<std::string>& known, const std::string& where,
                  std::vector<std::string>& warnings) {
  for (auto it = obj.begin(); it != obj.end(); ++it)
    if (!known.count(it.key())) warnings.push_back("unknown key " + where + it.key() + " (ignored)");
}

const json* find(const json& obj, const char* key) {
  auto it = obj.find(key);
  return it == obj.end() ? nullptr : &*it;
}

template <typename T>
void read_int(const json& obj, const char* key, T& out, int64_t min, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;  // 빠진 키는 기본값
  if (!v->is_number_integer()) throw ConfigErr(where + key + ": not an integer");
  const int64_t x = v->get<int64_t>();
  if (x < min) throw ConfigErr(where + key + ": out of range");
  out = static_cast<T>(x);
}

// 허용 범위 [min, max]가 있는 정수 (2단계 키 — 15_ §1.2·14_ §9)
template <typename T>
void read_int_in(const json& obj, const char* key, T& out, int64_t min, int64_t max, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number_integer()) throw ConfigErr(where + key + ": not an integer");
  const int64_t x = v->get<int64_t>();
  if (x < min || x > max)
    throw ConfigErr(where + key + ": out of range [" + std::to_string(min) + ", " + std::to_string(max) + "]");
  out = static_cast<T>(x);
}

// 0(끔) 또는 허용 범위 [min, max]인 정수 — 출력 파일 회전·보관 키 (29_ §6 — 11/08 이슈 #102)
template <typename T>
void read_off_or_in(const json& obj, const char* key, T& out, int64_t min, int64_t max, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number_integer()) throw ConfigErr(where + key + ": not an integer");
  const int64_t x = v->get<int64_t>();
  if (x != 0 && (x < min || x > max))
    throw ConfigErr(where + key + ": out of range (0 or [" + std::to_string(min) + ", " + std::to_string(max) + "])");
  out = static_cast<T>(x);
}

// 회전·보관 키 공통 (29_ §6): evidence·input_record 둘 다 같은 범위. keep_s는 정리 도구가 쓰고 탐지 엔진은 타입·범위만 본다
template <typename C>
void read_rotate_keys(const json& e, C& c, const std::string& w) {
  read_off_or_in(e, "rotate_s", c.rotate_s, 60, 86400, w);
  read_off_or_in(e, "rotate_max_bytes", c.rotate_max_bytes, 1048576, 4294967296LL, w);
  read_off_or_in(e, "keep_s", c.keep_s, 3600, 31536000, w);
}

// 허용 범위 [min, max]가 있는 실수 (ue_table.ghost_k — 14_ §9)
void read_real_in(const json& obj, const char* key, double& out, double min, double max, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number()) throw ConfigErr(where + key + ": not a number");
  const double x = v->get<double>();
  if (!(x >= min && x <= max))
    throw ConfigErr(where + key + ": out of range [" + std::to_string(min) + ", " + std::to_string(max) + "]");
  out = x;
}

void read_real(const json& obj, const char* key, double& out, double min_exclusive, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number()) throw ConfigErr(where + key + ": not a number");
  const double x = v->get<double>();
  if (!(x > min_exclusive)) throw ConfigErr(where + key + ": out of range");
  out = x;
}

// 하한을 포함하는 실수 (rules."L3-01-V".z — 3_ §4, 11/12: 0이면 C3 문턱이 base 자체)
void read_real_at_least(const json& obj, const char* key, double& out, double min, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number()) throw ConfigErr(where + key + ": not a number");
  const double x = v->get<double>();
  if (!(x >= min)) throw ConfigErr(where + key + ": out of range (>= " + std::to_string(min) + ")");
  out = x;
}

// 비율 (0, 1] (rules."L3-01-V".f_abs_frac — 3_ §4, 11/12)
void read_fraction(const json& obj, const char* key, double& out, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number()) throw ConfigErr(where + key + ": not a number");
  const double x = v->get<double>();
  if (!(x > 0.0 && x <= 1.0)) throw ConfigErr(where + key + ": out of range (0, 1]");
  out = x;
}

// 비율 [0, 1] — 0을 받는다 (rules."L3-01-O".n_stall_frac·"L3-21".n_fail_frac — 15_ §1.2, 11/15): 0이면 셀 한도 비율을 쓰지 않고
// 최소값만 문턱으로 쓴다. 1단계 f_abs_frac(0, 1]과 다른 것은 2단계 두 룰은 최소값(n_stall·n_fail)이 따로 있어 0이 '끔'으로 뜻이 서기 때문
void read_unit(const json& obj, const char* key, double& out, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number()) throw ConfigErr(where + key + ": not a number");
  const double x = v->get<double>();
  if (!(x >= 0.0 && x <= 1.0)) throw ConfigErr(where + key + ": out of range [0, 1]");
  out = x;
}

void read_bool(const json& obj, const char* key, bool& out, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_boolean()) throw ConfigErr(where + key + ": not a boolean");
  out = v->get<bool>();
}

void read_string(const json& obj, const char* key, std::string& out, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_string() || v->get_ref<const std::string&>().empty()) throw ConfigErr(where + key + ": not a string");
  out = v->get<std::string>();
}

// null을 허용하는 정수 (max_conn, pre_slots — 4_ §1.2)
template <typename T>
void read_nullable_int(const json& obj, const char* key, std::optional<T>& out, int64_t min, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (v->is_null()) {
    out.reset();
    return;
  }
  T tmp{};
  read_int(obj, key, tmp, min, where);
  out = tmp;
}

// ---- 룰 설정 키 표 (4_ §1.2 — 11/05 26_ R3, 이슈 #98) ----
// 룰마다 {키 이름, 읽는 법} 표 하나. 모르는 키 경고 목록(결정 G3)도 이 표에서 나오고, 룰별 파서 함수 13개는 표와 parse_keys 하나로
// 대신한다. 타입·허용 범위는 룰 명세의 설정 키 표(3_ §4, 15_ §1.2, 20_ §1.5, 21_ §1.2)다
template <typename T>
struct KeySpec {
  const char* name;
  void (*read)(const json& r, const char* key, T& c, const std::string& where);
};

// 읽는 법 — 캡처 없는 제네릭 람다라 KeySpec<T>::read 함수 포인터로 바뀐다
#define KEY_INT_IN(member, lo, hi) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_int_in(r, k, c.member, lo, hi, w); }
#define KEY_INT_MIN(member, lo) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_int(r, k, c.member, lo, w); }
#define KEY_REAL_MIN(member, lo) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_real(r, k, c.member, lo, w); }
#define KEY_REAL_AT_LEAST(member, lo) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_real_at_least(r, k, c.member, lo, w); }
#define KEY_FRACTION(member) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_fraction(r, k, c.member, w); }
#define KEY_UNIT(member) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_unit(r, k, c.member, w); }
#define KEY_NULLABLE_INT(member, lo) \
  [](const json& r, const char* k, auto& c, const std::string& w) { read_nullable_int(r, k, c.member, lo, w); }

// rules."L3-21".ignore_causes (15_ §1.2·§5.4): 5GMM 원인값(0~255) 배열 — 중복 없음, 빈 배열은 끔
void read_ignore_causes(const json& r, const char* key, UplinkDosConfig& c, const std::string& w) {
  const json* v = find(r, key);
  if (!v) return;
  if (!v->is_array()) throw ConfigErr(w + key + ": not an array");
  std::vector<int64_t> causes;
  for (const json& x : *v) {
    if (!x.is_number_integer()) throw ConfigErr(w + key + ": not an integer");
    const int64_t n = x.get<int64_t>();
    if (n < 0 || n > 255) throw ConfigErr(w + key + ": out of range [0, 255]");
    if (std::find(causes.begin(), causes.end(), n) != causes.end())
      throw ConfigErr(w + key + ": duplicate " + std::to_string(n));
    causes.push_back(n);
  }
  c.ignore_causes = std::move(causes);
}

// rules."L3-01-V" (3_ §4 파라미터 표 · §5 · §8). m_raise·k_clear·missing_key_slots는 상한도 검사 (4_ §1.2 — 11/05 W-31: int 필드라
// INT_MAX 초과값이 잘려 들어갔다). f_abs_frac은 (0, 1], z는 0 이상 (3_ §4 — 11/12, 그전 키 f_abs·k는 모르는 키 경고).
// max_conn은 null이면 C4와 C2a를 끔
const KeySpec<BtsVariantConfig> kBtsVariantKeys[] = {
    {"window_ms", KEY_INT_MIN(window_ms, 1)},
    {"a_min", KEY_INT_MIN(a_min, 0)},
    {"theta", KEY_REAL_MIN(theta, 0.0)},
    {"f_abs_frac", KEY_FRACTION(f_abs_frac)},
    {"z", KEY_REAL_AT_LEAST(z, 0.0)},
    {"m_raise", KEY_INT_IN(m_raise, 1, 1000000)},
    {"k_clear", KEY_INT_IN(k_clear, 1, 1000000)},
    {"h_sat_ms", KEY_INT_MIN(h_sat_ms, 0)},
    {"warmup_ms", KEY_INT_MIN(warmup_ms, 0)},
    {"baseline_tau_s", KEY_REAL_MIN(baseline_tau_s, 0.0)},
    {"h_hold_ms", KEY_INT_MIN(h_hold_ms, 0)},
    {"missing_key_slots", KEY_INT_IN(missing_key_slots, 0, 1000000)},
    {"max_conn", KEY_NULLABLE_INT(max_conn, 1)},
};

// rules."L3-20" (15_ §1.2·§2.4)
const KeySpec<BlindDosConfig> kBlindDosKeys[] = {
    {"accept_wait_ms", KEY_INT_IN(accept_wait_ms, 100, 60000)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};

// rules."L3-01-O" (15_ §1.2·§4.4). max_conn은 null이면 심각도 high를 쓰지 않고 문턱 N은 n_stall이다. n_stall_frac은 [0, 1] (11/15)
const KeySpec<AuthStallConfig> kAuthStallKeys[] = {
    {"auth_wait_ms", KEY_INT_IN(auth_wait_ms, 100, 60000)},
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_stall", KEY_INT_IN(n_stall, 1, 10000)},
    {"n_stall_frac", KEY_UNIT(n_stall_frac)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
    {"max_conn", KEY_NULLABLE_INT(max_conn, 1)},
};

// rules."L3-21" (15_ §1.2·§5.4). n_fail_frac은 [0, 1], max_conn은 1 이상 또는 null(문턱 N = n_fail) (11/15)
const KeySpec<UplinkDosConfig> kUplinkDosKeys[] = {
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_fail", KEY_INT_IN(n_fail, 1, 10000)},
    {"n_fail_frac", KEY_UNIT(n_fail_frac)},
    {"max_conn", KEY_NULLABLE_INT(max_conn, 1)},
    {"fail_accept_wait_ms", KEY_INT_IN(fail_accept_wait_ms, 100, 60000)},
    {"reg_repeat", KEY_INT_IN(reg_repeat, 2, 100)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
    {"ignore_causes", read_ignore_causes},
};

// 3단계 rules."L3-24"·"L3-14" (20_ §1.5·§3.4·§4.4)와 3단계로 올린 "L3-06" (20_ §5.4) — 키는 해제 시간 하나, 범위는 3단계 공통
const KeySpec<ImsiExtractorConfig> kImsiExtractorKeys[] = {
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<CapHijackConfig> kCapHijackKeys[] = {
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<NasDesyncConfig> kNasDesyncKeys[] = {
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};

// 4단계 rules."AN-xx" (21_ §1.2 표) — 룰 ID는 AN- 접두사를 그대로 쓴다
const KeySpec<SyncFailureConfig> kSyncFailureKeys[] = {
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_sync", KEY_INT_IN(n_sync, 1, 10000)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<SecReauthConfig> kSecReauthKeys[] = {
    {"n_reauth", KEY_INT_IN(n_reauth, 1, 100)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<IdentityRequestConfig> kIdentityRequestKeys[] = {
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_idreq", KEY_INT_IN(n_idreq, 1, 10000)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<ShortRepeatConfig> kShortRepeatKeys[] = {
    {"short_ms", KEY_INT_IN(short_ms, 100, 600000)},
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_short", KEY_INT_IN(n_short, 2, 10000)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<SetupRepeatConfig> kSetupRepeatKeys[] = {
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_fail", KEY_INT_IN(n_fail, 2, 10000)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};
const KeySpec<KnownRegBurstConfig> kKnownRegBurstKeys[] = {
    {"window_ms", KEY_INT_IN(window_ms, 1000, 600000)},
    {"n_reg", KEY_INT_IN(n_reg, 1, 10000)},
    {"known_ms", KEY_INT_IN(known_ms, 1000, 86400000)},
    {"clear_quiet_ms", KEY_INT_IN(clear_quiet_ms, 1000, 3600000)},
};

#undef KEY_INT_IN
#undef KEY_INT_MIN
#undef KEY_REAL_MIN
#undef KEY_REAL_AT_LEAST
#undef KEY_FRACTION
#undef KEY_UNIT
#undef KEY_NULLABLE_INT

// 키 표대로 객체 하나를 읽는다 — 표에 없는 키는 경고, 표의 키는 그 읽는 법으로(타입·범위 오류는 ConfigErr)
template <typename T, std::size_t N>
void parse_keys(const json& r, T& c, const std::string& where, const KeySpec<T> (&keys)[N],
                std::vector<std::string>& warnings) {
  std::set<std::string> known;
  for (const KeySpec<T>& k : keys) known.insert(k.name);
  warn_unknown(r, known, where, warnings);
  for (const KeySpec<T>& k : keys) k.read(r, k.name, c, where);
}

// 룰 설정 객체 하나를 그 룰의 키 표로 해석한다 (Q-46, 결정 J4)
template <typename T, std::size_t N>
RuleConfigResult<T> parse_rule(std::string_view json_text, const char* id, const KeySpec<T> (&keys)[N]) {
  RuleConfigResult<T> r;
  json j = json::parse(json_text.begin(), json_text.end(), nullptr, false);
  if (j.is_discarded() || !j.is_object()) {
    r.error = std::string("config: rules.") + id + ": not an object";
    return r;
  }
  try {
    parse_keys(j, r.config, std::string("rules.") + id + ".", keys, r.warnings);
    r.ok = true;
  } catch (const ConfigErr& e) {
    r.error = std::string("config: ") + e.what();
  }
  return r;
}

// ue_table (14_ §9 — 허용 범위는 10/29 이슈 #33 사용자 결정). tomb_*는 10/29까지 예약 키였으나 11/03 4단계 S-TMSI 이력 표 키가
// 되어(확인 지점 ⑤) alloc_*와 함께 범위를 검사한다 (14_ §3.2·§9, 11/04 이슈 #74)
void parse_ue_table(const json& e, UeTableConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "ue_table.";
  if (!e.is_object()) throw ConfigErr("ue_table: not an object");
  warn_unknown(e,
               {"max_ues", "recent_n", "stale_setup_ms", "closed_recent_max", "tomb_ms", "tomb_max", "alloc_ms",
                "alloc_max", "ghost_k", "ghost_margin", "ghost_hold_ms", "evict_protect_ms", "dl_unobserved_ms",
                "recent_keep_margin_ms"},
               w, warnings);
  read_int_in(e, "tomb_ms", c.tomb_ms, 60000, 86400000, w);
  read_int_in(e, "tomb_max", c.tomb_max, 100, 65536, w);
  read_int_in(e, "alloc_ms", c.alloc_ms, 60000, 86400000, w);
  read_int_in(e, "alloc_max", c.alloc_max, 100, 65536, w);
  read_int_in(e, "max_ues", c.max_ues, 100, 16384, w);
  read_int_in(e, "recent_n", c.recent_n, 1, 64, w);
  read_int_in(e, "stale_setup_ms", c.stale_setup_ms, 2000, 600000, w);
  read_int_in(e, "closed_recent_max", c.closed_recent_max, 0, 16384, w);
  // 유령 정리·보호 무리·상수 대체 키 (14_ §9 — 10/29 Q-56 해결·W-24, 이슈 #44)
  read_real_in(e, "ghost_k", c.ghost_k, 1.0, 10.0, w);
  read_int_in(e, "ghost_margin", c.ghost_margin, 0, 4096, w);
  read_int_in(e, "ghost_hold_ms", c.ghost_hold_ms, 0, 600000, w);
  read_int_in(e, "evict_protect_ms", c.evict_protect_ms, 0, 600000, w);
  read_int_in(e, "dl_unobserved_ms", c.dl_unobserved_ms, 1000, 600000, w);
  read_int_in(e, "recent_keep_margin_ms", c.recent_keep_margin_ms, 0, 60000, w);
}

// alert (14_ §9 — 허용 범위는 10/29 이슈 #33 사용자 결정)
void parse_alert(const json& e, AlertConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "alert.";
  if (!e.is_object()) throw ConfigErr("alert: not an object");
  warn_unknown(e, {"ues_max", "update_min_ms", "ue_evidence_max", "held_alert"}, w, warnings);
  read_int_in(e, "ues_max", c.ues_max, 1, 1000, w);
  read_int_in(e, "update_min_ms", c.update_min_ms, 100, 60000, w);
  read_int_in(e, "ue_evidence_max", c.ue_evidence_max, 0, 1000, w);
  read_bool(e, "held_alert", c.held_alert, w);  // 불확실 경보 켜기 (14_ §9, 이슈 #48)
}

// evidence (3_ §7.1 파라미터 표)
void parse_evidence(const json& e, EvidenceConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "evidence.";
  if (!e.is_object()) throw ConfigErr("evidence: not an object");
  warn_unknown(e, {"mode", "pre_slots", "post_slots", "queue_max", "out_path", "rotate_s", "rotate_max_bytes", "keep_s"}, w,
               warnings);
  if (const json* m = find(e, "mode")) {
    if (!m->is_string()) throw ConfigErr("evidence.mode: not a string");
    const std::string s = m->get<std::string>();
    if (s == "full") c.mode = EvidenceMode::Full;
    else if (s == "ref") c.mode = EvidenceMode::Ref;
    else if (s == "off") c.mode = EvidenceMode::Off;
    else throw ConfigErr("evidence.mode: must be full|ref|off");
  }
  read_nullable_int(e, "pre_slots", c.pre_slots, 1, w);
  read_int(e, "post_slots", c.post_slots, 0, w);
  read_int(e, "queue_max", c.queue_max, 0, w);
  read_string(e, "out_path", c.out_path, w);
  read_rotate_keys(e, c, w);  // 출력 파일 회전·보관 (29_ §6 — 11/08 이슈 #102)
}

// input_record (24_ §3.1): 받은 입력 줄을 남길 파일. path는 null(끔) 또는 빈 문자열이 아닌 경로, 큐 상한은 범위 검사.
// 증거 파일과 같은 파일인지는 작업 폴더가 있어야 비교할 수 있어 실행 파일이 본다 (core는 I/O 없음, 4_ §2)
void parse_input_record(const json& e, InputRecordConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "input_record.";
  if (!e.is_object()) throw ConfigErr("input_record: not an object");
  warn_unknown(e, {"path", "queue_max_bytes", "rotate_s", "rotate_max_bytes", "keep_s", "min_free_bytes"}, w, warnings);
  if (const json* p = find(e, "path")) {
    if (p->is_null()) {
      c.path.reset();
    } else {
      std::string s;
      read_string(e, "path", s, w);  // 문자열이 아니거나 빈 문자열이면 오류
      c.path = s;
    }
  }
  read_int_in(e, "queue_max_bytes", c.queue_max_bytes, 65536, 67108864, w);
  // 출력 파일 회전·보관 (29_ §6 — 11/08 이슈 #102). min_free_bytes는 정리 도구의 디스크 여유 하한 — 탐지 엔진은 타입·범위만 본다
  read_rotate_keys(e, c, w);
  read_off_or_in(e, "min_free_bytes", c.min_free_bytes, 104857600, 1099511627776LL, w);
}

}  // namespace

// 설정 파일 해석 (4_ §1.2). 빠진 키는 구조체 기본값(= 4_ §1.2 제안값)을 그대로 쓴다
ConfigResult parse_config(std::string_view json_text) {
  ConfigResult r;
  json j = json::parse(json_text.begin(), json_text.end(), nullptr, false);
  if (j.is_discarded()) {
    r.error = "config: invalid JSON";
    return r;
  }
  if (!j.is_object()) {
    r.error = "config: not a JSON object";
    return r;
  }
  try {
    warn_unknown(j, {"socket_path", "max_line_bytes", "max_cells", "max_slots", "input_silent_ms", "rules", "evidence",
                     "ue_table", "alert", "input_record"},
                 "", r.warnings);
    read_string(j, "socket_path", r.config.socket_path, "");
    read_int(j, "max_line_bytes", r.config.max_line_bytes, 1, "");
    read_int_in(j, "max_cells", r.config.max_cells, 1, 1024, "");  // 결정 D7 — 16_ W-24로 설정 키 (이슈 #44)
    read_int_in(j, "max_slots", r.config.max_slots, 32, 65536, "");  // 셀 버퍼 칸 수 상한 (2_ §3 — 11/05 W-31, 이슈 #92)
    read_int_in(j, "input_silent_ms", r.config.input_silent_ms, 1000, 600000, "");  // 입력 침묵 (3_ §8, Q-45 — 이슈 #50)
    // rules: 룰 ID → 설정 객체. 여기서는 객체인지만 보고 JSON 그대로 넘긴다 — 해석은 룰별 키 표, 모르는 룰 ID는
    // 등록된 룰을 아는 실행 파일이 경고한다 (Q-46, 결정 J4)
    if (const json* rules = find(j, "rules")) {
      if (!rules->is_object()) throw ConfigErr("rules: not an object");
      for (auto it = rules->begin(); it != rules->end(); ++it) {
        if (!it.value().is_object()) throw ConfigErr("rules." + it.key() + ": not an object");
        r.config.rules[it.key()] = it.value().dump();
      }
    }
    if (const json* e = find(j, "evidence")) parse_evidence(*e, r.config.evidence, r.warnings);
    if (const json* u = find(j, "ue_table")) parse_ue_table(*u, r.config.ue_table, r.warnings);
    if (const json* a = find(j, "alert")) parse_alert(*a, r.config.alert, r.warnings);
    if (const json* ir = find(j, "input_record")) parse_input_record(*ir, r.config.input_record, r.warnings);  // 24_ §3.1
    r.ok = true;
  } catch (const ConfigErr& e) {
    r.error = std::string("config: ") + e.what();
  }
  return r;
}

// 룰별 파서 (Q-46, 결정 J4): rules.<룰 ID>의 객체를 그 룰의 키 표로 읽는다
BtsVariantConfigResult parse_bts_variant_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-01-V", kBtsVariantKeys);
}
RuleConfigResult<BlindDosConfig> parse_blind_dos_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-20", kBlindDosKeys);
}
RuleConfigResult<AuthStallConfig> parse_auth_stall_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-01-O", kAuthStallKeys);
}
RuleConfigResult<UplinkDosConfig> parse_uplink_dos_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-21", kUplinkDosKeys);
}
RuleConfigResult<ImsiExtractorConfig> parse_imsi_extractor_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-24", kImsiExtractorKeys);
}
RuleConfigResult<CapHijackConfig> parse_cap_hijack_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-14", kCapHijackKeys);
}
RuleConfigResult<NasDesyncConfig> parse_nas_desync_config(std::string_view json_text) {
  return parse_rule(json_text, "L3-06", kNasDesyncKeys);
}
RuleConfigResult<SyncFailureConfig> parse_sync_failure_config(std::string_view json_text) {
  return parse_rule(json_text, "AN-01", kSyncFailureKeys);
}
RuleConfigResult<SecReauthConfig> parse_sec_reauth_config(std::string_view json_text) {
  return parse_rule(json_text, "AN-06a", kSecReauthKeys);
}
RuleConfigResult<IdentityRequestConfig> parse_identity_request_config(std::string_view json_text) {
  return parse_rule(json_text, "AN-02", kIdentityRequestKeys);
}
RuleConfigResult<ShortRepeatConfig> parse_short_repeat_config(std::string_view json_text) {
  return parse_rule(json_text, "AN-04", kShortRepeatKeys);
}
RuleConfigResult<SetupRepeatConfig> parse_setup_repeat_config(std::string_view json_text) {
  return parse_rule(json_text, "AN-07", kSetupRepeatKeys);
}
RuleConfigResult<KnownRegBurstConfig> parse_known_reg_burst_config(std::string_view json_text) {
  return parse_rule(json_text, "AN-08", kKnownRegBurstKeys);
}

}  // namespace detect
