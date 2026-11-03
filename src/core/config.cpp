#include "detect/config.h"

#include <nlohmann/json.hpp>

#include <algorithm>
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

// rules."L3-01-V" (3_ §4 파라미터 표 · §5 · §8)
void parse_bts(const json& r, BtsVariantConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "rules.L3-01-V.";
  warn_unknown(r, {"window_ms", "a_min", "theta", "f_abs", "k", "m_raise", "k_clear", "h_sat_ms", "warmup_ms",
                   "baseline_tau_s", "h_hold_ms", "missing_key_slots", "max_conn"},
               w, warnings);
  read_int(r, "window_ms", c.window_ms, 1, w);
  read_int(r, "a_min", c.a_min, 0, w);
  read_real(r, "theta", c.theta, 0.0, w);
  read_int(r, "f_abs", c.f_abs, 1, w);  // C2a 문턱 — 1 이상, 끄는 값은 두지 않음 (3_ §4, 결정 I1)
  read_real(r, "k", c.k, 0.0, w);
  read_int(r, "m_raise", c.m_raise, 1, w);
  read_int(r, "k_clear", c.k_clear, 1, w);
  read_int(r, "h_sat_ms", c.h_sat_ms, 0, w);
  read_int(r, "warmup_ms", c.warmup_ms, 0, w);
  read_real(r, "baseline_tau_s", c.baseline_tau_s, 0.0, w);
  read_int(r, "h_hold_ms", c.h_hold_ms, 0, w);
  read_int(r, "missing_key_slots", c.missing_key_slots, 0, w);
  read_nullable_int(r, "max_conn", c.max_conn, 1, w);
}

// rules."L3-20" (15_ §1.2·§2.4)
void parse_blind_dos(const json& r, BlindDosConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "rules.L3-20.";
  warn_unknown(r, {"accept_wait_ms", "clear_quiet_ms"}, w, warnings);
  read_int_in(r, "accept_wait_ms", c.accept_wait_ms, 100, 60000, w);
  read_int_in(r, "clear_quiet_ms", c.clear_quiet_ms, 1000, 3600000, w);
}

// rules."L3-01-O" (15_ §1.2·§4.4). max_conn은 null이면 심각도 high를 쓰지 않는다
void parse_auth_stall(const json& r, AuthStallConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "rules.L3-01-O.";
  warn_unknown(r, {"auth_wait_ms", "window_ms", "n_stall", "clear_quiet_ms", "max_conn"}, w, warnings);
  read_int_in(r, "auth_wait_ms", c.auth_wait_ms, 100, 60000, w);
  read_int_in(r, "window_ms", c.window_ms, 1000, 600000, w);
  read_int_in(r, "n_stall", c.n_stall, 1, 10000, w);
  read_int_in(r, "clear_quiet_ms", c.clear_quiet_ms, 1000, 3600000, w);
  read_nullable_int(r, "max_conn", c.max_conn, 1, w);
}

// rules."L3-21" (15_ §1.2·§5.4). ignore_causes는 5GMM 원인값(0~255) 배열 — 중복 없음, 빈 배열은 끔
void parse_uplink_dos(const json& r, UplinkDosConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "rules.L3-21.";
  warn_unknown(r, {"window_ms", "n_fail", "fail_accept_wait_ms", "reg_repeat", "clear_quiet_ms", "ignore_causes"}, w,
               warnings);
  read_int_in(r, "window_ms", c.window_ms, 1000, 600000, w);
  read_int_in(r, "n_fail", c.n_fail, 1, 10000, w);
  read_int_in(r, "fail_accept_wait_ms", c.fail_accept_wait_ms, 100, 60000, w);
  read_int_in(r, "reg_repeat", c.reg_repeat, 2, 100, w);
  read_int_in(r, "clear_quiet_ms", c.clear_quiet_ms, 1000, 3600000, w);
  if (const json* v = find(r, "ignore_causes")) {
    if (!v->is_array()) throw ConfigErr(w + "ignore_causes: not an array");
    std::vector<int64_t> causes;
    for (const json& x : *v) {
      if (!x.is_number_integer()) throw ConfigErr(w + "ignore_causes: not an integer");
      const int64_t n = x.get<int64_t>();
      if (n < 0 || n > 255) throw ConfigErr(w + "ignore_causes: out of range [0, 255]");
      if (std::find(causes.begin(), causes.end(), n) != causes.end())
        throw ConfigErr(w + "ignore_causes: duplicate " + std::to_string(n));
      causes.push_back(n);
    }
    c.ignore_causes = std::move(causes);
  }
}

// rules."L3-24" (20_ §1.5·§3.4) — 키는 해제 시간 하나
void parse_imsi_extractor(const json& r, ImsiExtractorConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "rules.L3-24.";
  warn_unknown(r, {"clear_quiet_ms"}, w, warnings);
  read_int_in(r, "clear_quiet_ms", c.clear_quiet_ms, 1000, 3600000, w);
}

// rules."L3-14" (20_ §1.5·§4.4) — 키는 해제 시간 하나
void parse_cap_hijack(const json& r, CapHijackConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "rules.L3-14.";
  warn_unknown(r, {"clear_quiet_ms"}, w, warnings);
  read_int_in(r, "clear_quiet_ms", c.clear_quiet_ms, 1000, 3600000, w);
}

// ue_table (14_ §9 — 허용 범위는 10/29 이슈 #33 사용자 결정). tomb_ms·tomb_max는 예약 키라 경고만 (14_ §3.2)
void parse_ue_table(const json& e, UeTableConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "ue_table.";
  if (!e.is_object()) throw ConfigErr("ue_table: not an object");
  warn_unknown(e,
               {"max_ues", "recent_n", "stale_setup_ms", "closed_recent_max", "tomb_ms", "tomb_max", "ghost_k",
                "ghost_margin", "ghost_hold_ms", "evict_protect_ms", "dl_unobserved_ms", "recent_keep_margin_ms"},
               w, warnings);
  for (const char* k : {"tomb_ms", "tomb_max"})
    if (find(e, k)) warnings.push_back("reserved key " + w + k + " (not used)");
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

// 룰 설정 객체 하나를 그 룰의 파서로 해석한다 (Q-46, 결정 J4)
template <typename T, typename Parse>
RuleConfigResult<T> parse_rule(std::string_view json_text, const char* id, Parse parse) {
  RuleConfigResult<T> r;
  json j = json::parse(json_text.begin(), json_text.end(), nullptr, false);
  if (j.is_discarded() || !j.is_object()) {
    r.error = std::string("config: rules.") + id + ": not an object";
    return r;
  }
  try {
    parse(j, r.config, r.warnings);
    r.ok = true;
  } catch (const ConfigErr& e) {
    r.error = std::string("config: ") + e.what();
  }
  return r;
}

// evidence (3_ §7.1 파라미터 표)
void parse_evidence(const json& e, EvidenceConfig& c, std::vector<std::string>& warnings) {
  const std::string w = "evidence.";
  if (!e.is_object()) throw ConfigErr("evidence: not an object");
  warn_unknown(e, {"mode", "pre_slots", "post_slots", "queue_max", "out_path"}, w, warnings);
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
    warn_unknown(j, {"socket_path", "max_line_bytes", "max_cells", "input_silent_ms", "rules", "evidence", "ue_table", "alert"},
                 "", r.warnings);
    read_string(j, "socket_path", r.config.socket_path, "");
    read_int(j, "max_line_bytes", r.config.max_line_bytes, 1, "");
    read_int_in(j, "max_cells", r.config.max_cells, 1, 1024, "");  // 결정 D7 — 16_ W-24로 설정 키 (이슈 #44)
    read_int_in(j, "input_silent_ms", r.config.input_silent_ms, 1000, 600000, "");  // 입력 침묵 (3_ §8, Q-45 — 이슈 #50)
    // rules: 룰 ID → 설정 객체. 여기서는 객체인지만 보고 JSON 그대로 넘긴다 — 해석은 룰별 파서, 모르는 룰 ID는
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
    r.ok = true;
  } catch (const ConfigErr& e) {
    r.error = std::string("config: ") + e.what();
  }
  return r;
}

// 룰별 파서 (Q-46, 결정 J4): rules.<룰 ID>의 객체를 받는다
BtsVariantConfigResult parse_bts_variant_config(std::string_view json_text) {
  return parse_rule<BtsVariantConfig>(json_text, "L3-01-V", parse_bts);
}

RuleConfigResult<BlindDosConfig> parse_blind_dos_config(std::string_view json_text) {
  return parse_rule<BlindDosConfig>(json_text, "L3-20", parse_blind_dos);
}

RuleConfigResult<AuthStallConfig> parse_auth_stall_config(std::string_view json_text) {
  return parse_rule<AuthStallConfig>(json_text, "L3-01-O", parse_auth_stall);
}

RuleConfigResult<UplinkDosConfig> parse_uplink_dos_config(std::string_view json_text) {
  return parse_rule<UplinkDosConfig>(json_text, "L3-21", parse_uplink_dos);
}

RuleConfigResult<ImsiExtractorConfig> parse_imsi_extractor_config(std::string_view json_text) {
  return parse_rule<ImsiExtractorConfig>(json_text, "L3-24", parse_imsi_extractor);
}

RuleConfigResult<CapHijackConfig> parse_cap_hijack_config(std::string_view json_text) {
  return parse_rule<CapHijackConfig>(json_text, "L3-14", parse_cap_hijack);
}

}  // namespace detect
