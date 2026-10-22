#include "detect/config.h"

#include <nlohmann/json.hpp>

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

void read_real(const json& obj, const char* key, double& out, double min_exclusive, const std::string& where) {
  const json* v = find(obj, key);
  if (!v) return;
  if (!v->is_number()) throw ConfigErr(where + key + ": not a number");
  const double x = v->get<double>();
  if (!(x > min_exclusive)) throw ConfigErr(where + key + ": out of range");
  out = x;
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
  if (!r.is_object()) throw ConfigErr("rules.L3-01-V: not an object");
  warn_unknown(r, {"window_ms", "a_min", "theta", "k", "m_raise", "k_clear", "h_sat_ms", "warmup_ms",
                   "baseline_tau_s", "h_hold_ms", "missing_key_slots", "max_conn"},
               w, warnings);
  read_int(r, "window_ms", c.window_ms, 1, w);
  read_int(r, "a_min", c.a_min, 0, w);
  read_real(r, "theta", c.theta, 0.0, w);
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
    warn_unknown(j, {"socket_path", "max_line_bytes", "rules", "evidence"}, "", r.warnings);
    read_string(j, "socket_path", r.config.socket_path, "");
    read_int(j, "max_line_bytes", r.config.max_line_bytes, 1, "");
    if (const json* rules = find(j, "rules")) {
      if (!rules->is_object()) throw ConfigErr("rules: not an object");
      warn_unknown(*rules, {"L3-01-V"}, "rules.", r.warnings);
      if (const json* b = find(*rules, "L3-01-V")) parse_bts(*b, r.config.bts, r.warnings);
    }
    if (const json* e = find(j, "evidence")) parse_evidence(*e, r.config.evidence, r.warnings);
    r.ok = true;
  } catch (const ConfigErr& e) {
    r.error = std::string("config: ") + e.what();
  }
  return r;
}

}  // namespace detect
