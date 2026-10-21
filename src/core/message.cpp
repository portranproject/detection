#include "detect/message.h"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <utility>

namespace detect {
namespace {

using json = nlohmann::json;

// 형식 오류를 파서 안에서 위로 올리기 위한 예외. parse_line 밖으로는 나가지 않는다
struct FormatErr : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// 필수 정수 필드 읽기. 정수가 아니거나 min보다 작으면 형식 오류 (결정 D2: 타입 틀림·음수는 줄 전체 오류)
int64_t req_int(const json& obj, const char* key, int64_t min) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) throw FormatErr(std::string("missing ") + key);
  if (!it->is_number_integer()) throw FormatErr(std::string("not an integer: ") + key);
  int64_t v = it->get<int64_t>();
  if (v < min) throw FormatErr(std::string("out of range: ") + key);
  return v;
}

// 측정값(카운터·SI 정수) 읽기 — 키 없음과 null은 '측정 안 함', 0은 '측정했고 0건'으로 구분한다 (2_ §4.5)
Count opt_count(const json& obj, const std::string& key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return std::nullopt;
  if (!it->is_number_integer()) throw FormatErr("not an integer: " + key);
  int64_t v = it->get<int64_t>();
  if (v < 0) throw FormatErr("negative: " + key);
  return v;
}

// SI 평균처럼 실수를 허용하는 값 (2_ §4.3 — Mean은 실수로 보내는 확장)
std::optional<double> opt_real(const json& obj, const std::string& key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return std::nullopt;
  if (!it->is_number()) throw FormatErr("not a number: " + key);
  double v = it->get<double>();
  if (v < 0) throw FormatErr("negative: " + key);
  return v;
}

std::string opt_string(const json& obj, const char* key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return {};
  if (!it->is_string()) throw FormatErr(std::string("not a string: ") + key);
  return it->get<std::string>();
}

// 원인별 세분 카운터 읽기 (2_ §4.2).
// - total은 필수: 원인만 있고 total이 없으면 값 없음 + 경고 (결정 D3, 원인 합으로 대신하지 않음)
// - total 불변식: 원인 합 ≠ total이면 total을 쓰고 경고
CauseCounter cause_counter(const json& obj, const std::string& key, std::vector<std::string>& warnings) {
  CauseCounter c;
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return c;
  if (!it->is_object()) throw FormatErr("not an object: " + key);

  int64_t sum = 0;
  for (auto m = it->begin(); m != it->end(); ++m) {
    if (m.key() == "total") continue;
    Count v = opt_count(*it, m.key());
    if (!v) continue;  // 원인 값이 null이면 그 원인은 빼고 본다
    c.causes[m.key()] = *v;
    sum += *v;
  }
  c.total = opt_count(*it, "total");
  if (!c.total) {
    if (!c.causes.empty()) warnings.push_back(key + ": total missing, causes ignored");
  } else if (!c.causes.empty() && sum != *c.total) {
    warnings.push_back(key + ": total " + std::to_string(*c.total) + " != sum of causes " +
                       std::to_string(sum) + ", using total");
  }
  return c;
}

// 공통 필드 (2_ §2). type·session은 문자열, ver·seq는 정수(seq ≥ 1)
Common parse_common(const json& j) {
  Common c;
  auto t = j.find("type");
  if (t == j.end() || !t->is_string()) throw FormatErr("missing or invalid type");
  c.type = t->get<std::string>();
  c.ver = req_int(j, "ver", 0);
  auto s = j.find("session");
  if (s == j.end() || !s->is_string() || s->get_ref<const std::string&>().empty())
    throw FormatErr("missing or invalid session");
  c.session = s->get<std::string>();
  c.seq = req_int(j, "seq", 1);
  return c;
}

// hello (2_ §3). 필수는 period_ms·noreply_timeout_ms뿐(결정 D1), si_sample_ms가 없으면 period_ms로 본다
Hello parse_hello(const json& j, std::vector<std::string>& warnings) {
  Hello h;
  h.producer = opt_string(j, "producer");
  h.node_id = opt_string(j, "node_id");
  h.period_ms = req_int(j, "period_ms", 1);
  h.noreply_timeout_ms = req_int(j, "noreply_timeout_ms", 1);
  auto si = j.find("si_sample_ms");
  h.si_sample_ms = (si == j.end() || si->is_null()) ? h.period_ms : req_int(j, "si_sample_ms", 1);
  h.clock = opt_string(j, "clock");
  if (h.clock != "realtime") warnings.push_back("hello: clock is '" + h.clock + "', expected 'realtime'");

  auto cells = j.find("cells");
  if (cells != j.end() && !cells->is_null()) {
    if (!cells->is_array()) throw FormatErr("cells: not an array");
    for (const auto& e : *cells) {
      if (!e.is_object()) throw FormatErr("cells: element is not an object");
      CellInfo ci;
      ci.cell_id = req_int(e, "cell_id", 0);
      ci.max_conn = opt_count(e, "max_conn");
      h.cells.push_back(ci);
    }
  }
  return h;
}

// kpm2 (2_ §4). 시간 필드는 필수이고 t_end > t_start. cc·si·ext는 모두 선택이며
// 빠진 값은 nullopt로 두어 룰 쪽에서 보류·DL 미관측 모드를 판단하게 한다 (3_ §4.1·§8)
Kpm2 parse_kpm2(const json& j, std::string_view line, std::vector<std::string>& warnings) {
  Kpm2 k;
  k.cell_id = req_int(j, "cell_id", 0);
  k.t_start_ms = req_int(j, "t_start_ms", 0);
  k.t_end_ms = req_int(j, "t_end_ms", 0);
  if (k.t_end_ms <= k.t_start_ms) throw FormatErr("t_end_ms <= t_start_ms");

  static const json kEmpty = json::object();
  auto section = [&](const char* name) -> const json& {
    auto it = j.find(name);
    if (it == j.end() || it->is_null()) return kEmpty;
    if (!it->is_object()) throw FormatErr(std::string(name) + ": not an object");
    return *it;
  };

  const json& cc = section("cc");
  k.conn_estab_att = cause_counter(cc, "RRC.ConnEstabAtt", warnings);
  k.conn_estab_succ = cause_counter(cc, "RRC.ConnEstabSucc", warnings);
  // FailCause는 원인 3개를 담은 객체. DL을 보지 못하면 null로 온다 (2_ §4.2)
  auto fc = cc.find("RRC.ConnEstabFailCause");
  if (fc != cc.end() && !fc->is_null()) {
    if (!fc->is_object()) throw FormatErr("RRC.ConnEstabFailCause: not an object");
    k.fail_no_reply = opt_count(*fc, "NoReply");
    k.fail_network_reject = opt_count(*fc, "NetworkReject");
    k.fail_other = opt_count(*fc, "Other");
  }
  k.rel_without_suspend_config = opt_count(cc, "RRC.RelWithoutSuspendConfig");
  k.uecntx_estab_att = cause_counter(cc, "UECNTX.ConnEstabAtt", warnings);
  k.uecntx_estab_succ = cause_counter(cc, "UECNTX.ConnEstabSucc", warnings);
  k.reestab_att = opt_count(cc, "RRC.ReEstabAtt");
  k.reestab_succ_with_ue_context = opt_count(cc, "RRC.ReEstabSuccWithUeContext");
  k.resume_att = cause_counter(cc, "RRC.ResumeAtt", warnings);
  k.resume_succ = cause_counter(cc, "RRC.ResumeSucc", warnings);

  const json& si = section("si");
  k.conn_mean = opt_real(si, "RRC.ConnMean");
  k.conn_max = opt_count(si, "RRC.ConnMax");
  k.inactive_conn_mean = opt_real(si, "RRC.InactiveConnMean");
  k.inactive_conn_max = opt_count(si, "RRC.InactiveConnMax");

  const json& ext = section("ext");
  k.crnti_alloc = opt_count(ext, "CrntiAlloc");
  k.ue_ctx_max = opt_count(ext, "UeCtxMax");
  k.du_cannot_serve = opt_count(ext, "DuCannotServe");

  k.raw = std::string(line);
  return k;
}

}  // namespace

// 줄 하나를 해석한다. 검사 순서: 줄 길이(2_ §1) → JSON 객체 → 공통 필드(2_ §2) → ver(2_ §3) → type별 본문.
// 모르는 필드는 읽지 않으므로 자연히 무시된다(2_ §2 뒤 호환)
ParseResult parse_line(std::string_view line, std::size_t max_line_bytes) {
  ParseResult r;
  if (line.size() > max_line_bytes) {
    r.status = ParseStatus::LineTooLong;
    r.error = "line exceeds " + std::to_string(max_line_bytes) + " bytes";
    return r;
  }

  json j = json::parse(line.begin(), line.end(), nullptr, /*allow_exceptions=*/false);
  if (j.is_discarded()) {
    r.status = ParseStatus::FormatError;
    r.error = "invalid JSON";
    return r;
  }
  if (!j.is_object()) {
    r.status = ParseStatus::FormatError;
    r.error = "not a JSON object";
    return r;
  }

  try {
    r.common = parse_common(j);
    if (r.common->ver != kSupportedVersion) {
      r.status = ParseStatus::UnsupportedVersion;
      r.error = "unsupported ver " + std::to_string(r.common->ver);
      return r;
    }
    const std::string& type = r.common->type;
    if (type == "hello") {
      r.msg = parse_hello(j, r.warnings);
    } else if (type == "kpm2") {
      r.msg = parse_kpm2(j, line, r.warnings);
    } else if (type == "ue_evt") {
      r.msg = UeEvt{};
    } else {
      r.status = ParseStatus::UnknownType;
      return r;
    }
    r.status = ParseStatus::Ok;
  } catch (const FormatErr& e) {
    r.status = ParseStatus::FormatError;
    r.error = e.what();
    r.msg = std::monostate{};
    r.warnings.clear();
  }
  return r;
}

}  // namespace detect
