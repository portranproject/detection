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

// 필수 문자열 (빈 문자열도 오류)
std::string req_string(const json& obj, const char* key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) throw FormatErr(std::string("missing ") + key);
  if (!it->is_string() || it->get_ref<const std::string&>().empty())
    throw FormatErr(std::string("not a string: ") + key);
  return it->get<std::string>();
}

// 키는 필수지만 값은 null일 수 있는 정수 (2_ §6.2 du_ue_id·crnti — '모르면 null')
std::optional<int64_t> req_nullable_int(const json& obj, const char* key, int64_t min) {
  auto it = obj.find(key);
  if (it == obj.end()) throw FormatErr(std::string("missing ") + key);
  if (it->is_null()) return std::nullopt;
  return req_int(obj, key, min);
}

// 선택 값 — 키 없음·null이면 nullopt (2_ §6.2 f: '꺼내지 못한 값은 키를 빼거나 null')
std::optional<std::string> opt_str(const json& obj, const char* key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return std::nullopt;
  if (!it->is_string()) throw FormatErr(std::string("not a string: ") + key);
  return it->get<std::string>();
}

std::optional<bool> opt_bool(const json& obj, const char* key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return std::nullopt;
  if (!it->is_boolean()) throw FormatErr(std::string("not a boolean: ") + key);
  return it->get<bool>();
}

// S-TMSI 값 "0x" + 16진수 → 정수 (2_ §6.3, 14_ §3.1). 대소문자·앞자리 0과 무관하게 같은 값이 되고,
// bits(48·39·9)를 넘으면 형식 오류. 키 없음·null이면 nullopt
std::optional<uint64_t> opt_hex(const json& obj, const char* key, int bits) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return std::nullopt;
  if (!it->is_string()) throw FormatErr(std::string("not a string: ") + key);
  const std::string& s = it->get_ref<const std::string&>();
  if (s.size() < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
    throw FormatErr(std::string("not a 0x hex value: ") + key);
  const uint64_t max = (uint64_t{1} << bits) - 1;
  uint64_t v = 0;
  for (std::size_t i = 2; i < s.size(); ++i) {
    const char c = s[i];
    uint64_t d = 0;
    if (c >= '0' && c <= '9') d = static_cast<uint64_t>(c - '0');
    else if (c >= 'a' && c <= 'f') d = static_cast<uint64_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') d = static_cast<uint64_t>(c - 'A' + 10);
    else throw FormatErr(std::string("not a 0x hex value: ") + key);
    if (v > (max >> 4)) throw FormatErr(std::string("out of range: ") + key);  // 한 자리 더하면 bits를 넘는다
    v = (v << 4) | d;
  }
  return v;
}

// 정수 배열 (f1_evt cells·du_ue_ids, 2_ §6.7). 키 없음·null이면 nullopt
std::optional<std::vector<int64_t>> opt_int_array(const json& obj, const char* key) {
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) return std::nullopt;
  if (!it->is_array()) throw FormatErr(std::string("not an array: ") + key);
  std::vector<int64_t> v;
  for (const auto& e : *it) {
    if (!e.is_number_integer() || e.get<int64_t>() < 0) throw FormatErr(std::string("not a non-negative integer in ") + key);
    v.push_back(e.get<int64_t>());
  }
  return v;
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
  // ue_evt 표시 (2_ §6.5): 없거나 false면 2단계 이상 룰을 끈다. 타입이 틀려도 hello를 버리지 않고 끔으로 본다 —
  // 2단계 필드 하나 때문에 1단계까지 멈추지 않게 (2_ §4.6 원칙)
  auto ue = j.find("ue_evt");
  if (ue != j.end() && !ue->is_null()) {
    if (ue->is_boolean()) h.ue_evt = ue->get<bool>();
    else warnings.push_back("hello: ue_evt is not a boolean, treated as false");
  }

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

  // ue_evt_lost (2_ §4.6): "UL"·"DL"의 배열. 키 없음·null은 알 수 없음(nullopt — 2단계는 양방향 로스로 본다).
  // 형식이 틀려도 kpm2는 버리지 않고 알 수 없음으로 둔다 — ue_evt 표시 때문에 1단계가 멈추지 않게 (2_ §4.6)
  auto lost = j.find("ue_evt_lost");
  if (lost != j.end() && !lost->is_null()) {
    UeEvtLost l;
    bool ok = lost->is_array();
    if (ok) {
      for (const auto& d : *lost) {
        if (d == "UL") l.ul = true;
        else if (d == "DL") l.dl = true;
        else ok = false;
      }
    }
    if (ok) k.ue_evt_lost = l;
    else warnings.push_back("ue_evt_lost: not an array of \"UL\"/\"DL\", treated as unknown");
  }

  k.raw = std::string(line);
  return k;
}

// ue_evt (2_ §6.2·§6.3·§6.5). 필수: t_ms·cell_id·du_ue_id(키)·crnti(키)·dir·proto·msg, NAS면 via·sht도.
// du_ue_id: null은 NGAP에서만 본 NAS 줄(F1AP ID에 잇지 못함)에만 허용한다 — 그 밖의 null은 형식 오류 (2_ §6.5·§6.6).
// msg는 모르는 이름도 받는다(이력에만 남고 판정에는 안 쓰임). f는 2_ §6.3 표의 값을 꺼내고 모르는 키는 무시한다
UeEvt parse_ue_evt(const json& j, std::string_view line) {
  UeEvt e;
  e.t_ms = req_int(j, "t_ms", 0);
  e.cell_id = req_int(j, "cell_id", 0);
  e.du_ue_id = req_nullable_int(j, "du_ue_id", 0);
  e.cu_ue_id = opt_count(j, "cu_ue_id");
  e.crnti = req_nullable_int(j, "crnti", 0);

  const std::string dir = req_string(j, "dir");
  if (dir == "UL") e.dir = Dir::UL;
  else if (dir == "DL") e.dir = Dir::DL;
  else throw FormatErr("dir: must be UL|DL");
  const std::string proto = req_string(j, "proto");
  if (proto == "RRC") e.proto = Proto::RRC;
  else if (proto == "NAS") e.proto = Proto::NAS;
  else if (proto == "F1AP") e.proto = Proto::F1AP;
  else throw FormatErr("proto: must be RRC|NAS|F1AP");
  e.msg = req_string(j, "msg");

  if (e.proto == Proto::NAS) {
    e.via = req_string(j, "via");
    if (e.via != "F1" && e.via != "NGAP") throw FormatErr("via: must be F1|NGAP");
    e.sht = req_int(j, "sht", 0);
    if (*e.sht > 4) throw FormatErr("out of range: sht");
  }
  if (!e.du_ue_id && !(e.proto == Proto::NAS && e.via == "NGAP"))
    throw FormatErr("du_ue_id: null only for NAS via NGAP");

  // f — 메시지 안에서 꺼낸 값 (2_ §6.3)
  auto fit = j.find("f");
  if (fit != j.end() && !fit->is_null()) {
    if (!fit->is_object()) throw FormatErr("f: not an object");
    const json& f = *fit;
    e.s_tmsi = opt_hex(f, "s_tmsi", 48);
    // RRCSetupRequest의 ue_identity: Part1이면 39비트 값이 필수, randomValue면 값은 보지 않는다
    auto id = f.find("ue_identity");
    if (id != f.end() && !id->is_null()) {
      if (!id->is_object()) throw FormatErr("ue_identity: not an object");
      const std::string type = req_string(*id, "type");
      if (type == "ng-5G-S-TMSI-Part1") {
        e.ue_identity = UeIdentityType::Part1;
        e.s_tmsi_part1 = opt_hex(*id, "value", 39);
        if (!e.s_tmsi_part1) throw FormatErr("missing ue_identity.value");
      } else if (type == "randomValue") {
        e.ue_identity = UeIdentityType::RandomValue;
      } else {
        throw FormatErr("ue_identity.type: must be ng-5G-S-TMSI-Part1|randomValue");
      }
    }
    e.s_tmsi_part2 = opt_hex(f, "s_tmsi_part2", 9);  // Part1과 합치지 못했을 때의 폴백 (2_ §7-14)
    e.est_cause = opt_str(f, "est_cause");
    e.reg_type = opt_str(f, "reg_type");
    e.id_type = opt_str(f, "id_type");
    e.cipher = opt_str(f, "cipher");
    e.integrity = opt_str(f, "integrity");
    e.suspend = opt_bool(f, "suspend");
    e.switch_off = opt_bool(f, "switch_off");
    // cause: NAS는 5GMM 원인값(숫자), F1AP는 "radioNetwork:…" 문자열 (2_ §6.3)
    if (e.proto == Proto::F1AP) e.f1ap_cause = opt_str(f, "cause");
    else e.cause = opt_count(f, "cause");
    e.wait_time = opt_count(f, "wait_time");
  }

  e.raw = std::string(line);
  return e;
}

// f1_evt (2_ §6.7). msg는 F1SetupRequest·F1Reset만 — 그 셀의 UE를 모두 닫는 근거라 모르는 이름으로는 움직이지 않는다.
// cells는 키가 필수이고 null이면 모든 셀, du_ue_ids는 없으면 전체
F1Evt parse_f1_evt(const json& j) {
  F1Evt e;
  e.t_ms = req_int(j, "t_ms", 0);
  e.msg = req_string(j, "msg");
  if (e.msg != "F1SetupRequest" && e.msg != "F1Reset") throw FormatErr("msg: must be F1SetupRequest|F1Reset");
  if (j.find("cells") == j.end()) throw FormatErr("missing cells");
  e.cells = opt_int_array(j, "cells");
  e.du_ue_ids = opt_int_array(j, "du_ue_ids");
  return e;
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
      r.msg = parse_ue_evt(j, line);
    } else if (type == "f1_evt") {
      r.msg = parse_f1_evt(j);
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
