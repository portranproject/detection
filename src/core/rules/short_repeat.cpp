#include "detect/rules/short_repeat.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;  // Part1 = 48비트 S-TMSI의 하위 39비트 (14_ §3.1)
// 걸림 키 — 연결이 아니라 S-TMSI. HitWindow의 (키, uid) 자리에 (셀, 표시) + 값을 넣는다. 표시는 du_ue_id에 쓰이지 않는 음수다
constexpr int64_t kKey48 = -1;
constexpr int64_t kKeyPart1 = -2;
// 후보 (21_ §6.3-4)
constexpr const char* kPagingCands[] = {"L3-02-Oa", "L3-34-OV", "L3-12-V"};
constexpr const char* kReleaseCand = "L3-33-V";

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

std::string hex(uint64_t v, int digits) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%0*" PRIx64, digits, v);
  return buf;
}

// 판정하는 닫힘 이유 (21_ §6.3-1·§1.3): released·stale_setup·reused·superseded. du_reset·evicted·ghost_purge·session_reset은 길이·
// 결과를 믿을 수 없어 판정하지 않고, 지난 레코드도 세지 않는다(AN04-T7, 11/04 구현 때 정함)
bool judged(CloseReason r) {
  return r == CloseReason::Released || r == CloseReason::StaleSetup || r == CloseReason::Reused ||
         r == CloseReason::Superseded;
}

// UE 하나의 후보 (21_ §6.3-4): est_cause가 mt-Access면 페이징에 답한 접속(#2 페이징형·#34·#12), DU가 해제를 요청했으면 #33을
// 더한다. 둘 다 아니면 네 경로 모두
std::vector<std::string> candidates_of(const AlertUe& u) {
  const ojson& v = u.values;
  const bool paging = v.contains("est_cause") && v.at("est_cause").is_string() && v.at("est_cause") == "mt-Access";
  const bool released_by_du = v.contains("rel_req_cause") && !v.at("rel_req_cause").is_null();
  std::vector<std::string> c;
  if (paging || !released_by_du)
    for (const char* s : kPagingCands) c.emplace_back(s);
  if (released_by_du || !paging) c.emplace_back(kReleaseCand);
  return c;
}

}  // namespace

// 셀 문턱이 없어 헬퍼의 N은 1이다 — 반복 수는 룰이 이력 표에서 센다(§6.3-2). 셀 창은 N = 1에서 쓰이지 않으므로 W와 같게 둔다
ShortRepeatRule::ShortRepeatRule(ShortRepeatConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), hits_(kId, alert, cfg.window_ms, 1, cfg.clear_quiet_ms) {}

// 증거 지평 (21_ §1.1 — 11/04 결정): 1,000 ms + UPDATE 모음 지연. 걸린 연결은 방금 닫힌 연결이라(보관 이유 released 등) 그 recent가
// RAISE 칸까지 남는다
int64_t ShortRepeatRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// 닫힘 (21_ §6.3-1·2): 판정하는 이유로 닫혔고 CONNECTED에 닿았고 길이 ≤ short_ms이고 S-TMSI(48비트 또는 Part1)를 알면 후보다.
// 이미 걸린 S-TMSI가 회복 전이면(마지막 짧은 연결 뒤 W 안) 새 칸 없이 경보 values.extra만 늘린다. 아니면 이력 표에서 (t − W, t] 안
// 같은 S-TMSI의 짧은 연결(CONNECTED, 판정 이유, 길이 ≤ S — 이 연결 포함) 수 K를 세어 K ≥ N이면 걸린다(t_hit = 닫힌 시각).
// 48비트를 알면 48비트 색인, Part1만 알면 Part1 색인으로 센다(§1.3). UE 칸 values는 걸릴 때 값(§1.1)
void ShortRepeatRule::on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx,
                                  RuleOutput&) {
  if (!judged(reason) || !last.ever_connected || t - last.t_start > cfg_.short_ms) return;
  const std::optional<uint64_t> p1 = last.s_tmsi ? std::optional<uint64_t>(*last.s_tmsi & kPart1Mask) : last.s_tmsi_part1;
  if (!last.s_tmsi && !p1) return;
  const int64_t cell = last.key.cell_id;
  const UeId id = last.s_tmsi ? UeId{UeKey{cell, kKey48}, static_cast<int64_t>(*last.s_tmsi)}
                              : UeId{UeKey{cell, kKeyPart1}, static_cast<int64_t>(*p1)};
  if (auto ls = last_short_.find(id); ls != last_short_.end()) {
    if (t - ls->second < cfg_.window_ms) {
      ls->second = t;
      hits_.add(id, "extra");
      return;
    }
    hits_.forget(id);  // 회복 — 같은 S-TMSI가 다시 반복하면 새 UE로 싣는다
    last_short_.erase(ls);
  }
  const int64_t since = t - cfg_.window_ms + 1;
  const auto recs = last.s_tmsi ? ctx.table.history(*last.s_tmsi, since) : ctx.table.history_part1(*p1, since);
  const int64_t k = static_cast<int64_t>(std::count_if(recs.begin(), recs.end(), [&](const ConnRecord* r) {
    return r->connected && judged(r->reason) && r->t_end - r->t_start <= cfg_.short_ms;
  }));
  if (k < cfg_.n_short) return;

  AlertUe u = alert_ue(last);
  u.cond = {"short_repeat"};
  u.t_hit = t;
  u.values["short_n"] = k;
  u.values["len_ms"] = t - last.t_start;
  u.values["est_cause"] = last.est_cause ? ojson(*last.est_cause) : ojson(nullptr);
  u.values["reason"] = to_string(reason);
  u.values["rel_req_cause"] = last.rel_req_cause ? ojson(*last.rel_req_cause) : ojson(nullptr);
  u.values["src"] = last.s_tmsi ? "48bit" : "part1";
  if (!last.s_tmsi) part1_of_[{cell, last.key.du_ue_id, last.uid}] = *p1;
  if (hits_.hit(id, std::move(u))) last_short_[id] = t;
}

// 셀 kpm2 (21_ §6.5): 걸림이 든 창의 kpm2에서 RAISE(UE 하나), 경보 중 새 S-TMSI는 UPDATE, 마지막 걸림 뒤 clear_quiet_ms면 CLEAR
// (extra는 늘리지 않음, 밀어내기 중 보류), input_lost면 END — 헬퍼가 한다. 마지막 짧은 연결 뒤 W가 지난 S-TMSI는 회복으로 보고 키를 지운다
void ShortRepeatRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                   RuleOutput& out) {
  hits_.tick(cell, k.t_end_ms, input_lost, ctx, out.alerts, [&](std::size_t from) { decorate(from, out); });
  for (auto it = last_short_.begin(); it != last_short_.end();) {
    if (it->first.first.cell_id == cell && k.t_end_ms - it->second >= cfg_.window_ms) {
      hits_.forget(it->first);
      it = last_short_.erase(it);
    } else {
      ++it;
    }
  }
}

// AN-04 값 채우기 (21_ §6.6): raise·update에 values(short_ues = ues_total, extra 실린 S-TMSI의 회복 전 반복 수, evicted), raise에 cond
// short_repeat·candidates(실린 UE들 후보의 합 — raise에만, 21_ §1)·params·로그 필드(맨 앞 kind=anomaly, ue는 RAISE를 일으킨 가장
// 최근 걸림 — 48비트를 알면 s_tmsi=, Part1만 알면 part1=). 심각도 medium 고정, branch 없음
void ShortRepeatRule::decorate(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["short_ues"] = e.ues_total;
    e.values["extra"] = hits_.count(e.cell_id, "extra");
    e.values["evicted"] = hits_.evicted(e.cell_id, raise, e.t);
    std::string ue_s;  // RAISE 로그의 식별자 칸
    if (raise && !e.ues.empty()) {
      const AlertUe& u = e.ues.back();
      if (u.s_tmsi) ue_s = "s_tmsi=" + hex(*u.s_tmsi, 12);
      else if (auto p = part1_of_.find({u.cell, u.du_ue_id, u.uid}); p != part1_of_.end()) ue_s = "part1=" + hex(p->second, 10);
    }
    for (const AlertUe& u : e.ues) part1_of_.erase({u.cell, u.du_ue_id, u.uid});
    if (!raise) continue;
    e.cond = {"short_repeat"};
    e.candidates.clear();
    for (const AlertUe& u : e.ues)
      for (const std::string& c : candidates_of(u))
        if (std::find(e.candidates.begin(), e.candidates.end(), c) == e.candidates.end()) e.candidates.push_back(c);
    e.params["short_ms"] = cfg_.short_ms;
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_short"] = cfg_.n_short;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (21_ §6.6): kind=anomaly ue= s_tmsi=(또는 part1=) short_n= len_ms= est_cause= n_short= window_ms=
    e.log_fields = {{"kind", "anomaly"}};
    if (!e.ues.empty()) {
      const AlertUe& u = e.ues.back();
      e.log_fields.emplace_back("ue", ue_name(u.cell, u.du_ue_id, u.uid));
      const auto eq = ue_s.find('=');
      if (eq != std::string::npos) e.log_fields.emplace_back(ue_s.substr(0, eq), ue_s.substr(eq + 1));
      e.log_fields.emplace_back("short_n", std::to_string(u.values.at("short_n").get<int64_t>()));
      e.log_fields.emplace_back("len_ms", std::to_string(u.values.at("len_ms").get<int64_t>()));
      const ojson& ec = u.values.at("est_cause");
      e.log_fields.emplace_back("est_cause", ec.is_string() ? ec.get<std::string>() : "null");
    }
    e.log_fields.emplace_back("n_short", std::to_string(cfg_.n_short));
    e.log_fields.emplace_back("window_ms", std::to_string(cfg_.window_ms));
  }
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 걸림·S-TMSI 기록을 모두 버린다
void ShortRepeatRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  hits_.end_all("session_reset", out.alerts);
  hits_.reset();
  last_short_.clear();
  part1_of_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 경보를 END(input_silent)로 끝낸다. 걸림·셀 기록은 그대로
void ShortRepeatRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) { hits_.end_all("input_silent", out.alerts); }

}  // namespace detect
