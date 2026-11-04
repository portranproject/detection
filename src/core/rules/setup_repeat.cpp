#include "detect/rules/setup_repeat.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

// 걸림 키 — 연결이 아니라 Part1. HitWindow의 (키, uid) 자리에 (셀, 표시) + Part1 값을 넣는다. 표시는 du_ue_id에 쓰이지 않는 음수다
constexpr int64_t kKeyPart1 = -2;
// 후보 (21_ §7.3-4) — 둘은 KPM으로 갈리지 않아 고정
constexpr const char* kCands[] = {"L3-11-V1", "L3-11-V2"};

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

std::string part1_hex(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%010" PRIx64, v);
  return buf;
}

// 판정하는 닫힘 이유 (21_ §7.3-1): released(CU의 Msg5 대기 뒤 해제)·stale_setup·reused. du_reset·evicted·session_reset 등은
// 결과를 믿을 수 없어 판정하지 않고, 지난 레코드도 세지 않는다(11/04 구현 때 정함 — AN-04와 같음)
bool judged(CloseReason r) {
  return r == CloseReason::Released || r == CloseReason::StaleSetup || r == CloseReason::Reused;
}

}  // namespace

// 셀 문턱이 없어 헬퍼의 N은 1이다 — 반복 수는 룰이 이력 표에서 센다(§7.3-2). 헬퍼의 셀 창은 성립 판정에는 쓰이지 않지만 RAISE에 싣는
// '창 안 걸림'의 폭이라 W와 같게 둔다 — CLEAR 뒤에는 창이 비어 옛 경보의 걸림은 싣지 않는다(이슈 #84)
SetupRepeatRule::SetupRepeatRule(SetupRepeatConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), hits_(kId, alert, cfg.window_ms, 1, cfg.clear_quiet_ms) {}

// 증거 지평 (21_ §1.1 — 11/04 결정): 1,000 ms + UPDATE 모음 지연. 걸린 연결은 방금 닫힌 연결이라 그 recent가 RAISE 칸까지 남는다
int64_t SetupRepeatRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// 닫힘 (21_ §7.3-1·2): CONNECTED에 닿지 못했고, 이 연결에서 RRCReject를 보지 않았고(11/04 사용자 결정 — rrc는 거절 뒤 해제 명령으로
// RELEASING이 되므로 '거절을 봤는지'로 본다), 판정하는 이유로 닫혔고, RRCSetupRequest에 Part1이 있었으면 후보다. mid_join은
// RRCSetupRequest가 없어 Part1이 없으므로 자연히 빠진다. 이미 걸린 Part1이 회복 전이면(마지막 미완료 연결 뒤 W 안) 새 칸 없이 경보
// values.extra만 늘린다. 아니면 이력 표 Part1 색인에서 (t − W, t] 안 같은 Part1의 미완료(connected false)·거절 없음(rejected false)·
// 판정 이유 레코드 수 K(이 연결 포함)를 세어 K ≥ N이면 걸린다(t_hit = 닫힌 시각). UE 칸 values는 걸릴 때 값(§1.1)
void SetupRepeatRule::on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx,
                                  RuleOutput&) {
  if (!judged(reason) || last.ever_connected || !last.s_tmsi_part1) return;
  if (last.count(Proto::RRC, "RRCReject") > 0) return;
  const uint64_t p1 = *last.s_tmsi_part1;
  const int64_t cell = last.key.cell_id;
  const UeId id{UeKey{cell, kKeyPart1}, static_cast<int64_t>(p1)};
  if (auto lf = last_fail_.find(id); lf != last_fail_.end()) {
    if (t - lf->second < cfg_.window_ms) {
      lf->second = t;
      hits_.add(id, "extra");
      return;
    }
    hits_.forget(id);  // 회복 — 같은 Part1이 다시 반복하면 새 UE로 싣는다
    last_fail_.erase(lf);
  }
  const auto recs = ctx.table.history_part1(p1, t - cfg_.window_ms + 1);
  const int64_t k = static_cast<int64_t>(std::count_if(recs.begin(), recs.end(), [](const ConnRecord* r) {
    return !r->connected && !r->rejected && judged(r->reason);
  }));
  if (k < cfg_.n_fail) return;

  AlertUe u = alert_ue(last);
  u.cond = {"setup_repeat_no_complete"};
  u.t_hit = t;
  u.values["fail_n"] = k;
  u.values["reason"] = to_string(reason);
  u.values["rrc_last"] = to_string(last.rrc);
  u.values["part1"] = part1_hex(p1);
  if (hits_.hit(id, std::move(u))) last_fail_[id] = t;
}

// 셀 kpm2 (21_ §7.5 — AN-04와 같음): 걸림이 든 창의 kpm2에서 RAISE(UE 하나), 경보 중 새 Part1은 UPDATE, 마지막 걸림 뒤
// clear_quiet_ms면 CLEAR(extra는 늘리지 않음, 밀어내기 중 보류), input_lost면 END — 헬퍼가 한다. 마지막 미완료 연결 뒤 W가 지난
// Part1은 회복으로 보고 키를 지운다
void SetupRepeatRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                   RuleOutput& out) {
  hits_.tick(cell, k.t_end_ms, input_lost, ctx, out.alerts,
             [&](std::size_t from, const AlertUe* hit) { decorate(from, out, hit); });
  for (auto it = last_fail_.begin(); it != last_fail_.end();) {
    if (it->first.first.cell_id == cell && k.t_end_ms - it->second >= cfg_.window_ms) {
      hits_.forget(it->first);
      it = last_fail_.erase(it);
    } else {
      ++it;
    }
  }
}

// AN-07 값 채우기 (21_ §7.6): raise·update에 values(fail_ues = ues_total, extra 실린 Part1의 회복 전 반복 수, evicted), raise에 cond
// setup_repeat_no_complete·candidates(고정 — raise에만, 21_ §1)·params·로그 필드(맨 앞 kind=anomaly, ue·part1·fail_n은 RAISE를
// 일으킨 가장 최근 걸림). 심각도 medium 고정, branch 없음
void SetupRepeatRule::decorate(std::size_t from, RuleOutput& out, const AlertUe* hit) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["fail_ues"] = e.ues_total;
    e.values["extra"] = hits_.count(e.cell_id, "extra");
    e.values["evicted"] = hits_.evicted(e.cell_id, raise, e.t);
    if (!raise) continue;
    e.cond = {"setup_repeat_no_complete"};
    e.candidates.assign(std::begin(kCands), std::end(kCands));
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_fail"] = cfg_.n_fail;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (21_ §7.6): kind=anomaly ue= part1= fail_n= n_fail= window_ms=
    e.log_fields = {{"kind", "anomaly"}};
    if (hit) {  // RAISE를 일으킨 이번 걸림 (이슈 #84)
      const AlertUe& u = *hit;
      e.log_fields.emplace_back("ue", ue_name(u.cell, u.du_ue_id, u.uid));
      e.log_fields.emplace_back("part1", u.values.at("part1").get<std::string>());
      e.log_fields.emplace_back("fail_n", std::to_string(u.values.at("fail_n").get<int64_t>()));
    }
    e.log_fields.emplace_back("n_fail", std::to_string(cfg_.n_fail));
    e.log_fields.emplace_back("window_ms", std::to_string(cfg_.window_ms));
  }
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 걸림·Part1 기록을 모두 버린다
void SetupRepeatRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  hits_.end_all("session_reset", out.alerts);
  hits_.reset();
  last_fail_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 경보를 END(input_silent)로 끝낸다. 걸림·셀 기록은 그대로
void SetupRepeatRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) { hits_.end_all("input_silent", out.alerts); }

}  // namespace detect
