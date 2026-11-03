#include "detect/rules/sec_reauth.h"

#include <string>
#include <utility>

namespace detect {
namespace {

constexpr const char* kAuthReq = "AuthenticationRequest";
constexpr const char* kSmc = "SecurityModeCommand";
constexpr const char* kCandidate = "L3-06-O1";  // 이상 유형별 고정 후보 — 좁힐 관측값이 없다 (21_ §4.3-5)

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

}  // namespace

// 셀 문턱이 없어 헬퍼의 N은 1이다(§4.3-3). 셀 창은 N = 1에서 쓰이지 않으므로 해제 시간과 같게 둔다
SecReauthRule::SecReauthRule(SecReauthConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), hits_(kId, alert, cfg.clear_quiet_ms, 1, cfg.clear_quiet_ms) {}

// 증거 지평 (21_ §1.1 — 11/04 결정): 1,000 ms(창 한 칸 몫) + UPDATE 모음 지연. UE 하나로 걸림 다음 칸에 RAISE한다
int64_t SecReauthRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// ue_evt 한 줄 (21_ §4.3-1·2): AuthenticationRequest(DL)·NAS SecurityModeCommand(DL)이고 갱신 전 nas_sec이 ON이면 '보안 뒤
// 재등장' 1회다. UNKNOWN(mid_join — 보안이 섰는지 모름)·CMD·AUTH·NONE이면 아니다 — AMF 재전송은 응답이 없을 때라 CMD·AUTH다.
// 재등장 뒤 응답·완료로 다시 ON이 되면 다음 명령도 센다. 연결의 재등장 수가 n_reauth에 닿으면 걸리고(연결당 한 번), 그 뒤
// 재등장은 경보 values.extra로 센다(§1.1). UE 칸 values는 걸릴 때 값 — 걸린 줄, 그때까지 본 인증 요청·NAS SMC 수(이 줄 포함),
// 갱신 전 rrc_sec. NAS SMC의 f(cipher·integrity)는 판정에 쓰지 않는다(§4.2)
void SecReauthRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx&,
                                RuleOutput&) {
  if (evt.proto != Proto::NAS || evt.dir != Dir::DL || (evt.msg != kAuthReq && evt.msg != kSmc)) return;
  if (before.nas_sec != NasSecState::On) return;
  const UeId id{after.key, after.uid};
  if (hits_.hit_before(id)) {
    hits_.add(id, "extra");
    return;
  }
  if (++reauth_n_[id] < cfg_.n_reauth) return;
  AlertUe u = alert_ue(after);
  u.cond = {"reauth_after_sec"};
  u.t_hit = evt.t_ms;
  u.values["msg"] = evt.msg;
  u.values["auth_req_n"] = before.count(Proto::NAS, kAuthReq) + (evt.msg == kAuthReq ? 1 : 0);
  u.values["smc_n"] = before.count(Proto::NAS, kSmc) + (evt.msg == kSmc ? 1 : 0);
  u.values["rrc_sec"] = to_string(before.rrc_sec);
  hits_.hit(id, std::move(u));
}

// 항목이 닫힘 — 연결 기록을 지운다. 아직 kpm2를 거치지 않은 걸림은 마지막 상태로 판정에 남는다(헬퍼)
void SecReauthRule::on_ue_close(const UeState& last, CloseReason, int64_t, const UeRuleCtx&, RuleOutput&) {
  hits_.on_close(last);
  reauth_n_.erase(UeId{last.key, last.uid});
}

// 셀 kpm2 (21_ §4.3-3·§4.5): 걸림이 든 창의 kpm2에서 RAISE, 경보 중 새 UE는 UPDATE, 마지막 걸림 뒤 clear_quiet_ms면 CLEAR
// (extra는 늘리지 않음, 밀어내기 중 보류), input_lost면 END — 헬퍼가 한다
void SecReauthRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                 RuleOutput& out) {
  hits_.tick(cell, k.t_end_ms, input_lost, ctx, out.alerts, [&](std::size_t from) { decorate(from, out); });
}

// AN-06a 값 채우기 (21_ §4.6): raise·update에 values(reauth_ues = ues_total, extra 경보에 실린 연결의 누적 수, evicted — raise면
// 직전 clear_quiet_ms 이동 창, update면 경보가 열린 뒤 누적), raise에 cond reauth_after_sec·candidates [L3-06-O1]·params·로그
// 필드(맨 앞 kind=anomaly, ue는 RAISE를 일으킨 가장 최근 걸림). 심각도 medium 고정(§4.3-4), branch·conditions 없음(21_ §1)
void SecReauthRule::decorate(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["reauth_ues"] = e.ues_total;
    e.values["extra"] = hits_.count(e.cell_id, "extra");
    e.values["evicted"] = hits_.evicted(e.cell_id, raise, e.t);
    if (!raise) continue;
    e.cond = {"reauth_after_sec"};
    e.candidates = {kCandidate};
    e.params["n_reauth"] = cfg_.n_reauth;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (21_ §4.6): kind=anomaly ue=cell/du_ue_id/uid msg= n_reauth=
    e.log_fields = {{"kind", "anomaly"}};
    if (!e.ues.empty()) {
      const AlertUe& u = e.ues.back();
      e.log_fields.emplace_back("ue", ue_name(u.cell, u.du_ue_id, u.uid));
      e.log_fields.emplace_back("msg", u.values.at("msg").get<std::string>());
    }
    e.log_fields.emplace_back("n_reauth", std::to_string(cfg_.n_reauth));
  }
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 걸림·연결 기록을 모두 버린다
void SecReauthRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  hits_.end_all("session_reset", out.alerts);
  hits_.reset();
  reauth_n_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 경보를 END(input_silent)로 끝낸다. 걸림·셀 기록은 그대로
void SecReauthRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) { hits_.end_all("input_silent", out.alerts); }

}  // namespace detect
