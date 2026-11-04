#include "detect/rules/sync_failure.h"

#include <string>
#include <utility>
#include <vector>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr int64_t kSynchFailure = 21;  // 5GMM 원인값 #21 synch failure (21_ §3.1, TS 24.501)
constexpr const char* kAuthReq = "AuthenticationRequest";
constexpr const char* kAuthFail = "AuthenticationFailure";
constexpr const char* kCandidate = "L3-07-OV";  // 이상 유형별 고정 후보 — 좁힐 관측값이 더 없다 (21_ §3.3-5)

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

}  // namespace

SyncFailureRule::SyncFailureRule(SyncFailureConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), hits_(kId, alert, cfg.window_ms, cfg.n_sync, cfg.clear_quiet_ms) {}

// 증거 지평 (21_ §1.1, 14_ §1.1): 4단계는 3단계와 같이 1,000 ms(창 한 칸 몫) + UPDATE 모음 지연이다(11/04 사용자 결정). 일반식대로
// 셀 창 W를 더하면 엔진이 지평 최댓값을 늦은 줄 제외 길이(late_until, 14_ §4.3)로도 쓰므로 2단계 '없음' 판정까지 W만큼 막힌다.
// 기본 N = 1은 걸림 다음 칸에 RAISE해 증거가 빠지지 않고, N > 1이면 창 앞쪽 걸림 중 이미 닫힌 연결의 pre 증거가 빠질 수 있다(§3.7)
int64_t SyncFailureRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// ue_evt 한 줄 (21_ §3.3-1·2):
//  - RegistrationRequest(UL): f.id_type을 연결마다 적어 둔다 (§3.2)
//  - AuthenticationFailure(UL)에 f.cause = 21: 동기 실패 연결로 걸린다(cond sync_failure, t_hit = 줄 시각). cause가 없거나 21이
//    아니면 아무것도 하지 않는다 — 원인을 모르거나 MAC 실패(#20)는 L3-21 몫이다(§3.1). mid_join이어도 건다 — 원인값은 줄 자체에
//    있다(§1.1). 이미 걸린 연결이면 새로 걸지 않고 경보 values.extra만 늘린다(연결당 한 번)
//  - 걸린 뒤 AuthenticationRequest(DL): 망이 재동기했다는 관측 — values.reauth에 연결당 1로 센다(판정 조건 아님)
// UE 칸 values는 걸릴 때 값이다(§1.1) — cause, 걸릴 때까지 본 인증 요청 수, 등록 요청의 id_type, 갱신 전 nas_sec
void SyncFailureRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx&,
                                  RuleOutput&) {
  if (evt.proto != Proto::NAS) return;
  const UeId id{after.key, after.uid};
  if (evt.dir == Dir::UL && evt.msg == "RegistrationRequest") {
    id_type_[id] = evt.id_type;
    return;
  }
  if (evt.dir == Dir::DL && evt.msg == kAuthReq) {
    if (hits_.hit_before(id) && reauth_.insert(id).second) hits_.add(id, "reauth");
    return;
  }
  if (evt.dir != Dir::UL || evt.msg != kAuthFail || !evt.cause || *evt.cause != kSynchFailure) return;
  if (hits_.hit_before(id)) {
    hits_.add(id, "extra");
    return;
  }
  AlertUe u = alert_ue(after);
  u.cond = {"sync_failure"};
  u.t_hit = evt.t_ms;
  u.values["cause"] = kSynchFailure;
  u.values["auth_req_n"] = before.count(Proto::NAS, kAuthReq);
  auto it = id_type_.find(id);
  u.values["id_type"] = it != id_type_.end() && it->second ? ojson(*it->second) : ojson(nullptr);
  u.values["nas_sec"] = to_string(before.nas_sec);
  hits_.hit(id, std::move(u));
}

// 항목이 닫힘 — 연결 기록을 지운다. 아직 kpm2를 거치지 않은 걸림은 마지막 상태로 판정에 남는다(헬퍼)
void SyncFailureRule::on_ue_close(const UeState& last, CloseReason, int64_t, const UeRuleCtx&, RuleOutput&) {
  const UeId id{last.key, last.uid};
  hits_.on_close(last);
  id_type_.erase(id);
  reauth_.erase(id);
}

// 셀 kpm2 (21_ §3.3-3·§3.5): 걸림이 든 창의 kpm2에서 셀 창 W 안 동기 실패 연결 수 S_W ≥ N이면 RAISE(경보 cond sync_count),
// 경보 중 새 걸림은 UPDATE, 마지막 걸림 뒤 clear_quiet_ms면 CLEAR(밀어내기 중 보류), input_lost면 END — 헬퍼가 한다
void SyncFailureRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                   RuleOutput& out) {
  hits_.tick(cell, k.t_end_ms, input_lost, ctx, out.alerts,
             [&](std::size_t from, const AlertUe* hit) { decorate(from, out, hit); });
}

// AN-01 값 채우기 (21_ §3.6): raise·update에 values(sync_w 가장 최근 걸림 기준 창 안 수, sync_total = ues_total, extra·reauth
// 경보에 실린 연결의 누적 수, evicted — raise면 직전 clear_quiet_ms 이동 창, update면 경보가 열린 뒤 누적), raise에 cond
// sync_count·candidates [L3-07-OV]·params·로그 필드(맨 앞 kind=anomaly — 14_ §6.2 표기, ue는 RAISE를 일으킨 가장 최근 걸림).
// 심각도는 medium 고정(§3.3-4), branch·conditions 없음(21_ §1)
void SyncFailureRule::decorate(std::size_t from, RuleOutput& out, const AlertUe* hit) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const bool raise = e.kind == AlertEventKind::Raise;
    const int64_t sync_w = hits_.window(e.cell_id);
    e.values["sync_w"] = sync_w;
    e.values["sync_total"] = e.ues_total;
    e.values["extra"] = hits_.count(e.cell_id, "extra");
    e.values["reauth"] = hits_.count(e.cell_id, "reauth");
    e.values["evicted"] = hits_.evicted(e.cell_id, raise, e.t);
    if (!raise) continue;
    e.cond = {"sync_count"};
    e.candidates = {kCandidate};
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_sync"] = cfg_.n_sync;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (21_ §3.6): kind=anomaly sync_w= n_sync= window_ms= ue=cell/du_ue_id/uid cause=21
    e.log_fields = {{"kind", "anomaly"},
                    {"sync_w", std::to_string(sync_w)},
                    {"n_sync", std::to_string(cfg_.n_sync)},
                    {"window_ms", std::to_string(cfg_.window_ms)}};
    if (hit) {  // RAISE를 일으킨 이번 걸림 (이슈 #84 — e.ues.back()은 ues_max로 잘리면 다른 UE)
      const AlertUe& u = *hit;
      e.log_fields.emplace_back("ue", ue_name(u.cell, u.du_ue_id, u.uid));
      e.log_fields.emplace_back("cause", std::to_string(kSynchFailure));
    }
  }
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 걸림·연결 기록을 모두 버린다
void SyncFailureRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  hits_.end_all("session_reset", out.alerts);
  hits_.reset();
  id_type_.clear();
  reauth_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 경보를 END(input_silent)로 끝낸다. 걸림·셀 기록은 그대로
void SyncFailureRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) { hits_.end_all("input_silent", out.alerts); }

}  // namespace detect
