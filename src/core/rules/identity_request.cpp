#include "detect/rules/identity_request.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr const char* kIdReq = "IdentityRequest";
constexpr const char* kCondKnown = "idreq_known_guti";  // 갈래 ① UE (21_ §5.3-1)
constexpr const char* kCondIdReq = "idreq";             // 갈래 ② UE (§5.3-2)
constexpr const char* kCandidate = "L3-25-OV";          // 이상 유형별 고정 후보 (§5.3-4)

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

bool has(const std::vector<std::string>& v, const char* s) { return std::find(v.begin(), v.end(), s) != v.end(); }

// '이 망이 준 식별자로 등록했나' (21_ §5.3-1, 11/04 사용자 결정): 등록 요청이 5G-GUTI였고, RRC에서 본 S-TMSI(48비트 또는 Part1)나
// 등록 요청 GUTI의 S-TMSI 가운데 하나라도 할당 기억에 있으면 그렇다. 중간자가 NAS의 GUTI만 모르는 값으로 바꾸면(#25) RRC 쪽은
// 원래 값이 남고, AMF 재시작 뒤 정상 재등록은 둘 다 원래 값이다
bool known_guti(const UeState& b, const UeTable& t) {
  if (!b.id_type || *b.id_type != "5G-GUTI") return false;
  if (b.reg_s_tmsi && t.allocated(*b.reg_s_tmsi)) return true;
  if (b.rrc_s_tmsi) return t.allocated(*b.rrc_s_tmsi).has_value();
  return b.s_tmsi_part1 && t.allocated_part1(*b.s_tmsi_part1);
}

}  // namespace

// 해제 기준은 마지막 성립 — 갈래 ① 걸림 또는 창 안 수 ≥ N (§5.5)
IdentityRequestRule::IdentityRequestRule(IdentityRequestConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), hits_(kId, alert, cfg.window_ms, cfg.n_idreq, cfg.clear_quiet_ms) {
  hits_.set_clear_on_satisfied(true);
}

// 증거 지평 (21_ §1.1 — 11/04 결정): 1,000 ms + UPDATE 모음 지연
int64_t IdentityRequestRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// ue_evt 한 줄 (21_ §5.3-1·2): 보안 전(갱신 전 nas_sec이 ON·CMD가 아님) IdentityRequest(DL)를 처음 받은 연결이 후보다 — 보안 뒤
// IMEISV 요청은 아니다(AN02-T6), 같은 연결의 다음 요청(AMF 재전송)은 다시 세지 않는다. 이 망이 준 식별자로 GUTI 등록했으면 갈래 ① —
// UE 하나로 성립(force). mid_join이면 등록 요청을 못 봐 갈래 ①은 판정하지 않고 갈래 ②에만 센다. 갈래 ① 연결도 갈래 ② 수에 든다.
// UE 칸 values는 걸릴 때 값 — 갈래, 등록 요청의 id_type, 할당 기억에 있었는지, 갱신 전 nas_sec
void IdentityRequestRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after,
                                      const UeRuleCtx& ctx, RuleOutput&) {
  if (evt.proto != Proto::NAS || evt.dir != Dir::DL || evt.msg != kIdReq) return;
  if (before.nas_sec == NasSecState::On || before.nas_sec == NasSecState::Cmd) return;
  const HitWindow::UeId id{after.key, after.uid};
  if (hits_.hit_before(id)) return;
  const bool known = known_guti(before, ctx.table);
  const bool branch1 = known && !before.mid_join;
  AlertUe u = alert_ue(after);
  u.cond = {branch1 ? kCondKnown : kCondIdReq};
  u.t_hit = evt.t_ms;
  u.values["branch"] = branch1 ? "1" : "2";
  u.values["id_type"] = before.id_type ? ojson(*before.id_type) : ojson(nullptr);
  u.values["known"] = known;
  u.values["nas_sec"] = to_string(before.nas_sec);
  hits_.hit(id, std::move(u), branch1);
}

void IdentityRequestRule::on_ue_close(const UeState& last, CloseReason, int64_t, const UeRuleCtx&, RuleOutput&) {
  hits_.on_close(last);
}

// 셀 kpm2 (21_ §5.3·§5.5): 갈래 ① 걸림이면 바로, 아니면 창 안 식별 요청 연결 수 ≥ N이면 RAISE(그때 창 안 연결 모두), 경보 중
// 새 연결은 UPDATE, 마지막 성립 뒤 clear_quiet_ms면 CLEAR(밀어내기 중 보류), input_lost면 END — 헬퍼가 한다
void IdentityRequestRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost,
                                       const UeRuleCtx& ctx, RuleOutput& out) {
  hits_.tick(cell, k.t_end_ms, input_lost, ctx, out.alerts,
             [&](std::size_t from, const AlertUe* hit) { decorate(from, out, hit); });
}

// AN-02 값 채우기 (21_ §5.6): branch는 모든 이벤트에 — 지금 경보에 갈래 ① UE가 한 번이라도 실렸으면 "1"(특정에 더 가까움), 아니면
// "2"(§5.3-3, RAISE에서 처음부터 센다). raise·update에 values(idreq_w 창 안 식별 요청 연결 수, known_w 그중 갈래 ①, evicted),
// raise에 cond(RAISE를 일으킨 갈래 — 갈래 ① 걸림이면 idreq_known_guti, 창 수로 성립했으면 idreq_count, 둘 다면 둘 다)·candidates
// [L3-25-OV]·params·로그 필드(맨 앞 kind=anomaly·branch, 갈래 ①은 ue·id_type·known, 갈래 ②는 idreq_w·known_w). 심각도 medium
void IdentityRequestRule::decorate(std::size_t from, RuleOutput& out, const AlertUe* hit) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    const bool raise = e.kind == AlertEventKind::Raise;
    bool& b1 = branch1_[e.cell_id];
    // 갈래 ① UE가 실렸나 — RAISE는 창 안 걸림 전부(레코드 ues가 ues_max로 잘려도), UPDATE는 새로 실린 UE와 이번 걸림 (이슈 #84)
    if (raise) b1 = hits_.window_with(e.cell_id, kCondKnown) > 0;
    if (e.kind == AlertEventKind::Update) {
      for (const AlertUe& u : e.ues)
        if (has(u.cond, kCondKnown)) b1 = true;
      if (hit && has(hit->cond, kCondKnown)) b1 = true;
    }
    e.branch = b1 ? "1" : "2";
    if (!raise && e.kind != AlertEventKind::Update) continue;
    const int64_t idreq_w = hits_.window(e.cell_id);
    const int64_t known_w = hits_.window_with(e.cell_id, kCondKnown);
    e.values["idreq_w"] = idreq_w;
    e.values["known_w"] = known_w;
    e.values["evicted"] = hits_.evicted(e.cell_id, raise, e.t);
    if (!raise) continue;
    e.cond.clear();
    const bool by_known = hit && has(hit->cond, kCondKnown);  // RAISE를 일으킨 이번 걸림 (이슈 #84 — e.ues.back()은 잘리면 다른 UE)
    if (by_known) e.cond.emplace_back(kCondKnown);
    if (idreq_w >= cfg_.n_idreq) e.cond.emplace_back("idreq_count");
    e.candidates = {kCandidate};
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_idreq"] = cfg_.n_idreq;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (21_ §5.6 두 모양): 갈래 ① branch=1 ue= id_type= known=1 idreq_w= n_idreq= / 갈래 ② branch=2 idreq_w= known_w=
    // n_idreq= window_ms=. RAISE 골격은 branch를 찍지 않아 룰이 넣는다
    e.log_fields = {{"kind", "anomaly"}, {"branch", *e.branch}};
    if (by_known) {
      const AlertUe& u = *hit;
      e.log_fields.emplace_back("ue", ue_name(u.cell, u.du_ue_id, u.uid));
      e.log_fields.emplace_back("id_type", u.values.at("id_type").is_null() ? "null"
                                                                             : u.values.at("id_type").get<std::string>());
      e.log_fields.emplace_back("known", "1");
      e.log_fields.emplace_back("idreq_w", std::to_string(idreq_w));
      e.log_fields.emplace_back("n_idreq", std::to_string(cfg_.n_idreq));
    } else {
      e.log_fields.emplace_back("idreq_w", std::to_string(idreq_w));
      e.log_fields.emplace_back("known_w", std::to_string(known_w));
      e.log_fields.emplace_back("n_idreq", std::to_string(cfg_.n_idreq));
      e.log_fields.emplace_back("window_ms", std::to_string(cfg_.window_ms));
    }
  }
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 걸림·셀 기록을 모두 버린다. END에도 branch를 싣는다
void IdentityRequestRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  hits_.end_all("session_reset", out.alerts);
  decorate(from, out);
  hits_.reset();
  branch1_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 경보를 END(input_silent)로 끝낸다. 걸림·셀 기록은 그대로
void IdentityRequestRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  hits_.end_all("input_silent", out.alerts);
  decorate(from, out);
}

}  // namespace detect
