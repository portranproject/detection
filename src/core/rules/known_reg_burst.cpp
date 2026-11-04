#include "detect/rules/known_reg_burst.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr const char* kRegReq = "RegistrationRequest";
constexpr const char* kMobility = "mobility";
// 걸림 키 — 연결이 아니라 S-TMSI. HitWindow의 (키, uid) 자리에 (셀, 표시) + 48비트 값을 넣는다. 표시는 du_ue_id에 쓰이지 않는 음수다
constexpr int64_t kKey48 = -1;
// 후보 (21_ §8.3-4) — 둘은 KPM으로 갈리지 않아 고정
constexpr const char* kCands[] = {"L3-17-OV", "L3-26-O"};

// '최근 본 UE'인가 (21_ §8.3-1): 할당 기억에 있으면 "alloc", 없고 now − known_ms 뒤에 닫힌 연결 레코드가 있으면 "history", 둘 다
// 없으면 nullptr. 할당 기억은 known_ms로 자르지 않는다 — 명세 문구('allocated(s)가 있음')대로이고 보관은 ue_table.alloc_ms다
// (11/04 구현 때 정함). 둘 다 있으면 alloc(AN08-T2)
const char* known_kind(uint64_t s, int64_t now, int64_t known_ms, const UeTable& t) {
  if (t.allocated(s)) return "alloc";
  if (!t.history(s, now - known_ms).empty()) return "history";
  return nullptr;
}

}  // namespace

// 해제 기준은 마지막 성립 — 창 안 서로 다른 S-TMSI 수 ≥ N (§8.5, AN-02와 같음)
KnownRegBurstRule::KnownRegBurstRule(KnownRegBurstConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), hits_(kId, alert, cfg.window_ms, cfg.n_reg, cfg.clear_quiet_ms) {
  hits_.set_clear_on_satisfied(true);
}

// 증거 지평 (21_ §1.1 — 11/04 결정): 1,000 ms + UPDATE 모음 지연. n_reg > 1이라 창 앞쪽 걸림의 연결이 RAISE 3 s 넘게 전에 닫혔으면
// pre 증거가 빠질 수 있다(§1.1 한계)
int64_t KnownRegBurstRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// ue_evt 한 줄 (21_ §8.3-1): RegistrationRequest(UL)의 reg_type이 mobility이고, 등록 요청의 S-TMSI(NAS f.s_tmsi)나 RRCSetupComplete의
// 48비트(RRC) 가운데 하나라도 '최근 본 UE'면 걸린다 — 맞은 쪽 값을 걸림 키로, 둘 다 맞으면 NAS 쪽(11/04 구현 때 정함, AN-02와 같은
// RRC 또는 NAS). reg_type이 없거나 initial·periodic·emergency면 세지 않는다. 같은 연결의 등록 요청 재전송은 다시 세지 않는다.
// 이미 걸린 S-TMSI가 회복 전이면(마지막 걸리는 이동 등록 뒤 W 안 — 새 연결이어도, 경보가 열려 있음) 새 칸 없이 경보 values.extra를
// 늘리고 해제 시계를 늘린다(11/04 사용자 결정 — 창 안 수는 서로 다른 S-TMSI, Q-69 (가)). CLEAR 뒤면 회복한 것으로 본다. mid_join이어도 판정한다(uncertain에 남음). UE 칸 values는 걸릴 때 값(§1.1)
void KnownRegBurstRule::on_ue_event(const UeEvt& evt, const UeState&, const UeState& after, const UeRuleCtx& ctx,
                                    RuleOutput&) {
  if (evt.proto != Proto::NAS || evt.dir != Dir::UL || evt.msg != kRegReq) return;
  if (!evt.reg_type || *evt.reg_type != kMobility) return;
  const UeId conn{after.key, after.uid};
  if (seen_.count(conn)) return;
  std::optional<uint64_t> s;
  const char* known = nullptr;
  for (const std::optional<uint64_t>& c : {evt.s_tmsi, after.rrc_s_tmsi}) {
    if (!c) continue;
    if (const char* k = known_kind(*c, evt.t_ms, cfg_.known_ms, ctx.table)) {
      s = c;
      known = k;
      break;
    }
  }
  if (!known) return;
  seen_.insert(conn);
  const int64_t cell = after.key.cell_id;
  const UeId id{UeKey{cell, kKey48}, static_cast<int64_t>(*s)};
  if (auto lr = last_reg_.find(id); lr != last_reg_.end()) {
    if (evt.t_ms - lr->second < cfg_.window_ms && hits_.active(id)) {
      // 회복 전 재등록 (21_ §8.3-1·§8.5 — 11/04 Q-69 (가)): 경보 values.extra로 세고 해제 시계(마지막 성립)를 늘린다
      lr->second = evt.t_ms;
      hits_.add(id, "extra");
      hits_.touch(id, evt.t_ms);
      return;
    }
    hits_.forget(id);  // 회복 — 창 W 동안 조용했거나 경보가 CLEAR됐다(21_ §8.3-1). 같은 S-TMSI가 다시 오면 새 UE로 싣는다
    last_reg_.erase(lr);
  }
  AlertUe u = alert_ue(after);
  u.cond = {"known_mobility_reg"};
  u.t_hit = evt.t_ms;
  u.values["reg_type"] = *evt.reg_type;
  u.values["id_type"] = evt.id_type ? ojson(*evt.id_type) : ojson(nullptr);
  u.values["known"] = known;
  u.values["est_cause"] = after.est_cause ? ojson(*after.est_cause) : ojson(nullptr);
  if (hits_.hit(id, std::move(u), false, conn)) last_reg_[id] = evt.t_ms;
}

// 닫힘: 아직 kpm2를 거치지 않은 걸림이면 마지막 상태로 식별·uncertain을 채운다. 연결 기록을 지운다
void KnownRegBurstRule::on_ue_close(const UeState& last, CloseReason, int64_t, const UeRuleCtx&, RuleOutput&) {
  hits_.on_close(last);
  seen_.erase({last.key, last.uid});
}

// 셀 kpm2 (21_ §8.3-2·§8.5): 창 안 서로 다른 S-TMSI 수 ≥ N이면 RAISE(그때 창 안 걸림 모두), 경보 중 새 S-TMSI는 UPDATE, 마지막 성립
// 뒤 clear_quiet_ms면 CLEAR(밀어내기 중 보류), input_lost면 END — 헬퍼가 한다. 마지막 걸리는 이동 등록 뒤 W가 지난 S-TMSI는 회복으로
// 보고 키를 지운다
void KnownRegBurstRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                     RuleOutput& out) {
  hits_.tick(cell, k.t_end_ms, input_lost, ctx, out.alerts,
             [&](std::size_t from, const AlertUe* hit) { decorate(from, out, hit); });
  for (auto it = last_reg_.begin(); it != last_reg_.end();) {
    if (it->first.first.cell_id == cell && k.t_end_ms - it->second >= cfg_.window_ms) {
      hits_.forget(it->first);
      it = last_reg_.erase(it);
    } else {
      ++it;
    }
  }
}

// AN-08 값 채우기 (21_ §8.6): raise·update에 values(reg_w 창 안 이동 등록 UE 수 — 서로 다른 S-TMSI, known_src 그중 할당 기억·이력으로
// 안 수 {"alloc","history"}(11/04 구현 때 정함), extra 실린 S-TMSI의 회복 전 재등록 수, evicted), raise에 cond known_reg_burst·
// candidates(고정 — raise에만, 21_ §1)·params·로그 필드(맨 앞 kind=anomaly, reg_w·n_reg·window_ms). 심각도 medium 고정, branch 없음
void KnownRegBurstRule::decorate(std::size_t from, RuleOutput& out, const AlertUe* /*hit*/) {  // AN-08 로그에는 UE 칸이 없어
                                                                                                // 이번 걸림을 쓰지 않는다
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    const bool raise = e.kind == AlertEventKind::Raise;
    const bool update = e.kind == AlertEventKind::Update;
    const int64_t reg_w = hits_.window(e.cell_id);
    auto known_is = [](const char* k) {
      return [k](const AlertUe& u) { return u.values.contains("known") && u.values.at("known") == k; };
    };
    // raise·update는 창 안 수 + 누적값, clear·end는 누적값만 (21_ §8.6, 14_ §8.3 — 11/04 Q-69 W-28)
    if (raise || update) {
      e.values["reg_w"] = reg_w;
      e.values["known_src"] = {{"alloc", hits_.window_if(e.cell_id, known_is("alloc"))},
                               {"history", hits_.window_if(e.cell_id, known_is("history"))}};
    }
    e.values["extra"] = hits_.count(e.cell_id, "extra");
    e.values["evicted"] = hits_.evicted(e.cell_id, raise, e.t);
    if (!raise) continue;
    e.cond = {"known_reg_burst"};
    e.candidates.assign(std::begin(kCands), std::end(kCands));
    e.params["window_ms"] = cfg_.window_ms;
    e.params["n_reg"] = cfg_.n_reg;
    e.params["known_ms"] = cfg_.known_ms;
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (21_ §8.6): kind=anomaly reg_w= n_reg= window_ms=
    e.log_fields = {{"kind", "anomaly"},
                    {"reg_w", std::to_string(reg_w)},
                    {"n_reg", std::to_string(cfg_.n_reg)},
                    {"window_ms", std::to_string(cfg_.window_ms)}};
  }
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 걸림·S-TMSI·연결 기록을 모두 버린다
void KnownRegBurstRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  hits_.end_all("session_reset", out.alerts);
  decorate(from, out);  // END에도 누적값 (14_ §8.3 — 11/04 Q-69 W-28)
  hits_.reset();
  last_reg_.clear();
  seen_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 경보를 END(input_silent)로 끝낸다. 걸림·셀 기록은 그대로
void KnownRegBurstRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  hits_.end_all("input_silent", out.alerts);
  decorate(from, out);  // END에도 누적값 (14_ §8.3 — 11/04 Q-69 W-28)
}

}  // namespace detect
