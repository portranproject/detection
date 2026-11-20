#include "detect/rules/nas_desync.h"

#include <algorithm>
#include <string>
#include <utility>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr const char* kCmd = "SecurityModeCommand";  // 짝인 요청 q (NAS DL)
constexpr const char* kRej = "SecurityModeReject";   // 후보가 되는 응답 줄 m (NAS UL)
constexpr const char* kCpl = "SecurityModeComplete"; // 응답 집합의 다른 하나 (NAS UL)
constexpr const char* kTag = "unsolicited";          // 표시 tag (20_ §1.2-3)
constexpr const char* kPremise = "mitm_ul_relay";    // 전제 — 중간자가 UE 응답을 정상 망으로 넘김 (20_ §1.3)
// 응답 집합 (20_ §5.3): 보안 모드 명령의 정상 응답은 Complete이고 거부는 Reject다. Reject만 세면 정상 명령 → Complete 뒤 주입된
// 명령의 Reject가 R 1·A 0으로 짝이 있어 보여 놓친다. 정상 명령 → UE 거부는 R 1·A 0이라 후보가 아니다
const std::vector<std::string> kResps = {kCpl, kRej};

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

// 불확실 경보 묶음의 값 (14_ §6.2, 20_ §5.7 — L3-24와 같은 문턱 1, 창 clear_quiet_ms). raise의 params는 clear_quiet_ms뿐
HeldBook::Spec held_spec(const NasDesyncConfig& cfg) {
  HeldBook::Spec s;
  s.rule = NasDesyncRule::kId;
  s.stage = 3;
  s.window_ms = cfg.clear_quiet_ms;
  s.n = 1;
  s.clear_quiet_ms = cfg.clear_quiet_ms;
  s.params["clear_quiet_ms"] = cfg.clear_quiet_ms;
  return s;
}

}  // namespace

NasDesyncRule::NasDesyncRule(NasDesyncConfig cfg, AlertConfig alert)
    : cfg_(cfg),
      alert_(alert),
      book_(kId, alert, "attack", 3),
      held_(held_spec(cfg), alert),
      evict_(cfg.clear_quiet_ms) {}

// 증거 지평 (20_ §5.4·§1.2-6, 14_ §1.1): L3-24와 같다 — 창 한 칸 몫 1,000 ms에 UPDATE 모음 지연을 더한다
int64_t NasDesyncRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// ue_evt 한 줄 (20_ §5.3-1·4): NAS SecurityModeReject(UL)가 '요청 없는 응답'이면(갱신 전 R = cnt[명령] ≤ A = cnt[Complete] +
// cnt[Reject], mid_join 아님, AS 무결성 전 — §1.2-1) 대기 표시를 건다. 표시에는 판정할 줄 때의 값(R, A + 1, Reject 수 + 1, 갱신 전
// 보안 상태)을 적어 둔다 — 마감 전에 닫혀도 판정할 수 있게. 이 연결에 이미 표시가 있으면(대기·결정됨) extra만 늘어난다 — 연결당
// 한 번. 걸린 연결의 extra는 경보가 열려 있으면 values.extra에 더하되 UPDATE는 내지 않는다. 심각도는 반복돼도 올리지 않는다 —
// 분석 엔진 중복 줄과 가를 수 없어서다(§5.3-3)
void NasDesyncRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                                RuleOutput&) {
  // 늦은 짝 요청 (20_ §1.2-4 — 11/05 Q-74, 이슈 #94): 짝 요청(DL)이 그 셀 시계보다 이른 시각으로 뒤늦게 오면 대기 중인 표시를 지운다 —
  // 놓친 요청이 뒤늦게 온 것이라 '요청 없는 응답'이 아니다. 판정과 무관한 늦은 줄은 막지 않는다(상태표 late_until은 2단계용)
  if (evt.proto == Proto::NAS && evt.dir == Dir::DL && evt.msg == kCmd) {
    if (const std::optional<int64_t> clock = ctx.deadlines.clock(after.key.cell_id); clock && evt.t_ms < *clock)
      marks_.erase_waiting(after.key, after.uid, kTag);
    return;
  }
  if (evt.proto != Proto::NAS || evt.dir != Dir::UL || evt.msg != kRej) return;
  if (!unsolicited(before, Proto::NAS, kCmd, kResps)) return;
  ojson snap;
  snap["req"] = before.count(Proto::NAS, kCmd);
  snap["resp"] = count_any(before, Proto::NAS, kResps) + 1;
  snap["rej"] = before.count(Proto::NAS, kRej) + 1;
  snap["rrc_sec"] = to_string(before.rrc_sec);
  snap["nas_sec"] = to_string(before.nas_sec);
  if (marks_.start(after, kTag, evt.t_ms, std::move(snap), ctx)) return;
  const int64_t cell = after.key.cell_id;
  const LookbackMarks::Mark* m = marks_.find(after.key, after.uid, kTag);
  // 걸린 연결의 반복 — 그 걸림을 실은 경보가 열려 있을 때만 (W-34): CLEAR 뒤 새 경보에 옛 표시의 반복이 섞이지 않게
  if (m && m->phase == LookbackMarks::Phase::Hit && book_.open(cell) && m->epoch == cells_[cell].epoch)
    ++cells_[cell].extra_open;
}

// 마감 (20_ §5.3-2): 걸리면 hit, 연결 시작 뒤 DL 로스면 보류 — 공격 경보 중이면 values.held로만, 아니면 불확실 경보용으로
// 적어 둔다(판정은 held_.tick, 14_ §6.2)
void NasDesyncRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) {
  const LookbackMarks::Decision dc = marks_.on_deadline(d, ctx);
  const int64_t cell = d.key.cell_id;
  const int64_t now = ctx.deadlines.clock(cell).value_or(d.at);
  if (dc.verdict == LookbackMarks::Verdict::Held) {
    held_.hold(cell, now, book_.open(cell), held_ue(dc, d.at));
  } else if (dc.verdict == LookbackMarks::Verdict::Hit) {
    hit(dc, now, ctx, out);
  }
}

// 걸린 UE (20_ §5.3-2·3·§5.6): cond unsolicited, t_hit = Reject 시각 t_r, 심각도는 늘 medium — Reject 한 번은 UL NAS COUNT를 1
// 올릴 뿐이다(§5.3-3). 경보 t는 마감을 처리한 kpm2의 t_end_ms. 새 경보면 열린 불확실 경보를 같은 줄에서 먼저 CLEAR하고
// (14_ §8.2) 누적값을 처음부터 센다. 대기 중에 온 extra는 이 걸림과 함께 더한다(L06-T8)
void NasDesyncRule::hit(const LookbackMarks::Decision& dc, int64_t now, const UeRuleCtx& ctx, RuleOutput& out) {
  const int64_t cell = dc.n.key.cell_id;
  CellState& c = cells_[cell];
  if (!book_.open(cell)) {
    held_.close(cell, now, out.alerts);
    ++c.epoch;  // 새 경보의 세대 (W-34)
    c.extra_open = 0;
    held_.new_attack_alert(cell);
    evict_.reset_open(cell);
  }
  c.extra_open += dc.mark.extra;
  c.t_hit_last = std::max(c.t_hit_last, dc.mark.t_from);
  marks_.included(dc.n.key, dc.n.uid, dc.mark.tag, c.epoch);

  AlertUe u = alert_ue(dc.n);
  u.cond = {"unsolicited"};
  u.t_hit = dc.mark.t_from;
  u.values = dc.mark.snap;
  const std::size_t from = out.alerts.size();
  std::vector<AlertUe> ues;
  ues.push_back(std::move(u));
  book_.add(cell, std::move(ues), Severity::Medium, now, ctx.session, ctx.seq, out.alerts);
  decorate(from, out);
}

// L3-06 값 채우기 (20_ §5.6): raise·update에 values(extra·held·evicted — raise의 held·evicted는 직전 clear_quiet_ms 이동 창,
// update는 경보가 열린 뒤 누적), raise에 cond(RAISE를 일으킨 UE의 것)·candidates [](같은 모양을 만드는 다른 공격이 목록에 없다 —
// #3 변형 a·#5 강등 변형의 Reject는 망이 보낸 명령의 짝이다, §5.1)·conditions [mitm_ul_relay](바뀌지 않으므로 update에는 싣지
// 않는다)·params·로그 필드. 갈래가 없어 branch는 뺀다
void NasDesyncRule::decorate(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    CellState& c = cells_[e.cell_id];
    const bool raise = e.kind == AlertEventKind::Raise;
    // raise·update·clear·end 모두 (14_ §8.3 — 11/04 Q-69 W-28): 경보가 열린 뒤 누적값. clear·end에도 실어 UE 하나의 지속 공격에서
    // 쌓인 수가 레코드에 남게 한다(raise의 held·evicted는 직전 clear_quiet_ms 이동 창)
    e.values["extra"] = c.extra_open;
    e.values["held"] = held_.held(e.cell_id, raise, e.t);
    e.values["evicted"] = raise ? evict_.window(e.cell_id, e.t) : evict_.open(e.cell_id);
    if (!raise || e.ues.empty()) continue;

    const AlertUe& u = e.ues.front();
    e.cond = u.cond;
    e.candidates.clear();
    e.conditions = std::vector<std::string>{kPremise};
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (20_ §5.6): ue=cell/du_ue_id/uid req=R resp=A+1 rej= rrc_sec= nas_sec=
    e.log_fields = {{"ue", ue_name(u.cell, u.du_ue_id, u.uid)},
                    {"req", std::to_string(u.values.at("req").get<int64_t>())},
                    {"resp", std::to_string(u.values.at("resp").get<int64_t>())},
                    {"rej", std::to_string(u.values.at("rej").get<int64_t>())},
                    {"rrc_sec", u.values.at("rrc_sec").get<std::string>()},
                    {"nas_sec", u.values.at("nas_sec").get<std::string>()}};
  }
}

// 셀 kpm2마다 (20_ §5.5): input_lost면 진행 중 경보를 END, 모아 둔 UE를 UPDATE 간격에 맞춰 내고, 마지막 걸림 뒤
// clear_quiet_ms가 지나면 CLEAR — extra는 t_hit를 늘리지 않는다. 보류는 걸림으로 세지 않으므로 해제를 막지 않는다(15_ §1).
// 직전 clear_quiet_ms 동안 그 셀에 상태표 밀어내기가 있었으면 풀지 않는다(Q-56, 14_ §4.4). 불확실 경보(14_ §6.2, 20_ §5.7 —
// L3-24와 같은 문턱 1)는 공격 묶음 뒤에 헬퍼가 본다
void NasDesyncRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost, const UeRuleCtx& ctx,
                                 RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  CellState& c = cells_[cell];
  evict_.note(cell, t, book_.open(cell), ctx);
  const std::size_t from = out.alerts.size();
  if (input_lost) book_.end(cell, t, "input_lost", out.alerts);
  book_.flush(cell, t, out.alerts);
  if (book_.open(cell) && t - c.t_hit_last >= cfg_.clear_quiet_ms && evict_.window(cell, t) == 0)
    book_.clear(cell, t, out.alerts);
  decorate(from, out);
  held_.tick(cell, t, input_lost, book_.open(cell), ctx, out.alerts);
}

// 보류된 UE 한 칸 (14_ §6.2 불확실 경보의 ues[], 20_ §5.7): cond held, t_hit = 마감, uncertain에 loss.
// wait_ms는 기다린 구간이 아니라 되돌아본 구간 t_r − t_s다
AlertUe NasDesyncRule::held_ue(const LookbackMarks::Decision& dc, int64_t t_hit) const {
  AlertUe u = alert_ue(dc.n);
  u.cond = {"held"};
  u.t_hit = t_hit;
  if (std::find(u.uncertain.begin(), u.uncertain.end(), "loss") == u.uncertain.end()) u.uncertain.emplace_back("loss");
  u.values["wait_ms"] = dc.mark.t_from - dc.n.t_start;
  u.values["dir"] = "DL";
  return u;
}

// 항목이 닫힘 (20_ §1.2-5·'표시의 생애'): 대기 표시는 released·reused·stale_setup이면 복사본을 남겨 마감 때 판정하고,
// 그 밖·결정된 표시는 지운다 — 헬퍼가 한다
void NasDesyncRule::on_ue_close(const UeState& last, CloseReason reason, int64_t, const UeRuleCtx&, RuleOutput&) {
  marks_.on_close(last, reason);
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 표시·누적값을 모두 버린다
void NasDesyncRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  book_.end_all("session_reset", out.alerts);
  decorate(from, out);  // END에도 누적값 (14_ §8.3 — 11/04 Q-69 W-28). 불확실 경보는 그대로
  held_.end_all("session_reset", out.alerts);
  marks_.clear();
  cells_.clear();
  held_.reset();
  evict_.reset();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 공격·불확실 경보를 END(input_silent)로 끝낸다. 표시·셀 기록은 그대로
void NasDesyncRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  book_.end_all("input_silent", out.alerts);
  decorate(from, out);  // END에도 누적값 (14_ §8.3 — 11/04 Q-69 W-28)
  held_.end_all("input_silent", out.alerts);
}

}  // namespace detect
