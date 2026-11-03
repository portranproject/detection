#include "detect/rules/imsi_extractor.h"

#include <algorithm>
#include <string>
#include <utility>

namespace detect {
namespace {

using ojson = nlohmann::ordered_json;

constexpr const char* kReq = "IdentityRequest";    // 짝인 요청 q (NAS DL)
constexpr const char* kResp = "IdentityResponse";  // 응답 m (NAS UL)
constexpr const char* kTag = "unsolicited";        // 표시 tag (20_ §1.2-3)
constexpr const char* kPremise = "mitm_ul_relay";  // 전제 — 중간자가 UE 응답을 정상 망으로 넘김 (20_ §1.3)
// 같은 모양을 만드는 다른 공격 — #28 MNmap 중간자 변형(여러 UE에 식별·능력 요청을 반복 주입하고 응답을 넘김).
// 11/03 결정으로 이 룰이 받는다(20_ §3.1·§3.6, 4단계 코드 작성 직전에 반영 — 4_ §6.3 #1)
constexpr const char* kCandMnmap = "L3-28-V";

std::string ue_name(int64_t cell, int64_t du_ue_id, int64_t uid) {
  return std::to_string(cell) + "/" + std::to_string(du_ue_id) + "/" + std::to_string(uid);
}

}  // namespace

ImsiExtractorRule::ImsiExtractorRule(ImsiExtractorConfig cfg, AlertConfig alert)
    : cfg_(cfg), alert_(alert), book_(kId, alert, "attack", 3), held_book_(kId, alert, "anomaly", 3) {}

// 증거 지평 (20_ §1.2-6, 14_ §1.1): 판정이 판정 줄이 든 창의 kpm2에서 나므로 창 한 칸이면 되지만, 지평은 룰을 등록할 때(hello 전)
// 돌려주는 값이라 hello.period_ms를 쓸 수 없다 — 창 한 칸 몫 1,000 ms(kpm2 주기 요청값 100 ms의 10배)에 UPDATE 모음 지연을 더한다
int64_t ImsiExtractorRule::evidence_horizon_ms() const { return 1000 + alert_.update_min_ms; }

// ue_evt 한 줄 (20_ §3.3-1·4): IdentityResponse(NAS UL)가 '요청 없는 응답'이면(갱신 전 R ≤ A, mid_join 아님, AS 무결성 전 —
// §1.2-1) 대기 표시를 건다. 표시에는 판정할 줄 때의 값(R, A + 1, 갱신 전 보안 상태)을 적어 둔다 — 마감 전에 닫혀도 판정할 수
// 있게. 이 연결에 이미 표시가 있으면(대기·결정됨) extra만 늘어난다 — 연결당 한 번. 걸린 연결의 extra는 경보가 열려 있으면
// values.extra에 더하되 UPDATE는 내지 않는다(새 판정이 아니다, §3.3-4)
void ImsiExtractorRule::on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after,
                                    const UeRuleCtx& ctx, RuleOutput&) {
  if (evt.proto != Proto::NAS || evt.dir != Dir::UL || evt.msg != kResp) return;
  if (!unsolicited(before, Proto::NAS, kReq, kResp)) return;
  ojson snap;
  snap["req"] = before.count(Proto::NAS, kReq);
  snap["resp"] = before.count(Proto::NAS, kResp) + 1;
  snap["rrc_sec"] = to_string(before.rrc_sec);
  snap["nas_sec"] = to_string(before.nas_sec);
  if (marks_.start(after, kTag, evt.t_ms, std::move(snap), ctx)) return;
  const int64_t cell = after.key.cell_id;
  const LookbackMarks::Mark* m = marks_.find(after.key, after.uid, kTag);
  if (m && m->phase == LookbackMarks::Phase::Hit && book_.open(cell)) ++cells_[cell].extra_open;
}

// 마감 (20_ §3.3-2): 걸리면 hit, 연결 시작 뒤 DL 로스면 보류 — 공격 경보 중이면 values.held로만, 아니면 불확실 경보용으로
// 적어 둔다(판정은 held_tick, 14_ §6.2). late로 판정하지 않은 표시는 헬퍼가 지웠다
void ImsiExtractorRule::on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) {
  const LookbackMarks::Decision dc = marks_.on_deadline(d, ctx);
  const int64_t cell = d.key.cell_id;
  const int64_t now = ctx.deadlines.clock(cell).value_or(d.at);
  if (dc.verdict == LookbackMarks::Verdict::Held) {
    CellState& c = cells_[cell];
    c.held_times.push_back(now);
    if (book_.open(cell)) ++c.held_open;
    else if (alert_.held_alert) c.fresh_held.push_back(held_ue(dc, d.at));
  } else if (dc.verdict == LookbackMarks::Verdict::Hit) {
    hit(dc, now, ctx, out);
  }
}

// 걸린 UE (20_ §3.3-2·3·§3.6): cond unsolicited, t_hit = 응답 시각 t_r, 심각도는 늘 medium — 식별자 종류를 받지 않아
// 가르지 않는다(§1.1·§3.3-3). 경보 t는 마감을 처리한 kpm2의 t_end_ms(응답이 든 창의 끝). 새 경보면 열린 불확실 경보를
// 같은 줄에서 먼저 CLEAR하고(14_ §8.2) 누적값을 처음부터 센다. 대기 중에 온 extra는 이 걸림과 함께 더한다(L24-T8)
void ImsiExtractorRule::hit(const LookbackMarks::Decision& dc, int64_t now, const UeRuleCtx& ctx, RuleOutput& out) {
  const int64_t cell = dc.n.key.cell_id;
  CellState& c = cells_[cell];
  if (!book_.open(cell)) {
    close_held(cell, now, out);
    c.extra_open = 0;
    c.held_open = 0;
    c.evicted_open = 0;
  }
  c.extra_open += dc.mark.extra;
  c.t_hit_last = std::max(c.t_hit_last, dc.mark.t_from);

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

// L3-24 값 채우기 (20_ §3.6): raise·update에 values(extra·held·evicted — raise의 held·evicted는 직전 clear_quiet_ms 이동 창,
// update는 경보가 열린 뒤 누적), raise에 cond(RAISE를 일으킨 UE의 것)·candidates [L3-28-V](#28 MNmap 중간자 변형, 20_ §3.1)·
// conditions [mitm_ul_relay](바뀌지 않으므로 update에는 싣지 않는다)·params·로그 필드. 갈래가 없어 branch는 뺀다
void ImsiExtractorRule::decorate(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    CellState& c = cells_[e.cell_id];
    const bool raise = e.kind == AlertEventKind::Raise;
    e.values["extra"] = c.extra_open;
    e.values["held"] = raise ? held_window(c, e.t) : c.held_open;
    e.values["evicted"] = raise ? evicted_window(c, e.t) : c.evicted_open;
    if (!raise || e.ues.empty()) continue;

    const AlertUe& u = e.ues.front();
    e.cond = u.cond;
    e.candidates = {kCandMnmap};
    e.conditions = std::vector<std::string>{kPremise};
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    // 로그 줄 (20_ §3.6): ue=cell/du_ue_id/uid req=R resp=A+1 rrc_sec= nas_sec=
    e.log_fields = {{"ue", ue_name(u.cell, u.du_ue_id, u.uid)},
                    {"req", std::to_string(u.values.at("req").get<int64_t>())},
                    {"resp", std::to_string(u.values.at("resp").get<int64_t>())},
                    {"rrc_sec", u.values.at("rrc_sec").get<std::string>()},
                    {"nas_sec", u.values.at("nas_sec").get<std::string>()}};
  }
}

// raise의 held — 직전 clear_quiet_ms 동안 보류된 판정 수. 경보가 없을 때도 셀별 이동 창으로 센다 (L3-20과 같음, 15_ §2.6)
int64_t ImsiExtractorRule::held_window(CellState& c, int64_t now) const {
  while (!c.held_times.empty() && c.held_times.front() <= now - cfg_.clear_quiet_ms) c.held_times.pop_front();
  return static_cast<int64_t>(c.held_times.size());
}

// 셀 kpm2마다 (20_ §3.5): input_lost면 진행 중 경보를 END, 모아 둔 UE를 UPDATE 간격에 맞춰 내고, 마지막 걸림 뒤
// clear_quiet_ms가 지나면 CLEAR — extra는 t_hit를 늘리지 않는다. 보류는 걸림으로 세지 않으므로 해제를 막지 않는다(15_ §1).
// 직전 clear_quiet_ms 동안 그 셀에 상태표 밀어내기가 있었으면 풀지 않는다 — 밀려난 UE는 판정되지 않아 조용해 보인다(Q-56, 14_ §4.4)
void ImsiExtractorRule::on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss&, bool input_lost,
                                     const UeRuleCtx& ctx, RuleOutput& out) {
  const int64_t t = k.t_end_ms;
  CellState& c = cells_[cell];
  note_evictions(c, cell, t, ctx);
  const std::size_t from = out.alerts.size();
  if (input_lost) book_.end(cell, t, "input_lost", out.alerts);
  book_.flush(cell, t, out.alerts);
  if (book_.open(cell) && t - c.t_hit_last >= cfg_.clear_quiet_ms && evicted_window(c, t) == 0)
    book_.clear(cell, t, out.alerts);
  decorate(from, out);
  held_window(c, t);
  held_tick(cell, c, t, input_lost, ctx, out);
}

// 보류된 UE 한 칸 (14_ §6.2 불확실 경보의 ues[], 20_ §3.7): cond held, t_hit = 마감, uncertain에 loss.
// wait_ms는 기다린 구간이 아니라 되돌아본 구간 t_r − t_s다
AlertUe ImsiExtractorRule::held_ue(const LookbackMarks::Decision& dc, int64_t t_hit) const {
  AlertUe u = alert_ue(dc.n);
  u.cond = {"held"};
  u.t_hit = t_hit;
  if (std::find(u.uncertain.begin(), u.uncertain.end(), "loss") == u.uncertain.end()) u.uncertain.emplace_back("loss");
  u.values["wait_ms"] = dc.mark.t_from - dc.n.t_start;
  u.values["dir"] = "DL";
  return u;
}

// 불확실 경보 (14_ §6.2, 20_ §3.7 — L3-20과 같은 문턱 1): 이번 마감 처리에서 보류된 UE마다 창(clear_quiet_ms) 안 보류 수 H_W를
// 세고, 공격 경보가 없으면 창 안 보류 UE로 RAISE(kind anomaly), 경보 중이면 UPDATE로 모은다. 공격 경보가 열려 있으면
// values.held로만 센다. 마지막 보류 뒤 clear_quiet_ms면 CLEAR, input_lost면 END
void ImsiExtractorRule::held_tick(int64_t cell, CellState& c, int64_t t, bool input_lost, const UeRuleCtx& ctx,
                                  RuleOutput& out) {
  const std::size_t from = out.alerts.size();
  if (input_lost) held_book_.end(cell, t, "input_lost", out.alerts);
  for (AlertUe& u : c.fresh_held) {
    c.held_ues.push_back(u);
    while (c.held_ues.front().t_hit <= u.t_hit - cfg_.clear_quiet_ms) c.held_ues.pop_front();
    c.t_last_held = u.t_hit;
    if (book_.open(cell)) {
      ++c.held_open;
      continue;
    }
    std::vector<AlertUe> ues;
    if (held_book_.open(cell)) ues.push_back(u);
    else ues.assign(c.held_ues.begin(), c.held_ues.end());
    held_book_.add(cell, std::move(ues), Severity::Medium, t, ctx.session, ctx.seq, out.alerts);
  }
  c.fresh_held.clear();
  held_book_.flush(cell, t, out.alerts);
  if (held_book_.open(cell) && t - c.t_last_held >= cfg_.clear_quiet_ms) held_book_.clear(cell, t, out.alerts);
  decorate_held(from, out);
  if (!held_book_.open(cell))
    while (!c.held_ues.empty() && c.held_ues.front().t_hit <= t - cfg_.clear_quiet_ms) c.held_ues.pop_front();
}

// 공격 경보가 RAISE되기 직전 — 열린 불확실 경보를 같은 줄에서 먼저 CLEAR한다 (14_ §8.2)
void ImsiExtractorRule::close_held(int64_t cell, int64_t t, RuleOutput& out) {
  if (!held_book_.open(cell)) return;
  const std::size_t from = out.alerts.size();
  held_book_.clear(cell, t, out.alerts);
  decorate_held(from, out);
}

// 불확실 경보 값 채우기 (14_ §6.2, 20_ §3.7): raise·update에 values.held_w(창 안 보류 수), raise에 cond held_count·
// candidates(이 룰)·params·로그 필드(맨 앞 kind=anomaly). conditions는 싣지 않는다 — 공격 판정이 아니다. update 로그에는 kind=anomaly만
void ImsiExtractorRule::decorate_held(std::size_t from, RuleOutput& out) {
  for (std::size_t i = from; i < out.alerts.size(); ++i) {
    AlertEvent& e = out.alerts[i];
    if (e.kind != AlertEventKind::Raise && e.kind != AlertEventKind::Update) continue;
    const CellState& c = cells_[e.cell_id];
    e.values["held_w"] = static_cast<int64_t>(c.held_ues.size());
    if (e.kind != AlertEventKind::Raise) {
      e.log_fields = {{"kind", "anomaly"}};
      continue;
    }
    e.cond = {"held_count"};
    e.candidates = {kId};
    e.params["clear_quiet_ms"] = cfg_.clear_quiet_ms;
    e.log_fields = {{"kind", "anomaly"}, {"held_w", std::to_string(c.held_ues.size())}};
  }
}

// 상태표 셀별 누적 evicted(14_ §6.3)의 증가분을 이 칸 시각으로 적는다 — 경보가 열려 있으면 evicted_open도
void ImsiExtractorRule::note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx) {
  const int64_t total = ctx.table.counts(cell).evicted;
  for (; c.evicted_seen < total; ++c.evicted_seen) {
    c.evict_times.push_back(t);
    if (book_.open(cell)) ++c.evicted_open;
  }
}

// 직전 clear_quiet_ms 동안의 밀어내기 수 (이동 창) — raise의 values.evicted와 해제 보류 기준
int64_t ImsiExtractorRule::evicted_window(CellState& c, int64_t now) const {
  while (!c.evict_times.empty() && c.evict_times.front() <= now - cfg_.clear_quiet_ms) c.evict_times.pop_front();
  return static_cast<int64_t>(c.evict_times.size());
}

// 항목이 닫힘 (20_ §1.2-5·'표시의 생애'): 대기 표시는 released·reused·stale_setup이면 복사본을 남겨 마감 때 판정하고,
// 그 밖·결정된 표시는 지운다 — 헬퍼가 한다
void ImsiExtractorRule::on_ue_close(const UeState& last, CloseReason reason, int64_t, const UeRuleCtx&, RuleOutput&) {
  marks_.on_close(last, reason);
}

// 새 세션 (14_ §7 hello): 진행 중 경보를 END(session_reset)로 끝내고 표시·누적값을 모두 버린다
void ImsiExtractorRule::on_session_reset(const UeRuleCtx&, RuleOutput& out) {
  book_.end_all("session_reset", out.alerts);
  held_book_.end_all("session_reset", out.alerts);
  marks_.clear();
  cells_.clear();
}

// 입력 침묵 (14_ §6.2 — Q-45): 진행 중 공격·불확실 경보를 END(input_silent)로 끝낸다. 표시·셀 기록은 그대로 —
// kpm2가 다시 오면 마감이 평소처럼 판정된다
void ImsiExtractorRule::on_input_silent(const UeRuleCtx&, RuleOutput& out) {
  book_.end_all("input_silent", out.alerts);
  held_book_.end_all("input_silent", out.alerts);
}

}  // namespace detect
