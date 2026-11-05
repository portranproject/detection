#include "detect/series.h"

#include <algorithm>
#include <utility>

namespace detect {

// 버퍼 최소 크기 (3_ §3): A 윈도우가 T_nr만큼 과거로 밀리므로 W/P + D칸에 현재 칸 1을 더한다.
// 증거 pre 스냅샷을 더 길게 잡으면 그만큼 키운다 (3_ §7.1 '버퍼 크기 = max(W/P + D + 1, pre_slots)')
namespace {
// ⌈a / b⌉ — a + b − 1이 넘치지 않게 나눗셈 먼저 (11/05 W-31: noreply_timeout_ms가 INT64 끝에 가까워도 안전)
uint64_t ceil_div(int64_t a, int64_t b) { return static_cast<uint64_t>(a / b) + (a % b != 0 ? 1 : 0); }
}  // namespace

std::size_t buffer_slots(int64_t window_ms, int64_t period_ms, int64_t noreply_timeout_ms,
                         std::optional<std::size_t> pre_slots) {
  const std::size_t w = static_cast<std::size_t>(ceil_div(window_ms, period_ms));
  const std::size_t d = static_cast<std::size_t>(ceil_div(noreply_timeout_ms, period_ms));
  const std::size_t min_slots = w + d + 1;
  return pre_slots ? std::max(min_slots, *pre_slots) : min_slots;
}

// 상한 확인 (2_ §3 — 11/05 W-31, 이슈 #92): W/P·D를 각각 상한과 먼저 비교해 합이 넘치지 않게 한다
bool slots_within(int64_t window_ms, int64_t period_ms, int64_t noreply_timeout_ms, std::optional<std::size_t> pre_slots,
                  std::size_t max_slots) {
  const uint64_t w = ceil_div(window_ms, period_ms);
  const uint64_t d = ceil_div(noreply_timeout_ms, period_ms);
  if (w > max_slots || d > max_slots || w + d + 1 > max_slots) return false;
  return !pre_slots || *pre_slots <= max_slots;
}

// ---- CellSeries ----

CellSeries::CellSeries(std::size_t capacity) : buf_(std::max<std::size_t>(capacity, 1)) {}

// 링버퍼에 칸 추가 — 가득 차면 가장 오래된 칸을 덮어쓴다(KPM 파기, 3_ §7.1).
// 증거는 이 칸을 복사해 가므로 덮어써도 이미 낸 증거는 바뀌지 않는다
void CellSeries::push(Slot slot) {
  last_t_end_ = slot.kpm.t_end_ms;
  if (size_ < buf_.size()) {
    buf_[(head_ + size_) % buf_.size()] = std::move(slot);
    ++size_;
  } else {
    buf_[head_] = std::move(slot);
    head_ = (head_ + 1) % buf_.size();
  }
}

void CellSeries::drop_before(int64_t t) {
  while (size_ > 0 && at(0).kpm.t_end_ms <= t) {
    head_ = (head_ + 1) % buf_.size();
    --size_;
  }
}

// 윈도우 합계 (3_ §3). 빠진 칸을 자리표시로 채우지 않고, 윈도우를 덮은 시간의 합이
// 윈도우 길이와 같은지로 완전성을 본다 — 끊김·버퍼 밖·값 없음이면 nullopt(룰이 보류, 3_ §8)
std::optional<int64_t> CellSeries::window_sum(int64_t from, int64_t to, CountGetter get) const {
  if (to <= from) return 0;
  int64_t sum = 0;
  int64_t covered = 0;
  for (std::size_t i = 0; i < size_; ++i) {
    const Kpm2& k = at(i).kpm;
    if (k.t_end_ms <= from || k.t_start_ms >= to) continue;
    if (k.t_start_ms < from || k.t_end_ms > to) return std::nullopt;  // 경계에 일부만 걸림 (결정 D8)
    Count v = get(k);
    if (!v) return std::nullopt;
    sum += *v;
    covered += k.t_end_ms - k.t_start_ms;
  }
  if (covered != to - from) return std::nullopt;
  return sum;
}

std::optional<std::pair<int64_t, int64_t>> CellSeries::seq_range(int64_t from, int64_t to) const {
  std::optional<std::pair<int64_t, int64_t>> r;
  for (std::size_t i = 0; i < size_; ++i) {
    const Slot& s = at(i);
    if (s.kpm.t_start_ms < from || s.kpm.t_end_ms > to) continue;
    if (!r) r = std::make_pair(s.seq, s.seq);
    r->second = s.seq;
  }
  return r;
}

// ---- Series ----

namespace {

Diag diag(DiagKind kind, std::optional<int64_t> cell, std::optional<int64_t> seq, std::string msg) {
  return Diag{kind, cell, seq, std::move(msg)};
}

// hello 파라미터 비교 (2_ §3). cells는 순서와 무관하게 비교한다
bool same_params(const Hello& a, const Hello& b) {
  if (a.period_ms != b.period_ms || a.noreply_timeout_ms != b.noreply_timeout_ms ||
      a.si_sample_ms != b.si_sample_ms)
    return false;
  auto by_id = [](const CellInfo& x, const CellInfo& y) { return x.cell_id < y.cell_id; };
  std::vector<CellInfo> ca = a.cells, cb = b.cells;
  std::sort(ca.begin(), ca.end(), by_id);
  std::sort(cb.begin(), cb.end(), by_id);
  return ca == cb;
}

}  // namespace

Series::Series(SeriesConfig cfg) : cfg_(std::move(cfg)), h_hold_eff_(cfg_.h_hold_ms) {}

const CellSeries* Series::cell(int64_t cell_id) const {
  auto it = cells_.find(cell_id);
  return it == cells_.end() ? nullptr : &it->second;
}

std::vector<int64_t> Series::cell_ids() const {
  std::vector<int64_t> ids;
  for (const auto& [id, _] : cells_) ids.push_back(id);
  return ids;
}

// 파싱 결과 분기. 형식 오류·ver 불일치는 버리고 진단만 남긴다 (2_ §1·§3, 1_ FR-6).
// 모르는 type은 쓰지 않지만 같은 session이면 seq는 이어서 본다 — seq는 모든 유형이 함께 쓰는 번호라서 (2_ §2).
// ue_evt·f1_evt는 series가 저장하지 않고 Passed로 넘긴다(14_ §7). hello 전·다른 session·seq 역행이면 kpm2처럼 버린다 (2_ §6.5)
FeedResult Series::feed(const ParseResult& r) {
  FeedResult out;
  const std::optional<int64_t> seq = r.common ? std::optional<int64_t>(r.common->seq) : std::nullopt;
  switch (r.status) {
    case ParseStatus::LineTooLong:
      out.diags.push_back(diag(DiagKind::LineTooLong, std::nullopt, seq, r.error));
      return out;
    case ParseStatus::FormatError:
      out.diags.push_back(diag(DiagKind::FormatError, std::nullopt, seq, r.error));
      return out;
    case ParseStatus::UnsupportedVersion:
      out.diags.push_back(diag(DiagKind::UnsupportedVersion, std::nullopt, seq, r.error));
      // ver가 달라도 같은 session의 줄이면 seq 번호열은 이어서 본다 — 모르는 type·ue_evt와 같은 규칙.
      // 소비하지 않으면 바로 다음 줄에서 seq 건너뜀 로그가 잘못 난다 (2_ §2, 10/27 이슈 #13 W-1)
      if (active() && r.common && r.common->session == session_) check_seq(r.common->seq, out);
      return out;
    case ParseStatus::UnknownType:
    case ParseStatus::Ok:
      break;
  }

  for (const auto& w : r.warnings) out.diags.push_back(diag(DiagKind::Warning, std::nullopt, seq, w));

  if (const auto* h = std::get_if<Hello>(&r.msg)) {
    FeedResult hr = on_hello(*r.common, *h);
    hr.diags.insert(hr.diags.begin(), out.diags.begin(), out.diags.end());
    return hr;
  }
  if (const auto* k = std::get_if<Kpm2>(&r.msg)) {
    FeedResult kr = on_kpm2(*r.common, *k);
    kr.diags.insert(kr.diags.begin(), out.diags.begin(), out.diags.end());
    return kr;
  }

  const auto* ue = std::get_if<UeEvt>(&r.msg);
  if (!ue && !std::holds_alternative<F1Evt>(r.msg)) {
    // 모르는 type
    out.outcome = FeedOutcome::Ignored;
    if (active() && r.common->session == session_) check_seq(r.common->seq, out);
    return out;
  }
  // ue_evt·f1_evt — series는 kpm2만 저장한다. 상태는 UE 상태표 몫 (14_ §7)
  const std::optional<int64_t> cell = ue ? std::optional<int64_t>(ue->cell_id) : std::nullopt;
  if (!active()) {
    out.diags.push_back(diag(DiagKind::EvtBeforeHello, cell, seq, r.common->type + " before hello, dropped"));
    return out;
  }
  if (r.common->session != session_) {
    out.diags.push_back(diag(DiagKind::ForeignSession, cell, seq,
                             r.common->type + " session " + r.common->session + " != " + session_ + ", dropped"));
    return out;
  }
  if (!check_seq(r.common->seq, out)) return out;
  out.outcome = FeedOutcome::Passed;
  return out;
}

bool Series::check_seq(int64_t seq, FeedResult& out) {
  if (last_seq_ && seq <= *last_seq_) {
    out.diags.push_back(diag(DiagKind::SeqRegress, std::nullopt, seq,
                             "seq " + std::to_string(seq) + " <= last " + std::to_string(*last_seq_)));
    return false;
  }
  if (last_seq_ && seq > *last_seq_ + 1) {
    out.diags.push_back(diag(DiagKind::SeqGap, std::nullopt, seq,
                             "seq skipped " + std::to_string(seq - *last_seq_ - 1) + " after " +
                                 std::to_string(*last_seq_)));
  }
  last_seq_ = seq;
  return true;
}

// 버퍼 칸 수 상한 (2_ §3, 3_ §3 — 11/05 W-31, 이슈 #92): W/P + D + 1(pre_slots 포함)이 max_slots를 넘으면 hello를 버린다 —
// 거대한 noreply_timeout_ms 한 줄이 벡터 할당(bad_alloc)으로 엔진을 멈추지 않게. 세션 상태는 그대로다(FR-6 — 형식 오류는 버리고 진단)
bool Series::accept_hello(const Common& c, const Hello& h, FeedResult& out) const {
  if (slots_within(cfg_.window_ms, h.period_ms, h.noreply_timeout_ms, cfg_.pre_slots, cfg_.max_slots)) return true;
  out.outcome = FeedOutcome::Dropped;
  out.diags.push_back(diag(DiagKind::HelloRejected, std::nullopt, c.seq,
                           "hello dropped: buffer slots for window_ms " + std::to_string(cfg_.window_ms) + " period_ms " +
                               std::to_string(h.period_ms) + " noreply_timeout_ms " + std::to_string(h.noreply_timeout_ms) +
                               (cfg_.pre_slots ? " pre_slots " + std::to_string(*cfg_.pre_slots) : std::string()) +
                               " exceed max_slots " + std::to_string(cfg_.max_slots)));
  return false;
}

void Series::start_session(const Common& c, const Hello& h, FeedResult& out) {
  session_ = c.session;
  hello_ = h;
  last_seq_ = c.seq;
  cells_.clear();
  health_.clear();
  capacity_ = buffer_slots(cfg_.window_ms, h.period_ms, h.noreply_timeout_ms, cfg_.pre_slots);  // accept_hello 뒤라 상한 안
  const int64_t P = h.period_ms;
  // W는 P의 배수여야 한다 (3_ §3 — 11/05 W-31): 아니면 모든 창이 칸 경계에 일부만 걸려 늘 보류된다(판정 0·진단 0이었음).
  // 창을 올림 정렬하지 않고(명세의 W를 코드가 바꾸지 않게) 진단 1회를 내고 이 세션 동안 판정하지 않는다(assess)
  misaligned_ = cfg_.window_ms % P != 0;
  if (misaligned_)
    out.diags.push_back(diag(DiagKind::WindowMisaligned, std::nullopt, c.seq,
                             "window_ms " + std::to_string(cfg_.window_ms) + " is not a multiple of period_ms " +
                                 std::to_string(P) + ": L3-01-V inactive for this session"));
  // h_hold 하한 (3_ §8 — 11/05 W-31): 보류 길이는 첫 보류 칸부터 재는데 창이 차는 데 (W/P + D − 1)칸이 걸리므로, H_hold가
  // 그 채움 시간 이하면 버퍼를 비우고 다시 채우다 또 넘겨 input_lost가 순환한다 → 채움 시간 + P로 올려 쓰고 경고 1회
  const int64_t fill_ms = (cfg_.window_ms / P + static_cast<int64_t>(ceil_div(h.noreply_timeout_ms, P)) - 1) * P;
  h_hold_eff_ = cfg_.h_hold_ms;
  if (h_hold_eff_ <= fill_ms) {
    h_hold_eff_ = fill_ms + P;
    out.diags.push_back(diag(DiagKind::Warning, std::nullopt, c.seq,
                             "h_hold_ms " + std::to_string(cfg_.h_hold_ms) + " <= window fill " + std::to_string(fill_ms) +
                                 " ms: using " + std::to_string(h_hold_eff_)));
  }
}

// hello 처리 규칙 (2_ §3, 3_ §8):
//  - 첫 hello → 시작
//  - 다른 session → 초기화 (분석 엔진 재시작)
//  - 같은 session → 파라미터가 같으면 상태 유지(재연결), 다르면 session 변경처럼 초기화
FeedResult Series::on_hello(const Common& c, const Hello& h) {
  FeedResult out;
  if (!active()) {
    if (!accept_hello(c, h, out)) return out;
    out.outcome = FeedOutcome::SessionStarted;
    out.diags.push_back(diag(DiagKind::SessionStarted, std::nullopt, c.seq, "session " + c.session));
    start_session(c, h, out);
    return out;
  }
  if (c.session != session_) {
    if (!accept_hello(c, h, out)) return out;  // 새 세션 hello가 상한을 넘으면 옛 세션 유지 (11/05 W-31)
    const std::string old = session_;
    out.outcome = FeedOutcome::SessionReset;
    out.diags.push_back(diag(DiagKind::SessionReset, std::nullopt, c.seq,
                             "session changed " + old + " -> " + c.session));
    start_session(c, h, out);
    return out;
  }
  if (!check_seq(c.seq, out)) {
    out.outcome = FeedOutcome::Dropped;
    return out;
  }
  if (same_params(*hello_, h)) {
    hello_ = h;  // producer 등 판정과 무관한 필드는 새 값으로
    out.outcome = FeedOutcome::SessionResumed;
    out.diags.push_back(diag(DiagKind::SessionResumed, std::nullopt, c.seq, "hello again, same params"));
    return out;
  }
  if (!accept_hello(c, h, out)) return out;  // 파라미터가 바뀐 hello가 상한을 넘으면 옛 상태 유지 (11/05 W-31)
  out.outcome = FeedOutcome::SessionReset;
  out.diags.push_back(diag(DiagKind::SessionReset, std::nullopt, c.seq, "hello params changed"));
  start_session(c, h, out);
  return out;
}

// kpm2 처리: hello·session 확인 → seq → 셀 찾기/만들기 → 셀별 시각 연속성 → 저장.
// 셀별 유실은 seq가 아니라 t_start_ms 연속성으로 판단한다 (2_ §4.1, 3_ §8)
FeedResult Series::on_kpm2(const Common& c, const Kpm2& k) {
  FeedResult out;
  if (!active()) {
    out.diags.push_back(diag(DiagKind::KpmBeforeHello, k.cell_id, c.seq, "kpm2 before hello, dropped"));
    return out;
  }
  if (c.session != session_) {  // 결정 D4: 초기화는 새 session의 hello가 올 때만
    out.diags.push_back(diag(DiagKind::ForeignSession, k.cell_id, c.seq,
                             "kpm2 session " + c.session + " != " + session_ + ", dropped"));
    return out;
  }
  if (!check_seq(c.seq, out)) return out;

  // 셀 찾기. hello에 없는 셀도 받되 한 번 경고하고, 셀 수 상한을 넘으면 버린다 (결정 D7)
  auto it = cells_.find(k.cell_id);
  if (it == cells_.end()) {
    if (cells_.size() >= cfg_.max_cells) {
      out.diags.push_back(diag(DiagKind::CellLimit, k.cell_id, c.seq,
                               "cell limit " + std::to_string(cfg_.max_cells) + " reached, dropped"));
      return out;
    }
    const auto& listed = hello_->cells;
    bool known = std::any_of(listed.begin(), listed.end(),
                             [&](const CellInfo& ci) { return ci.cell_id == k.cell_id; });
    if (!listed.empty() && !known)
      out.diags.push_back(diag(DiagKind::CellUnknown, k.cell_id, c.seq, "cell not listed in hello"));
    it = cells_.emplace(k.cell_id, CellSeries(capacity_)).first;
  }
  CellSeries& cs = it->second;

  // 시각 연속성 (2_ §4.1): 같은 셀의 다음 t_start = 이번 t_end. 겹침·역행은 버리고(결정 D6), 끊김은 GapEvent로
  if (auto last = cs.last_t_end()) {
    if (k.t_start_ms < *last) {
      out.diags.push_back(diag(DiagKind::CellOverlap, k.cell_id, c.seq,
                               "t_start " + std::to_string(k.t_start_ms) + " < last t_end " +
                                   std::to_string(*last) + ", dropped"));
      return out;
    }
    if (k.t_start_ms > *last) {
      GapEvent g;
      g.cell_id = k.cell_id;
      g.t_from = *last;
      g.t_to = k.t_start_ms;
      g.seq_before = cs.size() > 0 ? cs.back().seq : 0;
      g.seq_after = c.seq;
      out.gap = g;
      out.diags.push_back(diag(DiagKind::CellGap, k.cell_id, c.seq,
                               "gap [" + std::to_string(g.t_from) + ", " + std::to_string(g.t_to) + ")"));
    }
  }
  if (k.t_end_ms - k.t_start_ms != hello_->period_ms) {
    out.diags.push_back(diag(DiagKind::PeriodMismatch, k.cell_id, c.seq,
                             "interval " + std::to_string(k.t_end_ms - k.t_start_ms) + " ms != period " +
                                 std::to_string(hello_->period_ms) + " ms"));
  }

  cs.push(Slot{c.seq, k});
  out.outcome = FeedOutcome::Stored;
  out.cell_id = k.cell_id;
  assess(k, cs, health_[k.cell_id], out);
  return out;
}

namespace {
Count get_att(const Kpm2& k) { return k.conn_estab_att.total; }
Count get_succ(const Kpm2& k) { return k.conn_estab_succ.total; }
Count get_noreply(const Kpm2& k) { return k.fail_no_reply; }
}  // namespace

// 저장된 칸의 입력 건전성 (Q-46 — 룰에서 옮겨 옴, 3_ §3·§8):
//  1) 구간 끊김이 있으면 보류가 그 끊김의 시작부터 시작된 것으로 본다 (결정 E9)
//  2) 필수 키 A·S 누락 streak — 연속 missing_key_slots칸을 넘으면 비활성 진단, 다시 들어오면 재개 진단
//  3) 표준 윈도우 합계 — A는 T_nr(= D칸)만큼 과거, F·A′·S′는 시차 없음 (3_ §3)
//  4) 보류·모드 판단 (3_ §4.1 결정 E1 — 11/05 R4로 룰의 decide_mode를 여기로): A′·S′ 불완전, 또는 F 완전인데 A 불완전이면 보류.
//     판정하면 F 윈도우가 다 있을 때 normal, F가 불완전(null)하면 dl_missing(3_ §4.1).
//     보류가 H_hold보다 길면 input_lost — 이 칸 이전 버퍼를 비우고 보류 시작을 다시 잰다. 기준선은 룰이 유지
void Series::assess(const Kpm2& k, CellSeries& cs, InputHealth& h, FeedResult& out) {
  const int64_t t = k.t_end_ms;
  const int64_t P = hello_->period_ms;
  const int64_t D = (hello_->noreply_timeout_ms + P - 1) / P;
  const int64_t W = cfg_.window_ms;

  if (out.gap) h.hold_start = h.hold_start ? std::min(*h.hold_start, out.gap->t_from) : out.gap->t_from;

  // W가 P의 배수가 아닌 세션 (3_ §3 — 11/05 W-31): 창 합이 늘 불완전하므로 보류만 하고 H_hold·input_lost는 재지 않는다
  if (misaligned_) {
    out.hold = true;
    return;
  }

  if (!get_att(k) || !get_succ(k)) {
    if (++h.missing_streak > cfg_.missing_key_slots && !h.inactive) {
      h.inactive = true;
      out.diags.push_back(diag(DiagKind::RuleInactive, k.cell_id, std::nullopt,
                               "required keys A/S missing > " + std::to_string(cfg_.missing_key_slots) + " slots"));
    }
  } else {
    if (h.inactive) out.diags.push_back(diag(DiagKind::RuleResumed, k.cell_id, std::nullopt, "required keys A/S resumed"));
    h.inactive = false;
    h.missing_streak = 0;
  }

  out.sums.a_from = t - W - D * P;
  out.sums.a_to = t - D * P;
  out.sums.f_from = t - W;
  out.sums.f_to = t;
  out.sums.a_w = cs.window_sum(out.sums.a_from, out.sums.a_to, get_att);
  out.sums.f_w = cs.window_sum(out.sums.f_from, out.sums.f_to, get_noreply);
  out.sums.a2_w = cs.window_sum(out.sums.f_from, out.sums.f_to, get_att);
  out.sums.s2_w = cs.window_sum(out.sums.f_from, out.sums.f_to, get_succ);

  const bool judgeable = out.sums.a2_w && out.sums.s2_w && (!out.sums.f_w || out.sums.a_w);
  if (judgeable) {
    out.mode = out.sums.f_w ? AlertMode::Normal : AlertMode::DlMissing;
    h.hold_start.reset();
    return;
  }
  out.hold = true;
  if (!h.hold_start) h.hold_start = k.t_start_ms;
  if (k.t_start_ms - *h.hold_start > h_hold_eff_) {
    out.input_lost = true;
    // input_lost 진단 (3_ §8 — 11/05 W-31): 경보가 없을 때는 아무 줄도 남지 않았다
    out.diags.push_back(diag(DiagKind::InputLost, k.cell_id, std::nullopt,
                             "hold " + std::to_string(k.t_start_ms - *h.hold_start) + " ms > h_hold " +
                                 std::to_string(h_hold_eff_) + " ms: buffer before " + std::to_string(k.t_start_ms) +
                                 " dropped"));
    cs.drop_before(k.t_start_ms);
    h.hold_start = k.t_start_ms;
  }
}

}  // namespace detect
