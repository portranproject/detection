#include "detect/series.h"

#include <algorithm>
#include <utility>

namespace detect {

// 버퍼 최소 크기 (3_ §3): A 윈도우가 T_nr만큼 과거로 밀리므로 W/P + D칸에 현재 칸 1을 더한다.
// 증거 pre 스냅샷을 더 길게 잡으면 그만큼 키운다 (3_ §7.1 '버퍼 크기 = max(W/P + D + 1, pre_slots)')
std::size_t buffer_slots(int64_t window_ms, int64_t period_ms, int64_t noreply_timeout_ms,
                         std::optional<std::size_t> pre_slots) {
  auto ceil_div = [](int64_t a, int64_t b) { return (a + b - 1) / b; };
  const std::size_t w = static_cast<std::size_t>(ceil_div(window_ms, period_ms));
  const std::size_t d = static_cast<std::size_t>(ceil_div(noreply_timeout_ms, period_ms));
  const std::size_t min_slots = w + d + 1;
  return pre_slots ? std::max(min_slots, *pre_slots) : min_slots;
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

Series::Series(SeriesConfig cfg) : cfg_(std::move(cfg)) {}

const CellSeries* Series::cell(int64_t cell_id) const {
  auto it = cells_.find(cell_id);
  return it == cells_.end() ? nullptr : &it->second;
}

CellSeries* Series::cell(int64_t cell_id) {
  auto it = cells_.find(cell_id);
  return it == cells_.end() ? nullptr : &it->second;
}

std::vector<int64_t> Series::cell_ids() const {
  std::vector<int64_t> ids;
  for (const auto& [id, _] : cells_) ids.push_back(id);
  return ids;
}

// 파싱 결과 분기. 형식 오류·ver 불일치는 버리고 진단만 남긴다 (2_ §1·§3, 1_ FR-6).
// 모르는 type·ue_evt는 쓰지 않지만 같은 session이면 seq는 이어서 본다 — seq는 모든 유형이 함께 쓰는 번호라서 (2_ §2)
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

  // 모르는 type, ue_evt (2단계 룰 명세 전이라 본문은 쓰지 않음)
  out.outcome = FeedOutcome::Ignored;
  if (active() && r.common->session == session_) check_seq(r.common->seq, out);
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

void Series::start_session(const Common& c, const Hello& h) {
  session_ = c.session;
  hello_ = h;
  last_seq_ = c.seq;
  cells_.clear();
  capacity_ = buffer_slots(cfg_.window_ms, h.period_ms, h.noreply_timeout_ms, cfg_.pre_slots);
}

// hello 처리 규칙 (2_ §3, 3_ §8):
//  - 첫 hello → 시작
//  - 다른 session → 초기화 (분석 엔진 재시작)
//  - 같은 session → 파라미터가 같으면 상태 유지(재연결), 다르면 session 변경처럼 초기화
FeedResult Series::on_hello(const Common& c, const Hello& h) {
  FeedResult out;
  if (!active()) {
    start_session(c, h);
    out.outcome = FeedOutcome::SessionStarted;
    out.diags.push_back(diag(DiagKind::SessionStarted, std::nullopt, c.seq, "session " + c.session));
    return out;
  }
  if (c.session != session_) {
    const std::string old = session_;
    start_session(c, h);
    out.outcome = FeedOutcome::SessionReset;
    out.diags.push_back(diag(DiagKind::SessionReset, std::nullopt, c.seq,
                             "session changed " + old + " -> " + c.session));
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
  start_session(c, h);
  out.outcome = FeedOutcome::SessionReset;
  out.diags.push_back(diag(DiagKind::SessionReset, std::nullopt, c.seq, "hello params changed"));
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
  return out;
}

}  // namespace detect
