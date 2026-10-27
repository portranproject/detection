#pragma once
// 셀별 시계열 버퍼와 세션 상태 (2_ §2·§3·§4.1, 3_ §3·§7.1·§8).
// 셀별 입력 건전성 — 표준 윈도우 합계, 보류 판단, H_hold(input_lost)와 버퍼 비움, 필수 키 누락 streak — 도
// 여기서 계산해 FeedResult로 넘긴다(Q-46, 4_ §2). 룰은 이 결과를 읽기만 하고 판정·경보만 한다.

#include "detect/diag.h"
#include "detect/message.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace detect {

// 버퍼 칸 수 = max(W/P + D + 1, pre_slots), D = ⌈T_nr / P⌉ (3_ §3·§7.1)
std::size_t buffer_slots(int64_t window_ms, int64_t period_ms, int64_t noreply_timeout_ms,
                         std::optional<std::size_t> pre_slots = std::nullopt);

// 버퍼 한 칸 = kpm2 한 줄. 파싱 값과 원본 줄(kpm.raw)을 함께 보관한다 (3_ §7.1)
struct Slot {
  int64_t seq = 0;
  Kpm2 kpm;
};

// kpm2에서 합계를 낼 값을 고르는 함수. nullopt를 돌려주면 그 칸은 '알 수 없음'
using CountGetter = Count (*)(const Kpm2&);

// 한 셀의 링버퍼. 칸은 시각 순이고 서로 겹치지 않는다(Series가 보장)
class CellSeries {
 public:
  explicit CellSeries(std::size_t capacity);

  std::size_t size() const { return size_; }
  std::size_t capacity() const { return buf_.size(); }
  // i = 0이 가장 오래된 칸
  const Slot& at(std::size_t i) const { return buf_[(head_ + i) % buf_.size()]; }
  const Slot& back() const { return at(size_ - 1); }
  std::optional<int64_t> last_t_end() const { return last_t_end_; }

  void push(Slot slot);
  // t_end_ms ≤ t인 칸을 지운다 (H_hold 초과 시 끊김 이전 버퍼를 비우는 용도, 3_ §8)
  void drop_before(int64_t t);

  // [from, to) 윈도우 합계 (3_ §3). 다음이면 nullopt(불완전 → 보류):
  //  - 윈도우를 칸이 빈틈없이 덮지 못함(구간 끊김, 버퍼보다 오래됨)
  //  - 칸이 윈도우 경계에 일부만 걸림(결정 D8)
  //  - 걸린 칸 중 하나라도 값이 없음(키 없음·null, 2_ §4.5)
  std::optional<int64_t> window_sum(int64_t from, int64_t to, CountGetter get) const;
  // [from, to) 안에 통째로 든 칸들의 [첫 seq, 마지막 seq]. 없으면 nullopt (3_ §7.1 a_seq·f_seq)
  std::optional<std::pair<int64_t, int64_t>> seq_range(int64_t from, int64_t to) const;

 private:
  std::vector<Slot> buf_;
  std::size_t head_ = 0;
  std::size_t size_ = 0;
  std::optional<int64_t> last_t_end_;  // 버퍼를 비워도 연속성 검사용으로 남긴다
};

struct SeriesConfig {
  int64_t window_ms = 1000;               // 3_ §4 W
  std::optional<std::size_t> pre_slots;   // 3_ §7.1 evidence.pre_slots (null이면 W/P + D + 1)
  std::size_t max_cells = 64;             // 결정 D7
  int64_t h_hold_ms = 10000;              // 3_ §8 H_hold — 보류가 이보다 길면 input_lost (결정 J5: L3-01-V 설정에서 복사)
  int missing_key_slots = 10;             // 3_ §8 필수 키 A·S 누락 연속 칸 상한
};

// 셀 구간 끊김 (2_ §4.1, 3_ §8). 경보 중이면 룰이 gap 레코드로 낸다 (3_ §7.1)
struct GapEvent {
  int64_t cell_id = 0;
  int64_t t_from = 0;      // 빠진 구간 [t_from, t_to)
  int64_t t_to = 0;
  int64_t seq_before = 0;  // 참고용 seq 범위
  int64_t seq_after = 0;
};

// 표준 윈도우 합계 (3_ §3): A 윈도우는 T_nr(= D칸)만큼 과거, F·A′·S′는 시차 없음. nullopt = 불완전
struct WindowSums {
  std::optional<int64_t> a_w;   // [t−W−T_nr, t−T_nr)의 A 합 — ratio의 분모
  std::optional<int64_t> f_w;   // [t−W, t)의 F 합
  std::optional<int64_t> a2_w;  // [t−W, t)의 A 합 (A′_w)
  std::optional<int64_t> s2_w;  // [t−W, t)의 S 합 (S′_w)
};

enum class FeedOutcome {
  Stored,          // kpm2를 버퍼에 넣음
  Dropped,         // 버림 (형식 오류·ver·hello 전·다른 session·seq 역행·겹침·셀 상한)
  Ignored,         // 받았지만 쓰지 않음 (모르는 type, ue_evt)
  SessionStarted,  // 첫 hello
  SessionReset,    // 이전 상태를 버리고 새로 시작 — 룰은 진행 중 경보를 end(session_reset)로 끝낸다 (3_ §7.1·§8)
  SessionResumed,  // 같은 session·같은 파라미터 hello — 상태 유지
};

struct FeedResult {
  FeedOutcome outcome = FeedOutcome::Dropped;
  std::vector<Diag> diags;
  std::optional<GapEvent> gap;    // Stored일 때 이 칸 앞에 끊김이 있었으면
  std::optional<int64_t> cell_id; // Stored일 때 넣은 셀
  // Stored일 때의 입력 건전성 (Q-46): 표준 윈도우 합계, 보류 여부, H_hold 초과
  WindowSums sums;
  bool hold = false;        // 이 칸은 판정하지 않는다 — 윈도우 불완전 (3_ §8). 룰은 M·K·t_last를 그대로 둔다
  bool input_lost = false;  // 보류가 H_hold를 넘어 이 칸 이전 버퍼를 비웠다 — 룰은 진행 중 경보를 END(input_lost)로 (3_ §8)
};

class Series {
 public:
  explicit Series(SeriesConfig cfg = {});

  // 파싱 결과 하나를 받아 세션·seq·셀 상태를 갱신한다
  FeedResult feed(const ParseResult& r);

  bool active() const { return hello_.has_value(); }
  const std::string& session() const { return session_; }
  const Hello* hello() const { return hello_ ? &*hello_ : nullptr; }
  std::size_t slot_capacity() const { return capacity_; }

  const CellSeries* cell(int64_t cell_id) const;
  std::vector<int64_t> cell_ids() const;

 private:
  // 셀별 입력 건전성 상태 (3_ §8) — 보류 시작 시각, 필수 키 누락 streak
  struct InputHealth {
    std::optional<int64_t> hold_start;  // 보류가 시작된 데이터 시각 (결정 E9)
    int missing_streak = 0;
    bool inactive = false;
  };

  FeedResult on_hello(const Common& c, const Hello& h);
  FeedResult on_kpm2(const Common& c, const Kpm2& k);
  // 저장된 칸의 입력 건전성 평가: 누락 streak → 표준 윈도우 합계 → 보류·H_hold (3_ §3·§8)
  void assess(const Kpm2& k, CellSeries& cs, InputHealth& h, FeedResult& out);
  void start_session(const Common& c, const Hello& h);
  // seq 검사 (2_ §2). 역행·중복이면 false(버림, 결정 D5), 건너뜀은 진단만
  bool check_seq(int64_t seq, FeedResult& out);

  SeriesConfig cfg_;
  std::string session_;
  std::optional<Hello> hello_;
  std::optional<int64_t> last_seq_;
  std::size_t capacity_ = 0;
  std::map<int64_t, CellSeries> cells_;
  std::map<int64_t, InputHealth> health_;
};

}  // namespace detect
