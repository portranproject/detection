#pragma once
// 셀별 시계열 버퍼와 세션 상태 (2_ §2·§3·§4.1, 3_ §3·§7.1·§8).
// 셀별 입력 건전성 — 표준 윈도우 합계, 보류 판단, H_hold(input_lost)와 버퍼 비움, 필수 키 누락 streak — 도
// 여기서 계산해 FeedResult로 넘긴다(Q-46, 4_ §2). 룰은 이 결과를 읽기만 하고 판정·경보만 한다.

#include "detect/alert.h"
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

// 버퍼 칸 수 = max(W/P + D + 1, pre_slots), D = ⌈T_nr / P⌉ (3_ §3·§7.1). 부르기 전에 slots_within으로 상한을 확인한다
std::size_t buffer_slots(int64_t window_ms, int64_t period_ms, int64_t noreply_timeout_ms,
                         std::optional<std::size_t> pre_slots = std::nullopt);
// 버퍼 칸 수가 max_slots 안인가 (2_ §3, 3_ §3 — 11/05 W-31, 이슈 #92). 넘침 없이 센다 — 거대 T_nr이 와도 안전
bool slots_within(int64_t window_ms, int64_t period_ms, int64_t noreply_timeout_ms, std::optional<std::size_t> pre_slots,
                  std::size_t max_slots);

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
  std::size_t max_slots = 1024;           // 셀 버퍼 칸 수 상한 (2_ §3, 4_ §1.2 — 11/05 W-31). 넘는 hello는 버린다
};

// 셀 구간 끊김 (2_ §4.1, 3_ §8). 경보 중이면 룰이 gap 레코드로 낸다 (3_ §7.1)
struct GapEvent {
  int64_t cell_id = 0;
  int64_t t_from = 0;      // 빠진 구간 [t_from, t_to)
  int64_t t_to = 0;
  int64_t seq_before = 0;  // 참고용 seq 범위
  int64_t seq_after = 0;
};

// 표준 윈도우 합계 (3_ §3): A 윈도우는 T_nr(= D칸)만큼 과거, F·A′·S′는 시차 없음. nullopt = 불완전.
// 창 구간도 함께 준다 (11/05 26_ R4, 이슈 #98) — 룰이 D·P·W를 다시 계산하지 않고 증거 seq 범위(3_ §7.1)에 쓴다
struct WindowSums {
  std::optional<int64_t> a_w;   // [t−W−T_nr, t−T_nr)의 A 합 — ratio의 분모
  std::optional<int64_t> f_w;   // [t−W, t)의 F 합
  std::optional<int64_t> a2_w;  // [t−W, t)의 A 합 (A′_w)
  std::optional<int64_t> s2_w;  // [t−W, t)의 S 합 (S′_w)
  int64_t a_from = 0;           // A 윈도우 [a_from, a_to) = [t−W−D·P, t−D·P)
  int64_t a_to = 0;
  int64_t f_from = 0;           // F·A′·S′ 윈도우 [f_from, f_to) = [t−W, t)
  int64_t f_to = 0;
};

enum class FeedOutcome {
  Stored,          // kpm2를 버퍼에 넣음
  Dropped,         // 버림 (형식 오류·ver·hello 전·다른 session·seq 역행·겹침·셀 상한)
  Ignored,         // 받았지만 쓰지 않음 (모르는 type)
  Passed,          // ue_evt·f1_evt — series는 저장하지 않고 Engine이 UE 상태표로 넘긴다 (14_ §7)
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
  // 판정 모드 (3_ §4.1 결정 E1 — 11/05 26_ R4, 이슈 #98: 룰의 decide_mode를 여기로): 보류가 아니면 F 윈도우가 다 있으면 normal,
  // F가 불완전(null)한데 같은 구간 A′·S′는 다 있으면 dl_missing. 보류면 nullopt
  std::optional<AlertMode> mode;
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
  // hello·설정 경계 (2_ §3, 3_ §3 — 11/05 W-31): 버퍼 칸 수가 상한 안이면 true, 아니면 진단을 넣고 Dropped (세션 유지)
  bool accept_hello(const Common& c, const Hello& h, FeedResult& out) const;
  FeedResult on_kpm2(const Common& c, const Kpm2& k);
  // 저장된 칸의 입력 건전성 평가: 누락 streak → 표준 윈도우 합계 → 보류·모드·H_hold (3_ §3·§4.1·§8)
  void assess(const Kpm2& k, CellSeries& cs, InputHealth& h, FeedResult& out);
  // 세션 시작 — 버퍼 크기, W % P 정렬(3_ §3), h_hold 하한(3_ §8)을 정하고 진단을 out에 넣는다 (11/05 W-31)
  void start_session(const Common& c, const Hello& h, FeedResult& out);
  // seq 검사 (2_ §2). 역행·중복이면 false(버림, 결정 D5), 건너뜀은 진단만
  bool check_seq(int64_t seq, FeedResult& out);

  SeriesConfig cfg_;
  std::string session_;
  std::optional<Hello> hello_;
  std::optional<int64_t> last_seq_;
  std::size_t capacity_ = 0;
  bool misaligned_ = false;    // window_ms가 period_ms의 배수가 아님 — 이 세션은 판정하지 않는다 (3_ §3, 11/05 W-31)
  int64_t h_hold_eff_ = 0;     // 실제 쓰는 H_hold — 창 채움 시간 이하면 채움 시간 + P로 올린 값 (3_ §8, 11/05 W-31)
  std::map<int64_t, CellSeries> cells_;
  std::map<int64_t, InputHealth> health_;
};

}  // namespace detect
