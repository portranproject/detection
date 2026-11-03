#pragma once
// 4단계 '있는 것을 본 판정'의 공통 바탕 (21_ §1.1·§1.3, M9 이슈 #70). 4단계 룰은 줄 하나(또는 연결이 닫힐 때) 그 자리에서
// 성립하는 걸림을 적고, RAISE·UPDATE는 그 걸림이 든 창의 kpm2(on_cell_tick)에서 낸다 — L3-21 갈래 ②와 같은 방식(15_ §5.3).
// 셀 단위 성립은 가장 최근 걸림 t 기준 (t − W, t] 안 걸린 연결 수 ≥ N이다(UE 하나로 RAISE하는 룰은 N = 1). 해제는 경보에 실린
// 마지막 걸림 뒤 clear_quiet_ms(직전 clear_quiet_ms 동안 밀어내기가 있으면 보류 — Q-56), END는 공통이다. '없음'을 기다리지 않으므로
// 보류·불확실 경보가 없다(§1.1). 걸린 뒤 같은 연결에서 바뀌는 값(반복·재인증 관측 등)은 UE 칸에 다시 싣지 않고 경보 values의
// 누적 수로 낸다 — update에는 새로 걸린 UE만 실리기 때문이다(§1.1, 14_ §8.3, 1_ §6 11/04)

#include "detect/alert.h"
#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_rule.h"
#include "detect/ue_table.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace detect {

class HitWindow {
 public:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)
  // 경보 이벤트를 낸 직후 룰이 values·params·cond·candidates·로그 필드를 채우는 콜백 — out[from]부터가 새 이벤트
  using Decorate = std::function<void(std::size_t from)>;

  // rule = 룰 ID, window_ms·n = 셀 창 W·문턱 N, clear_quiet_ms = 해제 시간. 경보는 kind anomaly·stage 4 (21_ §1)
  HitWindow(std::string rule, AlertConfig alert, int64_t window_ms, int64_t n, int64_t clear_quiet_ms);

  // 걸림 (§1.1): 그 연결이 이미 걸렸으면 아무것도 하지 않고 false — 연결당 한 번(룰은 add로 누적 수만 늘린다). u의 cond·
  // t_hit·values는 룰이 걸릴 때 값으로 채운다. 식별·uncertain은 kpm2에서 그때 상태표 항목으로 다시 채운다 — 같은 창의 로스 표시는
  // 그 창 kpm2가 와서야 붙기 때문이다(14_ §7 kpm2 ②)
  bool hit(const UeId& id, AlertUe u);
  bool hit_before(const UeId& id) const;  // 열린 연결이 이미 걸렸나
  // 걸린 연결의 누적 수 (§1.1): 그 연결이 열린 경보에 실렸으면 바로 경보 값에, 아직 실리지 않았으면 걸림에 쌓아 두었다가
  // 실릴 때 함께 더한다
  void add(const UeId& id, const std::string& name, int64_t n = 1);
  // 연결이 닫힘 — 아직 kpm2를 거치지 않은 걸림은 마지막 상태로 식별·uncertain을 채우고, 연결 기록을 지운다
  void on_close(const UeState& last);

  // 셀 kpm2마다 (§1.1): input_lost면 END, 이번 걸림을 창에 넣어 성립을 보고 RAISE(창 안 걸림 전부)·UPDATE(새 걸림), 모아 둔
  // UPDATE, 해제. 이벤트를 낼 때마다 fn(from)을 부른다
  void tick(int64_t cell, int64_t t, bool input_lost, const UeRuleCtx& ctx, std::vector<AlertEvent>& out,
            const Decorate& fn);
  void end_all(const std::string& reason, std::vector<AlertEvent>& out) { book_.end_all(reason, out); }
  void reset();  // 걸림·연결·셀 기록을 모두 버린다 (session_reset)

  // decorate가 읽는 값
  int64_t window(int64_t cell) const;                                // 가장 최근 걸림 기준 창 안 걸린 연결 수
  int64_t count(int64_t cell, const std::string& name) const;       // 열린 경보에 실린 연결의 누적 수
  int64_t evicted(int64_t cell, bool raise, int64_t t);              // raise면 직전 clear_quiet_ms 이동 창, 아니면 경보가 열린 뒤 누적
  bool open(int64_t cell) const { return book_.open(cell); }

 private:
  struct Hit {
    UeId id;
    AlertUe u;
    std::map<std::string, int64_t> acc;  // 경보에 실리기 전에 쌓인 누적 수
  };
  struct Cell {
    std::vector<Hit> fresh;                     // 이번 kpm2 전에 적은 걸림
    std::deque<Hit> win;                        // 가장 최근 걸림 기준 (t − W, t] 안 걸림 (성립 전 포함)
    int64_t t_hit_last = 0;                     // 경보에 실린 마지막 걸림 시각 — CLEAR 기준 (21_ §3.5)
    std::map<std::string, int64_t> counts;      // 경보가 열린 뒤 누적 수
    int64_t evicted_seen = 0;                   // 상태표 셀별 누적 evicted 중 이미 적은 수
    int64_t evicted_open = 0;                   // 경보가 열린 뒤 밀어내기 수
    std::deque<int64_t> evict_times;            // 밀어내기 시각 (이동 창)
  };
  struct Conn {
    int64_t cell = 0;
    bool in_alert = false;  // 열린 경보에 실렸나 — 그 뒤 누적 수는 바로 경보 값에 더한다
  };

  void include(Cell& c, const Hit& h);
  void note_evictions(Cell& c, int64_t cell, int64_t t, const UeRuleCtx& ctx);
  int64_t evicted_window(Cell& c, int64_t now) const;

  int64_t window_ms_;
  int64_t n_;
  int64_t clear_quiet_ms_;
  UeAlertBook book_;
  std::map<int64_t, Cell> cells_;
  std::map<UeId, Conn> conns_;  // 걸린 열린 연결
};

}  // namespace detect
