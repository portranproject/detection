#pragma once
// 2·3단계 룰이 같은 모양으로 갖던 두 가지를 한 곳에 (26_ §3.4 R1, 이슈 #96 — 11/05):
//  - EvictWindow: 셀별 상태표 밀어내기 창 (14_ §6.3, 15_ §2.5·§4.5·§5.5 — Q-56 해결, 이슈 #44; 창 밖 자르기는 11/05 W-32).
//    raise의 values.evicted(직전 clear_quiet_ms 이동 창)·update의 values.evicted(경보가 열린 뒤 누적)·해제 보류("조용함" 아님)의 근거.
//    4단계 HitWindow도 이것을 쓴다
//  - HeldBook: 불확실 경보 묶음 (14_ §6.2 — Q-58 ② 해결, 이슈 #48). 보류 시각 목록(raise의 values.held), 공격 경보가 열린 뒤 보류 수
//    (update의 values.held), 창 안 보류 UE 수 H_W ≥ N이면 kind anomaly RAISE, 그 뒤 보류는 UPDATE로 모음, 마지막 보류 뒤 clear_quiet_ms면
//    CLEAR, 공격 RAISE 직전 CLEAR(14_ §8.2), END. 룰은 창·문턱·raise의 params·로그 필드만 넘긴다 — L3-20·L3-01-O·L3-21(2단계)·
//    L3-24·L3-14·L3-06(3단계). 이동 전 룰마다 60~90줄이 같은 코드였다(25_ §4, 26_ §3.4). (11/15) L3-01-O·L3-21은 문턱이 셀마다 달라
//    (15_ §1.2 셀 한도 비율 문턱) 문턱·raise 값을 셀별로 정하는 함수를 넘긴다

#include "detect/alert.h"
#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_rule.h"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace detect {

// 셀별 상태표 밀어내기 창 (14_ §6.3): 상태표 셀별 누적 evicted(14_ §4.4)의 증가분을 그것을 본 kpm2의 t_end_ms로 적고,
// 직전 clear_quiet_ms 동안의 수(이동 창)와 경보가 열린 뒤 누적 수를 돌려준다. 밀려난 UE는 판정되지 않아 조용해 보이므로
// 룰은 이 창이 0일 때만 CLEAR한다(Q-56 해결, 이슈 #44)
class EvictWindow {
 public:
  explicit EvictWindow(int64_t clear_quiet_ms) : clear_quiet_ms_(clear_quiet_ms) {}

  // 셀 kpm2 첫머리에: 증가분을 t로 적는다. alert_open이면 경보가 열린 뒤 누적도 더한다. 창 밖 시각은 경보가 없을 때도 버린다
  // (11/05 W-32, 이슈 #92 — 25_ §3.1-4: 그전에는 열린 경보의 해제 판단·RAISE에서만 잘라 경보 없는 포화 홍수에서 무한히 쌓였다)
  void note(int64_t cell, int64_t t, bool alert_open, const UeRuleCtx& ctx);
  // 직전 clear_quiet_ms 동안의 밀어내기 수 (이동 창) — raise의 values.evicted와 해제 보류 기준
  int64_t window(int64_t cell, int64_t now);
  int64_t open(int64_t cell) const;        // 경보가 열린 뒤 누적 — update의 values.evicted
  void reset_open(int64_t cell);           // 새 경보 — 누적을 처음부터
  std::size_t times_size(int64_t cell) const;  // 테스트용 — 시각 목록 길이 (W-32)
  void reset() { cells_.clear(); }         // session_reset

 private:
  struct Cell {
    int64_t seen = 0;             // 상태표 누적 evicted 중 이미 적은 수
    int64_t open = 0;             // 경보가 열린 뒤 밀어내기 수
    std::deque<int64_t> times;    // 밀어내기 시각 (이동 창)
  };
  int64_t clear_quiet_ms_;
  std::map<int64_t, Cell> cells_;
};

// 불확실 경보 묶음 (14_ §6.2). 룰·셀마다 보류 시각 목록과 창 안 보류 UE를 두고, 공격 경보와 별개의 UeAlertBook(kind anomaly)을 쓴다
class HeldBook {
 public:
  // 한 셀의 문턱과 raise 값 — n = 개수 문턱, params·log_fields = raise 레코드의 params와 로그 줄에서 kind=anomaly·held_w 뒤에 붙는 룰 필드
  struct CellSpec {
    int64_t n = 1;
    nlohmann::ordered_json params;
    std::vector<std::pair<std::string, std::string>> log_fields;
  };
  // 룰이 넘기는 것 (14_ §6.2): window_ms = 그 룰의 성립 창(L3-01-O·L3-21 갈래 ①은 W, L3-20·3단계는 clear_quiet_ms), n·params·log_fields =
  // 모든 셀에 같은 문턱과 raise 값(L3-20·3단계는 문턱 1, 모두 설정값이라 고정). per_cell이 있으면 그 셋 대신 tick이 그 셀의 지금
  // hello로 부른 값을 쓴다 — 셀 한도 비율 문턱(15_ §1.2 — 11/15, L3-01-O·L3-21): 보류 문턱은 공격 경보와 같은 셀의 N이고(15_ §4.7·§5.7),
  // raise에는 그 셀에 쓴 N(n_stall_th·n_fail_th)이 실린다
  struct Spec {
    std::string rule;
    int stage = 2;
    int64_t window_ms = 0;
    int64_t n = 1;
    int64_t clear_quiet_ms = 0;
    nlohmann::ordered_json params;
    std::vector<std::pair<std::string, std::string>> log_fields;
    std::function<CellSpec(const Hello& hello, int64_t cell)> per_cell;
  };

  HeldBook(Spec spec, AlertConfig alert);

  // 마감에서 보류 (14_ §6.2): 시각을 적고(raise의 held — 경보가 없을 때도 셀별 이동 창), 공격 경보가 열려 있으면 values.held로만 세고,
  // 아니면 불확실 경보용으로 둔다(판정은 tick). now = 그 셀 시계(없으면 마감), u = 보류 UE 칸(룰이 cond held·t_hit·wait_ms·dir을
  // 채운 것, 항목을 모르면 nullopt). alert.held_alert가 꺼져 있으면 세기만 한다
  void hold(int64_t cell, int64_t now, bool attack_open, std::optional<AlertUe> u);
  // 셀 kpm2마다, 공격 묶음 처리 뒤 (14_ §6.2 — Q-58 ② 해결, 이슈 #48): input_lost면 END. 이번 마감 처리에서 보류된 UE마다
  // (t_hit − W, t_hit] 안 보류 수 H_W를 세고, 공격 경보가 없으면 H_W ≥ N에서 창 안 보류 UE로 RAISE, 경보 중이면 UPDATE로 모은다.
  // 공격 경보가 열려 있으면 values.held로만 센다. 마지막 보류 뒤 clear_quiet_ms면 CLEAR
  void tick(int64_t cell, int64_t t, bool input_lost, bool attack_open, const UeRuleCtx& ctx,
            std::vector<AlertEvent>& out);
  // 공격 경보가 RAISE되기 직전 — 열린 불확실 경보를 같은 줄에서 먼저 CLEAR한다 (14_ §8.2)
  void close(int64_t cell, int64_t t, std::vector<AlertEvent>& out);
  // 새 공격 경보 — 경보가 열린 뒤 보류 수를 처음부터 센다
  void new_attack_alert(int64_t cell);
  // 공격 경보의 values.held: raise면 직전 clear_quiet_ms 동안 보류된 판정 수(이동 창), 아니면 경보가 열린 뒤 누적 (15_ §2.6)
  int64_t held(int64_t cell, bool raise, int64_t now);

  void end_all(const std::string& reason, std::vector<AlertEvent>& out) { book_.end_all(reason, out); }
  void reset() { cells_.clear(); }  // session_reset — 셀 기록을 버린다 (END는 end_all로 먼저)

  bool open(int64_t cell) const { return book_.open(cell); }
  int64_t total() const { return total_; }   // 테스트용 — 지금까지 보류한 판정 수
  int64_t held_w(int64_t cell) const;        // 테스트용 — 창 안 보류 UE 수

 private:
  struct Cell {
    int64_t held_open = 0;            // 공격 경보가 열린 뒤 보류된 판정 수
    std::deque<int64_t> held_times;   // 보류 시각 — raise의 held는 직전 clear_quiet_ms 동안 (이동 창)
    std::vector<AlertUe> fresh;       // 이번 kpm2의 마감 처리에서 보류된 UE — tick에서 본다
    std::deque<AlertUe> ues;          // 마지막 보류 시각 기준 (t − W, t] 안의 보류 UE — H_W와 RAISE의 ues
    int64_t t_last = 0;               // 마지막 보류 시각 — 불확실 경보 CLEAR 기준
  };

  int64_t window(Cell& c, int64_t now) const;
  CellSpec cell_spec(const Hello& hello, int64_t cell) const;  // 그 셀의 문턱·raise 값 (Spec::per_cell 또는 고정값)
  // cs = 이번 칸의 문턱·raise 값 — RAISE를 낼 수 있는 tick에서만 있고, close(CLEAR만)는 nullptr
  void decorate(std::size_t from, std::vector<AlertEvent>& out, const CellSpec* cs);

  Spec spec_;
  AlertConfig alert_;
  UeAlertBook book_;
  std::map<int64_t, Cell> cells_;
  int64_t total_ = 0;
};

}  // namespace detect
