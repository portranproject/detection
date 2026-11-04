#pragma once
// 4단계 '있는 것을 본 판정'의 공통 바탕 (21_ §1.1·§1.3, M9 이슈 #70). 4단계 룰은 줄 하나(또는 연결이 닫힐 때) 그 자리에서
// 성립하는 걸림을 적고, RAISE·UPDATE는 그 걸림이 든 창의 kpm2(on_cell_tick)에서 낸다 — L3-21 갈래 ②와 같은 방식(15_ §5.3).
// 셀 단위 성립은 가장 최근 걸림 t 기준 (t − W, t] 안 걸린 연결 수 ≥ N이다(UE 하나로 RAISE하는 룰은 N = 1). 해제는 경보에 실린
// 마지막 걸림 뒤 clear_quiet_ms(직전 clear_quiet_ms 동안 밀어내기가 있으면 보류 — Q-56), END는 공통이다. CLEAR·END 뒤에는 창을 비워 새 경보가 옛 경보의
// 걸림을 다시 싣지 않는다(23_ §3.1-2, 이슈 #84 — 창 W가 해제 시간보다 길면(AN-04 300 s > 60 s) 옛 S-TMSI가 재수록됐다). '없음'을 기다리지 않으므로
// 보류·불확실 경보가 없다(§1.1). 걸린 뒤 같은 연결에서 바뀌는 값(반복·재인증 관측 등)은 UE 칸에 다시 싣지 않고 경보 values의
// 누적 수로 낸다 — update에는 새로 걸린 UE만 실리기 때문이다(§1.1, 14_ §8.3, 1_ §6 11/04). clear·end에도 누적값을 실어(룰 decorate,
// 14_ §8.3 — 11/04 Q-69 W-28) UE 하나의 지속 공격에서 쌓인 수가 레코드에 남게 한다 — CLEAR·END 뒤에도 다음 RAISE까지 count·evicted가 남는다.
// (11/05 26_ R2, 이슈 #96) 2단계 L3-01-O의 셀 창 집계(고착 수 S_W ≥ N, 15_ §4.3·§4.5)도 이 위에 둔다 — 종류 attack·단계 2, 연결당 한 번은
// 룰 몫, 심각도는 칸마다 룰이 정함, CLEAR 기준은 마지막 성립(t_sat), END 뒤 창은 그대로(15_ §4.5는 CLEAR 때만 비움), 공격 RAISE 직전
// 불확실 경보 CLEAR는 HeldBook 고리로. 기본값은 모두 4단계 동작이라 4단계 룰은 바뀌지 않는다

#include "detect/alert.h"
#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_held.h"
#include "detect/ue_rule.h"
#include "detect/ue_table.h"

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

class HitWindow {
 public:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)
  // 경보 이벤트를 낸 직후 룰이 values·params·cond·candidates·로그 필드를 채우는 콜백 — out[from]부터가 새 이벤트. hit은 그 이벤트를
  // 일으킨 이번 걸림(식별·uncertain을 다시 채운 뒤) — 걸림을 처리하는 구간(RAISE·그 걸림의 UPDATE)에만 있고 END·모아 둔 UPDATE·CLEAR
  // 구간은 nullptr. 룰은 '이번 걸림'을 e.ues.back()으로 찾지 않는다 — ues가 alert.ues_max로 잘리면 마지막 칸이 이번 걸림이 아니다
  // (23_ §3.2-1, 이슈 #84). 이벤트가 없어도 걸림마다 한 번 불린다 — 룰이 '마지막 걸림 시각' 같은 값을 걸림 순서대로 갱신할 수 있게
  using Decorate = std::function<void(std::size_t from, const AlertUe* hit)>;

  // rule = 룰 ID, window_ms·n = 셀 창 W·문턱 N, clear_quiet_ms = 해제 시간. 경보는 기본 kind anomaly·stage 4 (21_ §1) —
  // 2단계 룰은 "attack"·2를 넘긴다(R2, 이슈 #96)
  HitWindow(std::string rule, AlertConfig alert, int64_t window_ms, int64_t n, int64_t clear_quiet_ms,
            std::string kind = "anomaly", int stage = 4);

  // 걸림 (§1.1): 그 연결이 이미 걸렸으면 아무것도 하지 않고 false — 연결당 한 번(룰은 add로 누적 수만 늘린다). u의 cond·
  // t_hit·values는 룰이 걸릴 때 값으로 채운다. 식별·uncertain은 kpm2에서 그때 상태표 항목으로 다시 채운다 — 같은 창의 로스 표시는
  // 그 창 kpm2가 와서야 붙기 때문이다(14_ §7 kpm2 ②). force면 창 안 수가 N 미만이어도 이 걸림으로 성립한다 — 한 룰 안에 UE 하나로
  // RAISE하는 갈래와 셀 개수 갈래가 함께 있을 때(AN-02 갈래 ①·②, 21_ §5.3). RAISE에는 어느 쪽이든 그때 창 안 걸림을 모두 싣는다.
  // ref는 식별·uncertain을 다시 채울 실제 연결 (키, uid) — 걸림 키가 연결이 아니라 S-TMSI인데 연결이 열려 있을 때 걸리는 룰
  // (AN-08, 21_ §8.3-1)이 준다. 없으면 id가 곧 연결이다
  bool hit(const UeId& id, AlertUe u, bool force = false, std::optional<UeId> ref = std::nullopt);
  // 해제 기준 (21_ §3.5·§5.5): 기본은 경보에 실린 마지막 걸림 시각. true면 마지막 '성립'(force 걸림 또는 창 안 수 ≥ N) 시각 —
  // 성립하지 않은 걸림은 경보에 실려도 해제를 늦추지 않는다(AN-02, L3-01-O 15_ §4.5)
  void set_clear_on_satisfied(bool v) { clear_on_satisfied_ = v; }
  // 연결당 한 번 (§1.1) — 기본 true. 2단계 L3-01-O는 false: 응답 뒤 새 기다림은 같은 연결이 다시 고착할 수 있고 '연결당 한 번'은
  // 룰이 stalled_로 한다(15_ §4.3-4). false면 같은 (키, uid)의 걸림이 창에 여러 칸 들어간다(한 UE가 두 번 고착하면 두 칸, 15_ §5.5)
  void set_once_per_conn(bool v) { once_per_conn_ = v; }
  // END(input_lost·input_silent) 뒤 창을 비우는가 — 기본 true(21_ §1.1, 이슈 #84). 2단계는 false: 15_ §4.5는 CLEAR 때만 비운다(Q-73)
  void set_forget_on_end(bool v) { forget_on_end_ = v; }
  // 이번 칸의 심각도 (15_ §4.3 — L3-01-O는 창 안 UeCtxMax로 칸마다 정한다). tick의 RAISE·UPDATE에 쓰고, 경보 중 medium에서 high가 되면
  // 모아 둔 UE와 함께 바로 UPDATE한다(14_ §8.2). 기본 medium(4단계 21_ §1)
  void set_severity(Severity sev) { severity_ = sev; }
  // 불확실 경보 묶음 (14_ §8.2): 있으면 공격 RAISE 직전에 그 셀의 열린 불확실 경보를 먼저 CLEAR하고 새 경보의 보류 수를 0부터 센다
  void set_held(HeldBook* held) { held_ = held; }
  bool hit_before(const UeId& id) const;  // 열린 연결이 이미 걸렸나
  // 걸린 연결의 누적 수 (§1.1): 그 연결이 열린 경보에 실렸으면 바로 경보 값에, 아직 실리지 않았으면 걸림에 쌓아 두었다가
  // 실릴 때 함께 더한다
  void add(const UeId& id, const std::string& name, int64_t n = 1);
  // 걸린 키의 회복 전 반복 (21_ §1.1·§6.5·§7.5·§8.5 — 11/04 Q-69 (가), 이슈 #86): 그 키가 열린 경보에 실려 있으면 해제 기준
  // (t_hit_last·t_sat)을 t로 올린다 — S-TMSI·Part1을 키로 쓰는 룰(AN-04·AN-07·AN-08)이 add("extra") 뒤에 부른다. 같은 UE의
  // 공격이 이어지는 동안 경보 하나가 열려 있고, 걸린 키들이 clear_quiet_ms 동안 조용해야 CLEAR한다. 경보가 없거나 아직 실리지
  // 않았으면 무동작. 연결을 키로 쓰는 룰은 부르지 않는다(같은 연결의 반복은 해제를 늦추지 않음 — 20_ §3.3-4)
  void touch(const UeId& id, int64_t t);
  // 걸린 키가 아직 살아 있는가 — 걸렸고(hit_before) 아직 실리기 전(RAISE 전)이거나 그 키를 실은 경보가 열려 있으면 true.
  // CLEAR·END 뒤면 false — S-TMSI 키 룰은 그때 그 키를 회복한 것으로 보아(forget) 다음 반복을 새로 센다(21_ §6.3-2·§7.3-2·
  // §8.3-1, 11/04 Q-69). 그렇지 않으면 60 s 쉬었다 다시 오는 공격이 회복 창 W(AN-04 300 s)까지 버려진다
  bool active(const UeId& id) const;
  // 연결이 닫힘 — 아직 kpm2를 거치지 않은 걸림은 마지막 상태로 식별·uncertain을 채우고, 연결 기록을 지운다
  void on_close(const UeState& last);
  // 걸림 키를 지운다 — 같은 키로 다시 걸릴 수 있다. 연결이 아니라 S-TMSI를 키로 쓰는 룰(AN-04 — 닫힐 때 판정, 21_ §6.3-2)이
  // 그 S-TMSI가 회복됐을 때 부른다. 경보에 실린 누적 수는 그대로다
  void forget(const UeId& id) { conns_.erase(id); }

  // 셀 kpm2마다 (§1.1): input_lost면 END, 이번 걸림을 창에 넣어 성립을 보고 RAISE(창 안 걸림 전부)·UPDATE(새 걸림), 모아 둔
  // UPDATE, 해제. 이벤트를 낼 때마다 fn(from, hit)을 부른다. CLEAR·END 뒤 창은 비어 새 경보는 그 뒤 걸림만 싣는다(이슈 #84)
  void tick(int64_t cell, int64_t t, bool input_lost, const UeRuleCtx& ctx, std::vector<AlertEvent>& out,
            const Decorate& fn);
  void end_all(const std::string& reason, std::vector<AlertEvent>& out);  // 모든 셀 END — 열려 있던 셀의 창도 비운다 (이슈 #84)
  void reset();  // 걸림·연결·셀 기록을 모두 버린다 (session_reset)

  // decorate가 읽는 값
  int64_t window(int64_t cell) const;                                // 가장 최근 걸림 기준 창 안 걸린 연결 수
  int64_t window_with(int64_t cell, const std::string& cond) const;  // 그중 UE cond에 cond가 있는 수 (AN-02 known_w)
  int64_t window_if(int64_t cell, const std::function<bool(const AlertUe&)>& pred) const;  // 그중 pred가 참인 수 (AN-08 known_src)
  int64_t count(int64_t cell, const std::string& name) const;       // 열린 경보에 실린 연결의 누적 수
  int64_t evicted(int64_t cell, bool raise, int64_t t);              // raise면 직전 clear_quiet_ms 이동 창, 아니면 경보가 열린 뒤 누적
  bool open(int64_t cell) const { return book_.open(cell); }
  std::optional<Severity> severity(int64_t cell) const { return book_.severity(cell); }
  std::size_t evict_times_size(int64_t cell) const { return evict_.times_size(cell); }  // 테스트용 (W-32)

 private:
  struct Hit {
    UeId id;
    UeId ref;  // 식별·uncertain을 다시 채울 연결 (hit의 ref, 없으면 id)
    AlertUe u;
    std::map<std::string, int64_t> acc;  // 경보에 실리기 전에 쌓인 누적 수
    bool force = false;                  // 이 걸림만으로 성립 (hit의 force)
  };
  struct Cell {
    std::vector<Hit> fresh;                     // 이번 kpm2 전에 적은 걸림
    std::deque<Hit> win;                        // 가장 최근 걸림 기준 (t − W, t] 안 걸림 (성립 전 포함). CLEAR·END 때 비운다 (이슈 #84)
    int64_t epoch = 0;                          // 경보 세대 — RAISE마다 +1. 걸림이 어느 경보에 실렸는지 (11/05 W-34, 이슈 #92)
    int64_t t_hit_last = 0;                     // 경보에 실린 마지막 걸림 시각 — CLEAR 기준 (21_ §3.5)
    int64_t t_sat = 0;                          // 마지막 성립 시각 — clear_on_satisfied면 CLEAR 기준 (21_ §5.5)
    std::map<std::string, int64_t> counts;      // 경보가 열린 뒤 누적 수
  };
  struct Conn {
    int64_t cell = 0;
    bool in_alert = false;  // 열린 경보에 실렸나 — 그 뒤 누적 수는 바로 경보 값에 더한다
    int64_t epoch = 0;      // 실린 경보의 세대 (Cell::epoch) — 지금 열린 경보와 같을 때만 '그 키를 실은 경보'다 (W-34)
  };
  // 그 키가 지금 열린 경보에 실려 있나 (11/05 W-34, 이슈 #92 — 25_ §3.2-1): 그전에는 '그 셀에 경보가 열려 있나'만 봐서 CLEAR 뒤
  // 새 경보가 열리면 옛 경보 키의 반복이 새 경보의 extra가 되고 해제를 늦췄다
  bool in_current_alert(const Conn& conn) const;

  void include(Cell& c, const Hit& h);
  void forget_window(Cell& c);  // CLEAR·END 뒤 창·해제 기준을 비운다 (이슈 #84)

  int64_t window_ms_;
  int64_t n_;
  int64_t clear_quiet_ms_;
  bool clear_on_satisfied_ = false;
  bool once_per_conn_ = true;
  bool forget_on_end_ = true;
  Severity severity_ = Severity::Medium;
  HeldBook* held_ = nullptr;
  UeAlertBook book_;
  EvictWindow evict_;  // 셀별 밀어내기 창 (14_ §6.3) — 2·3단계와 같은 헬퍼 (R1, 이슈 #96)
  std::map<int64_t, Cell> cells_;
  std::map<UeId, Conn> conns_;  // 걸린 열린 연결
};

}  // namespace detect
