#pragma once
// 마감 목록·셀 시계·로스 기록 (14_ §6). '일정 시간 응답 없음'은 매 줄 상태표를 훑지 않고 마감 시각 목록으로 처리한다
// (14_ §0 결정 5). 셀의 시계 = 그 셀 kpm2의 t_end_ms — kpm2는 사건이 없어도 period_ms마다 오고, 같은 창의 ue_evt는
// 그 kpm2보다 먼저 오므로 시계가 마감을 지났으면 마감 전 응답은 이미 반영돼 있다(14_ §6, 2_ §6.1).

#include "detect/diag.h"
#include "detect/message.h"
#include "detect/ue_table.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

namespace detect {

// 마감 하나 (14_ §6.1-1). 셀은 key.cell_id — 그 셀의 시계로 처리한다
struct Deadline {
  int64_t at = 0;      // 마감 시각 (데이터 시각)
  UeKey key;
  int64_t uid = 0;     // 그 항목의 인스턴스 번호 — 꺼낼 때 다르면 다른 항목이다 (14_ §2.4)
  int owner = 0;       // DeadlineQueue::kTableOwner 또는 등록 순서의 2단계 룰 번호
  std::string tag;     // 무엇을 기다리나 (예: auth_resp, stale_setup)
  Dir dir = Dir::UL;   // 기다리는 메시지의 방향 — 방향별 보류 (14_ §2.4·§6.2)
  int64_t t_from = 0;  // 기다림 시작
  uint64_t order = 0;  // 넣은 순서 — 같은 마감 시각이면 먼저 넣은 것부터 (14_ §6.1-4)
};

// 한 kpm2 창의 로스 — 그 방향의 ue_evt를 놓쳤을 수 있다 (14_ §6.2)
struct CellLoss {
  bool ul = false;
  bool dl = false;
  bool any() const { return ul || dl; }
};

class DeadlineQueue {
 public:
  static constexpr int kTableOwner = -1;        // 상태표 몫 마감 (14_ §6.1 표)

  // 진단을 내는 연속 시간 (14_ §6.2 — ue_table.dl_unobserved_ms, 기본 5 s = 100 ms 칸 50개). 칸 수는 kpm2 칸 길이로 나눠
  // 정한다 (16_ W-24: 상수 50칸에서 설정 키로, 이슈 #44)
  void set_diag_streak_ms(int64_t ms) { diag_streak_ms_ = ms; }

  // 마감을 넣는다 (14_ §6.1-1). order는 여기서 매긴다
  void add(Deadline d);
  // 셀 시계를 kpm2의 t_end_ms로 올린다 (14_ §6)
  void set_clock(int64_t cell, int64_t t);
  std::optional<int64_t> clock(int64_t cell) const;
  // 그 셀에서 마감 ≤ 시계인 것을 하나 꺼낸다(마감 시각 → 넣은 순서). 없으면 nullopt (14_ §6.1-2·4)
  std::optional<Deadline> pop_due(int64_t cell);

  // kpm2 한 칸의 로스 기록 (14_ §6.2) — 마감 처리보다 먼저 부른다. gap = 앞 칸과 구간이 끊김(2_ §4.1)
  struct LossResult {
    CellLoss loss;            // 이 창이 로스 창인 방향 (끊김이면 양방향)
    std::vector<Diag> diags;  // ue_evt_lost_missing·dl_unobserved
  };
  LossResult record_loss(const Kpm2& k, bool gap, int64_t seq);
  // 대기(t_from, dir) 구간에 기다리는 방향의 로스가 있었는가 — loss_end[dir] > t_from이면 판정하지 않고 보류 (14_ §6.2)
  bool held(int64_t cell, Dir dir, int64_t t_from) const;
  std::optional<int64_t> loss_end(int64_t cell, Dir dir) const;

  std::size_t size() const;
  // 룰 몫 마감 색인 (14_ §4.4 보호 무리·§4.2 유령 정리 — Q-56 해결, 이슈 #44): (키, uid)에 룰 몫 마감이 걸려 있는지.
  // 응답이 와서 룰이 표시를 지운 뒤에도 마감 자체는 꺼낼 때까지 목록에 남아 그동안 '보호'로 본다 — 보호 길이가
  // 그 룰의 대기 시간을 넘지 않으므로 허용한다
  bool has_rule_deadline(const UeKey& key, int64_t uid) const;
  // 새 세션 — 마감·시계·로스 기록을 모두 비운다 (14_ §6.2 끝, §7 hello)
  void clear();

 private:
  struct Later {
    bool operator()(const Deadline& a, const Deadline& b) const {
      return a.at != b.at ? a.at > b.at : a.order > b.order;
    }
  };
  struct CellTime {
    std::optional<int64_t> clock;
    std::optional<int64_t> loss_end_ul;
    std::optional<int64_t> loss_end_dl;
    bool missing_flagged = false;  // ue_evt_lost 없음 진단을 냈고 아직 필드가 돌아오지 않음 (14_ §6.2, 이슈 #48)
    int dl_streak = 0;             // ue_evt_lost에 "DL"이 든 칸 연속 수
    std::priority_queue<Deadline, std::vector<Deadline>, Later> due;
  };

  std::map<int64_t, CellTime> cells_;
  std::map<std::pair<UeKey, int64_t>, int> rule_waits_;  // (키, uid) → 걸려 있는 룰 몫 마감 수
  uint64_t next_order_ = 0;
  int64_t diag_streak_ms_ = 5000;
};

}  // namespace detect
