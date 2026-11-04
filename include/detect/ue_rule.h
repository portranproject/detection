#pragma once
// 2단계 이상 룰 인터페이스 (14_ §1.1). 룰은 UE 상태표를 읽기만 하고, 자기 판정용 대기 표시만 따로 가진다(14_ §1·§2.4).
// Engine이 줄 유형별로 14_ §7 순서에 따라 부른다. 출력(RuleOutput)은 1단계 룰(rule.h)과 같다.
// on_session_reset·on_input_silent는 14_ §1.1의 네 호출에 더한 것이다 — 14_ §7 hello의 '새 세션이면 진행 중 경보를 END'와
// 14_ §6.2의 입력 침묵(Q-45)을 룰에 알리는 길

#include "detect/deadline_queue.h"
#include "detect/message.h"
#include "detect/rule.h"
#include "detect/ue_table.h"

#include <cstdint>
#include <string>
#include <utility>

namespace detect {

// 룰을 부를 때 함께 넘기는 것: 읽기 전용 상태표·셀 시계·로스 기록, 지금 hello·세션·줄의 seq, 마감 등록
class UeRuleCtx {
 public:
  UeRuleCtx(const UeTable& table, DeadlineQueue& queue, const Hello& hello, const std::string& session, int64_t seq,
            int owner)
      : table(table), deadlines(queue), hello(hello), session(session), seq(seq), queue_(queue), owner_(owner) {}

  const UeTable& table;
  const DeadlineQueue& deadlines;  // 셀 시계·로스 기록 — 보류 판단은 deadlines.held(…) (14_ §6.2)
  const Hello& hello;              // cells[].max_conn 등 (15_ §4.3)
  const std::string& session;
  int64_t seq;                     // 지금 처리하는 줄의 seq — alert_id = session-룰-셀-seq (14_ §8.2)

  // 기다림 시작 — 마감 목록에 이 룰 몫으로 넣는다 (14_ §6.1-1)
  void add_deadline(int64_t at, const UeKey& key, int64_t uid, std::string tag, Dir dir, int64_t t_from) const {
    Deadline d;
    d.at = at;
    d.key = key;
    d.uid = uid;
    d.owner = owner_;
    d.tag = std::move(tag);
    d.dir = dir;
    d.t_from = t_from;
    queue_.add(std::move(d));
  }

 private:
  DeadlineQueue& queue_;
  int owner_;
};

class UeRule {
 public:
  virtual ~UeRule() = default;
  virtual const char* id() const = 0;
  // 증거 지평 (14_ §1.1, 10/29 이슈 #25): 닫힌 UE의 recent가 이 룰의 경보 증거로 필요할 수 있는 최대 시간 — 2단계는 대기 시간 +
  // 셀 창, 3·4단계는 창 한 칸 몫 1,000 ms + alert.update_min_ms(20_ §1.2-6, 21_ §1.1 — 셀 창을 더하지 않는다, 11/04).
  // 상태표는 등록된 룰의 최댓값만큼 닫힌 항목의 recent를 보관한다(14_ §2.3)
  virtual int64_t evidence_horizon_ms() const = 0;
  // 늦은 줄 지평 (14_ §1.1·§4.3 — 11/05 Q-72, 이슈 #94): late_until에 쓰는 값. 기본은 증거 지평과 같고, 불확실 경보가 보류 창 안 UE를
  // 실어 증거 보관이 더 긴 룰(L3-20)만 따로 둔다 — 증거 지평을 늘려도 '없음' 판정 제외 길이는 늘지 않게
  virtual int64_t late_horizon_ms() const { return evidence_horizon_ms(); }
  // ue_evt 1줄이 상태표에 반영된 직후 (14_ §7 ⑤). before·after = 갱신 전·후 상태 — '요청 없는 응답'처럼
  // 갱신 전 상태를 봐야 하는 판정을 위해 둘 다 넘긴다(14_ §1)
  virtual void on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                           RuleOutput& out) = 0;
  // 그 셀 시계가 이 룰의 마감을 지났을 때 (14_ §6.1-3). 대기 표시가 그대로인지(uid·t_from)는 룰이 확인한다
  virtual void on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) = 0;
  // UE 항목이 닫힐 때 (14_ §4.2). last = 닫히기 직전 상태, t = 닫힌 데이터 시각 — 마감 때 판정하려면 필요한 값을
  // 대기 표시에 복사해 둔다(14_ §2.4). 2단계 룰은 released·reused·stale_setup이면 표시를 남기고 나머지는 지운다(15_ §1)
  virtual void on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx,
                           RuleOutput& out) = 0;
  // 그 셀 kpm2가 올 때마다, 마감 처리 뒤 (14_ §7 kpm2 ④) — 셀 단위 창 집계·해제·ext 읽기, input_lost면 진행 중 경보 END
  virtual void on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss& loss, bool input_lost, const UeRuleCtx& ctx,
                            RuleOutput& out) = 0;
  // 새 세션이거나 2단계가 꺼질 때 — 진행 중 경보를 END(session_reset)로 끝내고 대기 표시를 모두 버린다 (14_ §7 hello)
  virtual void on_session_reset(const UeRuleCtx& ctx, RuleOutput& out) = 0;
  // 입력 침묵 (14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 진행 중 경보(불확실 경보 포함)를 END(reason=input_silent)로 끝낸다.
  // on_session_reset과 달리 대기 표시·셀 기록은 그대로 둔다 — kpm2가 다시 오면 마감이 평소처럼 판정된다. 기본은 무동작
  virtual void on_input_silent(const UeRuleCtx&, RuleOutput&) {}
};

}  // namespace detect
