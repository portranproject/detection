#pragma once
// 3단계 '되돌아보는 판정'의 공통 바탕 (20_ §1.2, 4_ §6.2 #4). 2단계 룰은 '요청 뒤 T 안에 응답이 오는가'를 앞으로 기다리지만,
// 3단계 룰은 '이 응답 앞에 요청이 있었는가'(L3-24·L3-14 갈래 ①)·'이 요청 앞에 보안이 섰는가'(L3-14 갈래 ②)를 되돌아본다.
// 판정 시점(판정할 줄이 든 창의 kpm2 — 마감 = 줄 시각 + 1 ms)·보류(연결 시작 뒤 DL 로스)·연결당 한 번·표시의 생애가 같아
// 여기 한 곳에 둔다. 3단계로 올린 L3-06(요청 없는 Security Mode Reject — 옛 4단계 AN-06b)도 같은 구조다 (20_ §5)

#include "detect/deadline_queue.h"
#include "detect/ue_rule.h"
#include "detect/ue_table.h"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace detect {

// AS 무결성이 섰는가 (20_ §1.2-1): 갱신 전 rrc_sec이 ON이고 rrc_alg.integrity가 nia0이 아니면 true. RRC 보안(무결성) 뒤에는
// 공중에서 넣은 요청이 PDCP 무결성 검사에서 걸러지므로 이 공격으로는 생길 수 없는 응답이다. 철자는 2_ §6.3의 소문자가 기준이고
// 대소문자는 가리지 않는다. integrity 값이 없거나(f 누락) 모르는 값이면 nia0이 아닌 것으로 본다 — 판정하지 않는 보수적인 쪽
bool as_integrity_on(const UeState& before);

// '요청 없는 응답' 후보 (20_ §1.2-1·2): 갱신 전 상태에서 n이 mid_join이 아니고(연결 앞부분을 봄), AS 무결성 전이고,
// 짝인 요청 수 R = cnt[req] ≤ 이미 본 응답 수 A = cnt[resp]. '한 번이라도 요청이 있었나'가 아니라 횟수로 맞춘다 —
// 정상 식별 절차 뒤 다시 주입하면 요청 1·응답 2가 되고, AMF 재전송에 여러 번 답해도 응답 수가 요청 수를 넘지 않는다
bool unsolicited(const UeState& before, Proto proto, const std::string& req, const std::string& resp);
// 응답 집합판 (20_ §1.2 m/q 표·§5.3, 11/03 L3-06): 요청에 대한 정상 응답이 둘 이상인 절차에서는 A = 집합 안 메시지 cnt의 합이다 —
// NAS 보안 모드 명령의 응답은 Complete와 Reject 둘이라, 정상 명령 → Complete 뒤 주입된 명령의 Reject를 R 1·A 1로 잡는다
bool unsolicited(const UeState& before, Proto proto, const std::string& req, const std::vector<std::string>& resps);
int64_t count_any(const UeState& n, Proto proto, const std::vector<std::string>& msgs);

// 되돌아보는 판정의 표시 (20_ §1.2 '표시의 생애'). 룰이 하나씩 갖고, 표시는 항목 (키, uid)와 tag(갈래 — L3-14는
// unsolicited·pre_sec_enquiry)마다 하나다. 상태는 대기(마감 처리 전)와 결정됨(걸림·보류)이고, 결정된 표시는 마감에서 지우지
// 않고 항목이 닫힐 때까지 두어 '연결당 한 번'의 근거로 쓴다 — 2단계 룰(마감에서 표시를 지운 뒤 판정)과 다르다
class LookbackMarks {
 public:
  enum class Phase { Waiting, Hit, Held };

  struct Mark {
    UeKey key;
    int64_t uid = 0;
    std::string tag;
    Phase phase = Phase::Waiting;
    int64_t t_from = 0;             // 판정할 줄의 t_ms — 응답 t_r 또는 요청 t_e. 걸리면 t_hit
    int64_t extra = 0;              // 이 연결에서 더 온 같은 갈래 신호 수 (20_ §1.2-2)
    nlohmann::ordered_json snap;    // 판정할 줄 때의 값 — 룰이 정한다(ues[].values). 마감 전에 닫혀도 판정할 수 있게
    std::optional<UeState> closed;  // 마감 전에 닫혔으면 닫힐 때의 상태 (20_ §1.2-5)
  };

  enum class Verdict { Stale, Skip, Held, Hit };
  // 마감 처리 결과 (20_ §1.2-4). Stale = 표시가 없거나 다름(할 일 없음), Skip = late로 판정하지 않음(표시를 지웠다),
  // Held = 연결 시작 뒤 DL 로스로 보류, Hit = 걸림. mark·n은 Held·Hit·Skip일 때 판정 때의 표시와 항목(열린 항목 또는 복사본)
  struct Decision {
    Verdict verdict = Verdict::Stale;
    Mark mark;
    UeState n;
  };

  // 후보 줄 (20_ §1.2-2·3): 이 (키, uid, tag)에 표시가 없으면 대기 표시를 걸고 마감 t + 1(방향 DL)을 넣고 true.
  // 이미 있으면(대기·결정됨) 다시 후보를 만들지 않고 extra만 1 늘리고 false — 연결당 한 번. 후보 조건은 룰이 미리 본다
  bool start(const UeState& n, const std::string& tag, int64_t t, nlohmann::ordered_json snap, const UeRuleCtx& ctx);
  // 마감 처리 (20_ §1.2-4)
  Decision on_deadline(const Deadline& d, const UeRuleCtx& ctx);
  // 항목이 닫힘 (20_ §1.2-5·'표시의 생애'): 대기 표시는 released·reused·stale_setup이면 닫힐 때 상태를 복사해 남기고(마감 때
  // 판정), 그 밖의 이유면 지운다. 결정된 표시는 닫힘 이유와 관계없이 지운다 — 더 판정할 것이 없다
  void on_close(const UeState& last, CloseReason reason);
  // 세션 리셋·2단계 꺼짐 — 모두 지운다 (14_ §7)
  void clear() { marks_.clear(); }

  const Mark* find(const UeKey& key, int64_t uid, const std::string& tag) const;  // 룰·테스트용
  std::size_t size() const { return marks_.size(); }

 private:
  using Id = std::tuple<UeKey, int64_t, std::string>;  // (키, uid, tag)
  std::map<Id, Mark> marks_;
};

}  // namespace detect
