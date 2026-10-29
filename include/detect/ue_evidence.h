#pragma once
// UE 단위 경보의 증거 (14_ §8.3·§8.4) — 걸린 UE의 최근 메시지(pre)와 경보 중 그 UE의 새 줄(active), 경보당 증거 UE 상한.
// EvidenceRecorder가 unit = "ue" 경보를 넘긴다. 큐와 경보별 보낸 수·버린 수는 기록기 몫이다(1단계와 함께 씀, 10/29 검수 B12)

#include "detect/alert.h"
#include "detect/config.h"
#include "detect/engine.h"
#include "detect/ue_table.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace detect {

class UeEvidence {
 public:
  UeEvidence(EvidenceMode mode, std::size_t ue_evidence_max);

  // 낼 증거 레코드 하나 — 그 경보 몫
  struct Record {
    std::string alert_id;
    std::string line;
  };

  // RAISE·UPDATE에 새로 실린 UE (14_ §8.3·§8.4): e.ues의 seq_range·evidence를 채우고 낼 pre 레코드를 돌려준다
  std::vector<Record> on_alert(AlertEvent& e, const UeTable& table);
  // ue_evt 한 줄 (14_ §8.4 active): 그 UE가 증거를 내는 열린 경보마다 레코드
  std::vector<Record> on_line(const EngineOutput::UeLine& line) const;
  // CLEAR·END — 그 경보의 증거 UE를 지운다. post는 없다 (14_ §8.4)
  void finish(const std::string& alert_id);

 private:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)

  EvidenceMode mode_;
  std::size_t max_;
  std::map<std::string, std::set<UeId>> by_alert_;  // 경보 → 증거를 내는 UE
  std::map<UeId, std::set<std::string>> by_ue_;     // UE → 그 UE가 증거를 내는 열린 경보
};

// UE 증거 레코드 한 줄 (14_ §8.4): type·alert_id·phase·seq·ue([cell, du_ue_id, uid])·raw.
// raw는 받은 원본 줄을 다시 직렬화하지 않고 그대로 이어 붙인다 (3_ §7.1)
std::string ue_evidence_record_line(const std::string& alert_id, const char* phase, int64_t seq, const UeKey& key,
                                    int64_t uid, const std::string& raw);

}  // namespace detect
