#pragma once
// 증거 기록기 (3_ §7.1) — 스레드 A에서 엔진 출력 뒤에 불러, 경보에 걸린 칸의 원본 kpm2 줄과
// 경보 기록을 레코드로 만들어 큐에 넣는다. I/O는 하지 않는다(파일 쓰기는 스레드 B의 EvidenceSink).
//
//   RAISE    : alert(raise) + 버퍼의 마지막 pre_slots칸을 phase=pre로
//   경보 중  : 그 셀의 새 kpm2 줄마다 phase=active (끊김이면 먼저 gap)
//   CLEAR    : 그 칸까지 active로 낸 뒤 alert(clear), 다음 칸부터 post_slots칸을 phase=post
//   END      : alert(end) — post 없음
// 위 kpm2 칸 증거는 셀 단위 경보(unit = "cell")만이다. UE 단위 경보는 alert 레코드만 낸다 (14_ §8.4)

#include "detect/config.h"
#include "detect/diag.h"
#include "detect/engine.h"
#include "detect/evidence_queue.h"
#include "detect/series.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace detect {

class EvidenceRecorder {
 public:
  EvidenceRecorder(EvidenceConfig cfg, EvidenceQueue& queue);

  // 엔진이 줄 하나를 처리한 직후 부른다. 반환값은 진단(버린 증거 등)
  std::vector<Diag> on_feed(const Series& series, const EngineOutput& out);

  // 경보별 집계 — 테스트·진단용
  struct Counts {
    int64_t sent = 0;     // 큐에 들어가 있거나 이미 꺼내진 evidence 수
    int64_t dropped = 0;  // 버린 evidence 수
  };
  Counts counts(const std::string& alert_id) const;
  std::size_t finished_count() const { return finished_.size(); }  // 테스트·진단용

  // 끝난 경보의 집계 보관 상한. clear·end 레코드를 낸 뒤에는 큐에서 늦게 버려진 증거의 수 보정에만 쓰이므로
  // 작아도 된다 — 상한이 없으면 경보마다 영구히 쌓인다 (3_ §7.1 구현에서 정한 것, 10/27 이슈 #13 W-2)
  static constexpr std::size_t kFinishedMax = 1024;

 private:
  enum class Phase { Active, Post };
  struct Track {
    std::string rule;
    int64_t cell_id = 0;
    bool cell_unit = true;  // 셀 단위 경보(unit = "cell")만 kpm2 칸 증거를 낸다 (14_ §8.4)
    Phase phase = Phase::Active;
    std::size_t post_left = 0;
    Counts counts;
    int64_t post_dropped = 0;
    bool drop_logged = false;
  };

  void push(RecordKind kind, const std::string& alert_id, std::string line, std::vector<Diag>& diags);
  void push_evidence(const std::string& alert_id, const char* phase, const Slot& slot, std::vector<Diag>& diags);
  void finish_post(const std::string& alert_id, std::vector<Diag>& diags);

  EvidenceConfig cfg_;
  EvidenceQueue& queue_;
  std::map<std::string, Track> tracks_;                                 // alert_id → 진행 중(active·post) 경보
  std::map<std::pair<std::string, int64_t>, std::string> by_rule_cell_;  // (룰, 셀) → alert_id
  std::map<std::string, Counts> finished_;                              // 끝난 경보의 집계 (kFinishedMax까지)
  std::deque<std::string> finished_order_;                              // finished_의 삽입 순서 — 오래된 것부터 지운다
};

// 레코드 한 줄 만들기 (3_ §7.1 레코드 표). 테스트에서도 쓴다
std::string alert_record_line(const AlertEvent& e, int64_t sent, int64_t dropped);
// raw는 받은 원본 줄을 다시 직렬화하지 않고 그대로 이어 붙인다 (3_ §7.1)
std::string evidence_record_line(const std::string& alert_id, const char* phase, int64_t seq, const std::string& raw);
std::string gap_record_line(const std::string& alert_id, const GapEvent& g);

}  // namespace detect
