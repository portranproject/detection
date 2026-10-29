#pragma once
// UE 경보 묶음 (14_ §8.2·§8.3) — 2단계 룰이 함께 쓰는 (룰, 셀)별 경보 골격 (10/29 이슈 #27 사용자 결정).
// 걸린 UE로 RAISE, 그 뒤 걸린 UE는 모았다가 alert.update_min_ms 간격으로 UPDATE(심각도가 오르면 바로),
// 한 레코드의 ues는 alert.ues_max칸까지(넘는 UE는 ues_total로만 센다), CLEAR·END.
// 룰은 여기서 만든 이벤트에 values·params·cond·candidates·로그 필드만 채운다. CLEAR 조건은 룰이 정한다

#include "detect/alert.h"
#include "detect/config.h"
#include "detect/ue_table.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace detect {

// 걸린 UE 한 칸의 식별·불확실 표시 (14_ §8.3 ues[]) — 상태표 항목에서 채운다. cond·t_hit·values·peers는 룰이 채운다
AlertUe alert_ue(const UeState& s);

class UeAlertBook {
 public:
  // kind = 경보 종류 "attack"(공격) 또는 "anomaly"(불확실 경보 — 14_ §6.2·§8.2, 이슈 #48). 룰은 종류마다 묶음을 하나씩 둔다
  UeAlertBook(std::string rule, AlertConfig cfg, std::string kind = "attack");

  // 걸린 UE (14_ §8.2): 그 셀에 열린 경보가 없으면 이 UE들로 RAISE, 있으면 모았다가 간격이 지났으면 UPDATE.
  // sev가 지금 심각도보다 높으면 기다리지 않고 바로 UPDATE(모아 둔 UE 포함). session·seq는 RAISE의 alert_id용
  void add(int64_t cell, std::vector<AlertUe> ues, Severity sev, int64_t t, const std::string& session, int64_t seq,
           std::vector<AlertEvent>& out);
  // 셀 kpm2마다 — 모아 둔 UE가 있고 간격이 지났으면 UPDATE
  void flush(int64_t cell, int64_t t, std::vector<AlertEvent>& out);
  // 바로 UPDATE — 룰의 셀 단위 신호로 심각도가 오르거나 갈래가 바뀔 때 (15_ §4.3·§5.5). 모아 둔 UE도 함께
  void update(int64_t cell, Severity sev, int64_t t, std::vector<AlertEvent>& out);
  // CLEAR — 조건은 룰이 정한다. 모아 둔 UE가 있으면 먼저 UPDATE로 낸다
  void clear(int64_t cell, int64_t t, std::vector<AlertEvent>& out);
  // END (14_ §8.2): input_lost는 그 셀, session_reset은 모든 셀(각 경보가 마지막으로 본 시각으로)
  void end(int64_t cell, int64_t t, const std::string& reason, std::vector<AlertEvent>& out);
  void end_all(const std::string& reason, std::vector<AlertEvent>& out);

  bool open(int64_t cell) const { return open_.count(cell) > 0; }
  std::optional<Severity> severity(int64_t cell) const;
  int64_t ues_total(int64_t cell) const;

 private:
  struct Open {
    std::string alert_id;
    int64_t raised_at = 0;
    int64_t last_emit = 0;  // 마지막 RAISE·UPDATE 시각 — UPDATE 간격의 기준
    int64_t t_last = 0;     // 이 경보에서 본 마지막 데이터 시각 — session_reset END 시각
    Severity severity = Severity::Medium;
    int64_t ues_total = 0;  // 지금까지 걸린 UE 수 — 레코드에 싣지 못한 UE도 센다
    std::vector<AlertUe> pending;
  };

  AlertEvent event(AlertEventKind kind, int64_t cell, const Open& o, int64_t t) const;
  void emit_update(int64_t cell, Open& o, int64_t t, std::vector<AlertEvent>& out);
  std::vector<AlertUe> take(std::vector<AlertUe>& ues) const;

  std::string rule_;
  AlertConfig cfg_;
  std::string kind_;
  std::map<int64_t, Open> open_;
};

}  // namespace detect
