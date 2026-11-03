// 탐지 엔진 실행 파일 (4_ §2 app, §3 처리 흐름, §5 배포).
//   detector --socket PATH [--config FILE]                  분석 엔진의 KPM을 Unix 소켓으로 받는다 (2_ §1)
//   detector --replay FILE [--speed max|N] [--config FILE]  .jsonl을 재생한다 (1_ FR-2)
// 스레드 A(이 main): 입력 → 엔진(파싱·저장·판정) → 경보 로그 → 증거 레코드를 큐에 넣기
// 소켓 모드는 벽시계로 입력 침묵도 감시한다 — 마지막 kpm2 뒤 input_silent_ms 동안 kpm2가 없으면 진행 중 경보 END (3_ §8, 이슈 #50)
// 스레드 B(EvidenceSink): 큐에서 꺼내 증거 파일에 쓰기 (3_ §7.1 동시성 모델)
#include "detect/config.h"
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/io/evidence_sink.h"
#include "detect/io/file_replay.h"
#include "detect/io/uds_server.h"
#include "detect/rules/auth_stall.h"
#include "detect/rules/blind_dos.h"
#include "detect/rules/bts_variant.h"
#include "detect/rules/cap_hijack.h"
#include "detect/rules/imsi_extractor.h"
#include "detect/rules/nas_desync.h"
#include "detect/rules/sec_reauth.h"
#include "detect/rules/sync_failure.h"
#include "detect/rules/uplink_dos.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

using namespace detect;

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }

// stderr 로그 한 줄 — 벽시계 시각(UTC, ms)을 앞에 붙인다 (결정 G1)
void log_err(const std::string& level, const std::string& msg) {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const std::time_t s = system_clock::to_time_t(now);
  const int ms = static_cast<int>(duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000);
  std::tm tm{};
  gmtime_r(&s, &tm);
  char ts[64];
  std::snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1,
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
  std::cerr << ts << ' ' << level << ' ' << msg << '\n';
}

void log_diag(const Diag& d) {
  std::string s = std::string(to_string(d.kind));
  if (d.cell_id) s += " cell=" + std::to_string(*d.cell_id);
  if (d.seq) s += " seq=" + std::to_string(*d.seq);
  if (!d.message.empty()) s += " " + d.message;
  log_err("DIAG", s);
}

// rules.<id>가 있으면 그 룰의 파서로 해석해 out에 넣는다. 경고는 WARN, 타입·범위 오류면 false (4_ §1.2 설정 오류 처리)
template <typename T, typename Parse>
bool read_rule(const DetectorConfig& cfg, const char* id, Parse parse, T& out) {
  auto it = cfg.rules.find(id);
  if (it == cfg.rules.end()) return true;
  RuleConfigResult<T> r = parse(it->second);
  for (const auto& w : r.warnings) log_err("WARN", w);
  if (!r.ok) {
    log_err("ERROR", r.error);
    return false;
  }
  out = r.config;
  return true;
}

void usage() {
  std::cerr << "usage: detector (--socket PATH | --replay FILE [--speed max|N]) [--config FILE]\n";
}

struct Args {
  std::string socket_path;
  std::string replay_path;
  std::string config_path;
  double speed = 0;
  bool socket_given = false;
};

// 명령줄 해석. 틀리면 종료 코드 2 (결정 G8)
bool parse_args(int argc, char** argv, Args& a) {
  for (int i = 1; i < argc; ++i) {
    const std::string k = argv[i];
    auto next = [&](std::string& out) {
      if (i + 1 >= argc) return false;
      out = argv[++i];
      return true;
    };
    std::string v;
    if (k == "--socket") {
      if (!next(a.socket_path)) return false;
      a.socket_given = true;
    } else if (k == "--replay") {
      if (!next(a.replay_path)) return false;
    } else if (k == "--config") {
      if (!next(a.config_path)) return false;
    } else if (k == "--speed") {
      if (!next(v)) return false;
      if (v == "max") {
        a.speed = 0;
      } else {
        char* end = nullptr;
        a.speed = std::strtod(v.c_str(), &end);
        if (!end || *end != '\0' || !(a.speed > 0)) return false;
      }
    } else {
      return false;
    }
  }
  // 입력은 둘 중 하나만 (--socket 또는 --replay)
  return a.socket_given != !a.replay_path.empty();
}

}  // namespace

int main(int argc, char** argv) {
  Args args;
  if (!parse_args(argc, argv, args)) {
    usage();
    return 2;
  }

  // 설정 (4_ §1.2, 결정 G3): --config가 없으면 기본값, 있으면 읽어서 해석. 오류면 종료 코드 1
  DetectorConfig cfg;
  if (!args.config_path.empty()) {
    std::ifstream in(args.config_path);
    if (!in) {
      log_err("ERROR", "cannot open config " + args.config_path);
      return 1;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    ConfigResult cr = parse_config(ss.str());
    for (const auto& w : cr.warnings) log_err("WARN", w);
    if (!cr.ok) {
      log_err("ERROR", cr.error);
      return 1;
    }
    cfg = cr.config;
  }
  if (args.socket_given) cfg.socket_path = args.socket_path;  // --socket이 설정보다 우선 (결정 G3)

  // 룰 설정 (4_ §1.2, Q-46 결정 J4): rules 맵에서 룰 ID로 꺼내 룰별 파서로 해석한다. 없으면 기본값.
  // 등록하지 않는 룰 ID가 있으면 경고만(오타를 알아채게, 결정 G3)
  BtsVariantConfig bts;
  BlindDosConfig blind_dos;
  AuthStallConfig auth_stall;
  UplinkDosConfig uplink_dos;
  ImsiExtractorConfig imsi_extractor;
  CapHijackConfig cap_hijack;
  NasDesyncConfig nas_desync;
  SyncFailureConfig sync_failure;
  SecReauthConfig sec_reauth;
  if (!read_rule(cfg, BtsVariantRule::kId, parse_bts_variant_config, bts) ||
      !read_rule(cfg, BlindDosRule::kId, parse_blind_dos_config, blind_dos) ||
      !read_rule(cfg, AuthStallRule::kId, parse_auth_stall_config, auth_stall) ||
      !read_rule(cfg, UplinkDosRule::kId, parse_uplink_dos_config, uplink_dos) ||
      !read_rule(cfg, ImsiExtractorRule::kId, parse_imsi_extractor_config, imsi_extractor) ||
      !read_rule(cfg, CapHijackRule::kId, parse_cap_hijack_config, cap_hijack) ||
      !read_rule(cfg, NasDesyncRule::kId, parse_nas_desync_config, nas_desync) ||
      !read_rule(cfg, SyncFailureRule::kId, parse_sync_failure_config, sync_failure) ||
      !read_rule(cfg, SecReauthRule::kId, parse_sec_reauth_config, sec_reauth))
    return 1;
  for (const auto& [id, _] : cfg.rules)
    if (id != BtsVariantRule::kId && id != BlindDosRule::kId && id != AuthStallRule::kId && id != UplinkDosRule::kId &&
        id != ImsiExtractorRule::kId && id != CapHijackRule::kId && id != NasDesyncRule::kId &&
        id != SyncFailureRule::kId && id != SecReauthRule::kId)
      log_err("WARN", "unknown rule id rules." + id + " (ignored)");

  // 엔진·룰·증거 (4_ §3). 버퍼 크기는 W와 pre_slots에서 정한다 (3_ §3·§7.1)
  SeriesConfig scfg;
  scfg.window_ms = bts.window_ms;
  scfg.h_hold_ms = bts.h_hold_ms;              // 입력 건전성은 series가 (Q-46, 결정 J5)
  scfg.missing_key_slots = bts.missing_key_slots;
  scfg.pre_slots = cfg.evidence.pre_slots;
  scfg.max_cells = cfg.max_cells;              // 결정 D7 — 설정 키 max_cells (16_ W-24)
  Engine engine(scfg, cfg.max_line_bytes, cfg.ue_table);
  engine.add_rule(std::make_unique<BtsVariantRule>(bts));
  // 2단계 룰 (15_). hello에 ue_evt 표시가 있을 때만 돈다(2_ §6.5). 경보 묶음·UE 증거는 alert.*를 함께 쓴다 (14_ §9)
  engine.add_ue_rule(std::make_unique<BlindDosRule>(blind_dos, cfg.alert));
  engine.add_ue_rule(std::make_unique<AuthStallRule>(auth_stall, cfg.alert));
  engine.add_ue_rule(std::make_unique<UplinkDosRule>(uplink_dos, cfg.alert));
  // 3단계 룰 (20_). 2단계 다음, L3-24 → L3-14 순서 (20_ §0, 4_ §6.2 #3). 2단계와 같이 hello.ue_evt가 있을 때만 돈다
  engine.add_ue_rule(std::make_unique<ImsiExtractorRule>(imsi_extractor, cfg.alert));
  engine.add_ue_rule(std::make_unique<CapHijackRule>(cap_hijack, cfg.alert));
  // 3단계로 올린 L3-06 (20_ §5). 등록은 구현 순서대로 뒤에 붙인다 — 같은 kpm2에서 여러 룰이 낼 때 기존 출력 순서가 그대로이게
  // (1_ §6 11/03 M9 착수 결정 ③)
  engine.add_ue_rule(std::make_unique<NasDesyncRule>(nas_desync, cfg.alert));
  // 4단계 룰 (21_). 이상 유형 + 후보(kind anomaly, stage 4). L3-06 다음 — 등록 순서는 위와 같은 원칙
  engine.add_ue_rule(std::make_unique<SyncFailureRule>(sync_failure, cfg.alert));
  engine.add_ue_rule(std::make_unique<SecReauthRule>(sec_reauth, cfg.alert));

  EvidenceQueue queue(cfg.evidence.queue_max);
  EvidenceRecorder recorder(cfg.evidence, queue, cfg.alert);
  EvidenceSink sink(queue, cfg.evidence.out_path);
  // 전달 스레드는 입력을 연 뒤에 띄운다 — 기동에 실패한 실행이 증거 파일을 건드리지 않게
  auto start_sink = [&]() {
    if (cfg.evidence.mode == EvidenceMode::Off) return true;
    if (sink.start()) return true;
    log_err("ERROR", "cannot open evidence file " + cfg.evidence.out_path);
    return false;
  };

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  // 엔진 출력 내보내기 (스레드 A): 경보는 stdout에 3_ §7 형식 그대로, 진단은 stderr (결정 G1) → 증거 기록
  auto emit = [&](const EngineOutput& out) {
    for (const auto& d : out.diags) log_diag(d);
    for (const auto& a : out.alerts) std::cout << format_log_line(a) << std::endl;
    for (const auto& d : recorder.on_feed(engine.series(), engine.ue_table(), out)) log_diag(d);
  };
  // 입력 침묵 감시용 — 마지막으로 저장된 kpm2(어느 셀이든)의 벽시계 시각과 '이미 알렸음' 표시 (3_ §8, 이슈 #50). 소켓 모드만 본다
  std::optional<std::chrono::steady_clock::time_point> last_kpm2;
  bool silent_flagged = false;
  // 줄 하나 처리: 엔진 → 내보내기. kpm2가 저장되면 침묵 시계를 되감고 표시를 내린다
  auto handle = [&](std::string_view line) {
    EngineOutput out = engine.feed_line(line);
    if (out.outcome == FeedOutcome::Stored) {
      last_kpm2 = std::chrono::steady_clock::now();
      silent_flagged = false;
    }
    emit(out);
  };

  int rc = 0;
  if (!args.replay_path.empty()) {
    log_err("INFO", "replay " + args.replay_path +
                        (args.speed > 0 ? " speed=" + std::to_string(args.speed) : std::string(" speed=max")));
    ReplayOptions ro;
    ro.speed = args.speed;
    ro.max_line_bytes = cfg.max_line_bytes;
    ro.stop = &g_stop;
    if (!start_sink()) return 1;
    ReplayResult rr = replay_file(args.replay_path, ro, handle);
    for (const auto& e : rr.events) log_err("WARN", e);
    if (!rr.ok) {
      log_err("ERROR", rr.error);
      rc = 1;
    } else {
      log_err("INFO", "replay done lines=" + std::to_string(rr.lines) + " skipped=" + std::to_string(rr.skipped));
    }
  } else {
    UdsServer server(cfg.socket_path, cfg.max_line_bytes);
    if (!server.open()) {
      log_err("ERROR", server.error());
      return 1;
    }
    if (!start_sink()) {
      server.close();
      return 1;
    }
    {
      for (const auto& e : server.take_events()) log_err("INFO", e);
      // 신호가 올 때까지 받는다. poll 대기 200 ms마다 종료 여부를 본다 (결정 G7)
      while (!g_stop.load()) {
        if (!server.poll_once(200, handle)) {
          log_err("ERROR", server.error());
          rc = 1;
          break;
        }
        for (const auto& e : server.take_events()) log_err("INFO", e);
        // 입력 침묵 (3_ §8, 14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 벽시계로 마지막 저장 kpm2 뒤 input_silent_ms 동안 kpm2가 없으면
        // 진단 input_silent 1회와 1·2단계 진행 중 경보 END(reason=input_silent). 셀 시계·버퍼·기준선·상태표는 그대로 두고, 다시
        // kpm2가 저장될 때까지 반복하지 않는다. 첫 kpm2 전에는 감시하지 않고, 재생 모드에서는 하지 않는다(결정성)
        if (last_kpm2 && !silent_flagged) {
          const int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now() - *last_kpm2)
                                      .count();
          if (elapsed >= cfg.input_silent_ms) {
            silent_flagged = true;
            emit(engine.on_input_silent(elapsed));
          }
        }
      }
      server.close();  // 소켓 파일 삭제
      log_err("INFO", "socket closed");
    }
  }

  // 종료 (결정 G7): 전달 스레드가 큐에 남은 레코드를 다 쓴 뒤 끝낸다
  sink.stop();
  if (cfg.evidence.mode != EvidenceMode::Off && rc == 0)
    log_err("INFO", "evidence written=" + std::to_string(sink.written()) + " to " + cfg.evidence.out_path);
  return rc;
}
