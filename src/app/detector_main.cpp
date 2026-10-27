// 탐지 엔진 실행 파일 (4_ §2 app, §3 처리 흐름, §5 배포).
//   detector --socket PATH [--config FILE]                  분석 엔진의 KPM을 Unix 소켓으로 받는다 (2_ §1)
//   detector --replay FILE [--speed max|N] [--config FILE]  .jsonl을 재생한다 (1_ FR-2)
// 스레드 A(이 main): 입력 → 엔진(파싱·저장·판정) → 경보 로그 → 증거 레코드를 큐에 넣기
// 스레드 B(EvidenceSink): 큐에서 꺼내 증거 파일에 쓰기 (3_ §7.1 동시성 모델)
#include "detect/config.h"
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/io/evidence_sink.h"
#include "detect/io/file_replay.h"
#include "detect/io/uds_server.h"
#include "detect/rules/bts_variant.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
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
  if (auto it = cfg.rules.find(BtsVariantRule::kId); it != cfg.rules.end()) {
    BtsVariantConfigResult br = parse_bts_variant_config(it->second);
    for (const auto& w : br.warnings) log_err("WARN", w);
    if (!br.ok) {
      log_err("ERROR", br.error);
      return 1;
    }
    bts = br.config;
  }
  for (const auto& [id, _] : cfg.rules)
    if (id != BtsVariantRule::kId) log_err("WARN", "unknown rule id rules." + id + " (ignored)");

  // 엔진·룰·증거 (4_ §3). 버퍼 크기는 W와 pre_slots에서 정한다 (3_ §3·§7.1)
  SeriesConfig scfg;
  scfg.window_ms = bts.window_ms;
  scfg.h_hold_ms = bts.h_hold_ms;              // 입력 건전성은 series가 (Q-46, 결정 J5)
  scfg.missing_key_slots = bts.missing_key_slots;
  scfg.pre_slots = cfg.evidence.pre_slots;
  Engine engine(scfg, cfg.max_line_bytes);
  engine.add_rule(std::make_unique<BtsVariantRule>(bts));

  EvidenceQueue queue(cfg.evidence.queue_max);
  EvidenceRecorder recorder(cfg.evidence, queue);
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

  // 줄 하나 처리 (스레드 A): 엔진 → 경보는 stdout에 3_ §7 형식 그대로, 진단은 stderr (결정 G1) → 증거 기록
  auto handle = [&](std::string_view line) {
    EngineOutput out = engine.feed_line(line);
    for (const auto& d : out.diags) log_diag(d);
    for (const auto& a : out.alerts) std::cout << format_log_line(a) << std::endl;
    for (const auto& d : recorder.on_feed(engine.series(), out)) log_diag(d);
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
