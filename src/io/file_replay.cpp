#include "detect/io/file_replay.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <thread>

namespace detect {

long long find_t_end_ms(std::string_view line) {
  static constexpr std::string_view key = "\"t_end_ms\":";
  const std::size_t p = line.find(key);
  if (p == std::string_view::npos) return -1;
  std::size_t i = p + key.size();
  while (i < line.size() && line[i] == ' ') ++i;
  long long v = 0;
  bool any = false;
  while (i < line.size() && line[i] >= '0' && line[i] <= '9') {
    v = v * 10 + (line[i] - '0');
    ++i;
    any = true;
  }
  return any ? v : -1;
}

// 재생 (결정 G2): 최대 속도면 바로 넘기고, N배속이면 kpm2의 t_end_ms 간격을 N으로 나눈 만큼 기다린다.
// 구간이 끝나는 시각에 그 줄이 오는 분석 엔진 동작(2_ §4)을 흉내 낸 것이다. hello처럼 t_end_ms가 없는 줄은 기다리지 않는다
ReplayResult replay_file(const std::string& path, const ReplayOptions& opt,
                         const std::function<void(std::string_view)>& on_line) {
  ReplayResult r;
  std::ifstream in(path);
  if (!in) {
    r.error = "cannot open " + path;
    return r;
  }
  using clock = std::chrono::steady_clock;
  const clock::time_point wall0 = clock::now();
  long long data0 = -1;
  std::string line;
  while (std::getline(in, line)) {
    if (opt.stop && opt.stop->load()) break;
    if (line.size() > opt.max_line_bytes) {
      ++r.skipped;
      r.events.push_back("line exceeds " + std::to_string(opt.max_line_bytes) + " bytes, skipped");
      continue;
    }
    if (opt.speed > 0) {
      const long long t = find_t_end_ms(line);
      if (t >= 0) {
        if (data0 < 0) data0 = t;
        const auto due = wall0 + std::chrono::duration_cast<clock::duration>(
                                     std::chrono::duration<double, std::milli>((t - data0) / opt.speed));
        // 멈춤 요청을 볼 수 있게 잘게 나눠 잔다
        while (clock::now() < due) {
          if (opt.stop && opt.stop->load()) break;
          std::this_thread::sleep_for(std::min<clock::duration>(due - clock::now(), std::chrono::milliseconds(50)));
        }
      }
    }
    on_line(line);
    ++r.lines;
  }
  r.ok = true;
  return r;
}

}  // namespace detect
