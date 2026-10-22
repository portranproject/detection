#pragma once
// .jsonl 재생 (1_ FR-2, 3_ §3): 합성·CU 로그 변환·분석 엔진 녹화 파일을 입력으로 넣는다.
// 룰은 데이터 시각만 쓰므로 최대 속도로 재생해도 결과가 같다 (T20).

#include <atomic>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace detect {

struct ReplayOptions {
  double speed = 0;                    // 0 = 최대 속도, N > 0 = N배속(1 = 실시간) — 결정 G2
  std::size_t max_line_bytes = 65536;  // 2_ §1 — 넘는 줄은 건너뛴다
  const std::atomic<bool>* stop = nullptr;  // 참이 되면 멈춘다 (신호 처리, 결정 G7)
};

struct ReplayResult {
  bool ok = false;
  std::string error;
  std::size_t lines = 0;    // 넘긴 줄 수
  std::size_t skipped = 0;  // 길이 상한을 넘어 건너뛴 줄 수
  std::vector<std::string> events;
};

ReplayResult replay_file(const std::string& path, const ReplayOptions& opt,
                         const std::function<void(std::string_view)>& on_line);

// 줄에서 "t_end_ms" 값을 꺼낸다(없으면 -1). 배속 재생의 간격 계산용 — 전체 파싱은 엔진이 한다
long long find_t_end_ms(std::string_view line);

}  // namespace detect
