// 퍼즈 하네스 — UdsServer::on_data 줄 분리 + Engine::feed_line 전체 경로 (2_ §1 줄 길이 상한·결정 G5, 4_ §3 처리 흐름;
// 16_ W-19 — 이슈 #52). 입력 바이트를 첫 바이트가 정한 크기(1~200)의 뭉치로 나눠 소켓 없이 on_data에 넣는다 —
// 부분 줄·줄 상한(4,096) 초과·다음 줄바꿈까지 버리기 경로가 걸린다. 줄은 실행 파일과 같은 룰(기본 설정)이 든 엔진과 증거 기록기
// (작은 큐 — 넘침 경로)로 가고, 끝에 입력 침묵(3_ §8)도 한 번 넣는다. 보는 것은 크래시·UB·누수·멈춤뿐이고 판정의 옳고
// 그름은 보지 않는다(그것은 시나리오 시험의 몫)
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/io/uds_server.h"
#include "detect/rules/auth_stall.h"
#include "detect/rules/blind_dos.h"
#include "detect/rules/bts_variant.h"
#include "detect/rules/cap_hijack.h"
#include "detect/rules/imsi_extractor.h"
#include "detect/rules/nas_desync.h"
#include "detect/rules/identity_request.h"
#include "detect/rules/sec_reauth.h"
#include "detect/rules/sync_failure.h"
#include "detect/rules/uplink_dos.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

using namespace detect;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  constexpr std::size_t kMaxLine = 4096;
  Engine engine(SeriesConfig{}, kMaxLine, UeTableConfig{});
  engine.add_rule(std::make_unique<BtsVariantRule>());
  engine.add_ue_rule(std::make_unique<BlindDosRule>());
  engine.add_ue_rule(std::make_unique<AuthStallRule>());
  engine.add_ue_rule(std::make_unique<UplinkDosRule>());
  engine.add_ue_rule(std::make_unique<ImsiExtractorRule>());
  engine.add_ue_rule(std::make_unique<CapHijackRule>());
  engine.add_ue_rule(std::make_unique<NasDesyncRule>());
  engine.add_ue_rule(std::make_unique<SyncFailureRule>());
  engine.add_ue_rule(std::make_unique<SecReauthRule>());
  engine.add_ue_rule(std::make_unique<IdentityRequestRule>());
  EvidenceQueue queue(16);
  EvidenceRecorder recorder(EvidenceConfig{}, queue);
  UdsServer server("fuzz-no-socket", kMaxLine);  // open()을 부르지 않는다 — 소켓·파일을 만들지 않음

  const auto handle = [&](std::string_view line) {
    const EngineOutput out = engine.feed_line(line);
    recorder.on_feed(engine.series(), engine.ue_table(), out);
  };
  const std::size_t step = size == 0 ? 1 : 1 + data[0] % 200;
  for (std::size_t i = 0; i < size; i += step)
    server.on_data(reinterpret_cast<const char*>(data) + i, std::min(step, size - i), handle);
  server.take_events();
  recorder.on_feed(engine.series(), engine.ue_table(), engine.on_input_silent(1));
  return 0;
}
