// 퍼즈 하네스 — parse_line (2_ §1 줄 길이 상한·§2 공통 필드·§3 hello·§4 kpm2·§6 ue_evt; 16_ W-19 — 이슈 #52).
// 입력 바이트 전체를 줄 하나로 넘긴다. 보는 것은 크래시·UB·누수(Sanitizer)와 결과 계약이다 —
//  - Ok: common·msg가 있고 error가 비며 msg 종류가 type과 맞음
//  - UnknownType: common은 있고 msg·error가 빔 / UnsupportedVersion: common·error 있음, msg 없음
//  - LineTooLong·FormatError: msg·warnings가 비고 error가 있음
//  - 같은 입력은 같은 결과(결정성), 상한보다 긴 줄은 LineTooLong
// 판정의 옳고 그름(값이 맞는지)은 단위 테스트(test_message)의 몫이다.
// libFuzzer(clang -fsanitize=fuzzer)로 링크하거나, 없으면 standalone_main.cpp가 main을 준다
#include "detect/message.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>

using namespace detect;

namespace {

[[noreturn]] void fail(const char* what) {
  std::fprintf(stderr, "fuzz_parse_line: contract violated: %s\n", what);
  std::abort();
}

void check(const ParseResult& r) {
  const bool has_msg = r.msg.index() != 0;
  switch (r.status) {
    case ParseStatus::Ok: {
      if (!r.common || !has_msg || !r.error.empty()) fail("Ok without common/msg, or with error");
      const std::string& t = r.common->type;
      const std::size_t want = t == "hello" ? 1 : t == "kpm2" ? 2 : t == "ue_evt" ? 3 : t == "f1_evt" ? 4 : 0;
      if (r.msg.index() != want) fail("Ok msg kind does not match type");
      break;
    }
    case ParseStatus::UnknownType:
      if (!r.common || has_msg || !r.error.empty()) fail("UnknownType shape");
      break;
    case ParseStatus::UnsupportedVersion:
      if (!r.common || has_msg || r.error.empty()) fail("UnsupportedVersion shape");
      break;
    case ParseStatus::LineTooLong:
    case ParseStatus::FormatError:
      if (has_msg || r.error.empty() || !r.warnings.empty()) fail("error status shape");
      break;
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
  const std::string_view line(reinterpret_cast<const char*>(data), size);
  const ParseResult a = parse_line(line);
  check(a);
  const ParseResult b = parse_line(line);  // 결정성
  if (a.status != b.status || a.error != b.error || a.warnings != b.warnings || a.msg.index() != b.msg.index())
    fail("not deterministic");
  const ParseResult s = parse_line(line, 64);  // 작은 상한 — LineTooLong 경로 (2_ §1)
  check(s);
  if (size > 64 && s.status != ParseStatus::LineTooLong) fail("line over limit is not LineTooLong");
  return 0;
}
