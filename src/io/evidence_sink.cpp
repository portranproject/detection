#include "detect/io/evidence_sink.h"

#include <utility>

namespace detect {

EvidenceSink::EvidenceSink(EvidenceQueue& queue, std::string path, RotateOptions rotate, FileOps ops)
    : queue_(queue), file_(std::move(path), rotate, std::move(ops)) {}

EvidenceSink::~EvidenceSink() { stop(); }

bool EvidenceSink::start() {
  // 이어 쓰기 — 다시 기동해도 이전 증거가 지워지지 않게 (결정 F8). 버퍼 없이 write(2)로 쓴다 (11/05 W-33).
  // 연 파일 끝이 반쪽 줄이면 첫 레코드 전에 회전한다 (29_ §2.4 — 회전 파일이 맡음)
  if (!file_.open()) return false;
  th_ = std::thread([this] { run(); });
  return true;
}

void EvidenceSink::stop() {
  queue_.close();
  if (th_.joinable()) th_.join();
  file_.close();
}

// 스레드 B 본체: 꺼낸 레코드를 한 줄씩 write(2)로 쓴다. 판정 쪽(스레드 A)과는 큐로만 이어진다 — 쓰기가 느려도 A는 기다리지 않는다
// (1_ NFR-6). 쓰기 직전의 회전과 쓰기 오류 뒤 처리는 회전 파일이 한다 (29_ §2): 회전 끔이면 오류 뒤 그 실행 동안 멈추고
// (3_ §7.1, 11/05 W-33), 회전 켬이면 60초마다 새 파일로 다시 해 본다. 쓰지 못한 레코드(오류가 난 레코드 포함)는 버린 수로 센다
void EvidenceSink::run() {
  EvidenceRecord rec;
  std::string buf;
  while (queue_.pop(rec)) {
    buf.assign(rec.line);
    buf += '\n';
    const RotatingFile::WriteResult r = file_.write(buf);
    if (r.skipped || r.err != 0) {
      ++dropped_;
      file_.note_dropped(1);
      continue;
    }
    ++written_;
  }
}

}  // namespace detect
