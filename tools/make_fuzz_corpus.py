#!/usr/bin/env python3
"""libFuzzer용 시드 코퍼스 만들기 (16_ W-19 — 이슈 #52). tests/data/**/*.jsonl에서

  <out>/parse_line/<sha1 앞 16자리>  고유 줄 하나 = 파일 하나 (fuzz_parse_line)
  <out>/uds_lines/<파일 이름>        .jsonl 파일 하나 = 입력 하나 (fuzz_uds_lines)

실행: python3 tools/make_fuzz_corpus.py build-fuzz/corpus [--data tests/data]
독립 실행 모드(GCC, standalone_main.cpp)는 .jsonl을 바로 읽으므로 이 도구가 필요 없다. 표준 라이브러리만 쓴다
"""

import argparse
import hashlib
import os
import shutil
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--data", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data"))
    a = ap.parse_args()
    lines_dir = os.path.join(a.out, "parse_line")
    files_dir = os.path.join(a.out, "uds_lines")
    os.makedirs(lines_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)
    n_lines = n_files = 0
    for root, _, names in os.walk(a.data):
        for name in sorted(names):
            if not name.endswith(".jsonl"):
                continue
            src = os.path.join(root, name)
            shutil.copyfile(src, os.path.join(files_dir, name))
            n_files += 1
            with open(src, "rb") as f:
                for line in f:
                    line = line.rstrip(b"\n")
                    p = os.path.join(lines_dir, hashlib.sha1(line).hexdigest()[:16])
                    if not os.path.exists(p):
                        with open(p, "wb") as g:
                            g.write(line)
                        n_lines += 1
    print(f"corpus: {n_lines} unique lines -> {lines_dir}, {n_files} files -> {files_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
