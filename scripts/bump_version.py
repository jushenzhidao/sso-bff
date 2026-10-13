#!/usr/bin/env python3
"""把版本号写回 sso_bff/__init__.py 的 __version__（发版流水线用）。

版本号的唯一真相是 git tag；本脚本负责让代码里的常量与 tag 保持一致，
这样镜像内自报的版本（FastAPI 的 OpenAPI info.version 走 __version__）不会漂移。

用法：
  python scripts/bump_version.py 1.2.3            # 写回
  python scripts/bump_version.py 1.2.3 --check    # 只校验，不写入（本地干跑用）

退出码：0 成功/无需变更；1 --check 不匹配；2 版本号格式错；3 正则未命中或命中多处。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "sso_bff" / "__init__.py"
PATTERN = re.compile(r'^(__version__\s*=\s*)"[^"]*"', re.MULTILINE)


def main() -> int:
    ap = argparse.ArgumentParser(description="写回 sso_bff 版本号")
    ap.add_argument("version", help="目标版本号，不带 v 前缀（X.Y.Z）")
    ap.add_argument("--check", action="store_true", help="只校验当前值，不写入")
    args = ap.parse_args()

    version = args.version.lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"ERROR: 版本号必须是 X.Y.Z，收到 {version!r}", file=sys.stderr)
        return 2

    src = TARGET.read_text(encoding="utf-8")
    hits = PATTERN.findall(src)
    if len(hits) != 1:
        # 0 处 = 常量被改名；多处 = 正则太宽。两种情况都必须报错，不能猜。
        print(f"ERROR: {TARGET} 中 __version__ 命中 {len(hits)} 处（应为 1）", file=sys.stderr)
        return 3

    current = PATTERN.search(src).group(0).split('"')[1]
    if current == version:
        print(f"already at {version} -- no change")
        return 0
    if args.check:
        print(f"CHECK FAILED: 当前 {current}，期望 {version}", file=sys.stderr)
        return 1

    TARGET.write_text(PATTERN.sub(lambda m: f'{m.group(1)}"{version}"', src), encoding="utf-8")
    print(f"bumped {current} -> {version} ({TARGET.relative_to(ROOT)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
