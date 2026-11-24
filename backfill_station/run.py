#!/usr/bin/env python3
"""项目根入口：保证 `python3 -I run.py ...` 也能找到本地包。

隔离模式（-I）下 sys.path 不含当前目录，因此显式注入项目根，
避免依赖 PYTHONPATH，同时杜绝从任意工作目录误载同名包。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backfill_station.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
