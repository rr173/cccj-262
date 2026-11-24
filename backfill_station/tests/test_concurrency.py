#!/usr/bin/env python3
"""跨进程并发压力测试：多个采集进程抢同一批额度。

断言：
1. 成功发放的许可封顶之和永远 <= 额度（无超支）；
2. 同一许可 ID 不会被两个进程同时启用；
3. 重放报告与实时报告完全一致，事件流全序确定。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backfill_station.canonical import canonical_json, digest_payload  # noqa: E402
from backfill_station.station import Station  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_PY = os.path.join(ROOT, "run.py")
KEY = "concurrency-hmac-key-0123456789"
N_PROCESSES = 12
PERMIT_CAP = 100
# 清单块长必须等于许可封顶（100），12 块全长 1200。
# 批次额度只给 200：清单允许（缺口留待后续账期回补），
# 运行时恰好只够 2 个在手许可（2*100=200，可用归零），
# 其余 10 个申请必须被准入拒绝。
QUOTA = 200


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="bfs_concurrency_")
    try:
        data_dir = os.path.join(tmp, "data")
        blocks = {f"b{i}": bytes([i]) * PERMIT_CAP
                  for i in range(N_PROCESSES)}
        manifest = {
            "batch_id": "BATCH-CONCURRENCY",
            "quota_bytes": QUOTA,
            "blocks": [
                {"block_id": bid, "length": len(data),
                 "sha256": digest_payload(data)}
                for bid, data in sorted(blocks.items())
            ],
        }
        Station.initialize(data_dir, manifest, KEY.encode())

        req_dir = os.path.join(tmp, "reqs")
        os.makedirs(req_dir)
        req_paths = []
        for i in range(N_PROCESSES):
            pid = f"PC{i:02d}"
            path = os.path.join(req_dir, f"{pid}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"permit_id": pid, "block_id": f"b{i}",
                           "cap": PERMIT_CAP}, fh)
            req_paths.append(path)

        # 同时拉起 12 个独立进程，全部撞同一把文件锁
        procs = [
            subprocess.Popen(
                [sys.executable, "-I", RUN_PY, "grant",
                 "--data-dir", data_dir, "--request", path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for path in req_paths
        ]
        granted, denied = [], []
        for proc, path in zip(procs, req_paths):
            out, err = proc.communicate(timeout=60)
            if proc.returncode not in (0, 2):
                print("意外退出:", proc.returncode, err)
                return 1
            result = json.loads(out)
            pid = os.path.basename(path).split(".")[0]
            (granted if result["ok"] else denied).append(pid)

        report = subprocess.run(
            [sys.executable, "-I", RUN_PY, "report", "--data-dir", data_dir],
            capture_output=True, text=True, check=True)
        live = json.loads(report.stdout)
        replay = subprocess.run(
            [sys.executable, "-I", RUN_PY, "replay", "--data-dir", data_dir],
            capture_output=True, text=True, check=True)
        replayed = json.loads(replay.stdout)
        replayed.pop("replay_only")

        qa = live["quota_account"]
        checks = [
            ("成功许可数恰好 2", len(granted) == 2),
            ("拒绝许可数恰好 10", len(denied) == 10),
            (f"义务 {qa['obligations_total']} <= 额度 {QUOTA}",
             qa["obligations_total"] <= QUOTA),
            ("封顶保留等于 200（额度用满）",
             qa["reserved_open_caps"] == QUOTA),
            ("可用额度为 0", qa["available"] == 0),
            ("重放与实时报告一致", replayed == live),
            ("不变量成立", qa["invariant_holds"]),
        ]
        ok = True
        for name, passed in checks:
            print(("PASS" if passed else "FAIL"), "-", name)
            ok = ok and passed
        print("发放:", sorted(granted))
        print("拒绝:", sorted(denied))
        print(canonical_json({"quota_account": qa}))
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
