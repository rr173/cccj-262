#!/usr/bin/env bash
# 一键自检：规则测试 + 并发压力 + 演示确定性 + 重演交叉核对
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1/4 规则测试 =="
python3 -I tests/test_station.py

echo "== 2/4 跨进程并发压力 =="
python3 -I tests/test_concurrency.py

echo "== 3/4 端到端演示（可重复） =="
python3 -I demo/run_demo.py >/dev/null
cp run/demo_report.json /tmp/bfs_report_1.json
cp run/demo_data/journal.jsonl /tmp/bfs_journal_1.jsonl
python3 -I demo/run_demo.py >/dev/null
diff -q /tmp/bfs_report_1.json run/demo_report.json
diff -q /tmp/bfs_journal_1.jsonl run/demo_data/journal.jsonl
echo "确定性核对通过：两次运行逐字节一致"

echo "== 4/4 重演交叉核对 =="
python3 -I run.py verify --data-dir run/demo_data
echo "全部自检通过"
