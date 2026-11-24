#!/usr/bin/env bash
# 一键自检：规则/恢复/退役/共享池测试 + 并发压力 + 演示确定性 + 重演交叉核对
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1/7 规则测试 =="
python3 -I tests/test_station.py

echo "== 2/7 档案恢复测试 =="
python3 -I tests/test_restore.py

echo "== 3/7 档案退役测试 =="
python3 -I tests/test_retire.py

echo "== 4/7 共享块池测试 =="
python3 -I tests/test_shared_pool.py

echo "== 5/7 跨进程并发压力 =="
python3 -I tests/test_concurrency.py

echo "== 6/7 端到端演示（可重复） =="
rm -rf /tmp/bfs_report_1.json /tmp/bfs_journal_1.jsonl /tmp/bfs_archives_1 \
  /tmp/bfs_restore_recheck /tmp/bfs_restore_out.json
python3 -I demo/run_demo.py >/dev/null
cp run/demo_report.json /tmp/bfs_report_1.json
cp run/demo_data/journal.jsonl /tmp/bfs_journal_1.jsonl
cp -r run/demo_archives /tmp/bfs_archives_1
python3 -I demo/run_demo.py >/dev/null
diff -q /tmp/bfs_report_1.json run/demo_report.json
diff -q /tmp/bfs_journal_1.jsonl run/demo_data/journal.jsonl
diff -rq /tmp/bfs_archives_1 run/demo_archives
echo "确定性核对通过：两次运行逐字节一致（报告、日志、恢复档案）"

# 共享池演示可重复运行且终态确定（库存清零、孤立对象被清扫）
python3 -I demo/run_shared_pool_demo.py >/dev/null
python3 -I demo/run_shared_pool_demo.py >/dev/null
echo "共享池演示通过：跨批次去重、按批退役、末关联释放与崩溃对账均正确"

echo "== 7/7 重演交叉核对 =="
python3 -I run.py verify --data-dir run/demo_data
# 演示结尾已退役 ARC-INSTR-FULL：restore 跳过退役档案，ARC-PENDING-B5
# 仍缺块使 restore 返回业务码 2（非致命），仅 ARC-INSTR-B14 落地
set +e
python3 -I run.py restore --data-dir run/demo_data \
  --output-dir /tmp/bfs_restore_recheck > /tmp/bfs_restore_out.json
restore_code=$?
set -e
if [ "$restore_code" -ne 2 ]; then
  echo "restore 退出码应为 2（存在缺块档案），实际 $restore_code"
  exit 1
fi
python3 -I - <<'PY'
import json
with open("/tmp/bfs_restore_out.json", encoding="utf-8") as fh:
    out = json.load(fh)
assert out["archives_declared"] == 3
assert out["archives_published"] == 1
assert out["archives_blocked"] == 1
assert out["archives_retired"] == 1
states = {r["archive_id"]: r["state"] for r in out["results"]}
assert states["ARC-INSTR-FULL"] == "retired"
assert states["ARC-INSTR-B14"] == "published"
assert states["ARC-PENDING-B5"] == "blocked"
blocked = out["results"][2]
assert blocked["missing_block_ids"] == ["b5"]
print("restore 退出码与退役/缺块报告语义正确：1 发布 / 1 退役跳过 / 1 挡下并报告 b5")
PY
diff -rq /tmp/bfs_restore_recheck run/demo_archives
echo "恢复重演核对通过：独立恢复结果与演示发布逐字节一致"
echo "全部自检通过"
