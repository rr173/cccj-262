#!/usr/bin/env python3
"""共享块池端到端演示（固定内容，离线可重复）。

故事线：
  两个独立采集批次 BATCH-A / BATCH-B 各自开账、各有独立许可/收据/额度，
  它们配置到同一个共享块池，且收到一块内容完全相同但 block_id 不同的数据；
  池中该内容只占一份物理存储，却分别挂着两个批次的关联。
  - pool-inventory 按内容列出库存、关联批次与存储占用；
  - 批次 A 档案退役只撤销 A 自己的关联，独占对象被释放、共享对象保留，
    批次 B 的档案仍可正常恢复；
  - 批次 B 退役后，共享对象失去最后关联，物理存储才被释放；
  - 崩溃对账：手工制造孤立对象，下次持锁打开自动清扫。
"""
from __future__ import annotations

import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backfill_station.canonical import canonical_json, digest_payload  # noqa: E402
from backfill_station.shared_pool import SharedBlockPool  # noqa: E402
from backfill_station.station import Station  # noqa: E402

HMAC_KEY = b"demo-shared-pool-key-0123456789ab"
RUN_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "run")
POOL_DIR = os.path.join(RUN_ROOT, "demo_shared_pool")


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def make_manifest(batch_id: str, blocks: dict[str, bytes],
                  archives: list[dict], pool_dir: str) -> dict:
    return {
        "batch_id": batch_id,
        "quota_bytes": 1_000_000,
        "blocks": [{"block_id": bid, "length": len(data),
                    "sha256": digest_payload(data)}
                   for bid, data in sorted(blocks.items())],
        "archives": archives,
        "shared_pool": {"path": pool_dir},
    }


def deliver(st: Station, permit_id: str, block_id: str, data: bytes) -> None:
    r = st.grant_permit(permit_id, block_id, len(data))
    assert r.ok, r.detail
    r = st.submit_block(permit_id, block_id, data)
    assert r.ok, r.detail


def main() -> int:
    shutil.rmtree(POOL_DIR, ignore_errors=True)
    tmp_root = os.path.join(RUN_ROOT, "demo_pool_batches")
    shutil.rmtree(tmp_root, ignore_errors=True)
    os.makedirs(RUN_ROOT, exist_ok=True)

    # 跨批次的相同内容（block_id 不同：A 批叫 ax，B 批叫 by）。
    shared = b"common-instrument-calibration-block" * 6
    only_a = b"alpha-only-telemetry" * 5
    only_b = b"bravo-only-telemetry" * 5
    arc_a_bytes = shared + only_a
    arc_b_bytes = shared + only_b

    dir_a = os.path.join(tmp_root, "batch_a")
    dir_b = os.path.join(tmp_root, "batch_b")
    out_a = os.path.join(tmp_root, "out_a")
    out_b = os.path.join(tmp_root, "out_b")

    manifest_a = make_manifest(
        "BATCH-A", {"ax": shared, "aonly": only_a},
        [{"archive_id": "ARC-A", "path": "a/instrument.dat",
          "block_ids": ["ax", "aonly"], "length": len(arc_a_bytes),
          "sha256": digest_payload(arc_a_bytes)}], POOL_DIR)
    manifest_b = make_manifest(
        "BATCH-B", {"by": shared, "bonly": only_b},
        [{"archive_id": "ARC-B", "path": "b/instrument.dat",
          "block_ids": ["by", "bonly"], "length": len(arc_b_bytes),
          "sha256": digest_payload(arc_b_bytes)}], POOL_DIR)

    banner("阶段一：两个独立批次开账并交付（共享同一池，含同内容块）")
    Station.initialize(dir_a, manifest_a, HMAC_KEY)
    Station.initialize(dir_b, manifest_b, HMAC_KEY)
    with Station(dir_a).open() as st:
        deliver(st, "PA1", "ax", shared)
        deliver(st, "PA2", "aonly", only_a)
        print("  A 批报告 shared_pool:",
              canonical_json(st.report()["shared_pool"]))
    with Station(dir_b).open() as st:
        deliver(st, "PB1", "by", shared)
        deliver(st, "PB2", "bonly", only_b)

    pool = SharedBlockPool(POOL_DIR)
    inv = pool.inventory()
    print(f"  池库存：{inv['objects_total']} 个内容对象 / "
          f"{inv['links_total']} 条批次关联 / "
          f"{inv['objects_occupying_storage']} 个占用存储")
    on_disk = sorted(os.listdir(os.path.join(POOL_DIR, "objects")))
    print("  物理对象文件:", on_disk)
    assert inv["objects_total"] == 3 and inv["links_total"] == 4
    assert len(on_disk) == 3  # 同内容只存一份
    shared_item = next(o for o in inv["objects"]
                       if o["sha256"] == digest_payload(shared))
    print("  共享内容关联:",
          sorted((l["batch_id"], l["block_id"]) for l in shared_item["links"]))

    banner("阶段二：各批独立恢复（结果只由本批清单决定）")
    with Station(dir_a).open() as st:
        ra = st.restore_archives(out_a)
    with Station(dir_b).open() as st:
        rb = st.restore_archives(out_b)
    assert ra["ok"] and rb["ok"]
    with open(os.path.join(out_a, "a", "instrument.dat"), "rb") as fh:
        assert fh.read() == arc_a_bytes
    with open(os.path.join(out_b, "b", "instrument.dat"), "rb") as fh:
        assert fh.read() == arc_b_bytes
    print("  两批档案各自原子发布，内容互不串用")

    banner("阶段三：批次 A 退役——只撤销 A 的关联，B 仍可恢复")
    with Station(dir_a).open() as st:
        rr = st.retire_archives(["ARC-A"], out_a)
    print("  撤销关联:", canonical_json(rr["pool_links_released"]))
    print("  物理释放对象:", rr["pool_objects_deleted"])
    inv2 = pool.inventory()
    digests = {o["sha256"] for o in inv2["objects"]}
    assert digest_payload(shared) in digests          # 共享对象保留
    assert digest_payload(only_a) not in digests      # A 独占对象释放
    fresh_b = os.path.join(tmp_root, "out_b_fresh")
    with Station(dir_b).open() as st:
        rb2 = st.restore_archives(fresh_b)
    assert rb2["ok"]
    with open(os.path.join(fresh_b, "b", "instrument.dat"), "rb") as fh:
        assert fh.read() == arc_b_bytes
    print("  B 批档案在 A 退役后仍正常恢复到全新输出目录")

    banner("阶段四：批次 B 退役——共享对象失去最后关联后释放存储")
    with Station(dir_b).open() as st:
        rr2 = st.retire_archives(["ARC-B"], fresh_b)
    inv3 = pool.inventory()
    print("  剩余对象:", inv3["objects_total"],
          " 剩余关联:", inv3["links_total"])
    assert inv3["objects_total"] == 0 and inv3["links_total"] == 0
    assert os.listdir(os.path.join(POOL_DIR, "objects")) == []

    banner("阶段五：崩溃对账——孤立对象下次打开自动清扫")
    orphan = os.path.join(POOL_DIR, "objects", "ef" * 32 + ".bin")
    os.makedirs(os.path.dirname(orphan), exist_ok=True)
    with open(orphan, "wb") as fh:
        fh.write(b"stale")
    pool.inventory()  # 持锁打开即对账
    assert not os.path.exists(orphan)
    print("  孤立对象已清扫；池库存恢复一致")

    report_path = os.path.join(RUN_ROOT, "demo_pool_inventory.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(pool.inventory(), indent=2,
                            ensure_ascii=False, sort_keys=True))
        fh.write("\n")
    print(f"\n演示完成，最终库存报告已写 {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
