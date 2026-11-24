"""共享块池规则测试（仅标准库 unittest，离线运行）。

覆盖需求：
- 共享池为可选配置：未配置的批次与旧批次继续只用本地 blocks/ 仓库；
- 配置到同一池的批次按内容（SHA-256）复用物理对象，即使 block_id 不同；
- 各批次许可/收据/额度/交付状态完全独立，恢复结果只由本批清单决定；
- 按内容查看库存：对象关联哪些批次、是否仍占用存储；
- 退役/清理只撤销本批关联，其他批次档案仍可恢复；最后关联撤销才释放存储；
- 重启与并发更新不丢失已确认关联（池日志 + 文件锁 + 幂等）；
- 崩溃对账：孤立对象清扫、缺失对象硬失败、残留关联 GC；
- CLI 退出码与 replay/verify 一致性。
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backfill_station.canonical import digest_payload  # noqa: E402
from backfill_station.block_store import BlockStore  # noqa: E402
from backfill_station.journal import Journal  # noqa: E402
from backfill_station.manifest import Manifest, ManifestError  # noqa: E402
from backfill_station.shared_pool import (  # noqa: E402
    POOL_JOURNAL_NAME, SharedBlockPool, SharedPoolError)
from backfill_station.station import Station  # noqa: E402

KEY = b"unit-test-hmac-key-0123456789ab"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_PY = os.path.join(ROOT, "run.py")


def block_entry(bid: str, data: bytes) -> dict:
    return {"block_id": bid, "length": len(data),
            "sha256": digest_payload(data)}


def archive_entry(aid: str, path: str, block_ids: list[str],
                  data: bytes) -> dict:
    return {"archive_id": aid, "path": path, "block_ids": block_ids,
            "length": len(data), "sha256": digest_payload(data)}


class PoolTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="bfs_pool_")
        self.pool_dir = os.path.join(self.tmp, "shared_pool")
        # 两份不同 block_id 但内容完全相同的字节，外加各自独占内容。
        self.shared = b"identical-content-bytes-" * 8
        self.uniq1 = b"batch-one-unique-bytes" * 4
        self.uniq2 = b"batch-two-unique-bytes" * 4

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def manifest(self, batch_id: str, blocks: dict[str, bytes],
                 *, archives: list[dict] | None = None,
                 use_pool: bool = True,
                 pool_path: str | None = None) -> dict:
        raw = {
            "batch_id": batch_id,
            "quota_bytes": 1_000_000,
            "blocks": [block_entry(b, d) for b, d in sorted(blocks.items())],
        }
        if use_pool:
            raw["shared_pool"] = {"path": pool_path or self.pool_dir}
        if archives is not None:
            raw["archives"] = archives
        return raw

    def init(self, data_dir: str, manifest: dict) -> Station:
        return Station.initialize(data_dir, manifest, KEY)

    def deliver(self, st: Station, permit_id: str, block_id: str,
                data: bytes) -> None:
        r = st.grant_permit(permit_id, block_id, len(data))
        self.assertTrue(r.ok, r.detail)
        r = st.submit_block(permit_id, block_id, data)
        self.assertTrue(r.ok, r.detail)

    def batch_dir(self, name: str) -> str:
        return os.path.join(self.tmp, name)

    def pool(self) -> SharedBlockPool:
        return SharedBlockPool(self.pool_dir)


class TestManifestPoolConfig(PoolTestBase):
    def test_shared_pool_is_optional_and_defaults_none(self):
        raw = self.manifest("B", {"b": self.shared}, use_pool=False)
        m = Manifest.from_dict(raw)
        self.assertIsNone(m.shared_pool)
        self.assertNotIn("shared_pool", m.to_dict())

    def test_pool_path_is_frozen_to_absolute_realpath(self):
        rel = os.path.join(self.tmp, "rel_pool")
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            m = Manifest.from_dict(
                self.manifest("B", {"b": self.shared}, pool_path="rel_pool"))
        finally:
            os.chdir(cwd)
        self.assertEqual(m.shared_pool.path, os.path.realpath(rel))
        # 同一路径确定性导出同一 pool_id；往返序列化保持一致。
        again = Manifest.from_dict(m.to_dict())
        self.assertEqual(again.shared_pool, m.shared_pool)

    def test_bad_pool_config_rejected_at_freeze(self):
        for bad in ({"path": ""}, {"path": None}, "not-an-object", {}):
            with self.assertRaises(ManifestError):
                Manifest.from_dict(
                    self.manifest("B", {"b": self.shared}, use_pool=False)
                    | {"shared_pool": bad})


class TestContentDedupAndIndependentBatches(PoolTestBase):
    def _two_batches_same_content(self):
        d1, d2 = self.batch_dir("b1"), self.batch_dir("b2")
        arc1 = [archive_entry("A1", "a1.dat", ["x", "u1"],
                              self.shared + self.uniq1)]
        arc2 = [archive_entry("A2", "a2.dat", ["y", "u2"],
                              self.shared + self.uniq2)]
        self.init(d1, self.manifest(
            "B1", {"x": self.shared, "u1": self.uniq1}, archives=arc1))
        self.init(d2, self.manifest(
            "B2", {"y": self.shared, "u2": self.uniq2}, archives=arc2))
        with Station(d1).open() as st:
            self.deliver(st, "P1", "x", self.shared)
            self.deliver(st, "P2", "u1", self.uniq1)
        with Station(d2).open() as st:
            self.deliver(st, "Q1", "y", self.shared)
            self.deliver(st, "Q2", "u2", self.uniq2)
        return d1, d2

    def test_identical_content_stored_once_with_two_links(self):
        self._two_batches_same_content()
        inv = self.pool().inventory()
        # 三种不同内容 => 三个物理对象；四个 (批次,块) 关联。
        self.assertEqual(inv["objects_total"], 3)
        self.assertEqual(inv["links_total"], 4)
        on_disk = os.listdir(os.path.join(self.pool_dir, "objects"))
        self.assertEqual(sorted(on_disk),
                         sorted(o["sha256"] + ".bin" for o in inv["objects"]))
        shared_item = next(o for o in inv["objects"]
                           if o["sha256"] == digest_payload(self.shared))
        self.assertEqual(shared_item["link_count"], 2)
        self.assertTrue(shared_item["occupying_storage"])
        self.assertEqual(
            sorted(l["batch_id"] for l in shared_item["links"]), ["B1", "B2"])
        # 块身份不同也能复用：两条关联的 block_id 分别是 x 和 y。
        self.assertEqual(
            sorted(l["block_id"] for l in shared_item["links"]),
            ["x", "y"])

    def test_pool_batches_keep_local_blocks_dir_empty(self):
        d1, _ = self._two_batches_same_content()
        local_blocks = os.path.join(d1, "blocks")
        # 池批次不再向本批 blocks/ 写物理块（目录不应被创建或为空）。
        self.assertFalse(os.path.exists(local_blocks)
                         and os.listdir(local_blocks))

    def test_each_batch_restores_only_from_its_own_manifest(self):
        d1, d2 = self._two_batches_same_content()
        o1, o2 = self.batch_dir("o1"), self.batch_dir("o2")
        with Station(d1).open() as st:
            r1 = st.restore_archives(o1)
        with Station(d2).open() as st:
            r2 = st.restore_archives(o2)
        self.assertTrue(r1["ok"] and r2["ok"])
        with open(os.path.join(o1, "a1.dat"), "rb") as fh:
            self.assertEqual(fh.read(), self.shared + self.uniq1)
        with open(os.path.join(o2, "a2.dat"), "rb") as fh:
            self.assertEqual(fh.read(), self.shared + self.uniq2)

    def test_batches_have_independent_ledger_and_quota(self):
        d1, d2 = self._two_batches_same_content()
        with Station(d1).open() as st:
            rep1 = st.report()
        with Station(d2).open() as st:
            rep2 = st.report()
        # 各自独立记账：许可互不相干，交付事实只含本批块。
        self.assertEqual({p["permit_id"] for p in rep1["permits"]},
                         {"P1", "P2"})
        self.assertEqual({p["permit_id"] for p in rep2["permits"]},
                         {"Q1", "Q2"})
        self.assertEqual({d["block_id"] for d in
                          rep1["delivery"]["delivered"]}, {"x", "u1"})
        self.assertEqual({d["block_id"] for d in
                          rep2["delivery"]["delivered"]}, {"y", "u2"})
        self.assertEqual(rep1["shared_pool"]["pool_id"],
                         rep2["shared_pool"]["pool_id"])

    def test_missing_block_in_one_batch_blocks_its_archive_only(self):
        d1 = self.batch_dir("b1")
        d2 = self.batch_dir("b2")
        # B1 的档案依赖 x(shared)+u1；B2 只有 y(shared)，缺 u2 不影响 B1。
        arc1 = [archive_entry("A1", "a1.dat", ["x", "u1"],
                              self.shared + self.uniq1)]
        self.init(d1, self.manifest(
            "B1", {"x": self.shared, "u1": self.uniq1}, archives=arc1))
        self.init(d2, self.manifest("B2", {"y": self.shared}))
        with Station(d1).open() as st:
            self.deliver(st, "P1", "x", self.shared)
            self.deliver(st, "P2", "u1", self.uniq1)
        with Station(d2).open() as st:
            self.deliver(st, "Q1", "y", self.shared)
        with Station(d1).open() as st:
            r = st.restore_archives(self.batch_dir("o1"))
        self.assertTrue(r["ok"])  # B1 自己的块齐全，正常发布

    def test_other_batch_link_cannot_substitute_for_missing_local_delivery(self):
        # 池中已有 B1 对某内容的关联；B2 清单含同内容块但从未交付，
        # B2 恢复时必须因本批未交付而挡下，不能借用 B1 的关联。
        d1 = self.batch_dir("b1")
        d2 = self.batch_dir("b2")
        self.init(d1, self.manifest("B1", {"x": self.shared}))
        self.init(d2, self.manifest(
            "B2", {"y": self.shared},
            archives=[archive_entry("A2", "a2.dat", ["y"], self.shared)]))
        with Station(d1).open() as st:
            self.deliver(st, "P1", "x", self.shared)
        with Station(d2).open() as st:
            r = st.restore_archives(self.batch_dir("o2"))
        self.assertEqual(r["archives_blocked"], 1)
        self.assertEqual(r["results"][0]["missing_block_ids"], ["y"])
        self.assertFalse(os.path.exists(
            os.path.join(self.batch_dir("o2"), "a2.dat")))


class TestRetireReleasesOnlyOwnLinks(PoolTestBase):
    def _setup(self):
        d1, d2 = self.batch_dir("b1"), self.batch_dir("b2")
        o1, o2 = self.batch_dir("o1"), self.batch_dir("o2")
        arc1 = [archive_entry("A1", "a1.dat", ["x", "u1"],
                              self.shared + self.uniq1)]
        arc2 = [archive_entry("A2", "a2.dat", ["y", "u2"],
                              self.shared + self.uniq2)]
        self.init(d1, self.manifest(
            "B1", {"x": self.shared, "u1": self.uniq1}, archives=arc1))
        self.init(d2, self.manifest(
            "B2", {"y": self.shared, "u2": self.uniq2}, archives=arc2))
        with Station(d1).open() as st:
            self.deliver(st, "P1", "x", self.shared)
            self.deliver(st, "P2", "u1", self.uniq1)
            st.restore_archives(o1)
        with Station(d2).open() as st:
            self.deliver(st, "Q1", "y", self.shared)
            self.deliver(st, "Q2", "u2", self.uniq2)
            st.restore_archives(o2)
        return d1, d2, o1, o2

    def test_retire_releases_own_links_but_keeps_other_batch_intact(self):
        d1, d2, o1, o2 = self._setup()
        with Station(d1).open() as st:
            rr = st.retire_archives(["A1"], o1)
        self.assertEqual(rr["storage_backend"], "shared_pool")
        # 撤销 B1 的两条关联；独占对象 u1 物理释放，共享对象仍被 B2 占用。
        statuses = {x["block_id"]: x for x in rr["pool_links_released"]}
        self.assertFalse(statuses["x"]["storage_released"])
        self.assertEqual(statuses["x"]["remaining_links"], 1)
        self.assertTrue(statuses["u1"]["storage_released"])
        self.assertEqual(rr["pool_objects_deleted"],
                         [digest_payload(self.uniq1)])
        inv = self.pool().inventory()
        # 共享内容仍在，且只剩 B2 关联；u1 对象消失。
        digests = {o["sha256"] for o in inv["objects"]}
        self.assertIn(digest_payload(self.shared), digests)
        self.assertNotIn(digest_payload(self.uniq1), digests)
        shared_item = next(o for o in inv["objects"]
                           if o["sha256"] == digest_payload(self.shared))
        self.assertEqual(
            [l["batch_id"] for l in shared_item["links"]], ["B2"])
        # B2 的档案仍可正常恢复到全新输出目录。
        fresh = self.batch_dir("o2_fresh")
        with Station(d2).open() as st:
            r = st.restore_archives(fresh)
        self.assertTrue(r["ok"])
        with open(os.path.join(fresh, "a2.dat"), "rb") as fh:
            self.assertEqual(fh.read(), self.shared + self.uniq2)

    def test_storage_freed_only_after_last_association_gone(self):
        d1, d2, o1, o2 = self._setup()
        shared_path = os.path.join(
            self.pool_dir, "objects", digest_payload(self.shared) + ".bin")
        self.assertTrue(os.path.exists(shared_path))
        with Station(d1).open() as st:
            st.retire_archives(["A1"], o1)
        self.assertTrue(os.path.exists(shared_path))  # B2 仍关联
        with Station(d2).open() as st:
            st.retire_archives(["A2"], o2)
        self.assertFalse(os.path.exists(shared_path))  # 最后关联撤销
        inv = self.pool().inventory()
        self.assertEqual(inv["objects_total"], 0)
        self.assertEqual(inv["links_total"], 0)
        self.assertEqual(os.listdir(os.path.join(self.pool_dir, "objects")), [])

    def test_retire_is_idempotent_and_does_not_touch_money(self):
        d1, _d2, o1, _o2 = self._setup()
        with Station(d1).open() as st:
            before = st.report()
            st.retire_archives(["A1"], o1)
            seq = st.ledger.last_seq
            again = st.retire_archives(["A1"], o1)
            self.assertEqual(st.ledger.last_seq, seq)  # 不重复追加批次事件
            after = st.report()
        self.assertEqual(again["code"], "archives_already_retired")
        for key in ("quota_account", "permits", "anomalies"):
            self.assertEqual(before[key], after[key], key)
        # 重复撤销不产生负关联数、不报错。
        self.assertEqual(
            [x["status"] for x in again["pool_links_released"]],
            ["not_linked", "not_linked"])

    def test_retire_history_delivery_facts_unchanged(self):
        d1, _d2, o1, _o2 = self._setup()
        with Station(d1).open() as st:
            st.retire_archives(["A1"], o1)
            rep = st.report()
        # 历史交付事实不随退役改变。
        self.assertEqual(
            {d["block_id"] for d in rep["delivery"]["delivered"]},
            {"x", "u1"})


class TestPersistenceConcurrencyAndReconcile(PoolTestBase):
    def test_links_survive_restart_and_replay_matches_live(self):
        d = self.batch_dir("b1")
        self.init(d, self.manifest("B1", {"x": self.shared}))
        with Station(d).open() as st:
            self.deliver(st, "P1", "x", self.shared)
        # 全新进程视角：池日志重放后关联仍在。
        inv = self.pool().inventory()
        self.assertEqual(inv["links_total"], 1)
        r = subprocess.run([sys.executable, "-I", RUN_PY, "verify",
                            "--data-dir", d],
                           capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertTrue(json.loads(r.stdout)["matched"])

    def test_orphan_objects_swept_and_missing_objects_are_fatal(self):
        d = self.batch_dir("b1")
        self.init(d, self.manifest("B1", {"x": self.shared}))
        with Station(d).open() as st:
            self.deliver(st, "P1", "x", self.shared)
        obj_dir = os.path.join(self.pool_dir, "objects")
        orphan = os.path.join(obj_dir, "cd" * 32 + ".bin")
        with open(orphan, "wb") as fh:
            fh.write(b"orphan")
        # 任何持锁打开都会对账并清扫孤立对象。
        inv = self.pool().inventory()
        self.assertFalse(os.path.exists(orphan))
        self.assertTrue(all(o["occupying_storage"] for o in inv["objects"]))
        # 有关联却删文件：硬失败，绝不静默。
        linked = inv["objects"][0]["sha256"]
        os.unlink(os.path.join(obj_dir, linked + ".bin"))
        with self.assertRaises(SharedPoolError):
            self.pool().inventory()

    def test_gc_removes_undelivered_stale_links_but_keeps_confirmed(self):
        d_good = self.batch_dir("good")
        d_stale = self.batch_dir("stale")
        self.init(d_good, self.manifest("BGOOD", {"x": self.shared}))
        self.init(d_stale, self.manifest("BSTALE", {"y": self.shared}))
        with Station(d_good).open() as st:
            self.deliver(st, "P1", "x", self.shared)
        # 直接在池里登记一条“批次未确认交付”的残留关联（模拟崩溃窗口）。
        pool = self.pool()
        pool.link_block(batch_id="BSTALE", block_id="y",
                        length=len(self.shared), sha256=digest_payload(self.shared),
                        data_dir=d_stale, payload=self.shared)
        self.assertEqual(pool.inventory()["links_total"], 2)
        gc = pool.gc_stale_links()
        self.assertEqual(gc["removed_count"], 1)
        self.assertEqual(gc["removed_links"][0]["batch_id"], "BSTALE")
        inv = pool.inventory()
        self.assertEqual(inv["links_total"], 1)
        self.assertEqual(inv["objects"][0]["links"][0]["batch_id"], "BGOOD")
        # 再跑一次 GC：无残留，幂等。
        self.assertEqual(pool.gc_stale_links()["removed_count"], 0)

    def test_gc_preview_flags_stale_without_modifying(self):
        d_stale = self.batch_dir("stale")
        self.init(d_stale, self.manifest("BSTALE", {"y": self.shared}))
        pool = self.pool()
        pool.link_block(batch_id="BSTALE", block_id="y",
                        length=len(self.shared), sha256=digest_payload(self.shared),
                        data_dir=d_stale, payload=self.shared)
        inv = pool.inventory(include_gc_check=True)
        self.assertEqual(len(inv["gc_preview"]), 1)
        self.assertTrue(inv["gc_preview"][0]["stale"])
        # 预览不修改状态。
        self.assertEqual(self.pool().inventory()["links_total"], 1)

    def test_redeliver_same_block_is_idempotent(self):
        d = self.batch_dir("b1")
        self.init(d, self.manifest("B1", {"x": self.shared}))
        with Station(d).open() as st:
            self.deliver(st, "P1", "x", self.shared)
            r = st.submit_block("P1", "x", self.shared)
            self.assertEqual(r.code, "block_already_delivered_ignored")
        self.assertEqual(self.pool().inventory()["links_total"], 1)

    def test_same_batch_id_from_different_data_dir_is_rejected(self):
        d1 = self.batch_dir("dup1")
        d2 = self.batch_dir("dup2")
        # 两个不同数据目录开账出相同 batch_id 且共用同一池：关联键碰撞。
        self.init(d1, self.manifest("DUP", {"x": self.shared}))
        self.init(d2, self.manifest("DUP", {"x": self.shared}))
        with Station(d1).open() as st:
            self.deliver(st, "P1", "x", self.shared)
        with self.assertRaises(SharedPoolError):
            with Station(d2).open() as st:
                self.deliver(st, "Q1", "x", self.shared)
        # 已确认的第一条关联不受影响。
        inv = self.pool().inventory()
        self.assertEqual(inv["links_total"], 1)
        self.assertEqual(inv["objects"][0]["links"][0]["data_dir"],
                         os.path.realpath(d1))

    def test_pool_journal_is_append_only_with_seq_and_crc(self):
        d = self.batch_dir("b1")
        self.init(d, self.manifest("B1", {"x": self.shared, "u": self.uniq1}))
        with Station(d).open() as st:
            self.deliver(st, "P1", "x", self.shared)
            self.deliver(st, "P2", "u", self.uniq1)
        events = list(Journal.replay(
            os.path.join(self.pool_dir, POOL_JOURNAL_NAME)))
        self.assertEqual(events[0].type, "pool_opened")
        self.assertTrue(all(e.seq == i + 1 for i, e in enumerate(events)))
        self.assertIn("pool_linked", [e.type for e in events])


class TestPoolCli(PoolTestBase):
    def _run(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", RUN_PY, *argv],
                              capture_output=True, text=True,
                              env=dict(os.environ))

    def test_inventory_via_data_dir_and_pool_dir(self):
        d = self.batch_dir("b1")
        self.init(d, self.manifest("B1", {"x": self.shared}))
        with Station(d).open() as st:
            self.deliver(st, "P1", "x", self.shared)
        r = self._run("pool-inventory", "--data-dir", d)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["objects_total"], 1)
        r2 = self._run("pool-inventory", "--pool-dir", self.pool_dir)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(json.loads(r2.stdout)["objects"], out["objects"])

    def test_inventory_on_missing_pool_is_usage_error(self):
        r = self._run("pool-inventory",
                      "--pool-dir", os.path.join(self.tmp, "no_such_pool"))
        self.assertEqual(r.returncode, 3)
        self.assertFalse(json.loads(r.stdout)["ok"])

    def test_inventory_on_batch_without_pool_is_usage_error(self):
        d = self.batch_dir("legacy")
        self.init(d, self.manifest("B", {"x": self.shared}, use_pool=False))
        r = self._run("pool-inventory", "--data-dir", d)
        self.assertEqual(r.returncode, 3)

    def test_pool_gc_cli(self):
        d_stale = self.batch_dir("stale")
        self.init(d_stale, self.manifest("BSTALE", {"y": self.shared}))
        self.pool().link_block(
            batch_id="BSTALE", block_id="y", length=len(self.shared),
            sha256=digest_payload(self.shared), data_dir=d_stale,
            payload=self.shared)
        r = self._run("pool-gc", "--pool-dir", self.pool_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["removed_count"], 1)


class TestLegacyBatchUnaffected(PoolTestBase):
    def test_batch_without_pool_uses_local_block_store_only(self):
        d = self.batch_dir("legacy")
        self.init(d, self.manifest("B", {"x": self.shared}, use_pool=False))
        with Station(d).open() as st:
            self.deliver(st, "P1", "x", self.shared)
            self.assertIsNone(st.report()["shared_pool"])
        # 物理块在本批 blocks/，池目录从未被创建。
        self.assertTrue(os.path.exists(BlockStore(d).path_for("x")))
        self.assertFalse(os.path.exists(self.pool_dir))
        # 退役仍按本地回收语义工作。
        with Station(d).open() as st:
            rep = st.report()
        self.assertEqual(rep["delivery"]["retained_block_ids"], ["x"])


def _concurrency_worker(args: tuple[str, str, str, str, int, bytes]) -> None:
    """子进程：开账一个批次并交付一个与其他批次内容相同的块。"""
    data_dir, pool_dir, batch_id, block_id, length, payload = args
    manifest = {
        "batch_id": batch_id, "quota_bytes": 10_000_000,
        "blocks": [{"block_id": block_id, "length": length,
                    "sha256": digest_payload(payload)}],
        "shared_pool": {"path": pool_dir},
    }
    Station.initialize(data_dir, manifest, KEY)
    with Station(data_dir).open() as st:
        r = st.grant_permit(f"P-{batch_id}", block_id, length)
        assert r.ok, r.detail
        r = st.submit_block(f"P-{batch_id}", block_id, payload)
        assert r.ok, r.detail


class TestPoolConcurrency(PoolTestBase):
    def test_parallel_batches_dedup_without_losing_links(self):
        n = 8
        ctx = mp.get_context("spawn")
        payload = b"concurrent-identical-content" * 16
        args = [
            (self.batch_dir(f"cb{i}"), self.pool_dir, f"CB{i}",
             f"k{i}", len(payload), payload)
            for i in range(n)
        ]
        with ctx.Pool(processes=n) as pool_proc:
            pool_proc.map(_concurrency_worker, args)
        inv = self.pool().inventory()
        # 全部批次内容相同：恰好一个物理对象，n 条关联，无一丢失。
        self.assertEqual(inv["objects_total"], 1)
        self.assertEqual(inv["links_total"], n)
        self.assertEqual(inv["objects_occupying_storage"], 1)
        item = inv["objects"][0]
        self.assertEqual(item["link_count"], n)
        self.assertEqual(
            sorted(l["batch_id"] for l in item["links"]),
            [f"CB{i}" for i in range(n)])
        # 每个批次都能凭自己的关联独立恢复读取。
        for i in range(n):
            data = SharedBlockPool(self.pool_dir).load_verified(
                batch_id=f"CB{i}", block_id=f"k{i}",
                length=len(payload), sha256=digest_payload(payload))
            self.assertEqual(data, payload)
        # 并发退役：每个批次撤销自己的关联，直到最后一个才释放对象。
        obj_path = os.path.join(self.pool_dir, "objects",
                                digest_payload(payload) + ".bin")
        for i in range(n - 1):
            SharedBlockPool(self.pool_dir).release_block(
                batch_id=f"CB{i}", block_id=f"k{i}",
                sha256=digest_payload(payload))
            self.assertTrue(os.path.exists(obj_path))
        SharedBlockPool(self.pool_dir).release_block(
            batch_id=f"CB{n - 1}", block_id=f"k{n - 1}",
            sha256=digest_payload(payload))
        self.assertFalse(os.path.exists(obj_path))
        self.assertEqual(self.pool().inventory()["links_total"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
