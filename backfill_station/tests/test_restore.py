"""档案恢复规则测试（仅标准库 unittest，离线运行）。

覆盖：
- 清单档案声明的冻结期校验（标识/路径/引用/长度/摘要）；
- 已核验块按序组装、跨档案共享块、嵌套相对路径；
- 缺块时不生成任何新文件并报告缺块；
- 原子发布（读取者看不到部分文件）、重复恢复幂等且权限不变；
- 恢复不触碰许可/额度/收据账，不新增日志事件；
- 块仓库缺失/被篡改、清单摘要不符时硬失败且不留临时文件；
- 路径越界（..、绝对路径、符号链接逃逸）拒绝；
- 无档案声明的旧批次行为不变；CLI 退出码语义。
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backfill_station.canonical import digest_payload  # noqa: E402
from backfill_station.block_store import BlockStore  # noqa: E402
from backfill_station.manifest import Manifest, ManifestError  # noqa: E402
from backfill_station.restore import RestoreError  # noqa: E402
from backfill_station.station import Station  # noqa: E402
from backfill_station.journal import Journal  # noqa: E402

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


class ArchiveTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="bfs_arc_")
        self.data_dir = os.path.join(self.tmp, "data")
        self.out_dir = os.path.join(self.tmp, "out")
        # 三块，b2 同时被两个档案引用
        self.b1 = bytes(range(100))
        self.b2 = b"shared-block-" * 8
        self.b3 = b"\x5a" * 40
        self.arc_a = self.b1 + self.b2            # 档案 A：b1,b2
        self.arc_b = self.b2 + self.b3 + self.b1  # 档案 B：共享 b2
        self.payloads = {"b1": self.b1, "b2": self.b2, "b3": self.b3}
        self.manifest = self._manifest(with_archives=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _manifest(self, *, with_archives: bool, extra: dict | None = None):
        raw = {
            "batch_id": "B-ARC",
            "quota_bytes": 4096,
            "blocks": [block_entry(bid, data)
                       for bid, data in sorted(self.payloads.items())],
        }
        if with_archives:
            raw["archives"] = [
                archive_entry("A1", "instr/a1.dat", ["b1", "b2"], self.arc_a),
                archive_entry("A2", os.path.join("nested", "a2.bin"),
                              ["b2", "b3", "b1"], self.arc_b),
            ]
        if extra:
            raw.update(extra)
        return raw

    def init_station(self, manifest: dict | None = None) -> Station:
        return Station.initialize(self.data_dir,
                                  manifest or self.manifest, KEY)

    def deliver(self, st: Station, *block_ids: str) -> None:
        """发许可并提交完备块（本测试不关心钱账细节，额度足够）。"""
        for idx, bid in enumerate(block_ids):
            pid = f"P-{bid}-{idx}"
            spec = next(b for b in self.manifest["blocks"]
                        if b["block_id"] == bid)
            r = st.grant_permit(pid, bid, spec["length"])
            self.assertTrue(r.ok, r.detail)
            r = st.submit_block(pid, bid, self.payloads[bid])
            self.assertTrue(r.ok, r.detail)

    def journal_seq(self) -> int:
        return sum(1 for _ in Journal.replay(
            os.path.join(self.data_dir, "journal.jsonl")))


class TestManifestArchives(ArchiveTestBase):
    def test_archives_parsed_and_round_trip(self):
        m = Manifest.from_dict(self.manifest)
        self.assertEqual(len(m.archives), 2)
        self.assertEqual(m.archives[0].block_ids, ("b1", "b2"))
        # 规范化往返保留档案声明
        again = Manifest.from_dict(m.to_dict())
        self.assertEqual(again.archives, m.archives)

    def test_legacy_manifest_without_archives(self):
        m = Manifest.from_dict(self._manifest(with_archives=False))
        self.assertEqual(m.archives, ())
        self.assertNotIn("archives", m.to_dict())

    def test_duplicate_archive_id_rejected(self):
        raw = self._manifest(with_archives=False)
        raw["archives"] = [
            archive_entry("X", "x.dat", ["b1"], self.b1),
            archive_entry("X", "y.dat", ["b2"], self.b2),
        ]
        with self.assertRaises(ManifestError):
            Manifest.from_dict(raw)

    def test_duplicate_archive_path_rejected(self):
        raw = self._manifest(with_archives=False)
        raw["archives"] = [
            archive_entry("X", "same.dat", ["b1"], self.b1),
            archive_entry("Y", "same.dat", ["b2"], self.b2),
        ]
        with self.assertRaises(ManifestError):
            Manifest.from_dict(raw)

    def test_unknown_block_reference_rejected(self):
        raw = self._manifest(with_archives=False)
        raw["archives"] = [
            archive_entry("X", "x.dat", ["b1", "ghost"], self.b1),
        ]
        with self.assertRaises(ManifestError):
            Manifest.from_dict(raw)

    def test_length_must_equal_sum_of_blocks(self):
        bad = archive_entry("X", "x.dat", ["b1", "b2"], self.arc_a)
        bad["length"] += 1
        raw = self._manifest(with_archives=False)
        raw["archives"] = [bad]
        with self.assertRaises(ManifestError):
            Manifest.from_dict(raw)

    def test_bad_digest_and_empty_block_list_rejected(self):
        raw = self._manifest(with_archives=False)
        bad = archive_entry("X", "x.dat", ["b1"], self.b1)
        bad["sha256"] = "z" * 64
        raw["archives"] = [bad]
        with self.assertRaises(ManifestError):
            Manifest.from_dict(raw)

        raw2 = self._manifest(with_archives=False)
        raw2["archives"] = [{"archive_id": "X", "path": "x.dat",
                             "block_ids": [], "length": 1,
                             "sha256": "0" * 64}]
        with self.assertRaises(ManifestError):
            Manifest.from_dict(raw2)

    def test_path_traversal_rejected_at_freeze(self):
        for bad_path in ("../escape.dat", "a/../../b", "/abs/path.dat",
                         "a/./b", "a//b", "a\\b.dat", "C:/win.dat"):
            raw = self._manifest(with_archives=False)
            raw["archives"] = [
                archive_entry("X", bad_path, ["b1"], self.b1)]
            with self.assertRaises(ManifestError, msg=bad_path):
                Manifest.from_dict(raw)


class TestRestoreHappyPath(ArchiveTestBase):
    def test_assembles_in_order_with_shared_blocks_and_nested_path(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
            result = st.restore_archives(self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["archives_published"], 2)
        p1 = os.path.join(self.out_dir, "instr", "a1.dat")
        p2 = os.path.join(self.out_dir, "nested", "a2.bin")
        with open(p1, "rb") as fh:
            self.assertEqual(fh.read(), self.arc_a)
        with open(p2, "rb") as fh:
            self.assertEqual(fh.read(), self.arc_b)
        # 同一块被两个档案复用：块仓库只有一份文件
        store_files = os.listdir(os.path.join(self.data_dir, "blocks"))
        self.assertEqual(sorted(store_files),
                         sorted(BlockStore(self.data_dir).block_filename(b)
                                for b in ("b1", "b2", "b3")))

    def test_block_store_re_verifies_on_load(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1")
        stored = BlockStore(self.data_dir).path_for("b1")
        with open(stored, "rb") as fh:
            self.assertEqual(fh.read(), self.b1)

    def test_report_lists_archive_readiness(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1")  # 两个档案都还缺块
            report = st.report()
        ids = {a["archive_id"]: a for a in report["archives"]}
        self.assertFalse(ids["A1"]["ready"])
        self.assertEqual(ids["A1"]["missing_block_ids"], ["b2"])
        self.assertEqual(ids["A2"]["missing_block_ids"], ["b2", "b3"])
        with station.open() as st:
            self.deliver(st, "b2", "b3")
            report = st.report()
        self.assertTrue(all(a["ready"] for a in report["archives"]))


class TestRestoreMissingBlocks(ArchiveTestBase):
    def test_missing_block_produces_no_file_and_reports_missing(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b3")  # b2 缺：两个档案都被挡
            before_seq = self.journal_seq()
            result = st.restore_archives(self.out_dir)
        self.assertFalse(result["ok"])
        self.assertEqual(result["archives_blocked"], 2)
        self.assertEqual(result["archives_published"], 0)
        for r in result["results"]:
            self.assertEqual(r["state"], "blocked")
            self.assertIn("b2", r["missing_block_ids"])
        # 输出目录未被创建，更没有任何档案文件或残留临时文件
        self.assertFalse(os.path.exists(self.out_dir))
        # 没有写日志
        self.assertEqual(self.journal_seq(), before_seq)

    def test_partial_batch_publishes_ready_archive_only(self):
        # 构造：A1 只依赖 b1；b2 仍缺，A2 被挡
        raw = self._manifest(with_archives=False)
        raw["archives"] = [
            archive_entry("A1", "a1.dat", ["b1"], self.b1),
            archive_entry("A2", "a2.dat", ["b1", "b2"], self.arc_a),
        ]
        station = self.init_station(raw)
        with station.open() as st:
            self.deliver(st, "b1")
            result = st.restore_archives(self.out_dir)
        self.assertFalse(result["ok"])
        states = {r["archive_id"]: r["state"] for r in result["results"]}
        self.assertEqual(states, {"A1": "published", "A2": "blocked"})
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "a1.dat")))
        self.assertFalse(os.path.exists(
            os.path.join(self.out_dir, "a2.dat")))


class TestRestoreIdempotencyAndSafety(ArchiveTestBase):
    def test_repeated_restore_keeps_files_and_permissions(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
            r1 = st.restore_archives(self.out_dir)
        target = os.path.join(self.out_dir, "instr", "a1.dat")
        os.chmod(target, 0o600)  # 收紧权限
        inode1 = os.stat(target).st_ino
        with station.open() as st:
            r2 = st.restore_archives(self.out_dir)
        st2 = os.stat(target)
        self.assertEqual(st2.st_ino, inode1)            # 文件未被重写
        self.assertEqual(stat.S_IMODE(st2.st_mode), 0o600)  # 权限不变
        self.assertEqual(
            [r["state"] for r in r2["results"]],
            ["verified_existing", "verified_existing"])
        # 两次结果除 state/detail 外发布路径一致
        self.assertEqual(
            {r["archive_id"]: r["output_path"] for r in r1["results"]},
            {r["archive_id"]: r["output_path"] for r in r2["results"]})

    def test_restore_does_not_touch_money_or_journal(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
            report_before = st.report()
            seq_before = self.journal_seq()
            st.restore_archives(self.out_dir)
            st.restore_archives(self.out_dir)  # 再恢复一次
            report_after = st.report()
        self.assertEqual(self.journal_seq(), seq_before)
        for key in ("quota_account", "permits", "anomalies", "delivery",
                    "missing_blocks"):
            self.assertEqual(report_before[key], report_after[key])

    def test_no_archives_is_noop(self):
        station = self.init_station(self._manifest(with_archives=False))
        with station.open() as st:
            self.deliver(st, "b1")
            result = st.restore_archives(self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["archives_declared"], 0)
        self.assertFalse(os.path.exists(self.out_dir))


class TestRestoreFailures(ArchiveTestBase):
    def _publish(self, station: Station):
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
            st.restore_archives(self.out_dir)

    def test_missing_block_store_file_is_fatal(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
        os.unlink(BlockStore(self.data_dir).path_for("b2"))
        with station.open() as st:
            with self.assertRaises(RestoreError):
                st.restore_archives(self.out_dir)
        # 失败后无临时文件残留，且未发布半成品
        for dirpath, _dirs, files in os.walk(self.out_dir):
            self.assertEqual([f for f in files if f.startswith(".")], [])
        self.assertFalse(os.path.exists(
            os.path.join(self.out_dir, "instr", "a1.dat")))

    def test_tampered_block_store_file_is_fatal(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
        path = BlockStore(self.data_dir).path_for("b1")
        with open(path, "r+b") as fh:
            fh.seek(0)
            fh.write(b"\xff")
        with station.open() as st:
            with self.assertRaises(RestoreError):
                st.restore_archives(self.out_dir)

    def test_manifest_digest_mismatch_blocks_publication(self):
        # 清单声称的档案摘要与实际组成不符：组装完成也必须拒绝发布
        raw = self._manifest(with_archives=False)
        raw["archives"] = [
            archive_entry("A1", "a1.dat", ["b1"], self.b1),
        ]
        raw["archives"][0]["sha256"] = "0" * 64
        station = self.init_station(raw)
        with station.open() as st:
            self.deliver(st, "b1")
            with self.assertRaises(RestoreError):
                st.restore_archives(self.out_dir)
        self.assertFalse(os.path.exists(
            os.path.join(self.out_dir, "a1.dat")))

    def test_symlink_escape_from_output_dir_rejected(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
        outside = os.path.join(self.tmp, "outside.dat")
        link_dir = os.path.join(self.out_dir, "instr")
        os.makedirs(link_dir, exist_ok=True)
        os.symlink(outside, os.path.join(link_dir, "a1.dat"))
        with station.open() as st:
            with self.assertRaises(RestoreError):
                st.restore_archives(self.out_dir)
        self.assertFalse(os.path.exists(outside))

    def test_existing_directory_at_target_is_fatal(self):
        station = self.init_station()
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
        os.makedirs(os.path.join(self.out_dir, "instr", "a1.dat"))
        with station.open() as st:
            with self.assertRaises(RestoreError):
                st.restore_archives(self.out_dir)


class TestRestoreCli(ArchiveTestBase):
    def test_cli_restore_exit_codes_and_output(self):
        manifest_path = os.path.join(self.tmp, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh)
        py = [sys.executable, "-I", RUN_PY]
        dd = self.data_dir
        shutil.rmtree(dd, ignore_errors=True)
        env = dict(os.environ)

        r = subprocess.run(py + ["init", "--data-dir", dd,
                                 "--manifest", manifest_path,
                                 "--key", KEY.decode()],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)

        # 只交付 b1：两个档案都缺块 -> 退出码 2
        req = os.path.join(self.tmp, "req.json")
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "P1", "block_id": "b1",
                       "cap": len(self.b1)}, fh)
        subprocess.run(py + ["grant", "--data-dir", dd, "--request", req],
                       capture_output=True, text=True, env=env, check=True)
        payload = os.path.join(self.tmp, "b1.bin")
        with open(payload, "wb") as fh:
            fh.write(self.b1)
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "P1", "block_id": "b1",
                       "payload_path": payload}, fh)
        subprocess.run(py + ["block", "--data-dir", dd, "--request", req],
                       capture_output=True, text=True, env=env, check=True)

        r = subprocess.run(py + ["restore", "--data-dir", dd,
                                 "--output-dir", self.out_dir],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)
        summary = json.loads(r.stdout)
        self.assertEqual(summary["archives_blocked"], 2)
        # 缺块时输出目录都不会被创建
        self.assertFalse(os.path.exists(self.out_dir))

        # 补齐其余块后退出码 0，文件落地
        with Station(dd).open() as st:
            self.deliver(st, "b2", "b3")
        r = subprocess.run(py + ["restore", "--data-dir", dd,
                                 "--output-dir", self.out_dir],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        summary = json.loads(r.stdout)
        self.assertEqual(summary["archives_published"], 2)
        self.assertTrue(os.path.isfile(
            os.path.join(self.out_dir, "instr", "a1.dat")))

        # verify 交叉核对仍逐字段一致（报告含 archives 派生节）
        r = subprocess.run(py + ["verify", "--data-dir", dd],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(json.loads(r.stdout)["matched"])

    def test_cli_traversal_manifest_rejected_at_init(self):
        # 越界路径在开账冻结期即被拒绝（退出码 3=用法/清单错误）
        raw = self._manifest(with_archives=False)
        raw["archives"] = [
            archive_entry("A1", "../escape.dat", ["b1"], self.b1)]
        manifest_path = os.path.join(self.tmp, "bad_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        r = subprocess.run(
            [sys.executable, "-I", RUN_PY, "init",
             "--data-dir", self.data_dir, "--manifest", manifest_path,
             "--key", KEY.decode()],
            capture_output=True, text=True, env=dict(os.environ))
        self.assertEqual(r.returncode, 3)
        self.assertFalse(os.path.exists(
            os.path.join(self.tmp, "escape.dat")))
        # 开账失败：数据目录没有留下日志
        self.assertFalse(os.path.exists(
            os.path.join(self.data_dir, "journal.jsonl")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
