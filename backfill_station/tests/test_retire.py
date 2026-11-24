"""档案退役规则测试（仅标准库 unittest，离线运行）。

覆盖：
- 退役标记、已发布文件移除、空父目录修剪；
- 未知 archive_id 整次拒绝且状态不变（不追加事件、不动文件）；
- 重复执行同一退役请求结果一致（幂等，不重复追加事件）；
- 退役档案不得再次恢复（restore 跳过，换输出目录也一样）；
- 共享块保留、专属块回收；回收后存活档案仍可按原样恢复；
- 回收不动传输额度、收据与历史交付事实；
- 报告区分历史已交付块、当前仍保留块与已退役档案；
- 退役状态跨重启持久化；重演/交叉核对一致；
- 未声明档案的旧批次行为不变；CLI 退出码语义。
"""
from __future__ import annotations

import json
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
from backfill_station.restore import RestoreError  # noqa: E402
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


class RetireTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="bfs_retire_")
        self.data_dir = os.path.join(self.tmp, "data")
        self.out_dir = os.path.join(self.tmp, "out")
        # b1 专属 A1，b3 专属 A2，b2 被两个档案共享
        self.b1 = bytes(range(100))
        self.b2 = b"shared-block-" * 8
        self.b3 = b"\x5a" * 40
        self.arc_a = self.b1 + self.b2            # A1: b1,b2
        self.arc_b = self.b2 + self.b3            # A2: b2,b3（共享 b2）
        self.payloads = {"b1": self.b1, "b2": self.b2, "b3": self.b3}
        self.manifest = self._manifest(with_archives=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _manifest(self, *, with_archives: bool):
        raw = {
            "batch_id": "B-RETIRE",
            "quota_bytes": 4096,
            "blocks": [block_entry(bid, data)
                       for bid, data in sorted(self.payloads.items())],
        }
        if with_archives:
            raw["archives"] = [
                archive_entry("A1", os.path.join("instr", "a1.dat"),
                              ["b1", "b2"], self.arc_a),
                archive_entry("A2", "a2.dat", ["b2", "b3"], self.arc_b),
            ]
        return raw

    def init_station(self, manifest: dict | None = None) -> Station:
        return Station.initialize(self.data_dir,
                                  manifest or self.manifest, KEY)

    def deliver(self, st: Station, *block_ids: str) -> None:
        for idx, bid in enumerate(block_ids):
            pid = f"P-{bid}-{idx}"
            spec = next(b for b in self.manifest["blocks"]
                        if b["block_id"] == bid)
            r = st.grant_permit(pid, bid, spec["length"])
            self.assertTrue(r.ok, r.detail)
            r = st.submit_block(pid, bid, self.payloads[bid])
            self.assertTrue(r.ok, r.detail)

    def publish_all(self) -> None:
        station = Station(self.data_dir)
        with station.open() as st:
            self.deliver(st, "b1", "b2", "b3")
            result = st.restore_archives(self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["archives_published"], 2)

    def journal_seq(self) -> int:
        return sum(1 for _ in Journal.replay(
            os.path.join(self.data_dir, "journal.jsonl")))

    def store_path(self, bid: str) -> str:
        return BlockStore(self.data_dir).path_for(bid)


class TestRetireBasic(RetireTestBase):
    def test_retire_marks_archive_and_removes_published_file(self):
        self.init_station()
        self.publish_all()
        target = os.path.join(self.out_dir, "instr", "a1.dat")
        self.assertTrue(os.path.isfile(target))
        with Station(self.data_dir).open() as st:
            result = st.retire_archives(["A1"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["code"], "archives_retired")
        self.assertEqual(result["retired_now"], ["A1"])
        self.assertEqual(result["removed_files"], [os.path.realpath(target)])
        # 已发布文件被移除，变空的父目录被修剪；A2 的文件原样保留
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "instr")))
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "a2.dat")))
        # b1 只被已退役的 A1 引用：存储文件被回收
        self.assertFalse(os.path.exists(self.store_path("b1")))
        # b2 仍被未退役的 A2 引用、b3 同理：必须保留
        self.assertTrue(os.path.exists(self.store_path("b2")))
        self.assertTrue(os.path.exists(self.store_path("b3")))
        self.assertEqual(result["blocks_reclaimed_now"], ["b1"])
        self.assertEqual(result["retained_block_ids"], ["b2", "b3"])
        self.assertEqual(result["reclaimed_block_ids"], ["b1"])

    def test_retire_event_is_journaled_and_state_survives_reopen(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1"], self.out_dir)
            seq = st.ledger.last_seq
        # 重启后仅凭日志重建：退役状态仍在
        with Station(self.data_dir).open() as st:
            self.assertIn("A1", st.ledger.retired_archives)
            report = st.report()
        self.assertEqual(report["journal_last_seq"], seq)
        self.assertEqual(report["retired_archives"], ["A1"])
        states = {a["archive_id"]: a for a in report["archives"]}
        self.assertTrue(states["A1"]["retired"])
        self.assertFalse(states["A1"]["ready"])
        self.assertFalse(states["A2"]["retired"])

    def test_retire_multiple_archives_in_one_request(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            result = st.retire_archives(["A1", "A2"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["retired_now"], ["A1", "A2"])
        # 全部档案退役：三个块都不再被未退役档案引用，全部回收
        self.assertEqual(result["blocks_reclaimed_now"], ["b1", "b2", "b3"])
        for bid in ("b1", "b2", "b3"):
            self.assertFalse(os.path.exists(self.store_path(bid)))
        self.assertFalse(os.path.exists(
            os.path.join(self.out_dir, "instr", "a1.dat")))
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "a2.dat")))

    def test_duplicate_ids_in_single_request_are_deduplicated(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            result = st.retire_archives(["A1", "A1", "A1"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["retired_now"], ["A1"])
        # 只追加一个退役事件
        events = [e for e in Journal.replay(
            os.path.join(self.data_dir, "journal.jsonl"))
            if e.type == "archives_retired"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload["archive_ids"], ["A1"])


class TestRetireUnknownRejected(RetireTestBase):
    def test_unknown_archive_id_rejects_whole_request_without_state_change(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            report_before = st.report()
            seq_before = self.journal_seq()
            result = st.retire_archives(["A1", "GHOST"], self.out_dir)
            report_after = st.report()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "archive_unknown")
        self.assertEqual(result["unknown_archive_ids"], ["GHOST"])
        # 状态完全不变：不追加事件、不移除文件、不回收块
        self.assertEqual(self.journal_seq(), seq_before)
        self.assertEqual(report_before, report_after)
        self.assertTrue(os.path.isfile(
            os.path.join(self.out_dir, "instr", "a1.dat")))
        self.assertTrue(os.path.exists(self.store_path("b1")))

    def test_unknown_only_request_also_rejected(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            seq_before = self.journal_seq()
            result = st.retire_archives(["NOPE"], self.out_dir)
        self.assertFalse(result["ok"])
        self.assertEqual(self.journal_seq(), seq_before)

    def test_malformed_request_is_usage_error(self):
        self.init_station()
        with Station(self.data_dir).open() as st:
            for bad in (None, [], "", ["", "A1"], [1], "A1"):
                with self.assertRaises(Exception, msg=repr(bad)):
                    st.retire_archives(bad, self.out_dir)


class TestRetireIdempotency(RetireTestBase):
    def test_repeated_retire_request_keeps_same_state(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            first = st.retire_archives(["A1"], self.out_dir)
            seq_after_first = self.journal_seq()
            report_first = st.report()
            second = st.retire_archives(["A1"], self.out_dir)
            report_second = st.report()
        # 第二次不再追加事件，账本与文件系统状态完全一致
        self.assertEqual(self.journal_seq(), seq_after_first)
        self.assertEqual(report_first, report_second)
        self.assertEqual(second["code"], "archives_already_retired")
        self.assertEqual(second["retired_now"], [])
        self.assertEqual(second["already_retired"], ["A1"])
        self.assertEqual(second["removed_files"], [])
        self.assertEqual(second["blocks_reclaimed_now"], [])
        # 策略视图（保留/回收）两次一致
        self.assertEqual(first["retained_block_ids"],
                         second["retained_block_ids"])
        self.assertEqual(first["reclaimed_block_ids"],
                         second["reclaimed_block_ids"])
        self.assertFalse(os.path.exists(self.store_path("b1")))
        self.assertTrue(os.path.exists(self.store_path("b2")))

    def test_partially_new_request_only_retires_new(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1"], self.out_dir)
            result = st.retire_archives(["A1", "A2"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["retired_now"], ["A2"])
        self.assertEqual(result["already_retired"], ["A1"])
        states = {r["archive_id"]: r["state"] for r in result["results"]}
        self.assertEqual(states, {"A1": "already_retired", "A2": "retired"})

    def test_retire_heals_interrupted_cleanup(self):
        # 退役事件已落账但文件清理被致命错误打断：重跑同一请求必须完成清理
        self.init_station()
        self.publish_all()
        target = os.path.join(self.out_dir, "instr", "a1.dat")
        os.unlink(target)
        os.makedirs(target)  # 目录占位：移除时触发致命拒绝
        with Station(self.data_dir).open() as st:
            with self.assertRaises(RestoreError):
                st.retire_archives(["A1"], self.out_dir)
        # 事件已持久化：档案仍被标记退役
        with Station(self.data_dir).open() as st:
            self.assertIn("A1", st.ledger.retired_archives)
        # 排除障碍后重跑同一请求：幂等完成，不再追加事件
        os.rmdir(target)
        seq_before = self.journal_seq()
        with Station(self.data_dir).open() as st:
            result = st.retire_archives(["A1"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["code"], "archives_already_retired")
        self.assertEqual(self.journal_seq(), seq_before)
        self.assertFalse(os.path.exists(self.store_path("b1")))


class TestRetiredArchiveNotRestorable(RetireTestBase):
    def test_restore_skips_retired_archives(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1"], self.out_dir)
            result = st.restore_archives(self.out_dir)
        states = {r["archive_id"]: r["state"] for r in result["results"]}
        self.assertEqual(states["A1"], "retired")
        self.assertEqual(states["A2"], "verified_existing")
        self.assertEqual(result["archives_retired"], 1)
        self.assertTrue(result["ok"])  # 退役不算缺块挡下

    def test_retired_archive_not_restorable_to_fresh_output_dir(self):
        self.init_station()
        self.publish_all()
        fresh_out = os.path.join(self.tmp, "fresh_out")
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1"], self.out_dir)
            result = st.restore_archives(fresh_out)
        states = {r["archive_id"]: r["state"] for r in result["results"]}
        self.assertEqual(states["A1"], "retired")
        self.assertEqual(states["A2"], "published")
        # A1 绝不重新出现；A2 用保留的共享块 b2 正常恢复
        self.assertFalse(os.path.exists(
            os.path.join(fresh_out, "instr", "a1.dat")))
        with open(os.path.join(fresh_out, "a2.dat"), "rb") as fh:
            self.assertEqual(fh.read(), self.arc_b)

    def test_restore_after_retiring_everything_is_noop_success(self):
        self.init_station()
        self.publish_all()
        other_out = os.path.join(self.tmp, "other_out")
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1", "A2"], self.out_dir)
            result = st.restore_archives(other_out)
        self.assertTrue(result["ok"])
        self.assertEqual(result["archives_published"], 0)
        self.assertEqual(result["archives_retired"], 2)
        self.assertFalse(os.path.exists(other_out))


class TestRetireKeepsMoneyAndHistory(RetireTestBase):
    def test_retire_does_not_touch_quota_receipts_or_delivery_facts(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            before = st.report()
            st.retire_archives(["A1", "A2"], self.out_dir)
            after = st.report()
        # 钱账、许可、异常、缺块表、历史交付事实逐项不变
        for key in ("quota_account", "permits", "anomalies",
                    "anomaly_count", "missing_blocks"):
            self.assertEqual(before[key], after[key], key)
        self.assertEqual(before["delivery"]["delivered"],
                         after["delivery"]["delivered"])
        self.assertEqual(before["delivery"]["blocks_delivered"],
                         after["delivery"]["blocks_delivered"])
        # 但保留/回收视图反映退役结果
        self.assertEqual(after["delivery"]["blocks_retained"], 0)
        self.assertEqual(after["delivery"]["reclaimed_block_ids"],
                         ["b1", "b2", "b3"])
        self.assertEqual(after["retired_archives"], ["A1", "A2"])

    def test_report_distinguishes_delivered_retained_and_retired(self):
        self.init_station()
        with Station(self.data_dir).open() as st:
            self.deliver(st, "b1", "b2", "b3")
            st.retire_archives(["A1"], self.out_dir)
            report = st.report()
        delivery = report["delivery"]
        # 历史已交付：三个块都在（事实不随退役改变）
        self.assertEqual(delivery["blocks_delivered"], 3)
        self.assertEqual({d["block_id"] for d in delivery["delivered"]},
                         {"b1", "b2", "b3"})
        # 当前仍保留：b2（共享）、b3（A2 专属）
        self.assertEqual(delivery["retained_block_ids"], ["b2", "b3"])
        self.assertEqual(delivery["blocks_retained"], 2)
        # 已回收：b1（只被退役的 A1 引用）
        self.assertEqual(delivery["reclaimed_block_ids"], ["b1"])
        self.assertEqual(report["retired_archives"], ["A1"])

    def test_reclaimed_block_is_not_recreated_by_redelivery(self):
        self.init_station()
        with Station(self.data_dir).open() as st:
            self.deliver(st, "b1", "b2", "b3")
            st.retire_archives(["A1", "A2"], self.out_dir)
            self.assertFalse(os.path.exists(self.store_path("b1")))
            # 同一完备块重送：覆盖不增加，被回收的存储文件也不复活
            r = st.submit_block("P-b1-0", "b1", self.b1)
            self.assertTrue(r.ok)
            self.assertEqual(r.code, "block_already_delivered_ignored")
            self.assertFalse(os.path.exists(self.store_path("b1")))
            # 历史交付事实仍在
            self.assertTrue(st.ledger.blocks["b1"].delivered)

    def test_replay_and_verify_consistent_after_retire(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1"], self.out_dir)
        env = dict(os.environ)
        r = subprocess.run([sys.executable, "-I", RUN_PY, "verify",
                            "--data-dir", self.data_dir],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertTrue(json.loads(r.stdout)["matched"])
        r = subprocess.run([sys.executable, "-I", RUN_PY, "replay",
                            "--data-dir", self.data_dir],
                           capture_output=True, text=True, env=env)
        replayed = json.loads(r.stdout)
        self.assertEqual(replayed["retired_archives"], ["A1"])
        self.assertEqual(replayed["delivery"]["reclaimed_block_ids"], ["b1"])


class TestRetireLegacyBatch(RetireTestBase):
    def test_legacy_batch_without_archives_rejects_retire_and_works_as_before(self):
        self.init_station(self._manifest(with_archives=False))
        with Station(self.data_dir).open() as st:
            self.deliver(st, "b1")
            seq_before = self.journal_seq()
            report_before = st.report()
            result = st.retire_archives(["A1"], self.out_dir)
            report_after = st.report()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "archive_unknown")
        self.assertEqual(self.journal_seq(), seq_before)
        self.assertEqual(report_before, report_after)
        # 旧批次其它行为不变：无退役档案、无回收块、恢复为空操作
        self.assertEqual(report_after["retired_archives"], [])
        self.assertEqual(report_after["delivery"]["retained_block_ids"],
                         ["b1"])
        with Station(self.data_dir).open() as st:
            restored = st.restore_archives(self.out_dir)
        self.assertTrue(restored["ok"])
        self.assertEqual(restored["archives_declared"], 0)


class TestRetireEdgeCases(RetireTestBase):
    def test_retire_with_undelivered_exclusive_block(self):
        # A1 的专属块 b1 从未交付：退役照样成功，只是没有文件可删
        self.init_station()
        with Station(self.data_dir).open() as st:
            self.deliver(st, "b2", "b3")
            result = st.retire_archives(["A1"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["blocks_reclaimed_now"], [])
        self.assertFalse(os.path.exists(self.store_path("b1")))
        # 缺块表不受影响：b1 仍是未交付块
        with Station(self.data_dir).open() as st:
            report = st.report()
        self.assertEqual([b["block_id"] for b in report["missing_blocks"]],
                         ["b1"])
        self.assertEqual(report["delivery"]["reclaimed_block_ids"], [])

    def test_retire_before_any_publish_is_fine(self):
        # 从未恢复过（输出目录不存在）：退役只标记状态并回收块存储
        self.init_station()
        with Station(self.data_dir).open() as st:
            self.deliver(st, "b1", "b2", "b3")
            result = st.retire_archives(["A1"], self.out_dir)
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed_files"], [])
        self.assertEqual(result["blocks_reclaimed_now"], ["b1"])
        self.assertFalse(os.path.exists(self.out_dir))

    def test_symlink_escape_target_is_fatal_and_outside_file_kept(self):
        self.init_station()
        self.publish_all()
        target = os.path.join(self.out_dir, "instr", "a1.dat")
        os.unlink(target)
        outside = os.path.join(self.tmp, "outside.dat")
        with open(outside, "wb") as fh:
            fh.write(b"do-not-touch")
        os.symlink(outside, target)
        with Station(self.data_dir).open() as st:
            with self.assertRaises(RestoreError):
                st.retire_archives(["A1"], self.out_dir)
        with open(outside, "rb") as fh:
            self.assertEqual(fh.read(), b"do-not-touch")

    def test_shared_block_kept_until_last_referencing_archive_retires(self):
        self.init_station()
        self.publish_all()
        with Station(self.data_dir).open() as st:
            st.retire_archives(["A1"], self.out_dir)
            # b2 仍被 A2 引用：保留
            self.assertTrue(os.path.exists(self.store_path("b2")))
            st.retire_archives(["A2"], self.out_dir)
            # 最后一个引用者退役后：b2 才被回收
            self.assertFalse(os.path.exists(self.store_path("b2")))


class TestRetireCli(RetireTestBase):
    def _run_cli(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", RUN_PY, *argv],
                              capture_output=True, text=True,
                              env=dict(os.environ))

    def test_cli_retire_exit_codes_and_output(self):
        manifest_path = os.path.join(self.tmp, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh)
        dd = self.data_dir
        shutil.rmtree(dd, ignore_errors=True)
        r = self._run_cli("init", "--data-dir", dd,
                          "--manifest", manifest_path, "--key", KEY.decode())
        self.assertEqual(r.returncode, 0, r.stderr)

        # 交付全部块并发布两个档案
        with Station(dd).open() as st:
            self.deliver(st, "b1", "b2", "b3")
            st.restore_archives(self.out_dir)

        req = os.path.join(self.tmp, "retire_req.json")
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"archive_ids": ["A1"]}, fh)
        r = self._run_cli("retire", "--data-dir", dd,
                          "--output-dir", self.out_dir, "--request", req)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        out = json.loads(r.stdout)
        self.assertTrue(out["ok"])
        self.assertEqual(out["retired_now"], ["A1"])
        self.assertFalse(os.path.exists(
            os.path.join(self.out_dir, "instr", "a1.dat")))
        self.assertFalse(os.path.exists(self.store_path("b1")))

        # 重复执行：幂等成功，退出码仍为 0
        r = self._run_cli("retire", "--data-dir", dd,
                          "--output-dir", self.out_dir, "--request", req)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual(json.loads(r.stdout)["code"],
                         "archives_already_retired")

        # 未知档案：整次拒绝，退出码 2
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"archive_ids": ["A2", "GHOST"]}, fh)
        r = self._run_cli("retire", "--data-dir", dd,
                          "--output-dir", self.out_dir, "--request", req)
        self.assertEqual(r.returncode, 2)
        self.assertFalse(json.loads(r.stdout)["ok"])
        self.assertTrue(os.path.isfile(os.path.join(self.out_dir, "a2.dat")))

        # 用法错误（缺 archive_ids）：退出码 3
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"archive_ids": []}, fh)
        r = self._run_cli("retire", "--data-dir", dd,
                          "--output-dir", self.out_dir, "--request", req)
        self.assertEqual(r.returncode, 3)

        # 退役后 restore：A1 跳过为 retired，A2 保持已发布，退出码 0
        r = self._run_cli("restore", "--data-dir", dd,
                          "--output-dir", self.out_dir)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        restored = json.loads(r.stdout)
        self.assertEqual(restored["archives_retired"], 1)
        states = {x["archive_id"]: x["state"] for x in restored["results"]}
        self.assertEqual(states["A1"], "retired")
        self.assertEqual(states["A2"], "verified_existing")

        # 报告与重演交叉核对一致
        r = self._run_cli("verify", "--data-dir", dd)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertTrue(json.loads(r.stdout)["matched"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
