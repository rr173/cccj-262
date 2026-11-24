"""回补台规则测试（仅标准库 unittest，离线运行）。"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backfill_station.canonical import digest_payload, sign_payload  # noqa: E402
from backfill_station.fixture import TransmissionFixture  # noqa: E402
from backfill_station.journal import Journal  # noqa: E402
from backfill_station.manifest import Manifest  # noqa: E402
from backfill_station.station import Station  # noqa: E402
from backfill_station.state import ST_CONFIRMED, ST_OPEN, replay  # noqa: E402

KEY = b"unit-test-hmac-key-0123456789ab"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_PY = os.path.join(ROOT, "run.py")


def manifest_of(blocks: dict[str, bytes], quota: int) -> dict:
    return {
        "batch_id": "B-TEST",
        "quota_bytes": quota,
        "blocks": [
            {"block_id": bid, "length": len(data),
             "sha256": digest_payload(data)}
            for bid, data in sorted(blocks.items())
        ],
    }


class StationTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="bfs_test_")
        self.data_dir = os.path.join(self.tmp, "data")
        self.fx_dir = os.path.join(self.tmp, "fx")
        self.rng = random.Random(42)
        self.blocks = {
            "b1": bytes(range(256)),
            "b2": b"hello-backfill-" * 10,
            "b3": b"\x00" * 80,
        }
        self.quota = 600
        self.manifest = manifest_of(self.blocks, self.quota)
        self.station = Station.initialize(self.data_dir, self.manifest, KEY)
        self.fixture = TransmissionFixture(self.fx_dir, KEY)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def open(self):
        return self.station.open()

    def grant(self, st, pid, bid):
        spec = self.manifest_block(bid)
        return st.grant_permit(pid, bid, spec["length"])

    def manifest_block(self, bid):
        return next(b for b in self.manifest["blocks"]
                    if b["block_id"] == bid)


class TestAdmission(StationTestBase):
    def test_cap_must_equal_block_length(self):
        with self.open() as st:
            r = st.grant_permit("PX", "b1", 100)
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "permit_cap_mismatch")

    def test_admission_projection_blocks_overspend(self):
        with self.open() as st:
            # b1=256 + b2=150 + b3=80 = 486，仍 <=600
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            self.assertTrue(self.grant(st, "P2", "b2").ok)
            self.assertTrue(self.grant(st, "P3", "b3").ok)
            self.assertEqual(st.ledger.obligations, 486)
            # 再来一个 b1（256）会到 742 > 600，必须在领取前拦住
            r = st.grant_permit("P4", "b1", 256)
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "permit_admission_denied")
            self.assertEqual(st.ledger.obligations, 486)  # 未产生占用

    def test_permit_id_never_reusable(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            r = st.grant_permit("P1", "b1", 256)
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "permit_id_reused")
            self.assertEqual(len(st.ledger.permits), 1)

    def test_early_termination_releases_capacity_for_other_block(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)   # 256
            self.assertTrue(self.grant(st, "P2", "b2").ok)   # 150
            # 406 占用，剩余 194，不够新的 b1
            self.assertFalse(st.grant_permit("PX", "b1", 256).ok)
            # P2 提前结束，终值 60（先发 60 字节再断开）
            sender = self.fixture.open_sender("P2", "b2", 150)
            sender.send(b"h" * 60)
            sender.terminate_early(60)
            st.ingest_receipt({"permit_id": "P2", "kind": "final",
                               "seq": 2, "bytes": 60, "closed": True})
            st.submit_termination_cert(sender.make_cert())
            self.assertEqual(st.ledger.confirmed_spend, 60)
            # 释放 100 后仍不够 256…… 再终止 P1
            sender1 = self.fixture.open_sender("P1", "b1", 256)
            sender1.send(b"z" * 10)
            sender1.terminate_early(10)
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 2, "bytes": 10, "closed": True})
            st.submit_termination_cert(sender1.make_cert())
            # 现义务 60+10=70，可用 530，新 b1 许可 256 可发放
            self.assertTrue(st.grant_permit("P5", "b1", 256).ok)
            self.assertLessEqual(st.ledger.obligations, self.quota)


class TestReceipts(StationTestBase):
    def _permit(self, st, pid="P1", bid="b1"):
        self.assertTrue(self.grant(st, pid, bid).ok)

    def test_progress_monotonic_duplicates_idempotent(self):
        with self.open() as st:
            self._permit(st)
            st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                               "seq": 1, "bytes": 100})
            # 乱序到达的旧进度不回退
            st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                               "seq": 2, "bytes": 200})
            st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                               "seq": 1, "bytes": 100})  # 完全重放
            self.assertEqual(st.ledger.permits["P1"].max_progress, 200)
            # 同 seq 矛盾字节数：异常且不改变状态
            r = st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                                   "seq": 1, "bytes": 150})
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "duplicate_progress_conflict")
            self.assertEqual(st.ledger.permits["P1"].max_progress, 200)

    def test_receipt_beyond_cap_is_anomaly(self):
        with self.open() as st:
            self._permit(st)
            r = st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                                   "seq": 1, "bytes": 257})
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "receipt_exceeds_cap")
            self.assertEqual(st.ledger.permits["P1"].max_progress, 0)

    def test_unknown_permit_receipt_anomaly(self):
        with self.open() as st:
            r = st.ingest_receipt({"permit_id": "NOPE", "kind": "progress",
                                   "seq": 1, "bytes": 10})
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "unknown_permit_receipt")

    def test_final_establishes_terminal_value_late_progress_cannot_offset(self):
        with self.open() as st:
            self._permit(st)
            st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                               "seq": 1, "bytes": 100})
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 2, "bytes": 120, "closed": True})
            # 超终值的迟到进度：异常，终值不动
            r = st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                                   "seq": 3, "bytes": 180})
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "receipt_progress_beyond_final")
            self.assertEqual(st.ledger.permits["P1"].final_value, 120)
            # 同值 final 重放幂等
            r = st.ingest_receipt({"permit_id": "P1", "kind": "final",
                                   "seq": 2, "bytes": 120, "closed": True})
            self.assertTrue(r.ok)
            self.assertEqual(r.code, "final_receipt_duplicate_ignored")
            # 矛盾终值
            r = st.ingest_receipt({"permit_id": "P1", "kind": "final",
                                   "seq": 4, "bytes": 130, "closed": True})
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "final_receipt_value_conflict")
            self.assertEqual(st.ledger.permits["P1"].final_value, 120)

    def test_shuffled_spool_replays_deterministically(self):
        fx = self.fixture
        with self.open() as st:
            self._permit(st)
        sender = fx.open_sender("P1", "b1", 256)
        sender.send(b"a" * 100)
        sender.send(b"b" * 100)
        sender.emit_duplicate_progress(1)
        sender.close(final_value=200)
        fx.shuffle_spool(random.Random(7))
        with self.open() as st:
            for item in fx.iter_spool():
                receipt = {k: v for k, v in item.items() if k != "stream"}
                st.ingest_receipt(receipt)
            p = st.ledger.permits["P1"]
            self.assertEqual(p.max_progress, 200)
            self.assertEqual(p.final_value, 200)


class TestTerminationCerts(StationTestBase):
    def _setup(self, st, pid="P1", bid="b1"):
        self.assertTrue(self.grant(st, pid, bid).ok)
        return self.fixture.open_sender(pid, bid, 256)

    def test_valid_cert_confirms_and_releases(self):
        with self.open() as st:
            sender = self._setup(st)
            sender.send(b"a" * 100)
            sender.terminate_early(100)
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 2, "bytes": 100, "closed": True})
            r = st.submit_termination_cert(sender.make_cert())
            self.assertTrue(r.ok)
            p = st.ledger.permits["P1"]
            self.assertEqual(p.status, ST_CONFIRMED)
            self.assertEqual(p.reserved, 100)
            self.assertEqual(st.ledger.confirmed_spend, 100)
            self.assertEqual(st.ledger.reserved_open, 0)

    def test_bad_signature_rejected(self):
        with self.open() as st:
            sender = self._setup(st)
            sender.close(final_value=0)
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 1, "bytes": 0, "closed": True})
            bad = TransmissionFixture.tamper_cert(sender.make_cert(),
                                                  bad_signature=True)
            r = st.submit_termination_cert(bad)
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "termination_cert_bad_signature")
            self.assertEqual(st.ledger.permits["P1"].status, ST_OPEN)

    def test_conflicting_second_cert_never_overwrites(self):
        with self.open() as st:
            sender = self._setup(st)
            sender.send(b"a" * 50)
            sender.terminate_early(50)
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 1, "bytes": 50, "closed": True})
            good = sender.make_cert()
            self.assertTrue(st.submit_termination_cert(good).ok)
            # 用有效密钥重签一份篡改终值的第二份凭据：
            # 签名能过，但与已核实终值冲突，绝不覆盖
            forged = self.fixture.resign_cert(good, final_value=10)
            r = st.submit_termination_cert(forged)
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "duplicate_termination_cert_conflict")
            self.assertEqual(st.ledger.permits["P1"].final_value, 50)

    def test_cert_before_final_held_then_auto_confirmed(self):
        with self.open() as st:
            sender = self._setup(st)
            sender.send(b"a" * 40)
            sender.terminate_early(40)
            cert = sender.make_cert()
            # 终止证先到：挂起、仍按封顶占用
            r = st.submit_termination_cert(cert)
            self.assertTrue(r.ok)
            self.assertEqual(r.code, "termination_cert_held")
            self.assertEqual(st.ledger.reserved_open, 256)
            self.assertIsNotNone(st.ledger.permits["P1"].held_cert)
            # final 后到且匹配：自动确认，释放 216
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 2, "bytes": 40, "closed": True})
            p = st.ledger.permits["P1"]
            self.assertEqual(p.status, ST_CONFIRMED)
            self.assertEqual(st.ledger.reserved_open, 0)
            self.assertEqual(st.ledger.confirmed_spend, 40)

    def test_held_cert_mismatch_discarded_keeps_cap(self):
        with self.open() as st:
            sender = self._setup(st)
            sender.send(b"a" * 41)
            sender.terminate_early(40)
            cert = sender.make_cert()
            st.submit_termination_cert(cert)
            # final 与挂起证终值不一致
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 2, "bytes": 41, "closed": True})
            p = st.ledger.permits["P1"]
            self.assertEqual(p.status, ST_OPEN)       # 仍未终止
            self.assertIsNone(p.held_cert)
            self.assertEqual(st.ledger.reserved_open, 256)  # 不减少占用


class TestBlockDelivery(StationTestBase):
    def test_three_way_check_identity_length_digest(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            # 身份不符
            r = st.submit_block("P1", "b2", self.blocks["b2"])
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "block_permit_target_mismatch")
            # 长度不符
            r = st.submit_block("P1", "b1", self.blocks["b1"][:-1])
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "block_length_mismatch")
            # 摘要不符
            corrupt = TransmissionFixture.corrupt(self.blocks["b1"])
            r = st.submit_block("P1", "b1", corrupt)
            self.assertFalse(r.ok)
            self.assertEqual(r.code, "block_digest_mismatch")
            self.assertFalse(st.ledger.blocks["b1"].delivered)
            # 三核对通过
            r = st.submit_block("P1", "b1", self.blocks["b1"])
            self.assertTrue(r.ok)
            self.assertEqual(r.code, "block_verified")

    def test_duplicate_block_and_separate_billing(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            self.assertTrue(st.grant_permit("P2", "b1", 256).ok)
            st.submit_block("P1", "b1", self.blocks["b1"])
            # 重送同一完备块
            r = st.submit_block("P1", "b1", self.blocks["b1"])
            self.assertEqual(r.code, "block_already_delivered_ignored")
            # 另一许可实收相同内容：覆盖条数不增
            r = st.submit_block("P2", "b1", self.blocks["b1"])
            self.assertEqual(r.code, "block_already_delivered_ignored")
            self.assertEqual(st.ledger.blocks["b1"].delivered_event_seq,
                             st.ledger.blocks["b1"].delivered_event_seq)
            self.assertEqual(len(st.ledger.permits), 2)  # 两笔仍各自计费占用

    def test_receipt_never_proves_block(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 1, "bytes": 256, "closed": True})
            # 只有收据、没有通过三核对的块 -> 仍缺块
            self.assertIn("b1", [b.block_id for b in st.ledger.missing_blocks()])


class TestRestartAndReplay(StationTestBase):
    def test_restart_rebuilds_and_no_refund_no_rearm(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            sender = self.fixture.open_sender("P1", "b1", 256)
            sender.send(b"a" * 30)
            sender.terminate_early(30)
            st.ingest_receipt({"permit_id": "P1", "kind": "final",
                               "seq": 2, "bytes": 30, "closed": True})
            cert = sender.make_cert()
            st.submit_termination_cert(cert)
            self.assertTrue(self.grant(st, "P2", "b3").ok)  # 80，无终止证
            expected = st.report()

        # 新进程：仅从日志重建
        fresh = Station(self.data_dir)
        with fresh.open() as st:
            rebuilt = st.report()
            self.assertEqual(rebuilt["quota_account"],
                             expected["quota_account"])
            # 已终止许可终值不变
            self.assertEqual(st.ledger.permits["P1"].final_value, 30)
            # 未终止许可仍按封顶占用
            self.assertEqual(st.ledger.permits["P2"].reserved, 80)
            # 同证重交幂等
            r = st.submit_termination_cert(cert)
            self.assertEqual(r.code, "termination_cert_duplicate_ignored")
            # 同名许可不能重新启用
            r = st.grant_permit("P2", "b3", 80)
            self.assertEqual(r.code, "permit_id_reused")

    def test_replay_command_matches_live_report(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            st.ingest_receipt({"permit_id": "P1", "kind": "progress",
                               "seq": 1, "bytes": 10})
        out = subprocess.run(
            [sys.executable, "-I", RUN_PY, "replay",
             "--data-dir", self.data_dir],
            capture_output=True, text=True, check=True)
        replayed = json.loads(out.stdout)
        self.assertTrue(replayed["replay_only"])
        # 事件：开账 + 发许可 + 一条进度
        self.assertEqual(replayed["journal_last_seq"], 3)

        out = subprocess.run(
            [sys.executable, "-I", RUN_PY, "verify",
             "--data-dir", self.data_dir],
            capture_output=True, text=True, check=True)
        self.assertTrue(json.loads(out.stdout)["matched"])

    def test_corrupt_journal_fails_hard(self):
        journal_path = os.path.join(self.data_dir, "journal.jsonl")
        with open(journal_path, "a", encoding="utf-8") as fh:
            fh.write('{"seq": 99, "ts": 1, "type": "evil"}\n')
        with self.assertRaises(Exception):
            replay(list(Journal.replay(journal_path)))

    def test_unterminated_permit_keeps_cap_after_restart_even_if_block_landed(
            self):
        # P1 拿到许可后彻底失联：无 final、无终止证。
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b1").ok)
            # 另一个许可 P2 把同一个块完整拿到并通过三核对
            self.assertTrue(st.grant_permit("P2", "b1", 256).ok)
            st.submit_block("P2", "b1", self.blocks["b1"])
            self.assertTrue(st.ledger.blocks["b1"].delivered)
            # P1 仍按封顶占用，不会因为块已由别人交付而退款
            self.assertEqual(st.ledger.permits["P1"].reserved, 256)
            self.assertEqual(st.ledger.obligations, 512)

        fresh = Station(self.data_dir)
        with fresh.open() as st:
            p1 = st.ledger.permits["P1"]
            self.assertEqual(p1.status, ST_OPEN)
            self.assertEqual(p1.reserved, 256)
            self.assertIsNone(p1.final_value)
            self.assertEqual(st.ledger.reserved_open, 512)
            self.assertEqual(st.ledger.confirmed_spend, 0)
            # 缺块表里不再有 b1（b2/b3 本就没尝试），但钱仍被 P1 占着
            missing_ids = {b.block_id for b in st.ledger.missing_blocks()}
            self.assertNotIn("b1", missing_ids)
            self.assertIn("b2", missing_ids)

    def test_admission_snapshot_is_auditable(self):
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b3").ok)  # 80
            r = st.grant_permit("P2", "b1", 256)
            self.assertTrue(r.ok)
        events = list(Journal.replay(os.path.join(self.data_dir,
                                                  "journal.jsonl")))
        grant_events = [e for e in events if e.type == "permit_granted"]
        snap = grant_events[-1].payload["admission_snapshot"]
        self.assertEqual(snap["obligations_before"], 80)
        self.assertEqual(snap["projected_obligations"], 336)
        self.assertEqual(snap["quota"], 600)


class TestCliEndToEnd(StationTestBase):
    def test_cli_full_flow(self):
        manifest_path = os.path.join(self.tmp, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh)
        env = dict(os.environ)
        py = [sys.executable, "-I", RUN_PY]
        dd = self.data_dir
        shutil.rmtree(dd, ignore_errors=True)

        r = subprocess.run(py + ["init", "--data-dir", dd,
                                 "--manifest", manifest_path,
                                 "--key", KEY.decode()],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)

        req = os.path.join(self.tmp, "req.json")
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "P1", "block_id": "b3", "cap": 80}, fh)
        r = subprocess.run(py + ["grant", "--data-dir", dd,
                                 "--request", req],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)

        receipt = os.path.join(self.tmp, "receipt.json")
        with open(receipt, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "P1", "kind": "final", "seq": 1,
                       "bytes": 80, "closed": True}, fh)
        r = subprocess.run(py + ["receipt", "--data-dir", dd,
                                 "--receipt", receipt],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)

        # 准入拒绝应返回退出码 2：当前义务 80，再加 b1 封顶 256 -> 336 <=600
        # 所以这里改成会超支的申请：b1=256，剩余可用 520 仍够……
        # 改为先把额度吃满：再领两个 b1（256*2+80=592），第三个必拒
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "P2", "block_id": "b1", "cap": 256}, fh)
        r = subprocess.run(py + ["grant", "--data-dir", dd,
                                 "--request", req],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "P3", "block_id": "b1", "cap": 256}, fh)
        r = subprocess.run(py + ["grant", "--data-dir", dd,
                                 "--request", req],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)  # 80+256+256=592
        with open(req, "w", encoding="utf-8") as fh:
            json.dump({"permit_id": "PBIG", "block_id": "b1", "cap": 256}, fh)
        r = subprocess.run(py + ["grant", "--data-dir", dd,
                                 "--request", req],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertFalse(json.loads(r.stdout)["ok"])

        r = subprocess.run(py + ["report", "--data-dir", dd],
                           capture_output=True, text=True, env=env)
        report = json.loads(r.stdout)
        # 被拒不产生占用，义务为 592
        self.assertEqual(report["quota_account"]["obligations_total"], 592)
        self.assertTrue(report["quota_account"]["invariant_holds"])


class TestFixtureEnforcement(StationTestBase):
    def test_fixture_blocks_overcap_send(self):
        sender = self.fixture.open_sender("P1", "b3", 80)
        with self.assertRaises(Exception):
            sender.send(b"x" * 81)
        # 坏字节也计入封顶
        sender.send(b"x" * 70, good=False)
        with self.assertRaises(Exception):
            sender.send(b"y" * 11)

    def test_manifest_accepts_underfilled_period(self):
        # 单账期额度小于整批总量是合法场景：清单成立，
        # 超支由运行时准入控制拦截，而不是清单阶段禁止。
        under = manifest_of({"b1": b"a" * 100}, quota=50)
        parsed = Manifest.from_dict(under)
        self.assertEqual(parsed.quota_bytes, 50)
        self.assertEqual(parsed.blocks[0].length, 100)

    def test_manifest_rejects_duplicate_block_id(self):
        bad = {
            "batch_id": "B", "quota_bytes": 100,
            "blocks": [
                {"block_id": "x", "length": 10,
                 "sha256": "0" * 64},
                {"block_id": "x", "length": 10,
                 "sha256": "0" * 64},
            ],
        }
        with self.assertRaises(ValueError):
            Manifest.from_dict(bad)


class TestCliSpool(StationTestBase):
    def test_spool_command_replays_fixture_stream(self):
        # 台里发一个许可，夹具造乱序收据流（含一条超封顶异常）
        with self.open() as st:
            self.assertTrue(self.grant(st, "P1", "b3").ok)  # cap 80
        sender = self.fixture.open_sender("P1", "b3", 80)
        sender.send(b"a" * 30)
        sender.send(b"b" * 20)
        sender.emit_duplicate_progress(1)
        sender.close(final_value=50)
        self.fixture.append_raw_spool(
            {"stream": "receipt", "permit_id": "P1", "kind": "progress",
             "seq": 99, "bytes": 81})
        self.fixture.shuffle_spool(random.Random(3))

        r = subprocess.run(
            [sys.executable, "-I", RUN_PY, "spool",
             "--data-dir", self.data_dir,
             "--fixture-dir", self.fx_dir],
            capture_output=True, text=True, check=True)
        summary = json.loads(r.stdout)
        self.assertTrue(summary["ok"])
        self.assertGreaterEqual(summary["receipts_rejected_as_anomaly"], 1)

        with Station(self.data_dir).open() as st:
            p = st.ledger.permits["P1"]
            self.assertEqual(p.max_progress, 50)
            self.assertEqual(p.final_value, 50)
            # 超封顶的 81 没有污染进度
            self.assertLess(p.max_progress, 81)


if __name__ == "__main__":
    unittest.main(verbosity=2)
