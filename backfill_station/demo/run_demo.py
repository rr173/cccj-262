#!/usr/bin/env python3
"""端到端演示：离线重演一个完整采集账期。

故事线（全部由固定种子驱动，重复运行逐字节一致）：
  P1 完整收齐 b1，final 收据先于块到、也先于终止证到；
  P2 收到一半提前断开，终止证先到（挂起、继续按封顶占用），
     final 收据后到才释放额度；重启后重交同证必须幂等；
  P3 收到坏字节（照计费），块摘要不符被拒；
  P4 重发同一完备块只确认一次；另一许可实收相同内容仍单独计费；
  P5 摘要正确但长度被截断的块被拒；
  P6 超封顶进度、矛盾重放、坏签名/冲突终止证全部记异常；
  中途模拟进程崩溃：丢弃全部内存状态，仅靠日志重建；
  P7 用 P2 提前结束释放的额度补到缺块 b2；
  P8/P10 在额度不足时被准入拒绝，缺块表准确列出 b5。
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backfill_station.canonical import canonical_json, digest_payload  # noqa: E402
from backfill_station.fixture import TransmissionFixture  # noqa: E402
from backfill_station.station import Station  # noqa: E402

HMAC_KEY = b"demo-shared-secret-key-0123456789"
SEED = 20261124
RUN_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "run")
DATA_DIR = os.path.join(RUN_ROOT, "demo_data")
FIXTURE_DIR = os.path.join(RUN_ROOT, "demo_fixture")
ARCHIVE_DIR = os.path.join(RUN_ROOT, "demo_archives")
REPORT_PATH = os.path.join(RUN_ROOT, "demo_report.json")
JOURNAL_COPY = os.path.join(RUN_ROOT, "demo_journal_copy.jsonl")


def make_content(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(length))


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(result) -> None:
    print("  ->", canonical_json(result.to_dict()))


def main() -> int:
    rng = random.Random(SEED)
    shutil.rmtree(RUN_ROOT, ignore_errors=True)
    os.makedirs(RUN_ROOT, exist_ok=True)

    # ---- 1. 档案清单：固定块身份、长度、摘要 ----
    lengths = {"b1": 200, "b2": 300, "b3": 150, "b4": 250, "b5": 400}
    contents = {bid: make_content(rng, length)
                for bid, length in lengths.items()}
    # 额度高于整批全长，为重复尝试/坏字节留空间；结尾留一笔未终止的
    # b5 许可按封顶 400 保留，使可用额度跌破 400，新的 b5 许可必被拒。
    quota = 2300

    # ---- 档案产物声明：不同档案可引用同一块，路径限定在输出目录内 ----
    archive_full = b"".join(contents[bid] for bid in ("b1", "b2", "b3", "b4"))
    archive_b14 = contents["b1"] + contents["b4"]      # 与 full 共享 b1/b4
    archives = [
        {"archive_id": "ARC-INSTR-FULL",
         "path": os.path.join("instrument", "full_profile.dat"),
         "block_ids": ["b1", "b2", "b3", "b4"],
         "length": len(archive_full),
         "sha256": digest_payload(archive_full)},
        {"archive_id": "ARC-INSTR-B14",
         "path": os.path.join("instrument", "b14_pair.dat"),
         "block_ids": ["b1", "b4"],
         "length": len(archive_b14),
         "sha256": digest_payload(archive_b14)},
        # b5 始终缺块：该档案在恢复时必须被整体挡下、不生成文件。
        {"archive_id": "ARC-PENDING-B5",
         "path": "pending/b5_only.dat",
         "block_ids": ["b5"],
         "length": len(contents["b5"]),
         "sha256": digest_payload(contents["b5"])},
    ]
    manifest = {
        "batch_id": "BATCH-DEMO-001",
        "quota_bytes": quota,
        "blocks": [
            {"block_id": bid, "length": len(contents[bid]),
             "sha256": digest_payload(contents[bid])}
            for bid in sorted(lengths)
        ],
        "archives": archives,
    }
    print(f"清单块全长合计 {sum(lengths.values())}，批次额度 {quota}")
    print(f"档案产物声明 {len(archives)} 个，"
          f"其中 ARC-PENDING-B5 依赖始终缺块的 b5")

    station = Station.initialize(DATA_DIR, manifest, HMAC_KEY)
    fixture = TransmissionFixture(FIXTURE_DIR, HMAC_KEY)
    print("HMAC 指纹（台与夹具共用一把密钥）:", fixture.hmac_footprint())

    # ---- 2. 预领全部许可（准入在领取瞬间检查） ----
    banner("阶段一：领取许可（含一笔超清单封顶的非法申请）")
    grants = [
        ("P1", "b1", 200), ("P2", "b2", 300), ("P3", "b3", 150),
        ("P4", "b4", 250), ("P4B", "b4", 250), ("P5", "b5", 400),
        ("P6", "b1", 200),
    ]
    with station.open() as st:
        for pid, bid, cap in grants:
            show(st.grant_permit(pid, bid, cap))
        # 封顶不等于块长度：拒绝并记异常
        show(st.grant_permit("P-BADCAP", "b1", 199))
        # 不可复用：同名许可再领一次
        show(st.grant_permit("P1", "b1", 200))
        print("  当前义务:", st.ledger.obligations,
              " 可用:", st.ledger.available)

    # ---- 3. 夹具侧传输（严格封顶，坏字节照计费） ----
    banner("阶段二：本地有界夹具传输")
    s1 = fixture.open_sender("P1", "b1", 200)
    s1.send(contents["b1"][:120])
    s1.send(contents["b1"][120:])          # 完整 200，全好字节
    r1 = s1.close()                          # final=200
    s1.emit_duplicate_progress(1)           # 重复进度条，稍后洗牌
    drop1 = s1.payload_full(contents["b1"])
    cert1 = s1.make_cert()

    s2 = fixture.open_sender("P2", "b2", 300)
    s2.send(contents["b2"][:100])
    s2.send(contents["b2"][100:160], good=False)  # 60 坏字节：计费不计实收
    s2.terminate_early(final_value=100)     # 收到一半断开，final=100
    cert2 = s2.make_cert()

    s3 = fixture.open_sender("P3", "b3", 150)
    s3.send(contents["b3"][:80])
    s3.send(contents["b3"][80:], good=False)     # 后 70 字节损坏
    s3.close(final_value=150)
    drop3 = s3.payload_corrupt(
        contents["b3"][:80] + TransmissionFixture.corrupt(contents["b3"][80:]))
    cert3 = s3.make_cert()

    s4 = fixture.open_sender("P4", "b4", 250)
    s4.send(contents["b4"])
    s4.close()
    drop4 = s4.payload_full(contents["b4"])
    cert4 = s4.make_cert()

    s4b = fixture.open_sender("P4B", "b4", 250)
    s4b.send(contents["b4"])                # 实收相同内容
    s4b.close()
    cert4b = s4b.make_cert()

    s5 = fixture.open_sender("P5", "b5", 400)
    s5.send(contents["b5"][:200])
    s5.send(contents["b5"][200:350])
    s5.terminate_early(final_value=350)     # 提前结束，缺 50
    truncated = contents["b5"][:350]
    drop5 = s5.payload_corrupt(truncated)
    cert5 = s5.make_cert()

    s6 = fixture.open_sender("P6", "b1", 200)
    s6.send(b"x" * 50)
    s6.close(final_value=50)
    cert6 = s6.make_cert()

    # 注入异常条目：超封顶进度、矛盾的同序号重放
    fixture.append_raw_spool({"stream": "receipt", "permit_id": "P6",
                              "kind": "progress", "seq": 99, "bytes": 201})
    fixture.append_raw_spool({"stream": "receipt", "permit_id": "P6",
                              "kind": "progress", "seq": 1, "bytes": 999})
    fixture.append_raw_spool({"stream": "receipt", "permit_id": "GHOST",
                              "kind": "progress", "seq": 1, "bytes": 10})
    fixture.shuffle_spool(rng)              # 乱序 + 重复落盘
    print("收据流已洗牌落盘:", fixture._spool_path)

    # ---- 4. 回放收据流，穿插终止证与块提交 ----
    banner("阶段三：回放收据流 + 终止证/块三核对")
    with station.open() as st:
        for item in fixture.iter_spool():
            receipt = {k: v for k, v in item.items() if k != "stream"}
            show(st.ingest_receipt(receipt))

        # P1：final 收据已随乱序流先到，这里终止证后到仍可核实确认
        show(st.submit_termination_cert(cert1))
        # P2：同证重交幂等与冲突证拒绝（P6）
        show(st.submit_termination_cert(cert2))
        show(st.submit_termination_cert(cert2))   # 同证重放：幂等
        show(st.submit_termination_cert(cert3))
        show(st.submit_termination_cert(cert4))
        show(st.submit_termination_cert(cert4b))
        show(st.submit_termination_cert(cert5))

        # P6 的坏签名终止证、有效签名但终值冲突的第二份凭据
        bad_sig = TransmissionFixture.tamper_cert(cert6, bad_signature=True)
        conflict = fixture.resign_cert(cert6, final_value=120)
        show(st.submit_termination_cert(bad_sig))
        show(st.submit_termination_cert(conflict))
        show(st.submit_termination_cert(cert6))    # 正本仍可核实
        show(st.submit_termination_cert(cert6))    # 再次幂等

        # 未知许可的终止证：签名即使有效也不能冒充
        ghost_cert = fixture.sign_termination_cert("GHOST", 100, 10)
        show(st.submit_termination_cert(ghost_cert))
        # P1 已立终值 200：超封顶的迟到进度直接记超封顶异常
        show(st.ingest_receipt(
            {"permit_id": "P1", "kind": "progress", "seq": 90,
             "bytes": 201}))
        # P2 终值 100 < 封顶 300：未超封顶但超终值，记超终值异常，
        # 终值不被抵销
        show(st.ingest_receipt(
            {"permit_id": "P2", "kind": "progress", "seq": 90,
             "bytes": 150}))
        # 矛盾终值的第二份 final
        show(st.ingest_receipt(
            {"permit_id": "P1", "kind": "final", "seq": 91,
             "bytes": 205, "closed": True}))

        # 块侧核对
        # b1：final 收据先到不证明块，必须三核对通过才计交付
        show(st.submit_block("P1", "b1",
                             open(os.path.join(FIXTURE_DIR, drop1.payload_path),
                                  "rb").read()))
        show(st.submit_block("P3", "b3",
                             open(os.path.join(FIXTURE_DIR, drop3.payload_path),
                                  "rb").read()))
        show(st.submit_block("P4", "b4",
                             open(os.path.join(FIXTURE_DIR, drop4.payload_path),
                                  "rb").read()))
        show(st.submit_block("P4", "b4",
                             open(os.path.join(FIXTURE_DIR, drop4.payload_path),
                                  "rb").read()))  # 重送：不重复计覆盖
        show(st.submit_block("P4B", "b4",
                             open(os.path.join(FIXTURE_DIR, drop4.payload_path),
                                  "rb").read()))  # 同内容他许可：覆盖不增
        show(st.submit_block("P5", "b5",
                             open(os.path.join(FIXTURE_DIR, drop5.payload_path),
                                  "rb").read()))  # 长度不符
        # 许可绑定块身份不符
        show(st.submit_block("P6", "b4", contents["b4"]))
        # 未知许可
        show(st.submit_block("GHOST", "b1", contents["b1"]))

    # ---- 5. 演示“终止证先到、final 后到”的挂起路径（新许可 P9） ----
    banner("阶段四：终止证先到挂起，final 收据后到自动确认")
    s9 = fixture.open_sender("P9", "b3", 150)
    s9.send(contents["b3"][:60])
    s9.terminate_early(final_value=60)
    cert9 = s9.make_cert()
    # 手工把 P9 的 final 条目从流里剥离：先只交终止证
    with station.open() as st:
        show(st.grant_permit("P9", "b3", 150))
        show(st.submit_termination_cert(cert9))   # 挂起，仍按 150 占用
        before = st.ledger.reserved_open
        show(st.ingest_receipt(
            {"permit_id": "P9", "kind": "progress", "seq": 1, "bytes": 60}))
        show(st.ingest_receipt(
            {"permit_id": "P9", "kind": "final", "seq": 2,
             "bytes": 60, "closed": True}))       # 匹配 -> 自动确认
        after = st.ledger.reserved_open
        print(f"  挂起期间保留 {before}，匹配确认后保留 {after}，"
              f"释放 {before - after}")

    # ---- 6. 崩溃：丢弃内存对象，仅靠日志重建 ----
    banner("阶段五：模拟进程崩溃，离线重演重建")
    del station
    shutil.copyfile(os.path.join(DATA_DIR, "journal.jsonl"), JOURNAL_COPY)
    station = Station(DATA_DIR)
    with station.open() as st:
        report_after_reopen = st.report()
        print("  重建后最后事件序号:", report_after_reopen["journal_last_seq"])
        print("  重建后已确认实付:",
              report_after_reopen["quota_account"]["confirmed_spend"])
        print("  重建后封顶保留:",
              report_after_reopen["quota_account"]["reserved_open_caps"])
        # 重启不能凭丢失进度退款：P9 已确认，同证再交仍幂等
        show(st.submit_termination_cert(cert9))
        # 同一许可不能重新启用一套封顶
        show(st.grant_permit("P9", "b3", 150))

    # ---- 7. 用提前释放的额度补块 ----
    banner("阶段六：回补缺块 b2、b3，准入拒绝留痕")
    s7 = fixture.open_sender("P7", "b2", 300)
    s7.send(contents["b2"])
    s7.close()
    drop7 = s7.payload_full(contents["b2"])
    cert7 = s7.make_cert()

    # b3 的第二次尝试：P3 坏字节失败后，新许可 P11 单独计费
    s11 = fixture.open_sender("P11", "b3", 150)
    s11.send(contents["b3"])
    s11.close()
    drop11 = s11.payload_full(contents["b3"])
    cert11 = s11.make_cert()

    with station.open() as st:
        show(st.grant_permit("P7", "b2", 300))
        show(st.ingest_receipt(
            {"permit_id": "P7", "kind": "progress", "seq": 1, "bytes": 300}))
        show(st.ingest_receipt(
            {"permit_id": "P7", "kind": "final", "seq": 2,
             "bytes": 300, "closed": True}))
        show(st.submit_termination_cert(cert7))
        show(st.submit_block("P7", "b2",
                             open(os.path.join(FIXTURE_DIR, drop7.payload_path),
                                  "rb").read()))

        show(st.grant_permit("P11", "b3", 150))
        show(st.ingest_receipt(
            {"permit_id": "P11", "kind": "progress", "seq": 1,
             "bytes": 150}))
        show(st.ingest_receipt(
            {"permit_id": "P11", "kind": "final", "seq": 2,
             "bytes": 150, "closed": True}))
        show(st.submit_termination_cert(cert11))
        show(st.submit_block("P11", "b3",
                             open(os.path.join(FIXTURE_DIR, drop11.payload_path),
                                  "rb").read()))

        # 再开一笔针对 b5 的许可但始终不终止：没有最终收据/终止证，
        # 即使进程重启也按封顶 400 保留，把可用额度压到 400 以下。
        show(st.grant_permit("P12", "b5", 400))
        print("  P12 已领取但无终止证，按封顶 400 保留，当前可用:",
              st.ledger.available)

        # b5 的任何新许可（400 封顶）此刻都付不起，必须准入拒绝；
        # 封顶不等于块长的非法申请单独记异常。
        show(st.grant_permit("P8", "b5", 400))
        show(st.grant_permit("P10", "b5", 399))

    # ---- 8. 最终对账 ----
    banner("阶段七：最终对账报告")
    with station.open() as st:
        report = st.report()
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
        fh.write("\n")

    qa = report["quota_account"]
    print(f"额度 {report['quota_bytes']} | 已确认实付 {qa['confirmed_spend']} "
          f"| 封顶保留 {qa['reserved_open_caps']} | 义务合计 "
          f"{qa['obligations_total']} | 可用 {qa['available']} "
          f"| 不变量 {qa['invariant_holds']}")
    print(f"交付 {report['delivery']['blocks_delivered']}/"
          f"{report['delivery']['blocks_total']}，缺块 "
          f"{[b['block_id'] for b in report['missing_blocks']]}")
    print(f"异常登记 {report['anomaly_count']} 条，报告已写 {REPORT_PATH}")
    print(f"日志副本 {JOURNAL_COPY}（可独立执行 replay 子命令重演）")

    # ---- 9. 档案恢复：组装已核验块，缺块档案整体挡下，重复恢复幂等 ----
    banner("阶段八：档案恢复（原子发布，缺块不生成文件，重复恢复一致）")
    with station.open() as st:
        restore_report = st.restore_archives(ARCHIVE_DIR)
        seq_after_restore = st.ledger.last_seq
    print("  首次恢复:")
    for item in restore_report["results"]:
        print(f"    {item['archive_id']:16s} {item['state']:16s} "
              f"{item['path']} {item['detail']}")
    # 再恢复一次：已发布文件应被原样确认，不重写、不改权限
    with station.open() as st:
        again = st.restore_archives(ARCHIVE_DIR)
        assert st.ledger.last_seq == seq_after_restore, "恢复不得新增日志事件"
    states_again = {r["archive_id"]: r["state"] for r in again["results"]}
    print("  二次恢复状态:", states_again)
    assert all(s == "verified_existing"
               for aid, s in states_again.items() if aid != "ARC-PENDING-B5")
    assert states_again["ARC-PENDING-B5"] == "blocked"

    # 发布结果逐字节核对；缺块档案在输出目录中不存在（含其父目录）
    full_path = os.path.join(ARCHIVE_DIR, "instrument", "full_profile.dat")
    pair_path = os.path.join(ARCHIVE_DIR, "instrument", "b14_pair.dat")
    with open(full_path, "rb") as fh:
        assert fh.read() == archive_full
    with open(pair_path, "rb") as fh:
        assert fh.read() == archive_b14
    assert not os.path.exists(os.path.join(ARCHIVE_DIR, "pending"))
    # 输出目录不得残留隐藏临时文件
    leftovers = []
    for dirpath, _dirs, files in os.walk(ARCHIVE_DIR):
        leftovers += [f for f in files if f.startswith(".archive.tmp.")]
    assert not leftovers
    print(f"  已发布: {full_path}")
    print(f"  已发布: {pair_path}")
    print("  ARC-PENDING-B5 因缺块 b5 未生成任何文件；无临时文件残留；"
          "日志序号未变")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
