"""回补台命令行：每个写命令独立持锁执行，可被任意 shell 脚本/多进程调用。

通用约定：
- 所有输入 JSON 从文件读（- 表示标准输入），字节载荷从二进制文件读；
- 结果以单行 JSON 写到标准输出，便于编排与断言；
- 业务被拒（如准入不足、摘要不符）退出码为 2，用法错误为 3，
  账目损坏等致命错误为 4，成功为 0。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .canonical import canonical_json
from .fixture import iter_spool_file
from .journal import Journal
from .manifest import Manifest
from .restore import RestoreError, archive_readiness
from .station import Station, StationError
from .state import Ledger, replay

EXIT_OK = 0
EXIT_BUSINESS_REJECT = 2
EXIT_USAGE = 3
EXIT_FATAL = 4


def _read_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _emit(obj: Any) -> None:
    sys.stdout.write(canonical_json(obj))
    sys.stdout.write("\n")


def _open_station(data_dir: str) -> Station:
    station = Station(data_dir)
    # 返回未进入上下文的对象；调用方负责 with station.open()
    return station


def cmd_init(args: argparse.Namespace) -> int:
    manifest_raw = _read_json(args.manifest)
    hmac_key = args.key.encode("utf-8")
    if len(hmac_key) < 16:
        print("HMAC 密钥至少 16 字节", file=sys.stderr)
        return EXIT_USAGE
    try:
        station = Station.initialize(args.data_dir, manifest_raw, hmac_key)
    except (StationError, ValueError) as exc:
        _emit({"ok": False, "error": str(exc)})
        return EXIT_USAGE
    _emit({"ok": True, "data_dir": args.data_dir,
           "batch_id": Manifest.read(args.data_dir).batch_id})
    return EXIT_OK


def cmd_grant(args: argparse.Namespace) -> int:
    req = _read_json(args.request)
    station = _open_station(args.data_dir)
    with station.open():
        result = station.grant_permit(
            str(req["permit_id"]), str(req["block_id"]), int(req["cap"]))
        _emit(result.to_dict())
        return EXIT_OK if result.ok else EXIT_BUSINESS_REJECT


def cmd_receipt(args: argparse.Namespace) -> int:
    receipt = _read_json(args.receipt)
    station = _open_station(args.data_dir)
    with station.open():
        result = station.ingest_receipt(receipt)
        _emit(result.to_dict())
        return EXIT_OK if result.ok else EXIT_BUSINESS_REJECT


def cmd_cert(args: argparse.Namespace) -> int:
    envelope = _read_json(args.cert)
    station = _open_station(args.data_dir)
    with station.open():
        result = station.submit_termination_cert(envelope)
        _emit(result.to_dict())
        return EXIT_OK if result.ok else EXIT_BUSINESS_REJECT


def cmd_block(args: argparse.Namespace) -> int:
    req = _read_json(args.request)
    with open(req["payload_path"], "rb") as fh:
        payload = fh.read()
    station = _open_station(args.data_dir)
    with station.open():
        result = station.submit_block(
            str(req["permit_id"]), str(req["block_id"]), payload)
        _emit(result.to_dict())
        return EXIT_OK if result.ok else EXIT_BUSINESS_REJECT


def cmd_report(args: argparse.Namespace) -> int:
    station = _open_station(args.data_dir)
    with station.open():
        _emit(station.report())
    return EXIT_OK


def cmd_replay(args: argparse.Namespace) -> int:
    """离线重演：只从日志重建账本并出报告，不打开追加句柄、不持写锁。"""
    try:
        events = list(Journal.replay(os.path.join(args.data_dir,
                                                  "journal.jsonl")))
        ledger = replay(events)
    except Exception as exc:  # 损坏即硬失败
        _emit({"ok": False, "error": f"重演失败: {exc}"})
        return EXIT_FATAL
    report = _report_from_ledger(ledger)
    report["replay_only"] = True
    _emit(report)
    return EXIT_OK

def _report_from_ledger(ledger: Ledger) -> dict[str, Any]:
    m = ledger.manifest
    missing = [{
        "block_id": b.spec.block_id,
        "length": b.spec.length,
        "sha256": b.spec.sha256,
        "attempt_permit_ids": list(b.attempt_permit_ids),
        "rejected_payloads": b.rejected_payloads,
    } for b in ledger.blocks.values() if not b.delivered]
    retained = ledger.retained_block_ids()
    reclaimed = ledger.reclaimed_block_ids()
    return {
        "batch_id": m.batch_id,
        "quota_bytes": m.quota_bytes,
        "journal_last_seq": ledger.last_seq,
        "quota_account": {
            "confirmed_spend": ledger.confirmed_spend,
            "reserved_open_caps": ledger.reserved_open,
            "obligations_total": ledger.obligations,
            "available": ledger.available,
            "invariant_holds": ledger.obligations <= m.quota_bytes,
            "note": "confirmed_spend=已终止许可终值之和；"
                    "reserved_open_caps=未终止许可按封顶保留之和",
        },
        "delivery": {
            "blocks_total": len(ledger.blocks),
            "blocks_delivered": sum(1 for b in ledger.blocks.values()
                                    if b.delivered),
            "blocks_retained": len(retained),
            "blocks_missing": len(missing),
            "delivered": [
                {"block_id": bid, "permit_id": b.delivered_by_permit,
                 "event_seq": b.delivered_event_seq}
                for bid, b in ledger.blocks.items() if b.delivered],
            "retained_block_ids": retained,
            "reclaimed_block_ids": reclaimed,
            "note": "delivered=历史可信交付事实（不随退役改变）；"
                    "retained_block_ids=当前仍保留存储的已交付块；"
                    "reclaimed_block_ids=已交付但存储已回收的块",
        },
        "missing_blocks": missing,
        "archives": archive_readiness(ledger),
        "retired_archives": sorted(ledger.retired_archives),
        "permits": [{
            "permit_id": p.permit_id, "block_id": p.block_id, "cap": p.cap,
            "status": p.status, "max_progress": p.max_progress,
            "final_value": p.final_value, "reserved_now": p.reserved,
            "has_final_receipt": p.final_value is not None,
            "has_verified_termination": p.cert_seq is not None,
            "cert_pending": p.held_cert is not None,
        } for p in ledger.permits.values()],
        "anomalies": ledger.anomalies,
        "anomaly_count": len(ledger.anomalies),
    }


def cmd_verify(args: argparse.Namespace) -> int:
    """交叉核对：日志重放报告 vs 实时报告，必须逐字段一致。"""
    events = list(Journal.replay(os.path.join(args.data_dir,
                                              "journal.jsonl")))
    replayed = _report_from_ledger(replay(events))
    station = _open_station(args.data_dir)
    with station.open():
        live = station.report()
    live.pop("replay_only", None)
    if replayed != live:
        _emit({"ok": False, "error": "重放报告与实时报告不一致",
               "replayed": replayed, "live": live})
        return EXIT_FATAL
    invariant_ok = live["quota_account"]["invariant_holds"]
    _emit({"ok": invariant_ok, "matched": True,
           "journal_last_seq": live["journal_last_seq"],
           "anomaly_count": live["anomaly_count"]})
    return EXIT_OK if invariant_ok else EXIT_FATAL


def cmd_spool(args: argparse.Namespace) -> int:
    """把夹具收据流逐条喂给回补台（离线重演传输过程）。"""
    rejects = 0
    processed = 0
    station = _open_station(args.data_dir)
    with station.open():
        for item in iter_spool_file(args.fixture_dir):
            if item.get("stream") != "receipt":
                continue
            receipt = {k: v for k, v in item.items() if k != "stream"}
            result = station.ingest_receipt(receipt)
            processed += 1
            if not result.ok:
                rejects += 1
            if args.verbose:
                _emit({"receipt": receipt, "result": result.to_dict()})
    _emit({"ok": True, "receipts_processed": processed,
           "receipts_rejected_as_anomaly": rejects})
    return EXIT_OK


def cmd_restore(args: argparse.Namespace) -> int:
    """档案恢复：已核验块按清单顺序组装并原子发布到输出目录。

    退出码：全部档案已发布（或本就没有档案声明）0；存在缺块被挡下
    的档案 2；路径越界/块仓库损坏等致命错误 4。已退役档案跳过不计。
    """
    station = _open_station(args.data_dir)
    with station.open():
        try:
            result = station.restore_archives(args.output_dir)
        except RestoreError as exc:
            _emit({"ok": False, "error": str(exc)})
            return EXIT_FATAL
    _emit(result)
    if result["archives_blocked"]:
        return EXIT_BUSINESS_REJECT
    return EXIT_OK


def cmd_retire(args: argparse.Namespace) -> int:
    """档案退役：标记退役、移除已发布文件并回收不再被引用的块存储。

    退出码：成功 0；请求含未声明 archive_id（整次拒绝，状态不变）2；
    用法错误 3；路径越界等致命错误 4。
    """
    req = _read_json(args.request)
    archive_ids = req.get("archive_ids") if isinstance(req, dict) else None
    station = _open_station(args.data_dir)
    with station.open():
        try:
            result = station.retire_archives(archive_ids, args.output_dir)
        except RestoreError as exc:
            _emit({"ok": False, "error": str(exc)})
            return EXIT_FATAL
    _emit(result)
    return EXIT_OK if result["ok"] else EXIT_BUSINESS_REJECT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="backfill-station",
        description="离线可重演的采集回补台")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="开账：冻结清单与 HMAC 密钥")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--manifest", required=True, help="清单 JSON 文件，- 为 stdin")
    p.add_argument("--key", required=True, help="HMAC 密钥字符串（>=16 字节）")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("grant", help="领取许可（带准入控制）")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--request", required=True,
                   help='{"permit_id","block_id","cap"}')
    p.set_defaults(func=cmd_grant)

    p = sub.add_parser("receipt", help="摄入一条可信收据")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--receipt", required=True)
    p.set_defaults(func=cmd_receipt)

    p = sub.add_parser("cert", help="提交正式终止证信封")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--cert", required=True)
    p.set_defaults(func=cmd_cert)

    p = sub.add_parser("block", help="提交实收块做三核对")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--request", required=True,
                   help='{"permit_id","block_id","payload_path"}')
    p.set_defaults(func=cmd_block)

    p = sub.add_parser("report", help="实时对账报告")
    p.add_argument("--data-dir", required=True)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("replay", help="只凭日志离线重演并出报告")
    p.add_argument("--data-dir", required=True)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("verify", help="重放报告与实时报告交叉核对")
    p.add_argument("--data-dir", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("spool", help="回放夹具收据流目录")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--fixture-dir", required=True)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_spool)

    p = sub.add_parser("restore", help="把已核验块恢复成完整档案文件")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--output-dir", required=True,
                   help="档案发布目录；清单相对路径不得越出该目录")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("retire", help="退役档案并回收不再被引用的块存储")
    p.add_argument("--data-dir", required=True)
    p.add_argument("--output-dir", required=True,
                   help="已发布档案所在目录；与恢复时使用的输出目录一致")
    p.add_argument("--request", required=True,
                   help='{"archive_ids": ["ARC-1", ...]}，- 为 stdin')
    p.set_defaults(func=cmd_retire)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RestoreError as exc:
        _emit({"ok": False, "error": str(exc)})
        return EXIT_FATAL
    except (StationError, ValueError, KeyError, FileNotFoundError) as exc:
        _emit({"ok": False, "error": str(exc)})
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
