"""回补台主体：所有写命令都在文件锁内做“校验 -> 追加事件 -> 折叠状态”。

钱与数据严格分账：
- 钱（额度）只由许可发放、正式终止证驱动；块数据永远不动钱。
- 交付覆盖只由身份/长度/摘要三核对通过的完备块驱动；收据永远不证明块。
"""
from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from typing import Any, Optional

from .canonical import digest_payload, verify_signature
from .journal import DataDirLock, Event, Journal, JOURNAL_NAME
from .manifest import Manifest
from .state import Ledger, ST_CONFIRMED, ST_OPEN, replay

HMAC_KEY_NAME = "hmac.key"

# ---- 异常码（全部进入 anomaly 登记表，可逐条审计） ----
ANOM = {
    "PERMIT_REUSED": "permit_id_reused",
    "CAP_MISMATCH": "permit_cap_mismatch",
    "UNKNOWN_BLOCK": "block_unknown",
    "ADMISSION_DENIED": "permit_admission_denied",
    "UNKNOWN_PERMIT_RECEIPT": "unknown_permit_receipt",
    "RECEIPT_EXCEEDS_CAP": "receipt_exceeds_cap",
    "PROGRESS_BEYOND_FINAL": "receipt_progress_beyond_final",
    "DUP_PROGRESS_CONFLICT": "duplicate_progress_conflict",
    "FINAL_VALUE_CONFLICT": "final_receipt_value_conflict",
    "UNKNOWN_PERMIT_CERT": "unknown_permit_cert",
    "CERT_BAD_SIGNATURE": "termination_cert_bad_signature",
    "CERT_PAYLOAD_MISMATCH": "termination_cert_payload_mismatch",
    "CERT_FINAL_MISMATCH": "termination_cert_final_value_mismatch",
    "DUP_CERT_CONFLICT": "duplicate_termination_cert_conflict",
    "BLOCK_PERMIT_MISMATCH": "block_permit_target_mismatch",
    "BLOCK_LENGTH_MISMATCH": "block_length_mismatch",
    "BLOCK_DIGEST_MISMATCH": "block_digest_mismatch",
}


class StationError(RuntimeError):
    pass


@dataclass
class CommandResult:
    ok: bool
    code: str
    detail: str = ""
    event_seq: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "code": self.code, "detail": self.detail,
                "event_seq": self.event_seq}


class Station:
    """持锁打开后使用；关闭即释放锁并 flush 日志。"""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self._lock = DataDirLock(data_dir)
        self._journal: Optional[Journal] = None
        self.ledger: Optional[Ledger] = None
        self.hmac_key: bytes = b""

    # ---- 生命周期 ----
    @classmethod
    def initialize(cls, data_dir: str, manifest_raw: dict[str, Any],
                   hmac_key: bytes) -> "Station":
        """冷启动：冻结清单、登记 HMAC 密钥、写入开账事件。"""
        os.makedirs(data_dir, exist_ok=True)
        journal_path = os.path.join(data_dir, JOURNAL_NAME)
        if os.path.exists(journal_path):
            raise StationError(f"数据目录已开账: {data_dir}")
        manifest = Manifest.from_dict(manifest_raw)
        key_path = os.path.join(data_dir, HMAC_KEY_NAME)
        if os.path.exists(key_path):
            raise StationError("HMAC 密钥文件已存在，拒绝覆盖")
        station = cls(data_dir)
        with station._lock.locked():
            with open(key_path, "wb") as fh:
                fh.write(hmac_key)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(key_path, 0o600)
            manifest.write(data_dir)
            try:
                station._open_unsafe()
                station._journal.append("batch_opened",
                                        {"manifest": manifest.to_dict()})
                station._reload()
            finally:
                if station._journal is not None:
                    station._journal.close()
                    station._journal = None
                    station.ledger = None
        return station

    @contextlib.contextmanager
    def open(self):
        with self._lock.locked():
            with open(os.path.join(self.data_dir, HMAC_KEY_NAME), "rb") as fh:
                self.hmac_key = fh.read()
            self._open_unsafe()
            self._reload()
            try:
                yield self
            finally:
                if self._journal is not None:
                    self._journal.close()
                    self._journal = None

    def _open_unsafe(self) -> None:
        self._journal = Journal(os.path.join(self.data_dir, JOURNAL_NAME))
        self._journal.open_for_append()

    def _reload(self) -> None:
        assert self._journal is not None
        events = list(Journal.replay(self._journal.path))
        self.ledger = replay(events)

    def _append(self, event_type: str, payload: dict[str, Any]) -> Event:
        assert self._journal is not None and self.ledger is not None
        event = self._journal.append(event_type, payload)
        self.ledger.apply(event)  # 当场再折叠一次，失败即日志不一致，硬停
        return event

    def _anomaly(self, code: str, detail: str, *, permit_id: Optional[str] = None,
                 block_id: Optional[str] = None) -> Event:
        return self._append("anomaly", {
            "code": code, "detail": detail,
            "permit_id": permit_id, "block_id": block_id,
        })

    # ---- 1. 许可领取（准入控制） ----
    def grant_permit(self, permit_id: str, block_id: str,
                     cap: int) -> CommandResult:
        ledger = self._require_ready()
        if not isinstance(permit_id, str) or not permit_id:
            raise StationError("permit_id 非法")
        if permit_id in ledger.permits:
            # 不可复用：重启后重放同名许可也只能被拒，绝不重发一套封顶。
            self._anomaly(ANOM["PERMIT_REUSED"],
                          f"许可 {permit_id} 已存在，禁止复用/重新启用",
                          permit_id=permit_id, block_id=block_id)
            return CommandResult(False, ANOM["PERMIT_REUSED"])
        spec = ledger.manifest.get(block_id)
        if spec is None:
            self._anomaly(ANOM["UNKNOWN_BLOCK"],
                          f"清单中不存在块 {block_id}", block_id=block_id)
            return CommandResult(False, ANOM["UNKNOWN_BLOCK"])
        if not isinstance(cap, int) or isinstance(cap, bool) or cap != spec.length:
            self._anomaly(ANOM["CAP_MISMATCH"],
                          f"许可封顶 {cap} 必须等于块长度 {spec.length}",
                          permit_id=permit_id, block_id=block_id)
            return CommandResult(False, ANOM["CAP_MISMATCH"])

        # 领取之前就必须保证：本账期仍付得起 已用费用 + 在手许可最大风险。
        projected = ledger.obligations + cap
        snapshot = {
            "quota": ledger.manifest.quota_bytes,
            "confirmed_spend": ledger.confirmed_spend,
            "reserved_open": ledger.reserved_open,
            "obligations_before": ledger.obligations,
            "projected_obligations": projected,
        }
        if projected > ledger.manifest.quota_bytes:
            event = self._append("permit_rejected", {
                "permit_id": permit_id, "block_id": block_id, "cap": cap,
                "reason": (f"准入拒绝：发放后义务 {projected} > 额度 "
                           f"{ledger.manifest.quota_bytes}（剩余可用 "
                           f"{ledger.available}）"),
                "snapshot": snapshot,
            })
            return CommandResult(False, ANOM["ADMISSION_DENIED"],
                                 event.payload["reason"], event.seq)
        event = self._append("permit_granted", {
            "permit_id": permit_id, "block_id": block_id, "cap": cap,
            "admission_snapshot": snapshot,
        })
        return CommandResult(True, "permit_granted", event_seq=event.seq)

    # ---- 2. 可信收据流摄入 ----
    def ingest_receipt(self, receipt: dict[str, Any]) -> CommandResult:
        ledger = self._require_ready()
        permit_id = receipt.get("permit_id")
        permit = ledger.permits.get(permit_id)
        if permit is None:
            self._anomaly(ANOM["UNKNOWN_PERMIT_RECEIPT"],
                          f"收据引用未知许可 {permit_id}", permit_id=permit_id)
            return CommandResult(False, ANOM["UNKNOWN_PERMIT_RECEIPT"])

        kind = receipt.get("kind")
        if kind not in ("progress", "final"):
            raise StationError(f"收据 kind 非法: {kind!r}")
        seq = receipt.get("seq")
        bytes_reported = receipt.get("bytes")
        if (not isinstance(seq, int) or isinstance(seq, bool) or seq < 0
                or not isinstance(bytes_reported, int)
                or isinstance(bytes_reported, bool) or bytes_reported < 0):
            raise StationError("收据 seq/bytes 字段非法")

        # final 收据是关闭事件，单独优先处理：重放必须保持 final 语义。
        if kind == "final":
            if permit.final_value is not None:
                if bytes_reported == permit.final_value:
                    # 终值相同的重复 final：不重复确认。
                    return CommandResult(True,
                                         "final_receipt_duplicate_ignored")
                self._anomaly(ANOM["FINAL_VALUE_CONFLICT"],
                              f"许可 {permit_id} 终值冲突：已立 "
                              f"{permit.final_value}，又报 {bytes_reported}",
                              permit_id=permit_id)
                return CommandResult(False, ANOM["FINAL_VALUE_CONFLICT"])
            if bytes_reported > permit.cap:
                self._anomaly(ANOM["RECEIPT_EXCEEDS_CAP"],
                              f"许可 {permit_id} final 字节 {bytes_reported} "
                              f"超过封顶 {permit.cap}", permit_id=permit_id)
                return CommandResult(False, ANOM["RECEIPT_EXCEEDS_CAP"])
            event = self._append("receipt_accepted", {
                "permit_id": permit_id, "kind": "final", "receipt_seq": seq,
                "bytes_reported": bytes_reported, "closed": True,
            })
            # final 收据先到而终止证后到：若已有匹配的挂起终止证，
            # 此刻自动完成终止确认。
            self._try_confirm_with_held_cert(permit_id)
            return CommandResult(True, "final_receipt_accepted",
                                 event_seq=event.seq)

        # 同一进度条重放：只认第一次的真实字节。
        key = (kind, seq)
        if key in permit.receipts_seen:
            if permit.receipts_seen[key] == bytes_reported:
                # 完全相同的重送：幂等忽略，不重复记账。
                return CommandResult(True, "receipt_duplicate_ignored")
            self._anomaly(ANOM["DUP_PROGRESS_CONFLICT"],
                          f"许可 {permit_id} 的 {kind}#seq={seq} 出现矛盾字节数 "
                          f"{permit.receipts_seen[key]} != {bytes_reported}",
                          permit_id=permit_id)
            return CommandResult(False, ANOM["DUP_PROGRESS_CONFLICT"])

        # 传输侧只允许在封顶内发送：超封顶即异常，不得入账。
        if bytes_reported > permit.cap:
            self._anomaly(ANOM["RECEIPT_EXCEEDS_CAP"],
                          f"许可 {permit_id} 收据字节 {bytes_reported} 超过封顶 "
                          f"{permit.cap}", permit_id=permit_id)
            return CommandResult(False, ANOM["RECEIPT_EXCEEDS_CAP"])

        # 终值已立：任何超终值的进度都是异常，不能抵销/覆盖终值。
        if (permit.final_value is not None
                and bytes_reported > permit.final_value):
            self._anomaly(ANOM["PROGRESS_BEYOND_FINAL"],
                          f"许可 {permit_id} 进度 {bytes_reported} 超过已立终值 "
                          f"{permit.final_value}", permit_id=permit_id)
            return CommandResult(False, ANOM["PROGRESS_BEYOND_FINAL"])

        event = self._append("receipt_accepted", {
            "permit_id": permit_id, "kind": "progress", "receipt_seq": seq,
            "bytes_reported": bytes_reported,
        })
        return CommandResult(True, "progress_receipt_accepted",
                             event_seq=event.seq)

    # ---- 3. 正式终止证（每许可至多一份，可离线核实） ----
    def submit_termination_cert(self, envelope: dict[str, Any]) -> CommandResult:
        ledger = self._require_ready()
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise StationError("终止证必须包含 payload 与 signature")
        permit_id = payload.get("permit_id")
        permit = ledger.permits.get(permit_id)
        if permit is None:
            self._anomaly(ANOM["UNKNOWN_PERMIT_CERT"],
                          f"终止证引用未知许可 {permit_id}", permit_id=permit_id)
            return CommandResult(False, ANOM["UNKNOWN_PERMIT_CERT"])

        if not verify_signature(payload, signature, self.hmac_key):
            self._anomaly(ANOM["CERT_BAD_SIGNATURE"],
                          f"许可 {permit_id} 终止证签名核实失败",
                          permit_id=permit_id)
            return CommandResult(False, ANOM["CERT_BAD_SIGNATURE"])

        final_value = payload.get("final_value")
        cert_id = payload.get("cert_id")
        if (payload.get("closed") is not True
                or not isinstance(cert_id, str) or not cert_id
                or not isinstance(final_value, int)
                or isinstance(final_value, bool) or final_value < 0):
            self._anomaly(ANOM["CERT_PAYLOAD_MISMATCH"],
                          f"许可 {permit_id} 终止证载荷字段不合规",
                          permit_id=permit_id)
            return CommandResult(False, ANOM["CERT_PAYLOAD_MISMATCH"])
        if payload.get("cap") != permit.cap:
            self._anomaly(ANOM["CERT_PAYLOAD_MISMATCH"],
                          f"许可 {permit_id} 终止证封顶 {payload.get('cap')} "
                          f"与在册封顶 {permit.cap} 不一致", permit_id=permit_id)
            return CommandResult(False, ANOM["CERT_PAYLOAD_MISMATCH"])
        if final_value > permit.cap:
            self._anomaly(ANOM["CERT_PAYLOAD_MISMATCH"],
                          f"许可 {permit_id} 终止证终值 {final_value} 超过封顶 "
                          f"{permit.cap}", permit_id=permit_id)
            return CommandResult(False, ANOM["CERT_PAYLOAD_MISMATCH"])

        if permit.status == ST_CONFIRMED:
            # 每许可至多一份：同证重放幂等，任何不一致都是异常，
            # 绝不能覆盖已经核实的终值。
            if (permit.term_cert_id == cert_id
                    and permit.final_value == final_value):
                return CommandResult(True, "termination_cert_duplicate_ignored")
            self._anomaly(ANOM["DUP_CERT_CONFLICT"],
                          f"许可 {permit_id} 已有终止证 {permit.term_cert_id}"
                          f"/终值 {permit.final_value}，冲突凭据 {cert_id}/"
                          f"{final_value} 被拒绝", permit_id=permit_id)
            return CommandResult(False, ANOM["DUP_CERT_CONFLICT"])

        if permit.held_cert is not None:
            held = permit.held_cert
            if (held["cert_id"] == cert_id
                    and held["final_value"] == final_value):
                return CommandResult(True, "termination_cert_duplicate_ignored")
            self._anomaly(ANOM["DUP_CERT_CONFLICT"],
                          f"许可 {permit_id} 已有挂起终止证 {held['cert_id']}"
                          f"/终值 {held['final_value']}，矛盾凭据 {cert_id}/"
                          f"{final_value} 被拒绝", permit_id=permit_id)
            return CommandResult(False, ANOM["DUP_CERT_CONFLICT"])

        # 没有最终收据 => 仍以封顶占用；终止证先挂起（持久化），
        # 等 final 收据匹配后自动确认。
        if permit.final_value is None:
            event = self._append("termination_cert_held", {
                "permit_id": permit_id, "cert_id": cert_id,
                "final_value": final_value, "cap": permit.cap,
                "detail": (f"终止证已到、最终收据未到，继续按封顶 "
                           f"{permit.cap} 占用"),
            })
            return CommandResult(True, "termination_cert_held",
                                 event_seq=event.seq)

        if final_value != permit.final_value:
            self._anomaly(ANOM["CERT_FINAL_MISMATCH"],
                          f"许可 {permit_id} 终止证终值 {final_value} 与最终收据 "
                          f"{permit.final_value} 不一致，拒绝减少占用",
                          permit_id=permit_id)
            return CommandResult(False, ANOM["CERT_FINAL_MISMATCH"])

        return self._confirm_termination(permit_id, cert_id, final_value)

    def _try_confirm_with_held_cert(self, permit_id: str) -> None:
        permit = self.ledger.permits[permit_id]
        held = permit.held_cert
        if held is None or permit.final_value is None:
            return
        if held["final_value"] != permit.final_value:
            self._anomaly(ANOM["CERT_FINAL_MISMATCH"],
                          f"许可 {permit_id} 挂起终止证终值 "
                          f"{held['final_value']} 与最终收据 "
                          f"{permit.final_value} 不一致，继续按封顶占用",
                          permit_id=permit_id)
            # 矛盾凭据作废：弹出挂起证并记录，许可继续按封顶保留。
            self._append("termination_cert_discarded", {
                "permit_id": permit_id, "cert_id": held["cert_id"],
                "reason": "held_cert_final_value_mismatch",
            })
            return
        self._confirm_termination(permit_id, held["cert_id"],
                                  held["final_value"])

    def _confirm_termination(self, permit_id: str, cert_id: str,
                             final_value: int) -> CommandResult:
        permit = self.ledger.permits[permit_id]
        event = self._append("termination_confirmed", {
            "permit_id": permit_id, "cert_id": cert_id,
            "final_value": final_value, "cap": permit.cap,
            "released_bytes": permit.cap - final_value,
        })
        return CommandResult(True, "termination_confirmed",
                             f"占用 {permit.cap} -> {final_value}，释放 "
                             f"{permit.cap - final_value} 字节额度",
                             event.seq)

    # ---- 4. 数据侧：块交付（三核对） ----
    def submit_block(self, permit_id: str, block_id: str,
                     payload: bytes) -> CommandResult:
        ledger = self._require_ready()
        if not isinstance(payload, (bytes, bytearray)):
            raise StationError("块载荷必须是字节串")
        permit = ledger.permits.get(permit_id)
        if permit is None:
            self._anomaly(ANOM["UNKNOWN_PERMIT_RECEIPT"],
                          f"块提交引用未知许可 {permit_id}", permit_id=permit_id,
                          block_id=block_id)
            return CommandResult(False, "unknown_permit_block")
        if permit.block_id != block_id:
            self._anomaly(ANOM["BLOCK_PERMIT_MISMATCH"],
                          f"许可 {permit_id} 绑定块 {permit.block_id}，"
                          f"不得提交块 {block_id}",
                          permit_id=permit_id, block_id=block_id)
            return CommandResult(False, ANOM["BLOCK_PERMIT_MISMATCH"])
        spec = ledger.manifest.get(block_id)
        if spec is None:  # 理论上不可达：许可发放时已校验
            self._anomaly(ANOM["UNKNOWN_BLOCK"],
                          f"清单中不存在块 {block_id}", block_id=block_id)
            return CommandResult(False, ANOM["UNKNOWN_BLOCK"])
        block = ledger.blocks[block_id]

        if len(payload) != spec.length:
            event = self._append("block_rejected", {
                "permit_id": permit_id, "block_id": block_id,
                "reason": f"长度 {len(payload)} != 清单长度 {spec.length}",
            })
            self._anomaly(ANOM["BLOCK_LENGTH_MISMATCH"], event.payload["reason"],
                          permit_id=permit_id, block_id=block_id)
            return CommandResult(False, ANOM["BLOCK_LENGTH_MISMATCH"],
                                 event_seq=event.seq)
        actual_digest = digest_payload(bytes(payload))
        if actual_digest != spec.sha256:
            event = self._append("block_rejected", {
                "permit_id": permit_id, "block_id": block_id,
                "reason": f"摘要 {actual_digest[:16]}... 与清单不符",
            })
            self._anomaly(ANOM["BLOCK_DIGEST_MISMATCH"], event.payload["reason"],
                          permit_id=permit_id, block_id=block_id)
            return CommandResult(False, ANOM["BLOCK_DIGEST_MISMATCH"],
                                 event_seq=event.seq)

        if block.delivered:
            # 重送同一完备块：覆盖不增加、账不重复确认。
            return CommandResult(True, "block_already_delivered_ignored",
                                 f"块 {block_id} 已由许可 "
                                 f"{block.delivered_by_permit} 交付")
        event = self._append("block_verified", {
            "permit_id": permit_id, "block_id": block_id,
            "length": spec.length, "sha256": spec.sha256,
        })
        return CommandResult(True, "block_verified", event_seq=event.seq)

    # ---- 5. 对账报告 ----
    def report(self) -> dict[str, Any]:
        ledger = self._require_ready()
        m = ledger.manifest
        missing = []
        for block in ledger.blocks.values():
            if not block.delivered:
                missing.append({
                    "block_id": block.spec.block_id,
                    "length": block.spec.length,
                    "sha256": block.spec.sha256,
                    "attempt_permit_ids": list(block.attempt_permit_ids),
                    "rejected_payloads": block.rejected_payloads,
                })
        permits_view = []
        for permit in ledger.permits.values():
            permits_view.append({
                "permit_id": permit.permit_id,
                "block_id": permit.block_id,
                "cap": permit.cap,
                "status": permit.status,
                "max_progress": permit.max_progress,
                "final_value": permit.final_value,
                "reserved_now": permit.reserved,
                "has_final_receipt": permit.final_value is not None,
                "has_verified_termination": permit.status == ST_CONFIRMED,
                "cert_pending": permit.held_cert is not None,
            })
        delivered = [
            {"block_id": bid,
             "permit_id": b.delivered_by_permit,
             "event_seq": b.delivered_event_seq}
            for bid, b in ledger.blocks.items() if b.delivered
        ]
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
                "blocks_delivered": len(delivered),
                "blocks_missing": len(missing),
                "delivered": delivered,
            },
            "missing_blocks": missing,
            "permits": permits_view,
            "anomalies": list(ledger.anomalies),
            "anomaly_count": len(ledger.anomalies),
        }

    # ---- 内部 ----
    def _require_ready(self) -> Ledger:
        if self.ledger is None or self._journal is None:
            raise StationError("回补台未打开，请在 open() 上下文中使用")
        return self.ledger
