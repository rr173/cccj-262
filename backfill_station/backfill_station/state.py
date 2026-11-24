"""事件回放投影：把仅追加日志重放成当前账本状态。

所有业务规则在 station.py 做前置校验，这里负责：
1. 把事件折叠成可查询状态；
2. 对每一步重放强制检查额度不变量，任何违反都视为日志被篡改并硬失败。
重放是纯函数式的：同一份日志永远得到同一份状态。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .journal import Event
from .manifest import ArchiveSpec, BlockSpec, Manifest

# 许可生命周期：
#   open      已领取、尚未拿到正式终止证，按封顶占用预算
#   confirmed 已持终止证核实终值，占用降为终值（终值可为 0=提前结束）
ST_OPEN = "open"
ST_CONFIRMED = "confirmed"


class StateError(RuntimeError):
    pass


@dataclass
class PermitState:
    permit_id: str
    block_id: str
    cap: int
    status: str = ST_OPEN
    # 已观察到的最大累计进度（同一许可的真实字节只记一次，
    # 进度单调，乱序/重复到达取最大值，绝不回退）。
    max_progress: int = 0
    final_value: Optional[int] = None      # 终止证核实的最终实收
    final_receipt_seq: Optional[int] = None
    cert_seq: Optional[int] = None         # 已核实终止证的事件序号
    term_cert_id: Optional[str] = None
    # 终止证先于最终收据到达：挂起保存（不释放任何预算），
    # 等匹配的 final 收据到达后自动确认。该状态持久化在日志里，
    # 重启重放后同证重交仍然幂等。
    held_cert: Optional[dict[str, Any]] = None
    receipts_seen: dict[tuple[str, int], int] = field(default_factory=dict)
    # receipts_seen 键为 (kind, seq)，值为该进度条上报的 bytes，
    # 用于识别同一进度条的重复/矛盾重放。

    @property
    def reserved(self) -> int:
        """当前占用预算：未终止按封顶，已确认按终值。"""
        return self.cap if self.status == ST_OPEN else (self.final_value or 0)


@dataclass
class BlockState:
    spec: BlockSpec
    delivered: bool = False
    delivered_by_permit: Optional[str] = None
    delivered_event_seq: Optional[int] = None
    attempt_permit_ids: list[str] = field(default_factory=list)
    rejected_payloads: int = 0  # 身份/长度/摘要不符的到达次数

    @property
    def block_id(self) -> str:
        return self.spec.block_id


@dataclass
class Ledger:
    manifest: Manifest
    permits: dict[str, PermitState] = field(default_factory=dict)
    blocks: dict[str, BlockState] = field(default_factory=dict)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    # 已退役档案标识集合：退役只影响档案可恢复性与块存储回收，
    # 绝不改动许可、额度、收据与历史交付事实。
    retired_archives: set[str] = field(default_factory=set)
    last_seq: int = 0

    # ---- 派生口径 ----
    @property
    def confirmed_spend(self) -> int:
        """带终值的已确认实付（已终止许可终值之和）。"""
        return sum(
            p.final_value or 0
            for p in self.permits.values()
            if p.status == ST_CONFIRMED
        )

    @property
    def reserved_open(self) -> int:
        """仍按封顶保留的金额（未终止许可封顶之和）。"""
        return sum(
            p.cap for p in self.permits.values() if p.status == ST_OPEN
        )

    @property
    def obligations(self) -> int:
        """当前总义务 = 已确认实付 + 封顶保留。"""
        return self.confirmed_spend + self.reserved_open

    @property
    def available(self) -> int:
        return self.manifest.quota_bytes - self.obligations

    def missing_blocks(self) -> list[BlockState]:
        return [b for b in self.blocks.values() if not b.delivered]

    # ---- 档案退役派生口径（纯账本推导，不触碰文件系统） ----
    def live_archives(self) -> list[ArchiveSpec]:
        """未退役的档案声明：恢复操作只服务这些档案。"""
        return [a for a in self.manifest.archives
                if a.archive_id not in self.retired_archives]

    def reclaimable_block_ids(self) -> list[str]:
        """只被已退役档案引用的块：存储文件可回收（无论是否交付过）。"""
        live_refs: set[str] = set()
        for archive in self.live_archives():
            live_refs.update(archive.block_ids)
        all_refs: set[str] = set()
        for archive in self.manifest.archives:
            all_refs.update(archive.block_ids)
        return sorted(all_refs - live_refs)

    def retained_block_ids(self) -> list[str]:
        """当前仍保留存储的已交付块（未被退役回收的）。"""
        reclaimable = set(self.reclaimable_block_ids())
        return [bid for bid, b in self.blocks.items()
                if b.delivered and bid not in reclaimable]

    def reclaimed_block_ids(self) -> list[str]:
        """已交付但不再保留存储的块（只被已退役档案引用）。"""
        reclaimable = set(self.reclaimable_block_ids())
        return sorted(bid for bid, b in self.blocks.items()
                      if b.delivered and bid in reclaimable)

    def check_invariant(self, where: str) -> None:
        if self.obligations > self.manifest.quota_bytes:
            raise StateError(
                f"{where}: 额度不变量被破坏 "
                f"（义务 {self.obligations} > 额度 {self.manifest.quota_bytes}）"
            )

    # ---- 事件折叠 ----
    def apply(self, event: Event) -> None:
        p = event.payload
        etype = event.type
        self.last_seq = event.seq

        if etype == "batch_opened":
            if self.manifest is not None:
                raise StateError("批次重复开账")
            self.manifest = Manifest.from_dict(p["manifest"])
            for spec in self.manifest.blocks:
                self.blocks[spec.block_id] = BlockState(spec=spec)
            self.check_invariant("开账")
            return

        if self.manifest is None:
            raise StateError(f"事件 {etype} 先于开账事件")

        if etype == "permit_granted":
            if p["permit_id"] in self.permits:
                raise StateError(f"许可 {p['permit_id']} 重复领取")
            spec = self.manifest.get(p["block_id"])
            if spec is None or p["cap"] != spec.length:
                raise StateError("许可封顶与清单长度不符")
            self.permits[p["permit_id"]] = PermitState(
                permit_id=p["permit_id"],
                block_id=p["block_id"],
                cap=p["cap"],
            )
            self.blocks[p["block_id"]].attempt_permit_ids.append(p["permit_id"])
            self.check_invariant("发许可")

        elif etype == "permit_rejected":
            # 被拒不产生占用，仅留审计轨迹；同一许可重复被拒记为异常。
            if p["permit_id"] in self.permits:
                raise StateError("已发放许可不得再出现拒绝事件")
            self.anomalies.append({
                "code": "permit_admission_denied",
                "permit_id": p["permit_id"],
                "block_id": p["block_id"],
                "detail": p.get("reason", ""),
                "event_seq": event.seq,
            })

        elif etype == "receipt_accepted":
            permit = self._require_permit(p["permit_id"], event.seq)
            key = (p["kind"], p["receipt_seq"])
            permit.receipts_seen[key] = p["bytes_reported"]
            if p["bytes_reported"] > permit.max_progress:
                permit.max_progress = p["bytes_reported"]
            if p["kind"] == "final":
                if permit.final_value is not None:
                    raise StateError("final 收据被重复接受")
                permit.final_value = p["bytes_reported"]
                permit.final_receipt_seq = event.seq

        elif etype == "anomaly":
            self.anomalies.append({
                "code": p["code"],
                "permit_id": p.get("permit_id"),
                "block_id": p.get("block_id"),
                "detail": p.get("detail", ""),
                "event_seq": event.seq,
            })

        elif etype == "termination_cert_held":
            permit = self._require_permit(p["permit_id"], event.seq)
            if permit.status != ST_OPEN or permit.held_cert is not None:
                raise StateError("终止证挂起状态非法")
            permit.held_cert = {
                "cert_id": p["cert_id"], "final_value": p["final_value"],
            }
            self.anomalies.append({
                "code": "termination_cert_pending_final_receipt",
                "permit_id": p["permit_id"],
                "block_id": permit.block_id,
                "detail": p.get("detail", ""),
                "event_seq": event.seq,
            })

        elif etype == "termination_cert_discarded":
            permit = self._require_permit(p["permit_id"], event.seq)
            if permit.held_cert is None:
                raise StateError("作废事件引用了不存在的挂起终止证")
            permit.held_cert = None
            self.anomalies.append({
                "code": "termination_cert_final_value_mismatch",
                "permit_id": p["permit_id"],
                "block_id": permit.block_id,
                "detail": p.get("reason", ""),
                "event_seq": event.seq,
            })

        elif etype == "termination_confirmed":
            permit = self._require_permit(p["permit_id"], event.seq)
            if permit.status != ST_OPEN:
                raise StateError("终止证被重复确认")
            if permit.cert_seq is not None:
                raise StateError("每个许可至多一份终止证")
            permit.status = ST_CONFIRMED
            permit.final_value = p["final_value"]
            permit.term_cert_id = p["cert_id"]
            permit.cert_seq = event.seq
            permit.held_cert = None
            # 提前结束：占用从封顶降为终值，差额立刻可给其他缺块。
            self.check_invariant("终止确认")

        elif etype == "block_verified":
            block = self._require_block(p["block_id"], event.seq)
            if block.delivered:
                raise StateError("完备块被重复计入覆盖")
            block.delivered = True
            block.delivered_by_permit = p["permit_id"]
            block.delivered_event_seq = event.seq

        elif etype == "block_rejected":
            block = self._require_block(p["block_id"], event.seq)
            block.rejected_payloads += 1

        elif etype == "archives_retired":
            # 退役只登记档案状态，不动钱账与交付事实，无需检查额度不变量。
            for archive_id in p["archive_ids"]:
                if self.manifest.get_archive(archive_id) is None:
                    raise StateError(
                        f"退役事件引用未声明档案 {archive_id}")
                if archive_id in self.retired_archives:
                    raise StateError(f"档案 {archive_id} 被重复退役")
                self.retired_archives.add(archive_id)

        else:
            raise StateError(f"未知事件类型: {etype}")

    def _require_permit(self, permit_id: str, seq: int) -> PermitState:
        permit = self.permits.get(permit_id)
        if permit is None:
            raise StateError(f"事件 {seq} 引用未知许可 {permit_id}")
        return permit

    def _require_block(self, block_id: str, seq: int) -> BlockState:
        block = self.blocks.get(block_id)
        if block is None:
            raise StateError(f"事件 {seq} 引用未知块 {block_id}")
        return block


def replay(events: list[Event]) -> Ledger:
    ledger = Ledger(manifest=None)  # type: ignore[arg-type]
    for event in events:
        ledger.apply(event)
    return ledger


def shared_pool_view(ledger: Ledger) -> Optional[dict[str, Any]]:
    """报告用：本批共享池配置的纯账本派生视图（不触碰池文件系统）。

    只含清单冻结的配置与本批已交付块的内容摘要，实时的跨批次关联与
    物理占用由 `pool-inventory` 命令按池查看，因此该视图可由日志独立
    重放并与实时报告逐字段一致。
    """
    spec = ledger.manifest.shared_pool if ledger.manifest else None
    if spec is None:
        return None
    delivered_digests = sorted({
        b.spec.sha256 for b in ledger.blocks.values() if b.delivered
    })
    return {
        "pool_id": spec.pool_id,
        "pool_path": spec.path,
        "delivered_content_digests": delivered_digests,
        "delivered_distinct_contents": len(delivered_digests),
        "note": "按内容（SHA-256）复用块存储；跨批次关联与物理占用请用 "
                "pool-inventory 按池查看",
    }
