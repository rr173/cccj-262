"""本地有界传输夹具（不接真实网关，全部可离线重演）。

夹具模拟传输侧，提供两类独立产物：
1. 可信收据流（spool/*.jsonl）：每个许可的累计实收进度，可乱序、重复
   到达；final 收据明确“本次传输已关闭 + 最终实收”。
2. 正式终止证（HMAC-SHA256 签名信封）：每个许可至多一份，回补台用
   批次 HMAC 密钥即可离线核实。

夹具自己也严格执行封顶：传输侧只能在封顶内发送，坏字节与重复尝试
全部计入已发送字节，无法超发。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional

from .canonical import canonical_bytes, digest_payload, sign_payload

SPOOL_NAME = "spool.jsonl"
PAYLOAD_DIR = "payloads"


class FixtureError(RuntimeError):
    pass


@dataclass
class Receipt:
    permit_id: str
    kind: str          # progress | final
    seq: int
    bytes_field: int   # 累计实收（不是增量）
    closed: bool = False

    def to_dict(self) -> dict[str, Any]:
        out = {"stream": "receipt", "permit_id": self.permit_id,
               "kind": self.kind, "seq": self.seq,
               "bytes": self.bytes_field}
        if self.kind == "final":
            out["closed"] = True
        return out


@dataclass
class BlockDrop:
    """数据侧产物：某次尝试实际落到本地的块字节（可能损坏）。"""
    permit_id: str
    block_id: str
    payload: bytes
    corrupted: bool

    @property
    def payload_path(self) -> str:
        tag = "corrupt" if self.corrupted else "full"
        return os.path.join(PAYLOAD_DIR, f"{self.permit_id}.{tag}.bin")


class Sender:
    """单个许可对应的一次传输尝试。"""

    def __init__(self, fixture: "TransmissionFixture", permit_id: str,
                 block_id: str, cap: int):
        self.fixture = fixture
        self.permit_id = permit_id
        self.block_id = block_id
        self.cap = cap
        self.sent = 0          # 传输侧累计已发（含坏字节），单调不减
        self.acked = 0         # 可信收据累计实收，单调不减
        self.receipt_seq = 0
        self.closed = False
        self.final_value: Optional[int] = None

    def _ensure_open(self) -> None:
        if self.closed:
            raise FixtureError(f"许可 {self.permit_id} 传输已关闭，禁止再发")

    def send(self, chunk: bytes, *, good: bool = True) -> int:
        """发送一段字节。good=False 表示坏字节：照收费、照占封顶，
        但不增加可信实收进度。返回发送后累计已发。"""
        self._ensure_open()
        if not isinstance(chunk, (bytes, bytearray)) or len(chunk) == 0:
            raise FixtureError("发送内容必须是非空字节串")
        if self.sent + len(chunk) > self.cap:
            raise FixtureError(
                f"传输侧封顶拦截：许可 {self.permit_id} 拟发至 "
                f"{self.sent + len(chunk)} > 封顶 {self.cap}（坏字节同样计费）"
            )
        self.sent += len(chunk)
        if good:
            # 实收也是累计口径，且不可能超过已发。
            self.acked = min(self.sent, self.acked + len(chunk))
        self.receipt_seq += 1
        self.fixture._emit_receipt(Receipt(
            self.permit_id, "progress", self.receipt_seq, self.acked))
        return self.sent

    def emit_duplicate_progress(self, seq: Optional[int] = None) -> None:
        """重放某条进度（乱序/重复到达由夹具台统一洗牌）。"""
        if seq is None:
            seq = self.receipt_seq
        if seq <= 0:
            raise FixtureError("没有可重放的进度")
        self.fixture._emit_receipt(Receipt(
            self.permit_id, "progress", seq, self.acked))

    def close(self, *, final_value: Optional[int] = None,
              hard_cap: Optional[int] = None) -> Receipt:
        """正常关闭。final_value 默认等于当前可信累计实收。

        hard_cap 给出终值允许的上限（断流场景为已发字节 sent：
        坏字节已过网、照计费，但可信实收可能更小）。
        """
        self._ensure_open()
        if final_value is None:
            final_value = self.acked
        upper = self.sent if hard_cap is None else hard_cap
        if not (0 <= final_value <= upper):
            raise FixtureError(
                f"终值 {final_value} 超出允许上限 {upper}，也不能为负"
            )
        self.closed = True
        self.final_value = final_value
        self.receipt_seq += 1
        receipt = Receipt(self.permit_id, "final", self.receipt_seq,
                          final_value, closed=True)
        self.fixture._emit_receipt(receipt)
        return receipt

    def terminate_early(self, final_value: Optional[int] = None) -> Receipt:
        """对端确认提前结束（可能只收到一半就断开）。

        网络流过的字节（含坏字节）已经付费，因此终值上限按已发字节
        sent 而不是可信实收 acked 约束。
        """
        return self.close(final_value=final_value, hard_cap=self.sent)

    def make_cert(self) -> dict[str, Any]:
        """签发正式终止证：每许可至多一份，HMAC 签名可离线核实。"""
        if not self.closed:
            raise FixtureError("传输未关闭，不能签发终止证")
        return self.fixture.sign_termination_cert(
            self.permit_id, self.cap, self.final_value)

    def payload_full(self, content: bytes) -> BlockDrop:
        if len(content) != self.cap:
            raise FixtureError("完整块载荷长度必须等于许可封顶")
        drop = BlockDrop(self.permit_id, self.block_id, bytes(content), False)
        self.fixture._register_drop(drop)
        return drop

    def payload_corrupt(self, content: bytes) -> BlockDrop:
        drop = BlockDrop(self.permit_id, self.block_id, bytes(content), True)
        self.fixture._register_drop(drop)
        return drop


class TransmissionFixture:
    """有界传输夹具：管理多个许可的发送器、收据流文件与终止证。"""

    def __init__(self, fixture_dir: str, hmac_key: bytes):
        self.dir = fixture_dir
        self.hmac_key = hmac_key
        self.senders: dict[str, Sender] = {}
        self._cert_counter = 0
        os.makedirs(fixture_dir, exist_ok=True)
        os.makedirs(os.path.join(fixture_dir, PAYLOAD_DIR), exist_ok=True)
        self._spool_path = os.path.join(fixture_dir, SPOOL_NAME)
        # 截断重建，保证每次重演的夹具目录是确定的。
        open(self._spool_path, "w", encoding="utf-8").close()
        self._raw_receipts: list[Receipt] = []

    def open_sender(self, permit_id: str, block_id: str, cap: int) -> Sender:
        if permit_id in self.senders:
            raise FixtureError(f"许可 {permit_id} 的发送器已存在")
        sender = Sender(self, permit_id, block_id, cap)
        self.senders[permit_id] = sender
        return sender

    # ---- 收据流 ----
    def _emit_receipt(self, receipt: Receipt) -> None:
        self._raw_receipts.append(receipt)

    def shuffle_spool(self, rng) -> None:
        """用注入的随机源洗牌后落盘，模拟乱序到达；重复条目不消去。"""
        ordered = list(self._raw_receipts)
        rng.shuffle(ordered)
        with open(self._spool_path, "w", encoding="utf-8") as fh:
            for receipt in ordered:
                fh.write(json.dumps(receipt.to_dict(), sort_keys=True,
                                    ensure_ascii=False))
                fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())

    def append_raw_spool(self, obj: dict[str, Any]) -> None:
        """直接向收据流写入构造条目（用于注入异常凭据）。"""
        with open(self._spool_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, sort_keys=True, ensure_ascii=False))
            fh.write("\n")

    def iter_spool(self):
        with open(self._spool_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    # ---- 终止证 ----
    def sign_termination_cert(self, permit_id: str, cap: int,
                              final_value: int) -> dict[str, Any]:
        self._cert_counter += 1
        payload = {
            "cert_id": f"TC-{permit_id}-{self._cert_counter:04d}",
            "permit_id": permit_id,
            "cap": cap,
            "final_value": final_value,
            "closed": True,
        }
        return {"payload": payload,
                "signature": sign_payload(payload, self.hmac_key)}

    @staticmethod
    def tamper_cert(envelope: dict[str, Any], *,
                    bad_signature: bool = False,
                    final_value: Optional[int] = None) -> dict[str, Any]:
        """制造异常凭据：改坏签名或篡改终值（签名不重算）。"""
        payload = dict(envelope["payload"])
        if final_value is not None:
            payload["final_value"] = final_value
        signature = envelope["signature"]
        if bad_signature:
            signature = "0" * len(signature)
        return {"payload": payload, "signature": signature}

    def resign_cert(self, envelope: dict[str, Any], *,
                    final_value: Optional[int] = None) -> dict[str, Any]:
        """用同一把密钥对篡改后的载荷重新签名。

        用于模拟“签名本身有效、但内容与已核实终值冲突”的凭据：
        传输侧密钥泄露或越权签发时可能出现，回补台仍必须拒绝覆盖。
        """
        payload = dict(envelope["payload"])
        if final_value is not None:
            payload["final_value"] = final_value
        # cert_id 保持不变或换新都可；换新更贴近“第二份凭据”。
        self._cert_counter += 1
        payload["cert_id"] = f"{payload['cert_id']}-R{self._cert_counter:04d}"
        return {"payload": payload,
                "signature": sign_payload(payload, self.hmac_key)}

    # ---- 数据侧产物 ----
    def _register_drop(self, drop: BlockDrop) -> None:
        path = os.path.join(self.dir, drop.payload_path)
        with open(path, "wb") as fh:
            fh.write(drop.payload)
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def corrupt(content: bytes, *, at: int = 0) -> bytes:
        if not content:
            raise FixtureError("空内容无法损坏")
        data = bytearray(content)
        data[at % len(data)] ^= 0xFF
        return bytes(data)

    @staticmethod
    def sha256(content: bytes) -> str:
        return digest_payload(content)

    def hmac_footprint(self) -> str:
        """暴露密钥指纹，便于脚本确认台与夹具用的是同一把密钥。"""
        return digest_payload(canonical_bytes(
            {"key_check": self.hmac_key.hex()}))[:16]


def iter_spool_file(fixture_dir: str):
    """只读方式遍历收据流，不创建/截断任何文件。

    供回补台的 spool 回放命令使用：回放方绝不能实例化
    TransmissionFixture（其构造函数会重建并清空 spool）。
    """
    path = os.path.join(fixture_dir, SPOOL_NAME)
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
