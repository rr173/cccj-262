"""档案清单（manifest）：固定块身份、长度与摘要。

清单是批次的事实来源，一旦开账即冻结：任何取数尝试的目标块必须在
清单内，许可封顶必须等于清单长度，实收块必须同时核对块身份、整块
长度与 SHA-256 摘要才算交付。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json

MANIFEST_NAME = "manifest.json"


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class BlockSpec:
    block_id: str
    length: int
    sha256: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "BlockSpec":
        if not isinstance(raw, Mapping):
            raise ManifestError("块条目必须是对象")
        block_id = raw.get("block_id")
        length = raw.get("length")
        sha = raw.get("sha256")
        if not isinstance(block_id, str) or not block_id:
            raise ManifestError(f"块身份非法: {raw!r}")
        if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
            raise ManifestError(f"块长度必须为正整数: {raw!r}")
        if (not isinstance(sha, str) or len(sha) != 64
                or any(c not in "0123456789abcdef" for c in sha.lower())):
            raise ManifestError(f"块摘要必须为 64 位十六进制 SHA-256: {raw!r}")
        return cls(block_id=block_id, length=length, sha256=sha.lower())


@dataclass(frozen=True)
class Manifest:
    batch_id: str
    quota_bytes: int
    blocks: tuple[BlockSpec, ...]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Manifest":
        if not isinstance(raw, Mapping):
            raise ManifestError("清单必须是 JSON 对象")
        batch_id = raw.get("batch_id")
        quota = raw.get("quota_bytes")
        raw_blocks = raw.get("blocks")
        if not isinstance(batch_id, str) or not batch_id:
            raise ManifestError("batch_id 非法")
        if not isinstance(quota, int) or isinstance(quota, bool) or quota < 0:
            raise ManifestError("quota_bytes 必须为非负整数")
        if not isinstance(raw_blocks, list) or not raw_blocks:
            raise ManifestError("blocks 必须为非空列表")
        blocks = tuple(BlockSpec.from_dict(b) for b in raw_blocks)
        ids = [b.block_id for b in blocks]
        if len(set(ids)) != len(ids):
            raise ManifestError("块身份必须唯一，不得重复")
        # 注意：不强制块全长合计 <= 额度。单个账期的额度可能小于整批
        # 总量（缺口留待后续账期/回补），运行时准入控制负责保证任何
        # 时刻在手义务不超过本账期额度。
        return cls(batch_id=batch_id, quota_bytes=quota, blocks=blocks)

    def get(self, block_id: str) -> BlockSpec | None:
        for spec in self.blocks:
            if spec.block_id == block_id:
                return spec
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "quota_bytes": self.quota_bytes,
            "blocks": [
                {"block_id": b.block_id, "length": b.length,
                 "sha256": b.sha256}
                for b in self.blocks
            ],
        }

    def write(self, data_dir: str) -> str:
        path = os.path.join(data_dir, MANIFEST_NAME)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(canonical_json(self.to_dict()))
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        return path

    @classmethod
    def read(cls, data_dir: str) -> "Manifest":
        path = os.path.join(data_dir, MANIFEST_NAME)
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls.from_dict(raw)
