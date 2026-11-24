"""档案清单（manifest）：固定块身份、长度与摘要，以及档案产物声明。

清单是批次的事实来源，一旦开账即冻结：任何取数尝试的目标块必须在
清单内，许可封顶必须等于清单长度，实收块必须同时核对块身份、整块
长度与 SHA-256 摘要才算交付。

清单还可声明若干档案产物（archives）：每个档案给出唯一标识、批次内
相对路径、按原顺序排列的块标识、完整长度与 SHA-256；不同档案允许
引用同一块。没有档案声明的旧批次按原方式工作（archives 为空元组）。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .canonical import canonical_json, digest_payload, canonical_bytes

MANIFEST_NAME = "manifest.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class ManifestError(ValueError):
    pass


def _is_hex64(sha: Any) -> bool:
    return isinstance(sha, str) and bool(_HEX64.match(sha.lower()))


@dataclass(frozen=True)
class SharedPoolSpec:
    """可选共享块池配置：配置到同一池的批次按内容复用块存储。

    path 在开账冻结时规范化为绝对真实路径并随清单冻结，之后批次仅凭
    清单即可定位池，不依赖调用时的工作目录。pool_id 由该路径确定性
    导出，指向同一物理池的两个批次必然得到同一 pool_id。
    """
    pool_id: str
    path: str

    @staticmethod
    def derive_pool_id(real_path: str) -> str:
        return digest_payload(canonical_bytes({"shared_pool_path": real_path}))[:16]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SharedPoolSpec":
        if not isinstance(raw, Mapping):
            raise ManifestError("shared_pool 必须是对象")
        raw_path = raw.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ManifestError("shared_pool.path 必须是非空字符串")
        if "\x00" in raw_path:
            raise ManifestError("shared_pool.path 含 NUL 字节")
        # 开账即冻结：把相对路径按当前工作目录解析成绝对真实路径，
        # 避免同一池在不同工作目录下被解释成不同位置。
        real_path = os.path.realpath(raw_path)
        return cls(pool_id=cls.derive_pool_id(real_path), path=real_path)

    def to_dict(self) -> dict[str, Any]:
        return {"pool_id": self.pool_id, "path": self.path}


def _validate_archive_path(raw: Any) -> str:
    """档案路径必须是输出目录内的相对路径，任何越界写法都在冻结期拒绝。"""
    if not isinstance(raw, str) or not raw:
        raise ManifestError(f"档案路径非法: {raw!r}")
    if "\x00" in raw:
        raise ManifestError(f"档案路径含 NUL 字节: {raw!r}")
    if raw.startswith(("/", os.sep)) or _WINDOWS_DRIVE.match(raw):
        raise ManifestError(f"档案路径必须是相对路径: {raw!r}")
    # 只接受 POSIX 风格分隔符：反斜杠在其他平台可能是分隔符，统一拒绝，
    # 避免同一份清单在不同系统上解释不一致。
    if "\\" in raw:
        raise ManifestError(f"档案路径不得使用反斜杠: {raw!r}")
    parts = raw.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise ManifestError(
                f"档案路径含空段/'.'/'..'，禁止越出输出目录: {raw!r}")
    return raw


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
        if not _is_hex64(sha):
            raise ManifestError(f"块摘要必须为 64 位十六进制 SHA-256: {raw!r}")
        return cls(block_id=block_id, length=length, sha256=sha.lower())


@dataclass(frozen=True)
class ArchiveSpec:
    """档案产物声明：有序块序列还原成的完整文件。"""
    archive_id: str
    path: str
    block_ids: tuple[str, ...]
    length: int
    sha256: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ArchiveSpec":
        if not isinstance(raw, Mapping):
            raise ManifestError("档案条目必须是对象")
        archive_id = raw.get("archive_id")
        path = _validate_archive_path(raw.get("path"))
        raw_block_ids = raw.get("block_ids")
        length = raw.get("length")
        sha = raw.get("sha256")
        if not isinstance(archive_id, str) or not archive_id:
            raise ManifestError(f"档案标识非法: {raw!r}")
        if (not isinstance(raw_block_ids, list) or not raw_block_ids
                or not all(isinstance(b, str) and b for b in raw_block_ids)):
            raise ManifestError(
                f"档案 {archive_id} 的 block_ids 必须是非空字符串列表")
        block_ids = tuple(raw_block_ids)
        if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
            raise ManifestError(
                f"档案 {archive_id} 的完整长度必须为正整数")
        if not _is_hex64(sha):
            raise ManifestError(
                f"档案 {archive_id} 的摘要必须为 64 位十六进制 SHA-256")
        return cls(archive_id=archive_id, path=path, block_ids=block_ids,
                   length=length, sha256=sha.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive_id": self.archive_id,
            "path": self.path,
            "block_ids": list(self.block_ids),
            "length": self.length,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class Manifest:
    batch_id: str
    quota_bytes: int
    blocks: tuple[BlockSpec, ...]
    archives: tuple[ArchiveSpec, ...] = ()
    shared_pool: Optional[SharedPoolSpec] = None

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
        block_lengths = {b.block_id: b.length for b in blocks}

        # 档案声明为可选：没有该字段的旧批次继续按原方式工作。
        raw_archives = raw.get("archives")
        if raw_archives is None:
            archives: tuple[ArchiveSpec, ...] = ()
        else:
            if not isinstance(raw_archives, list):
                raise ManifestError("archives 必须是列表")
            archives = tuple(ArchiveSpec.from_dict(a) for a in raw_archives)
            archive_ids = [a.archive_id for a in archives]
            if len(set(archive_ids)) != len(archive_ids):
                raise ManifestError("档案标识必须唯一，不得重复")
            paths = [a.path for a in archives]
            if len(set(paths)) != len(paths):
                raise ManifestError("档案相对路径必须唯一，不得重复")
            for archive in archives:
                # 同一块可在同一档案内、或跨档案重复引用；但引用的块
                # 必须都在块清单内，且声明全长必须等于组成块长度之和。
                total = 0
                for block_id in archive.block_ids:
                    if block_id not in block_lengths:
                        raise ManifestError(
                            f"档案 {archive.archive_id} 引用了清单中不存在的块 "
                            f"{block_id}")
                    total += block_lengths[block_id]
                if total != archive.length:
                    raise ManifestError(
                        f"档案 {archive.archive_id} 声明长度 {archive.length} "
                        f"与组成块长度合计 {total} 不一致")
        # 注意：不强制块全长合计 <= 额度。单个账期的额度可能小于整批
        # 总量（缺口留待后续账期/回补），运行时准入控制负责保证任何
        # 时刻在手义务不超过本账期额度。

        # 共享块池为可选配置：没有该字段的旧批次继续按原方式工作，
        # 已核验块只落在本批数据目录自己的 blocks/ 仓库。
        raw_pool = raw.get("shared_pool")
        if raw_pool is None:
            shared_pool = None
        else:
            shared_pool = SharedPoolSpec.from_dict(raw_pool)
        return cls(batch_id=batch_id, quota_bytes=quota, blocks=blocks,
                   archives=archives, shared_pool=shared_pool)

    def get(self, block_id: str) -> BlockSpec | None:
        for spec in self.blocks:
            if spec.block_id == block_id:
                return spec
        return None

    def get_archive(self, archive_id: str) -> ArchiveSpec | None:
        for spec in self.archives:
            if spec.archive_id == archive_id:
                return spec
        return None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "batch_id": self.batch_id,
            "quota_bytes": self.quota_bytes,
            "blocks": [
                {"block_id": b.block_id, "length": b.length,
                 "sha256": b.sha256}
                for b in self.blocks
            ],
        }
        if self.archives:
            out["archives"] = [a.to_dict() for a in self.archives]
        if self.shared_pool is not None:
            out["shared_pool"] = self.shared_pool.to_dict()
        return out

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
