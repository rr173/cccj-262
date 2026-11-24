"""档案恢复：把已核验块按清单顺序还原成可直接使用的完整档案文件。

恢复操作严格只读账本与块仓库、只写输出目录，不追加任何日志事件，
因此绝不改变许可、额度或收据账。安全要点：

- 输出目录做 realpath 规范化，每个档案的目标路径必须落在输出目录
  之内（共同前缀判定），符号链接逃逸同样会被拦住；
- 先确认档案所需的每一块都已通过三核对，缺任一块就整体跳过、
  不生成该档案的任何新文件（含临时文件），并报告缺少的块；
- 组装在输出目录内的隐藏临时文件中进行，逐块复核长度与 SHA-256，
  再核对组成文件的总长度与整档摘要；全部匹配后用 os.replace 原子
  发布，读取者任何时刻都看不到部分文件；
- 重复恢复对相同状态产生相同文件与状态：已发布且内容一致的档案
  原样保留（含权限），临时文件绝不遗留。
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from .block_store import BlockStore, BlockStoreError
from .manifest import ArchiveSpec, Manifest
from .state import Ledger

CHUNK_SIZE = 64 * 1024
_TMP_PREFIX = ".archive.tmp."


class RestoreError(RuntimeError):
    """致命错误：数据目录/块仓库损坏或发布失败，调用方按致命错误处理。"""


@dataclass
class ArchiveRestoreStatus:
    archive_id: str
    path: str
    state: str                 # published | blocked | verified_existing
    length: int
    sha256: str
    missing_block_ids: list[str] = field(default_factory=list)
    output_path: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive_id": self.archive_id,
            "path": self.path,
            "state": self.state,
            "length": self.length,
            "sha256": self.sha256,
            "missing_block_ids": self.missing_block_ids,
            "output_path": self.output_path,
            "detail": self.detail,
        }


def resolve_output_path(output_dir: str, archive_path: str) -> str:
    """把清单相对路径安全地拼到输出目录，并证明它无法越界。

    清单冻结期已挡掉空段、'.'、'..'、绝对路径与反斜杠；这里再用
    realpath 做一次基于真实文件系统的包含判定，连输出目录内预先
    布置的符号链接逃逸也一并拦截。
    """
    root_real = os.path.realpath(output_dir)
    target = os.path.join(root_real, *archive_path.split("/"))
    target_real = os.path.realpath(target)
    if target_real != root_real and not target_real.startswith(
            root_real + os.sep):
        raise RestoreError(
            f"档案路径 {archive_path!r} 越出输出目录 {root_real}，拒绝发布")
    return target_real


def _same_existing_file(path: str, length: int, sha256: str) -> bool:
    """已发布文件逐字节仍与清单一致（长度 + 摘要双核对）。"""
    if not os.path.isfile(path):
        return False
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            h.update(chunk)
    return total == length and h.hexdigest() == sha256


def restore_archives(ledger: Ledger, store: BlockStore,
                     output_dir: str) -> dict[str, Any]:
    """恢复清单声明的全部档案，返回逐档案状态与汇总。"""
    manifest: Manifest = ledger.manifest
    results: list[ArchiveRestoreStatus] = []

    # 输出目录惰性创建：没有档案声明、或全部档案缺块时不触碰文件系统。
    root_real = os.path.realpath(output_dir)
    for archive in manifest.archives:
        results.append(_restore_one(ledger, store, root_real, archive))

    published = [r for r in results if r.state in
                 ("published", "verified_existing")]
    blocked = [r for r in results if r.state == "blocked"]
    return {
        "ok": not blocked,
        "output_dir": root_real,
        "archives_declared": len(manifest.archives),
        "archives_published": len(published),
        "archives_blocked": len(blocked),
        "results": [r.to_dict() for r in results],
    }


def _restore_one(ledger: Ledger, store: BlockStore, root_real: str,
                 archive: ArchiveSpec) -> ArchiveRestoreStatus:
    target_path = resolve_output_path(root_real, archive.path)

    # 1. 准入：所需块全部已核验交付，缺任一块则整体跳过、不写任何文件。
    missing = [bid for bid in archive.block_ids
               if not ledger.blocks[bid].delivered]
    if missing:
        return ArchiveRestoreStatus(
            archive_id=archive.archive_id, path=archive.path,
            state="blocked", length=archive.length, sha256=archive.sha256,
            missing_block_ids=missing,
            detail=(f"缺少 {len(missing)} 个块，未生成新文件: "
                    f"{', '.join(missing)}"))

    # 2. 幂等快路：目标已存在且与清单逐字节一致，原样保留
    #    （不动权限、不重写、不改时间以外的任何状态）。
    if _same_existing_file(target_path, archive.length, archive.sha256):
        return ArchiveRestoreStatus(
            archive_id=archive.archive_id, path=archive.path,
            state="verified_existing", length=archive.length,
            sha256=archive.sha256, output_path=target_path,
            detail="已发布文件与清单一致，保持原样")

    parent = os.path.dirname(target_path)
    os.makedirs(parent, exist_ok=True)
    # makedirs 可能经过符号链接，再次确认真实父目录仍在输出目录内。
    parent_real = os.path.realpath(parent)
    if parent_real != root_real and not parent_real.startswith(
            root_real + os.sep):
        raise RestoreError(
            f"档案 {archive.archive_id} 的父目录越出输出目录，拒绝发布")
    if os.path.exists(target_path) and not os.path.isfile(target_path):
        raise RestoreError(
            f"目标路径 {target_path} 已存在且不是普通文件，拒绝覆盖")

    # 3. 组装到同目录隐藏临时文件：逐块复核，读取者看不到部分文件。
    tmp_path = os.path.join(
        parent_real,
        f"{_TMP_PREFIX}{os.getpid()}.{archive.archive_id}.{_counter_next()}")
    digest = hashlib.sha256()
    total = 0
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            for block_id in archive.block_ids:
                spec = ledger.manifest.get(block_id)
                try:
                    payload = store.load_verified(block_id, spec.length,
                                                  spec.sha256)
                except BlockStoreError as exc:
                    # 块仓库缺失/被篡改与发布失败同属数据目录致命损坏，
                    # 统一成 RestoreError 让调用方按致命错误处理。
                    raise RestoreError(str(exc)) from exc
                _write_all(fd, payload)
                digest.update(payload)
                total += len(payload)
            os.fsync(fd)
        finally:
            os.close(fd)

        # 4. 发布前最后闸门：总长度与整档摘要都匹配清单才原子改名。
        if total != archive.length:
            raise RestoreError(
                f"档案 {archive.archive_id} 组成长度 {total} 与清单长度 "
                f"{archive.length} 不符，拒绝发布")
        if digest.hexdigest() != archive.sha256:
            raise RestoreError(
                f"档案 {archive.archive_id} 组成摘要 {digest.hexdigest()} "
                f"与清单摘要 {archive.sha256} 不符，拒绝发布")
        os.replace(tmp_path, target_path)
        _fsync_dir(parent_real)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return ArchiveRestoreStatus(
        archive_id=archive.archive_id, path=archive.path,
        state="published", length=archive.length, sha256=archive.sha256,
        output_path=target_path,
        detail=f"已按 {len(archive.block_ids)} 个块顺序组装并原子发布")


_counter = 0


def _counter_next() -> int:
    global _counter
    _counter += 1
    return _counter


def _write_all(fd: int, payload: bytes) -> None:
    """循环写完整段，防止 os.write 短写导致发布截断档案。"""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise RestoreError("档案临时文件写入中断")
        view = view[written:]


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def archive_readiness(ledger: Ledger) -> list[dict[str, Any]]:
    """报告用：纯派生视图，列出每个档案的就绪状态与缺块。"""
    view = []
    for archive in ledger.manifest.archives:
        missing = [bid for bid in archive.block_ids
                   if not ledger.blocks[bid].delivered]
        view.append({
            "archive_id": archive.archive_id,
            "path": archive.path,
            "length": archive.length,
            "sha256": archive.sha256,
            "block_ids": list(archive.block_ids),
            "blocks_total": len(archive.block_ids),
            "missing_block_ids": missing,
            "ready": not missing,
        })
    return view
