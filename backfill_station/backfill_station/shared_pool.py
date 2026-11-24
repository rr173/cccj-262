"""可选的共享块池（shared block pool）：按内容去重的跨批次块存储。

多个独立采集批次可能收到内容完全相同的数据块；若各自保存，同一份字节
会在磁盘上重复占用。配置到同一共享池的批次，其三核对通过的块不再落到
本批数据目录，而是按 SHA-256 内容寻址落入池中：内容相同的块（即使
block_id 不同、即使来自不同批次）只保留一份物理对象，池为每个批次各自
登记一条关联（link）。

设计要点（与批次自身的事件溯源架构保持一致）：

- 池拥有独立的仅追加日志（pool.jsonl，CRC32 + 单调序号 + fsync）与
  跨进程文件锁（pool.lock）。批次之间的钱账、许可、收据、交付状态完全
  独立，池只负责字节存储与关联登记，绝不参与批次账本；
- 关联键为 (batch_id, block_id)，对象键为内容 SHA-256。一个物理对象
  可被任意多批次/块身份关联；只有当某对象不再关联任何批次时才删除其
  存储文件；
- 每个批次仍只能凭自己的账本恢复：恢复时除逐块复核长度/摘要外，还要求
  池中存在本批对该块的有效关联，别的批次的关联不能顶替；
- 关联的登记与撤销都在池锁内“校验 -> 追加事件 -> 折叠”，重启与并发
  更新都不会让已确认的关联消失（事件持久化、操作幂等）；
- 崩溃自愈：每次持锁打开先做对账——磁盘上无关联的孤立对象被清扫；
  有关联却缺失的对象属于池存储损坏，硬失败；批次未确认交付的残留关联
  由显式 GC 凭各批日志核实后撤销。
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from .block_store import BlockStoreError
from .journal import Event, Journal
from .manifest import SharedPoolSpec

POOL_JOURNAL_NAME = "pool.jsonl"
POOL_LOCK_NAME = "pool.lock"
POOL_OBJECTS_DIR = "objects"
_TMP_PREFIX = ".poolobj.tmp."


class SharedPoolError(RuntimeError):
    pass


# ---- 池内文件锁（与批次锁相互独立；锁序永远是先批次锁、后池锁） ----
class PoolLock:
    def __init__(self, pool_dir: str):
        self.pool_dir = pool_dir
        os.makedirs(pool_dir, exist_ok=True)
        self._fh: Optional[Any] = None

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        lock_path = os.path.join(self.pool_dir, POOL_LOCK_NAME)
        self._fh = open(lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None


@dataclass
class PoolLink:
    batch_id: str
    block_id: str
    length: int
    data_dir: str

    def to_dict(self) -> dict[str, Any]:
        return {"batch_id": self.batch_id, "block_id": self.block_id,
                "length": self.length, "data_dir": self.data_dir}


@dataclass
class PoolObject:
    digest: str
    length: int
    links: dict[tuple[str, str], PoolLink] = field(default_factory=dict)

    @property
    def link_count(self) -> int:
        return len(self.links)


@dataclass
class PoolState:
    """池日志的回放投影：digest -> 对象，对象内挂全部有效关联。"""
    objects: dict[str, PoolObject] = field(default_factory=dict)
    last_seq: int = 0

    def link(self, batch_id: str, block_id: str) -> Optional[tuple[PoolObject, PoolLink]]:
        for obj in self.objects.values():
            link = obj.links.get((batch_id, block_id))
            if link is not None:
                return obj, link
        return None

    def apply(self, event: Event) -> None:
        p = event.payload
        etype = event.type
        self.last_seq = event.seq

        if etype == "pool_opened":
            return

        if etype == "pool_linked":
            digest = p["sha256"]
            key = (p["batch_id"], p["block_id"])
            existing = self.link(*key)
            if existing is not None:
                obj, link = existing
                if obj.digest != digest or link.length != p["length"]:
                    raise SharedPoolError(
                        f"池日志损坏：关联 {key} 被重复登记为不同对象")
                raise SharedPoolError("pool_linked 事件重复")
            obj = self.objects.get(digest)
            if obj is None:
                obj = PoolObject(digest=digest, length=p["length"])
                self.objects[digest] = obj
            elif obj.length != p["length"]:
                raise SharedPoolError(
                    f"池日志损坏：同摘要对象长度不一致 {obj.length} != {p['length']}")
            obj.links[key] = PoolLink(
                batch_id=p["batch_id"], block_id=p["block_id"],
                length=p["length"], data_dir=p["data_dir"])
            return

        if etype in ("pool_released", "pool_link_gc"):
            # 两类撤销语义相同：删除一条关联；最后一条撤销后对象消失。
            # pool_link_gc 额外带 reason，用于崩溃窗口的残留关联回收。
            digest = p["sha256"]
            key = (p["batch_id"], p["block_id"])
            obj = self.objects.get(digest)
            if obj is None or key not in obj.links:
                raise SharedPoolError(
                    f"池日志损坏：撤销事件 {event.seq} 引用不存在的关联 {key}")
            del obj.links[key]
            if not obj.links:
                del self.objects[digest]
            return

        if etype == "pool_reconciled":
            return

        raise SharedPoolError(f"未知池事件类型: {etype}")


def _replay_pool(journal: Journal) -> PoolState:
    state = PoolState()
    for event in Journal.replay(journal.path):
        state.apply(event)
    return state


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise SharedPoolError("共享池对象写入返回非正值，写入中断")
        view = view[written:]


class SharedBlockPool:
    """按内容寻址的共享块池。所有公开操作都在池锁内自包含执行。"""

    def __init__(self, pool_dir: str):
        self.dir = os.path.realpath(pool_dir)
        self.objects_dir = os.path.join(self.dir, POOL_OBJECTS_DIR)
        self._lock = PoolLock(self.dir)

    @classmethod
    def from_spec(cls, spec: SharedPoolSpec) -> "SharedBlockPool":
        return cls(spec.path)

    # ---- 路径 ----
    @staticmethod
    def object_filename(digest: str) -> str:
        # 摘要本身即 64 位十六进制，扁平命名、无路径分隔、不可越界。
        return digest + ".bin"

    def object_path(self, digest: str) -> str:
        return os.path.join(self.objects_dir, self.object_filename(digest))

    def _fsync_dir(self, path: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _atomic_write_object(self, digest: str, payload: bytes) -> str:
        """同目录隐藏临时文件 + 原子改名 + fsync；已存在则保持不动。"""
        os.makedirs(self.objects_dir, exist_ok=True)
        final_path = self.object_path(digest)
        if os.path.exists(final_path):
            return final_path
        tmp_path = os.path.join(
            self.objects_dir, f"{_TMP_PREFIX}{os.getpid()}.{digest}.tmp")
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                _write_all(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp_path, final_path)
            self._fsync_dir(self.objects_dir)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        return final_path

    # ---- 打开与对账 ----
    @contextlib.contextmanager
    def _open(self) -> Iterator[tuple[Journal, PoolState]]:
        with self._lock.locked():
            os.makedirs(self.objects_dir, exist_ok=True)
            journal_path = os.path.join(self.dir, POOL_JOURNAL_NAME)
            fresh = not os.path.exists(journal_path)
            journal = Journal(journal_path)
            journal.open_for_append()
            try:
                if fresh:
                    journal.append("pool_opened", {"pool_dir": self.dir})
                state = _replay_pool(journal)
                self._reconcile_unsafe(journal, state)
                yield journal, state
            finally:
                journal.close()

    def _reconcile_unsafe(self, journal: Journal,
                          state: PoolState) -> list[str]:
        """持锁对账：清扫无关联孤立对象；有关联却缺文件即硬失败。

        崩溃可能发生在“对象已写、关联事件未落”或“最后关联已撤销、
        文件未删”之间，两类残留都在此收敛。返回本次清扫的孤立摘要。
        """
        on_disk: set[str] = set()
        if os.path.isdir(self.objects_dir):
            for name in os.listdir(self.objects_dir):
                if name.endswith(".bin") and len(name) == 68:
                    on_disk.add(name[:-4])
        linked = set(state.objects.keys())
        orphans = sorted(on_disk - linked)
        for digest in orphans:
            os.unlink(self.object_path(digest))
        missing = sorted(linked - on_disk)
        if missing:
            raise SharedPoolError(
                "共享池存储损坏：以下对象仍被批次关联但物理文件缺失: "
                + ", ".join(missing))
        if orphans:
            self._fsync_dir(self.objects_dir)
            journal.append("pool_reconciled", {
                "reason": "sweep_orphan_objects",
                "orphan_sha256": orphans,
            })
            # 对账事件不改变投影状态，无需再折叠。
        return orphans

    # ---- 关联登记（三核对已在批次侧通过后调用） ----
    def link_block(self, *, batch_id: str, block_id: str, length: int,
                   sha256: str, data_dir: str,
                   payload: bytes) -> dict[str, Any]:
        """登记一个已核验块的内容对象与本批关联，返回操作结果。

        幂等：同一 (batch_id, block_id) 以同一摘要重交为无操作；摘要
        冲突说明批次日志/池状态被破坏，硬失败。不同批次或不同 block_id
        关联同一摘要时复用同一物理对象，只新增关联。
        """
        with self._open() as (journal, state):
            key = (batch_id, block_id)
            existing = state.link(*key)
            if existing is not None:
                obj, link = existing
                if obj.digest != sha256:
                    raise SharedPoolError(
                        f"共享池关联冲突：{key} 已关联 {obj.digest[:16]}...，"
                        f"拒绝改关联到 {sha256[:16]}...")
                # 同一批次身份只能对应一个数据目录：不同目录复用同一
                # batch_id 会让关联键碰撞，属配置错误，硬失败拒绝。
                if os.path.realpath(data_dir) != os.path.realpath(link.data_dir):
                    raise SharedPoolError(
                        f"共享池批次身份冲突：batch_id {batch_id!r} 已被数据目录 "
                        f"{link.data_dir} 使用，拒绝来自 {data_dir} 的关联")
                # 幂等重交：对象文件经对账确认存在，不重复写、不重复登记。
                return {"status": "already_linked", "sha256": sha256,
                        "link_count": obj.link_count, "storage_written": False}
            self._atomic_write_object(sha256, payload)
            event = journal.append("pool_linked", {
                "batch_id": batch_id, "block_id": block_id,
                "length": length, "sha256": sha256,
                "data_dir": os.path.realpath(data_dir),
            })
            state.apply(event)
            obj = state.objects[sha256]
            return {"status": "linked", "sha256": sha256,
                    "link_count": obj.link_count, "storage_written": True,
                    "event_seq": event.seq,
                    "stored_path": os.path.relpath(
                        self.object_path(sha256), self.dir)}

    # ---- 关联撤销（批次退役/清理后调用） ----
    def release_block(self, *, batch_id: str, block_id: str,
                      sha256: str) -> dict[str, Any]:
        """撤销本批对某块的关联；无任何批次关联后才删除物理对象。

        幂等：关联已不存在时返回 released=False 且不动任何文件。其他
        批次的关联完全不受影响，其档案恢复继续可用。
        """
        with self._open() as (journal, state):
            obj = state.objects.get(sha256)
            key = (batch_id, block_id)
            if obj is None or key not in obj.links:
                return {"status": "not_linked", "sha256": sha256,
                        "storage_released": False}
            remaining = obj.link_count - 1
            storage_released = False
            if remaining == 0:
                path = self.object_path(sha256)
                if os.path.exists(path):
                    os.unlink(path)
                    self._fsync_dir(self.objects_dir)
                    storage_released = True
            event = journal.append("pool_released", {
                "batch_id": batch_id, "block_id": block_id,
                "sha256": sha256, "remaining_links": remaining,
                "storage_released": storage_released,
            })
            state.apply(event)
            return {"status": "released", "sha256": sha256,
                    "remaining_links": remaining,
                    "storage_released": storage_released,
                    "event_seq": event.seq}

    # ---- 读取并复核（恢复档案时使用） ----
    def load_verified(self, *, batch_id: str, block_id: str, length: int,
                      sha256: str) -> bytes:
        """读取对象并复核：必须存在本批有效关联，且长度/摘要再次匹配。"""
        with self._open() as (_journal, state):
            found = state.link(batch_id, block_id)
            if found is None:
                raise BlockStoreError(
                    f"共享池中不存在批次 {batch_id} 对块 {block_id} 的有效关联")
            obj, link = found
            if obj.digest != sha256:
                raise BlockStoreError(
                    f"块 {block_id} 的池关联摘要 {obj.digest} 与清单摘要 "
                    f"{sha256} 不符，共享池状态可能已损坏")
            path = self.object_path(sha256)
            if not os.path.isfile(path):
                # 对账本应拦住此情形：按存储损坏硬失败。
                raise BlockStoreError(
                    f"共享池对象文件缺失: {path}")
            with open(path, "rb") as fh:
                payload = fh.read()
            if len(payload) != length or link.length != length:
                raise BlockStoreError(
                    f"块 {block_id} 池对象长度与清单长度 {length} 不符，"
                    f"共享池可能已损坏")
            actual = hashlib.sha256(payload).hexdigest()
            if actual != sha256:
                raise BlockStoreError(
                    f"块 {block_id} 池对象摘要 {actual} 与清单摘要 {sha256} "
                    f"不符，共享池可能已损坏")
            return payload

    # ---- 残留关联 GC：凭各批日志核实后撤销未确认交付的关联 ----
    def gc_stale_links(self) -> dict[str, Any]:
        """扫描全部关联，撤销对应批次未确认交付（或批次目录已不存在）
        的残留关联，并清扫因此失去全部关联的对象。

        用于收敛“池关联已落、批次 block_verified 未确认”的崩溃窗口。
        仍被存活批次确认交付的关联绝不撤销。
        """
        from .state import replay as replay_ledger  # 避免循环导入
        from .journal import Journal as BatchJournal
        from .manifest import Manifest

        removed: list[dict[str, Any]] = []
        with self._open() as (journal, state):
            # 先快照全部关联，避免边遍历边改。
            snapshot = [
                (obj.digest, obj.length, dict(obj.links))
                for obj in state.objects.values()
            ]
            for digest, _length, links in snapshot:
                for key, link in list(links.items()):
                    batch_id, block_id = key
                    stale_reason: Optional[str] = None
                    batch_journal = os.path.join(link.data_dir, "journal.jsonl")
                    if not os.path.exists(batch_journal):
                        stale_reason = "batch_data_dir_missing"
                    else:
                        try:
                            ledger = replay_ledger(
                                BatchJournal.replay(batch_journal))
                        except Exception as exc:  # 损坏的批次日志不静默删除
                            raise SharedPoolError(
                                f"GC 无法核实批次 {batch_id} 的日志: {exc}") from exc
                        block = ledger.blocks.get(block_id)
                        if block is None or not block.delivered:
                            stale_reason = "block_not_delivered_in_batch"
                    if stale_reason is None:
                        continue
                    obj = state.objects.get(digest)
                    remaining = (obj.link_count - 1) if obj else 0
                    storage_released = False
                    if remaining == 0:
                        path = self.object_path(digest)
                        if os.path.exists(path):
                            os.unlink(path)
                            self._fsync_dir(self.objects_dir)
                            storage_released = True
                    event = journal.append("pool_link_gc", {
                        "batch_id": batch_id, "block_id": block_id,
                        "length": link.length, "sha256": digest,
                        "data_dir": link.data_dir, "reason": stale_reason,
                        "remaining_links": remaining,
                        "storage_released": storage_released,
                    })
                    state.apply(event)
                    removed.append({"batch_id": batch_id, "block_id": block_id,
                                    "sha256": digest, "reason": stale_reason,
                                    "storage_released": storage_released,
                                    "event_seq": event.seq})
        return {"removed_links": removed, "removed_count": len(removed)}

    # ---- 按内容查看库存 ----
    def inventory(self, *, include_gc_check: bool = False) -> dict[str, Any]:
        """按内容（SHA-256）列出池库存：每个对象关联哪些批次、是否仍
        占用物理存储。include_gc_check=True 时额外标注疑似残留关联。"""
        with self._open() as (_journal, state):
            on_disk = (set(os.listdir(self.objects_dir))
                       if os.path.isdir(self.objects_dir) else set())
            items = []
            for digest in sorted(state.objects):
                obj = state.objects[digest]
                file_name = self.object_filename(digest)
                occupying = file_name in on_disk
                items.append({
                    "sha256": digest,
                    "length": obj.length,
                    "occupying_storage": occupying,
                    "link_count": obj.link_count,
                    "links": sorted(
                        (link.to_dict() for link in obj.links.values()),
                        key=lambda d: (d["batch_id"], d["block_id"])),
                })
            result = {
                "ok": True,
                "pool_dir": self.dir,
                "journal_last_seq": state.last_seq,
                "objects_total": len(items),
                "objects_occupying_storage": sum(
                    1 for it in items if it["occupying_storage"]),
                "links_total": sum(it["link_count"] for it in items),
                "objects": items,
            }
            if include_gc_check:
                result["gc_preview"] = self._gc_preview_unsafe(state)
            return result

    def _gc_preview_unsafe(self, state: PoolState) -> list[dict[str, Any]]:
        from .state import replay as replay_ledger
        from .journal import Journal as BatchJournal

        preview = []
        for obj in state.objects.values():
            for link in obj.links.values():
                batch_journal = os.path.join(link.data_dir, "journal.jsonl")
                if not os.path.exists(batch_journal):
                    reason = "batch_data_dir_missing"
                else:
                    try:
                        ledger = replay_ledger(
                            BatchJournal.replay(batch_journal))
                    except Exception as exc:
                        reason = f"batch_journal_unreadable: {exc}"
                        preview.append({
                            "batch_id": link.batch_id,
                            "block_id": link.block_id,
                            "sha256": obj.digest, "stale": False,
                            "reason": reason})
                        continue
                    block = ledger.blocks.get(link.block_id)
                    if block is None or not block.delivered:
                        reason = "block_not_delivered_in_batch"
                    else:
                        continue
                preview.append({
                    "batch_id": link.batch_id, "block_id": link.block_id,
                    "sha256": obj.digest, "stale": True, "reason": reason,
                    "data_dir": link.data_dir})
        return preview


class PoolBlockStorage:
    """让共享池呈现与本地 BlockStore 相同的块存储接口（适配恢复/退役）。

    恢复路径只依赖 path 无关的 load_verified；本适配把批次身份透传给
    池，确保批次只能读取自己持有有效关联的对象。
    """

    def __init__(self, pool: SharedBlockPool, batch_id: str, data_dir: str):
        self.pool = pool
        self.batch_id = batch_id
        self.data_dir = data_dir
        self.is_pool = True

    def store(self, block_id: str, payload: bytes, *, length: int,
              sha256: str) -> str:
        result = self.pool.link_block(
            batch_id=self.batch_id, block_id=block_id, length=length,
            sha256=sha256, data_dir=self.data_dir, payload=payload)
        return os.path.join(self.pool.dir, result["stored_path"]) \
            if "stored_path" in result else self.pool.object_path(sha256)

    def load_verified(self, block_id: str, length: int,
                      sha256: str) -> bytes:
        return self.pool.load_verified(
            batch_id=self.batch_id, block_id=block_id,
            length=length, sha256=sha256)

    def remove(self, block_id: str, *, sha256: str) -> dict[str, Any]:
        return self.pool.release_block(
            batch_id=self.batch_id, block_id=block_id, sha256=sha256)
