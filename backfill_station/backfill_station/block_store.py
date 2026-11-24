"""已核验块的本地仓库（block store）。

三核对通过的块载荷在追加 block_verified 事件之前先落到这里，作为
档案恢复时唯一可信的取数来源。仓库是清单与日志的**派生产物**：

- 文件名不直接使用块身份，而是其十六进制编码，保证目录始终扁平、
  不可能出现路径分隔或越界写法；
- 写入走同目录隐藏临时文件 + 原子改名 + fsync，读取者永远看不到
  半个块；
- 恢复档案时逐块重新核对长度与 SHA-256，块文件缺失或被篡改一律
  按数据目录完整性损坏硬失败，绝不静默用坏字节发布档案。
"""
from __future__ import annotations

import hashlib
import os

BLOCK_STORE_DIR = "blocks"
_TMP_PREFIX = ".block.tmp."


class BlockStoreError(RuntimeError):
    pass


def _write_all(fd: int, payload: bytes) -> None:
    """POSIX 允许 os.write 短写，循环写完整段，避免留下截断块。"""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise BlockStoreError("块仓库写入返回非正值，写入中断")
        view = view[written:]


class BlockStore:
    def __init__(self, data_dir: str):
        self.dir = os.path.join(data_dir, BLOCK_STORE_DIR)

    # ---- 路径 ----
    @staticmethod
    def block_filename(block_id: str) -> str:
        # 任意合法块身份（含分隔符、点号、Unicode）都编码成安全的
        # 十六进制文件名；编码可逆且无碰撞。
        return block_id.encode("utf-8").hex() + ".bin"

    def path_for(self, block_id: str) -> str:
        return os.path.join(self.dir, self.block_filename(block_id))

    # ---- 写入 ----
    def store(self, block_id: str, payload: bytes) -> str:
        """原子写入一个已核验块，返回最终路径。已存在则保持不动。"""
        os.makedirs(self.dir, exist_ok=True)
        final_path = self.path_for(block_id)
        if os.path.exists(final_path):
            return final_path
        tmp_path = os.path.join(
            self.dir, f"{_TMP_PREFIX}{os.getpid()}.{self.block_filename(block_id)}")
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                _write_all(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp_path, final_path)
            self._fsync_dir()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        return final_path

    # ---- 读取与复核 ----
    def load_verified(self, block_id: str, length: int,
                      sha256: str) -> bytes:
        """读取块并重新核对长度与摘要；任何不符都是数据目录损坏。"""
        path = self.path_for(block_id)
        if not os.path.isfile(path):
            raise BlockStoreError(
                f"已核验块 {block_id} 的仓库文件缺失: {path}")
        with open(path, "rb") as fh:
            payload = fh.read()
        if len(payload) != length:
            raise BlockStoreError(
                f"块 {block_id} 仓库文件长度 {len(payload)} 与清单长度 "
                f"{length} 不符，数据目录可能已损坏")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != sha256:
            raise BlockStoreError(
                f"块 {block_id} 仓库文件摘要 {actual} 与清单摘要 {sha256} "
                f"不符，数据目录可能已损坏")
        return payload

    def _fsync_dir(self) -> None:
        try:
            fd = os.open(self.dir, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
