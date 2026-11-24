"""仅追加的持久事件日志（journal）。

设计要点：
- 每条记录一行 JSON，带 seq（单调序号）、ts（单调时钟，仅展示用）、
  type、payload、crc32（覆盖除 crc 外整行的 CRC32）。
- 追加后 fsync，保证进程崩溃后已确认的事件不会丢。
- 损坏（CRC 不符、序号断裂、JSON 非法）一律硬失败：宁可停机也不基于
  被篡改/截断的账目继续记账。
- 同一数据目录通过文件锁串行化，多个采集进程的命令排队执行，
  事件流保持全序，因此回放结果确定。
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import zlib
from dataclasses import dataclass
from typing import Any, Iterator, Optional

JOURNAL_NAME = "journal.jsonl"
LOCK_NAME = "station.lock"


class JournalError(RuntimeError):
    pass


@dataclass(frozen=True)
class Event:
    seq: int
    ts: int
    type: str
    payload: dict[str, Any]

    def to_envelope(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "type": self.type,
                "payload": self.payload}


def _encode(seq: int, ts: int, event_type: str, payload: dict[str, Any]) -> str:
    envelope = {"seq": seq, "ts": ts, "type": event_type, "payload": payload}
    body = json.dumps(
        envelope, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    crc = zlib.crc32(body.encode("utf-8")) & 0xFFFFFFFF
    # crc 独立放在行尾，校验时先剥掉它再算。
    return body + "|crc=" + f"{crc:08x}" + "\n"


def _decode(line: str, expected_seq: int) -> Event:
    line = line.rstrip("\n")
    marker = "|crc="
    if marker not in line:
        raise JournalError(f"日志行缺少 CRC 标记: {line[:80]!r}")
    body, crc_text = line.rsplit(marker, 1)
    actual = zlib.crc32(body.encode("utf-8")) & 0xFFFFFFFF
    try:
        expected = int(crc_text, 16)
    except ValueError as exc:
        raise JournalError(f"日志行 CRC 非法: {line[:80]!r}") from exc
    if actual != expected:
        raise JournalError(
            f"日志行 CRC 不匹配（行 {expected_seq}）：账目可能已损坏"
        )
    try:
        envelope = json.loads(body)
    except json.JSONDecodeError as exc:
        raise JournalError(f"日志行 JSON 非法: {exc}") from exc
    if envelope.get("seq") != expected_seq:
        raise JournalError(
            f"日志序号断裂：期望 {expected_seq}，实际 {envelope.get('seq')}"
        )
    if not isinstance(envelope.get("payload"), dict):
        raise JournalError(f"日志行 payload 非法（行 {expected_seq}）")
    return Event(
        seq=expected_seq,
        ts=int(envelope["ts"]),
        type=str(envelope["type"]),
        payload=envelope["payload"],
    )


class Journal:
    """仅追加日志；一个进程内通过 DataDir 的文件锁保证互斥。"""

    def __init__(self, path: str):
        self.path = path
        self._fh: Optional[Any] = None
        self._next_seq = 1
        self._clock = 0

    def open_for_append(self) -> "Journal":
        new_file = not os.path.exists(self.path)
        self._fh = open(self.path, "a+", encoding="utf-8")
        if new_file:
            os.fsync(self._fh.fileno())
        else:
            self._fh.seek(0)
            for line in self._fh:
                if line.strip():
                    event = _decode(line, self._next_seq)
                    self._next_seq += 1
                    if event.ts > self._clock:
                        self._clock = event.ts
            self._fh.seek(0, os.SEEK_END)
        return self

    def append(self, event_type: str, payload: dict[str, Any]) -> Event:
        if self._fh is None:
            raise JournalError("日志未打开")
        self._clock += 1  # 单调逻辑时钟，回放确定，不依赖墙钟
        event = Event(self._next_seq, self._clock, event_type, payload)
        self._fh.write(_encode(event.seq, event.ts, event.type, event.payload))
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._next_seq += 1
        return event

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    @staticmethod
    def replay(path: str) -> Iterator[Event]:
        if not os.path.exists(path):
            raise JournalError(f"日志不存在: {path}")
        seq = 1
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                yield _decode(line, seq)
                seq += 1


class DataDirLock:
    """跨进程互斥锁。所有会改账的命令都必须持锁执行。"""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._fh: Optional[Any] = None

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        lock_path = os.path.join(self.data_dir, LOCK_NAME)
        self._fh = open(lock_path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
