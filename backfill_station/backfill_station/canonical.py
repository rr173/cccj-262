"""规范化编码与 HMAC-SHA256 签名工具。

终止证需要在离线环境下可核实，因此不依赖任何外部 PKI，只使用标准库
hmac/hashlib。签名载荷先做确定性（规范化）JSON 编码，保证同一份语义
产生完全相同的字节串，跨进程、跨重启都可重复验证。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

# 规范化 JSON：键排序、无多余空白、不转义非 ASCII、分隔符固定。
# 任何参与签名或摘要比较的结构都必须走这里，禁止各自 json.dumps。


def canonical_json(obj: Any) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def digest_payload(payload: bytes) -> str:
    """块体摘要：SHA-256 十六进制小写。"""
    return hashlib.sha256(payload).hexdigest()


def sign_payload(payload: Mapping[str, Any], hmac_key: bytes) -> str:
    """对规范化载荷做 HMAC-SHA256，返回十六进制签名。"""
    return hmac.new(
        hmac_key, canonical_bytes(payload), hashlib.sha256
    ).hexdigest()


def verify_signature(
    payload: Mapping[str, Any], signature: str, hmac_key: bytes
) -> bool:
    """常数时间比较，防止时序侧信道。"""
    if not isinstance(signature, str):
        return False
    expected = sign_payload(payload, hmac_key)
    return hmac.compare_digest(expected, signature)
