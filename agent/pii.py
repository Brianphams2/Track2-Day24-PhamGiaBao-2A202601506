"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}(?![\w-])",
    re.IGNORECASE,
)
_CCCD_RE = re.compile(
    r"(?i)(?:\bCCCD\b|căn\s*cước(?:\s*công\s*dân)?)\s*(?:của\s+[^:\n]{0,60}?\s*)?[:#-]?\s*"
    r"(?P<value>(?<!\d)\d(?:[ .-]?\d){11}(?!\d))"
)
_BANK_RE = re.compile(
    r"(?i)(?:\bSTK\b|số\s*tài\s*khoản|tài\s*khoản|bank\s*account)"
    r"[^\d\n]{0,30}(?P<value>(?<!\d)\d(?:[ .-]?\d){7,15}(?!\d))"
)
_PHONE_RE = re.compile(
    r"(?i)(?:\bSĐT\b|\bSDT\b|số\s*điện\s*thoại|điện\s*thoại|phone)"
    r"[^\d+\n]{0,30}(?P<value>(?<!\w)(?:\+?84|0)(?:[ .-]?\d){9}(?!\d))"
)
_GENERIC_PHONE_RE = re.compile(r"(?<![\w\d])(?:\+?84|0)(?:[ .-]?\d){9}(?!\d)")


def _overlaps(candidate: dict, entities: list[dict]) -> bool:
    return any(candidate["start"] < item["end"] and item["start"] < candidate["end"] for item in entities)


def _add_matches(text: str, pattern: re.Pattern, entity_type: str, entities: list[dict]) -> None:
    for match in pattern.finditer(text):
        start, end = match.span("value") if "value" in pattern.groupindex else match.span()
        candidate = {"type": entity_type, "start": start, "end": end}
        if not _overlaps(candidate, entities):
            entities.append(candidate)


def detect(text: str) -> list[dict]:
    """Detect supported Vietnamese PII while preserving source offsets.

    Context-bearing identifiers are evaluated before the generic phone
    recognizer so a CCCD or bank account is not double-labelled.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    entities: list[dict] = []
    _add_matches(text, _EMAIL_RE, "EMAIL", entities)
    _add_matches(text, _CCCD_RE, "VN_CCCD", entities)
    _add_matches(text, _BANK_RE, "VN_BANK_ACCOUNT", entities)
    _add_matches(text, _PHONE_RE, "VN_PHONE", entities)
    _add_matches(text, _GENERIC_PHONE_RE, "VN_PHONE", entities)
    return sorted(entities, key=lambda item: (item["start"], item["end"], item["type"]))


def redact(text: str) -> str:
    redacted = text
    for entity in reversed(detect(text)):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]
    return redacted
