"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path


_GENESIS_HASH = "0" * 64
_REQUIRED_FIELDS = {
    "ts",
    "agent_id",
    "run_id",
    "tool",
    "args_hash",
    "classification",
    "decision",
    "reason",
}
_APPEND_LOCK = threading.Lock()


def _canonical(entry: dict) -> str:
    payload = {key: value for key, value in entry.items() if key != "hash"}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry).encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    missing = sorted(_REQUIRED_FIELDS - set(entry))
    if missing:
        raise ValueError(f"ledger entry missing required fields: {', '.join(missing)}")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _APPEND_LOCK:
        previous_hash = _GENESIS_HASH
        if path.exists():
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                try:
                    previous_hash = str(json.loads(lines[-1])["hash"])
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise ValueError("cannot append to a malformed ledger") from exc

        complete = dict(entry)
        complete.pop("hash", None)
        complete["prev_hash"] = previous_hash
        complete["hash"] = _hash(complete)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(complete, ensure_ascii=False, sort_keys=True) + "\n")
        return complete


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return False

    expected_previous = _GENESIS_HASH
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                continue
            entry = json.loads(line)
            if not isinstance(entry, dict):
                return False
            if _REQUIRED_FIELDS - set(entry):
                return False
            if not str(entry.get("reason", "")).strip():
                return False
            if entry.get("decision") not in {"allow", "deny"}:
                return False
            if entry.get("prev_hash") != expected_previous:
                return False
            stored_hash = entry.get("hash")
            if not isinstance(stored_hash, str) or stored_hash != _hash(entry):
                return False
            expected_previous = stored_hash
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return False
    return True
