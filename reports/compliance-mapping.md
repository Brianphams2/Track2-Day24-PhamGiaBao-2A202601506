# Compliance mapping

Mapping này chứng minh control kỹ thuật trong phạm vi lab; nó không tự
khẳng định toàn bộ hệ thống đã tuân thủ pháp luật hoặc tiêu chuẩn.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade. Giữ ledger bất biến nhưng cần quy trình xoá dữ liệu nguồn, xử lý bản sao và retention exception trước production. | Gap và hành động tiếp theo: `reports/dpia-lite.md` §4 |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory phân biệt `--mock` cục bộ và luồng tới model provider khi dùng `--model`; yêu cầu review trước khi bật luồng ngoài nước. | `reports/dpia-lite.md` §3, đoạn “Nếu chọn --model” |
| ASI03 — privilege abuse | Identity riêng cho Run A/Run B, delegation depth, TTL 5 phút, purpose và egress state được PEP đánh giá rồi ghi ledger. | `agent/runner.py:130-204`; các field `agent_owner`, `identity_expires_at` tại `reports/ledger.jsonl:1-3` |
| ASI01 — goal hijack | Trifecta split: free text dừng ở Run A; Run B chỉ nhận ticket ID typed và dùng mapping tin cậy. Egress injection bị deny trước execution. | `agent/runner.py:135-213`; `reports/attack-after.log`; `tests/test_split.py` |
| ISO 42001 Clause 5-6 | Policy-as-code có input rõ, deny rule, reason bắt buộc và lịch sử review bằng commit riêng. | `agent/policy.py:39-61`; commit `2719454` (`git log -- agent/policy.py`) |
