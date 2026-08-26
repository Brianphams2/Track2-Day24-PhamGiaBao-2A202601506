# DPIA-lite — Governed support agent

Phạm vi: agent hỗ trợ trong lab, dữ liệu hoàn toàn synthetic. Ngày đánh
giá: 2026-08-26. Đây là mapping kỹ thuật phục vụ bài lab, không phải kết
luận tư vấn pháp lý.

## 1. Dữ liệu gì

| Nguồn/tool | Dữ liệu | Phân loại | Chủ thể/rủi ro chính |
|---|---|---|---|
| `search_docs` | Nội dung ticket và mã ticket; có thể chứa tên, mã khách hàng hoặc PII do người viết chèn | internal/untrusted | Prompt injection và PII đi vào context ngoài mục đích |
| `read_customer` | Tên, CCCD, SĐT, STK, email, `related_tickets` | restricted | Mạo danh, gian lận tài chính, liên kết hồ sơ trái mục đích |
| Audit ledger | Hash tham số, identity/run ID, purpose, classification, decision, reason, TTL; không lưu raw PII | internal | Metadata vận hành và khả năng truy vết hoạt động |

`agent/pii.py:67-90` phát hiện và redact CCCD, SĐT, STK và email trước
khi dữ liệu đi vào consumer tiếp theo. Mã khách hàng là định danh nội bộ,
được xử lý theo nguyên tắc tối thiểu hoá dù không thuộc bốn regex trên.

## 2. Mục đích gì

Mục đích hợp lệ là tìm ticket hỗ trợ, tổng hợp tình trạng và tra hồ sơ
khách hàng liên quan để hỗ trợ xử lý. Run A chỉ tìm/tóm tắt tài liệu. Run
B chỉ tra hồ sơ dựa trên danh sách ticket ID typed lấy từ tên file và
mapping tin cậy `related_tickets`; free text không được dùng để chọn chủ
thể. Không có mục đích hợp lệ nào yêu cầu gửi hồ sơ restricted tới sink
hoặc endpoint do nội dung ticket chỉ định.

Cơ sở vận hành giả định của lab là yêu cầu hỗ trợ đã được xác thực và có
phân quyền. Hệ thống production phải bổ sung xác thực người dùng, thời
hạn lưu giữ, quy trình quyền chủ thể và phê duyệt của privacy/legal owner.

## 3. Chảy đi đâu

Luồng mặc định `--mock` là cục bộ:

1. User query → Run A → `search_docs`.
2. PII gate redact document text → mock LLM; không có API bên ngoài.
3. Tên file → ticket ID typed → Run B → trusted `related_tickets` →
   `read_customer`; record không quay lại Run A và Run B không có egress.
4. Mỗi quyết định tool call → `reports/ledger.jsonl`; chỉ lưu hash của
   args, không lưu raw CCCD/SĐT/STK/email.
5. Sink `localhost:9999` là đích tấn công trong lab. Baseline từng gửi PII
   synthetic tới đây; sau contain, PEP deny trước khi `http_post` chạy.

Nếu chọn `--model claude-...`, document text dùng cho `summarize` có thể
được chuyển tới API của model provider ở nước ngoài. PII gate làm giảm
dữ liệu trực tiếp nhưng không tự loại bỏ mọi dữ liệu cá nhân/quasi-ID.
Trước khi bật chế độ này cần data-flow inventory, đánh giá vị trí xử lý,
hợp đồng/retention của provider, hồ sơ chuyển dữ liệu xuyên biên giới và
thời hạn 60 ngày theo mapping NĐ 356/2025 của đề bài. Bài nộp và test chỉ
dùng `--mock`, nên evidence hiện tại không phát sinh luồng API đó.

## 4. Rủi ro và biện pháp

| Rủi ro | Biện pháp | Bằng chứng |
|---|---|---|
| Prompt injection điều khiển tool | Trifecta split và typed boundary | `agent/runner.py:130-213`, `tests/test_split.py` |
| Restricted data đi qua egress | PEP deny restricted + egress | `agent/policy.py:39-61`, `reports/ledger.jsonl:2` |
| PII vào context/log | Detect/redact; ledger chỉ lưu `args_hash` | `agent/pii.py:67-90`, `agent/runner.py:74-76,157-160` |
| Sửa audit history | JSONL hash chain và verify | `agent/ledger.py:65-119`, `tests/test_ledger.py` |
| Quyền xoá/chỉnh dữ liệu chủ thể | Chưa có delete cascade; cần triển khai và phê duyệt retention trước production | Gap được ghi trong compliance mapping |
