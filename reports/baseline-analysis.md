# Baseline analysis

## 1. Agent có identity riêng không?

Không. Hàm baseline `agent/loop.py:27` chỉ nhận `message` và `llm`; không
tạo `agent_id`, `run_id`, owner hoặc TTL. Identity theo run chỉ xuất hiện
sau containment tại `agent/runner.py:132-133` và được ghi vào ledger ở
`agent/runner.py:89-100`.

## 2. Ai quyết định agent được gọi `http_post`?

Ở baseline, nội dung không tin cậy quyết định gián tiếp qua kết quả
`llm.find_injection()` tại `agent/loop.py:33-34`. Nếu model nhận chỉ thị,
loop đọc customer rồi gọi thẳng `tools.http_post()` tại
`agent/loop.py:44`; không có PEP hay kiểm tra quyền ở giữa.

## 3. Làm sao biết agent đã gửi sai dữ liệu?

Baseline không có audit ledger. Chỉ biết sau khi đích nhận dữ liệu và ghi
`reports/sink.log`. Bằng chứng thực nghiệm nằm tại
`reports/attack-before.log`: sink đã nhận record synthetic của
`KH-000999`. Sau containment, mọi quyết định tool call được ghi vào
`reports/ledger.jsonl`, gồm `decision`, `reason`, identity, TTL và hash
chain.
