# Đánh giá tác động xử lý dữ liệu (DPIA) - LLM Agent

## 1. Bản chất và Mục đích
- **Dữ liệu xử lý:** Hồ sơ khách hàng bao gồm Tên, CMND/CCCD, SĐT, Email, STK ngân hàng và nội dung ticket hỗ trợ (từ `data/customers.json` và `corpus/`).
- **Mục đích:** Tóm tắt ticket và đối soát dữ liệu (reconciliation) dựa trên yêu cầu của người dùng.

## 2. Luồng dữ liệu (Data-flow Inventory)
- **Nguồn:** Local disk (`data/`, `corpus/`).
- **Xử lý trung gian (LLM API):** Prompt và context (chỉ chứa metadata hoặc text đã mã hóa/không chứa PII) được đẩy qua biên giới (xuyên quốc gia) để gọi API của mô hình (Anthropic/OpenAI) khi sử dụng `--model`. Hành động này tuân thủ yêu cầu lưu hồ sơ 60 ngày theo NĐ 356/2025.
- **Đích đến (Egress):** API nội bộ `http://localhost:9999/reconcile`.

## 3. Đánh giá rủi ro & Biện pháp giảm thiểu
- **Rủi ro bị Prompt Injection (Goal Hijack):** Áp dụng mô hình **Trifecta Split** (Tách quyền truy cập dữ liệu cá nhân ra khỏi context text của attacker).
- **Rủi ro lộ lọt PII:** Áp dụng **PII Gate** (Regex redaction) trước lưu trữ/LLM.
- **Rủi ro lạm quyền (Privilege Abuse):** Xác thực **Policy-as-code** (Egress Control) dựa trên `data_classification` và `agent_owner`.
- **Rủi ro không truy vết được:** Bắt buộc ghi **Tamper-evident Ledger** bằng mã băm SHA-256 chuỗi cho mọi hoạt động truy cập và xuất dữ liệu.
