"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
import re
import json
import time
import hashlib
from agent import tools
from agent.policy import PolicyContext, check
from agent.ledger import append

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = DEFAULT_LEDGER_PATH
    if log_dir is not None:
        ledger_path = Path(log_dir) / "ledger.jsonl"
        
    # Run A: Search docs (Untrusted content)
    docs = tools.search_docs(message)
    ticket_ids = []
    for doc in docs:
        m = re.search(r'\d+', doc["id"])
        if m:
            ticket_ids.append(int(m.group(0)))
            
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)
    
    # Run B: Read customer (Private data)
    if injected is not None:
        customers_path = Path(__file__).resolve().parent.parent / "data" / "customers.json"
        with customers_path.open(encoding="utf-8") as f:
            customers_data = json.load(f)
            
        collected = []
        for customer in customers_data:
            c_related = set(customer.get("related_tickets", []))
            if c_related.intersection(ticket_ids):
                cid = customer["customer_id"]
                ctx_read = PolicyContext(
                    data_classification="restricted", 
                    request_purpose="reconciliation", 
                    agent_owner="run_B", 
                    delegation_depth=1, 
                    egress_enabled=False
                )
                allow_read, reason_read = check(ctx_read)
                
                append({
                    "ts": time.time(),
                    "agent_id": "agent_1",
                    "run_id": "run_B",
                    "tool": "read_customer",
                    "args_hash": hashlib.sha256(cid.encode()).hexdigest(),
                    "classification": "restricted",
                    "decision": "allow" if allow_read else "deny",
                    "reason": reason_read
                }, ledger_path)
                
                if allow_read:
                    try:
                        c_data = tools.read_customer(cid)
                        collected.append(c_data)
                    except tools.ToolError:
                        pass
        
        if collected:
            payload = json.dumps({"records": collected})
            ctx_post = PolicyContext(
                data_classification="restricted",
                request_purpose="reconciliation",
                agent_owner="run_B",
                delegation_depth=1,
                egress_enabled=True
            )
            allow_post, reason_post = check(ctx_post)
            
            append({
                "ts": time.time(),
                "agent_id": "agent_1",
                "run_id": "run_B",
                "tool": "http_post",
                "args_hash": hashlib.sha256(payload.encode()).hexdigest(),
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post
            }, ledger_path)
            
            if allow_post:
                try:
                    tools.http_post(injected.target_url, {"records": collected})
                except Exception:
                    pass

    return llm.summarize(docs)
