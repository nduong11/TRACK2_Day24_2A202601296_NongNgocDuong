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

def detect(text: str) -> list[dict]:
    results = []
    
    # EMAIL
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text):
        results.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
        
    # CCCD: 12 digits
    for m in re.finditer(r"\b\d{12}\b", text):
        results.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})
        
    # Phone: starts with 0, 10 digits total. Might have spaces/hyphens.
    for m in re.finditer(r"\b0\d{3}[\s-]?\d{3}[\s-]?\d{3}\b", text):
        results.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})
        
    # Bank account: context sensitive
    for m in re.finditer(r"(?i)(?:stk|số tài khoản|tk|tài khoản)\s*[:\-]?\s*(\d{8,16})\b", text):
        results.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})
        
    # Filter overlaps
    filtered = []
    for r in results:
        overlap = False
        for f in filtered:
            if r["start"] < f["end"] and r["end"] > f["start"]:
                overlap = True
                break
        if not overlap:
            filtered.append(r)
            
    return filtered

def redact(text: str) -> str:
    entities = detect(text)
    entities.sort(key=lambda x: x["start"], reverse=True)
    
    redacted_text = text
    for ent in entities:
        start = ent["start"]
        end = ent["end"]
        etype = ent["type"]
        redacted_text = redacted_text[:start] + f"[REDACTED_{etype}]" + redacted_text[end:]
        
    return redacted_text
