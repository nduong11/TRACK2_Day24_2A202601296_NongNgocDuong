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

import json
import hashlib
from pathlib import Path

def _get_hash(entry_without_hash: dict) -> str:
    serialized = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def append(entry: dict, path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = "0" * 64
    
    if path.exists() and path.stat().st_size > 0:
        with path.open("r", encoding="utf-8") as f:
            last_line = None
            for line in f:
                if line.strip():
                    last_line = line
            if last_line:
                try:
                    last_entry = json.loads(last_line)
                    if "hash" in last_entry:
                        prev_hash = last_entry["hash"]
                except json.JSONDecodeError:
                    pass

    new_entry = dict(entry)
    new_entry["prev_hash"] = prev_hash
    if "hash" in new_entry:
        del new_entry["hash"]
        
    new_entry["hash"] = _get_hash(new_entry)
    
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(new_entry, ensure_ascii=False, sort_keys=True) + "\n")
        
    return new_entry

def verify(path: Path) -> bool:
    if not path.exists():
        return False
        
    prev_hash = "0" * 64
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False
                
            if not entry.get("reason"):
                return False
                
            if entry.get("prev_hash") != prev_hash:
                return False
                
            expected_hash = entry.get("hash")
            temp_entry = dict(entry)
            if "hash" in temp_entry:
                del temp_entry["hash"]
                
            if expected_hash != _get_hash(temp_entry):
                return False
                
            prev_hash = expected_hash
            
    return True
