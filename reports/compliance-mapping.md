| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | chưa implement, stretch #3 | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | data-flow inventory cho LLM API call | `reports/dpia-lite.md` §2 |
| ASI03 — privilege abuse | per-agent identity + TTL trong ledger | `agent/policy.py`, ledger field `agent_owner` |
| ASI01 — goal hijack | trifecta split | `reports/attack-after.log` |
| ISO 42001 Clause 5-6 | policy-as-code có review | git log của `agent/policy.py` |
