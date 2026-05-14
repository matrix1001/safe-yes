---
description: Show safe-yes statistics and status
allowed-tools: Bash
---

# safe-yes Status

```bash
python ${CLAUDE_PLUGIN_ROOT}/scripts/status.py
```

## Present to User

Show the key numbers:

```
safe-yes v2.1.1

Enabled: {on/off} | Profile: {security_level} | LLM: {on/off} | Memory: {on/off}

Decisions {total}: {allowed} allowed ({percent}%) · {passthrough} passthrough
LLM calls: {llm_calls} · Memory: {memory_count} entries, {memory_hits} hits
```

Skip the by_tool breakdown unless there's an anomaly worth noting.

Print HINT lines verbatim. If no hints, skip.

Edge cases:
- Disabled → "Guard is disabled. Run `/safe-yes:enable` or `/safe-yes:setup`."
- No profile → "No profile. Run `/safe-yes:setup`."

Keep it brief — one overall sentence is enough.
