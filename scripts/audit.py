"""Safe-Yes audit — structured JSONL logging."""

import json
from datetime import datetime
from pathlib import Path

# Cache known directories to avoid repeated mkdir calls
_known_dirs = set()


def _append_log(log_dir, filename, record):
    """Append a single JSONL record. Silently ignores write errors."""
    try:
        if log_dir not in _known_dirs:
            log_dir.mkdir(parents=True, exist_ok=True)
            _known_dirs.add(log_dir)
        log_path = log_dir / filename
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def log_decision(tool_name, tool_input, decision, reason,
                 cwd, duration_ms=0, profile=None, session_id="", layer=None):
    """Append a JSONL record to project-local and optionally central audit logs."""
    summary = _summarize(tool_name, tool_input)

    record = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "tool": tool_name,
        "summary": summary,
        "decision": decision,
        "reason": reason,
        "duration_ms": round(duration_ms, 1),
    }
    if session_id:
        record["session_id"] = session_id
    if layer:
        record["layer"] = layer

    # Project-local log (always)
    _append_log(Path(cwd).resolve() / ".claude" / "security", "decisions.jsonl", record)

    # Central log (optional)
    if profile:
        audit_cfg = profile.get("audit", {})
        if audit_cfg.get("central_log", False):
            central_path = audit_cfg.get("central_log_path", "")
            if not central_path:
                central_path = str(Path.home() / ".claude" / "security")
            else:
                central_path = str(Path(central_path).expanduser().resolve())
            _append_log(Path(central_path), "decisions.jsonl", record)


def _summarize(tool_name, tool_input):
    if not isinstance(tool_input, dict):
        return f"{tool_name}: ?"
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        return cmd[:80] + ("..." if len(cmd) > 80 else "")
    elif tool_name in ("Write", "Edit", "Read"):
        return f"{tool_name} -> {tool_input.get('file_path', '?')}"
    elif tool_name == "WebSearch":
        q = tool_input.get("query", "")
        return f"WebSearch: {q[:60]}"
    elif tool_name == "WebFetch":
        return f"WebFetch: {tool_input.get('url', '?')[:60]}"
    elif tool_name == "Glob":
        return f"Glob: {tool_input.get('pattern', '?')[:60]}"
    elif tool_name == "Grep":
        pat = tool_input.get('pattern', '?')
        path = tool_input.get('path', '')
        return f"Grep: {pat[:40]} in {str(path)[:30]}"
    elif tool_name == "TodoWrite":
        return "TodoWrite"
    elif tool_name == "Task":
        subj = tool_input.get('subject', tool_input.get('description', '?'))
        return f"Task: {str(subj)[:60]}"
    elif tool_name.startswith("mcp__"):
        return f"MCP: {tool_name}"
    return f"{tool_name}: {str(tool_input)[:60]}"
