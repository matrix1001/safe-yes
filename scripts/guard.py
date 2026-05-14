#!/usr/bin/env python3
"""Safe-Yes guard — yes-only accelerator. Safe ops → allow, rest → passthrough to native."""

import json
import os
import re
import sys
import time
from pathlib import Path

# Add script directory to path for module imports
_script_dir = str(Path(__file__).resolve().parent)
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from config import load_profile, is_llm_configured
from rules import match_rules
from memory import check_memory, write_memory, add_pending, consume_pending
from llm import llm_review
from file_check import check_file_safety
from audit import log_decision


def _decision(decision, reason):
    """Build hook result dict for allow decisions."""
    return {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
    }


def analyze_bash(command, cwd, profile):
    """
    Analyze Bash command through four-tier pipeline:
    Code Rules → Memory → LLM → Passthrough.
    Returns (permissionDecision, reason, layer).
    """
    level = profile.get("security_level", "normal")

    # P1: Code rules
    rule_dec, rule_reason = match_rules(command, cwd, profile)

    if rule_dec == "yes":
        return ("allow", rule_reason, "rules")

    if rule_dec == "no":
        return ("passthrough", rule_reason, "rules")

    # P2: Decision Memory (skip if danger words present)
    mem_result = check_memory(command, cwd, profile)
    if mem_result:
        return (mem_result[0], mem_result[1], "memory")

    # P3: LLM review
    if not is_llm_configured(profile):
        if level == "tolerant":
            return ("allow", f"LLM unavailable, tolerant mode: {rule_reason}", "passthrough")
        return ("passthrough", f"LLM unavailable, normal mode: {rule_reason}", "passthrough")

    llm_dec, llm_reason = llm_review(command, cwd, profile)

    if llm_dec == "yes":
        write_memory(command, "allow", cwd, source="llm", profile=profile)
        return ("allow", llm_reason, "llm")

    if llm_dec == "no":
        return ("passthrough", llm_reason, "llm")

    # llm_dec == "uncertain"
    if level == "tolerant":
        return ("allow", f"Tolerant mode: {llm_reason}", "passthrough")
    return ("passthrough", f"Uncertain — {llm_reason}", "passthrough")


_RE_TOOL_NAME = re.compile(r'"tool_name"\s*:\s*"(\w+)"')


def _extract_json_string(raw, key):
    """Extract a JSON string value for key from raw text, handling \\-escapes correctly."""
    search_key = f'"{key}"'
    pos = raw.find(search_key)
    if pos == -1:
        return None

    rest = raw[pos + len(search_key):]
    colon_idx = rest.find(':')
    if colon_idx == -1:
        return None

    rest = rest[colon_idx + 1:]
    quote_idx = rest.find('"')
    if quote_idx == -1:
        return None

    result = []
    i = quote_idx + 1
    while i < len(rest):
        ch = rest[i]
        if ch == '\\':
            result.append(ch)
            if i + 1 < len(rest):
                result.append(rest[i + 1])
                i += 1
        elif ch == '"':
            break
        else:
            result.append(ch)
        i += 1

    return ''.join(result)


def _salvage_input(raw):
    """Try to extract key fields from malformed JSON so we can still make a decision.

    Claude Code sometimes passes very long commands whose JSON serialization
    can be corrupted. Uses manual string extraction so escape sequences
    (e.g. \\\\\" inside quoted content) are handled correctly.
    """
    m = _RE_TOOL_NAME.search(raw)
    if not m:
        return None, {}, None
    tool_name = m.group(1)

    cwd = _extract_json_string(raw, "cwd") or os.getcwd()

    tool_input = {}
    if tool_name == "Bash":
        cmd = _extract_json_string(raw, "command")
        if cmd:
            tool_input["command"] = cmd
    elif tool_name in ("Write", "Edit", "Read"):
        fp = _extract_json_string(raw, "file_path")
        if fp:
            tool_input["file_path"] = fp

    return tool_name, tool_input, cwd


def main():
    # Pre-init defaults so except handler always has safe values
    tool_name = "?"
    tool_input = {}
    cwd = os.getcwd()
    profile = None
    duration_ms = 0

    try:
        # Force UTF-8 on Windows (system locale defaults to GBK)
        try:
            sys.stdin.reconfigure(encoding='utf-8')
        except (AttributeError, OSError):
            pass
        raw = sys.stdin.read()
        if not raw.strip():
            print(json.dumps({"continue": True, "hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "allow"}}))
            return

        # Fast reject: if it cannot possibly be a hook input (no tool_name key),
        # let it through silently — hook system init / test events send arbitrary
        # data that should not trigger a permission prompt.
        if '"tool_name"' not in raw:
            print(json.dumps({"continue": True, "hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "allow"}}))
            return

        try:
            hook_input = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            # JSON corrupted (e.g. very long command) — salvage key fields via regex
            salvaged_name, salvaged_input, salvaged_cwd = _salvage_input(raw)
            if salvaged_name:
                hook_input = {
                    "hook_event_name": "PreToolUse",
                    "tool_name": salvaged_name,
                    "tool_input": salvaged_input,
                    "cwd": salvaged_cwd,
                }
            else:
                raise  # Can't salvage — outer except will passthrough

        event = hook_input.get("hook_event_name", "PreToolUse")
        tool_name = hook_input.get("tool_name", "")
        tool_input = hook_input.get("tool_input", {})
        cwd = hook_input.get("cwd", os.getcwd())
        session_id = hook_input.get("session_id", "")

        t0 = time.time()
        profile = load_profile(cwd)

        # Disabled via profile toggle — pass everything through
        if profile and not profile.get("enabled", True):
            print(json.dumps({"continue": True}))
            return

        if event == "PostToolUse":
            # Track user-approved commands for memory learning
            # Only write to memory if the command was pending (user manually approved it)
            cmd = tool_input.get("command", "")
            if cmd and tool_name == "Bash":
                if consume_pending(cmd, cwd):
                    write_memory(cmd, "allow", cwd, source="user", profile=profile)
            print(json.dumps({"continue": True, "hookSpecificOutput": {
                "hookEventName": "PostToolUse", "permissionDecision": "allow"}}))
            return

        reason = ""
        decision = "passthrough"
        layer = "passthrough"

        if tool_name == "Bash":
            command = tool_input.get("command", "")
            if command:
                decision, reason, layer = analyze_bash(command, cwd, profile)
                if decision == "passthrough":
                    add_pending(command, cwd)
            else:
                reason = "Empty command"

        elif tool_name in ("Write", "Edit", "Read"):
            file_path = tool_input.get("file_path", "")
            project_root = profile.get("project_root", cwd) if profile else cwd
            dec, reason = check_file_safety(file_path, tool_name, project_root=project_root)
            decision = "allow" if dec == "yes" else "passthrough"
            layer = "file_check"

        elif tool_name in ("WebSearch", "WebFetch"):
            decision = "allow"
            reason = "Read-only web operation"
            layer = "rules"

        elif tool_name in ("Glob", "Grep"):
            decision = "allow"
            reason = "Read-only file search"
            layer = "rules"

        elif tool_name.startswith("mcp__"):
            decision = "allow"
            reason = "MCP tool — safe"
            layer = "rules"

        else:
            decision = "allow"
            reason = "Read-only / safe operation"
            layer = "rules"

        duration_ms = (time.time() - t0) * 1000

        if decision == "allow":
            result = _decision("allow", reason)
        elif decision == "passthrough":
            log_decision(tool_name, tool_input, "passthrough", reason,
                         cwd, duration_ms, profile, session_id, layer=layer)
            print(json.dumps({"continue": True}))
            return

    except Exception as e:
        log_decision(tool_name, tool_input, "passthrough",
                     f"Guard analysis failed: {e}",
                     cwd, duration_ms, profile, session_id, layer="error")
        print(json.dumps({"continue": True}))
        return

    # Audit log
    log_decision(tool_name, tool_input, "allow",
                 result["hookSpecificOutput"]["permissionDecisionReason"],
                 cwd, duration_ms, profile, session_id, layer=layer)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
