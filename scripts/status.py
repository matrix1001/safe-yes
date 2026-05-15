#!/usr/bin/env python3
"""Safe-Yes status check — hook state, profile, decision stats, memory stats."""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

_script_dir = str(Path(__file__).resolve().parent)
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from config import load_profile


def status(tail=None):
    cwd = Path.cwd().resolve()
    out = {}

    # ── Hook status ──
    # Hooks live in the plugin's hooks/hooks.json (loaded automatically).
    plugin_hooks = Path(__file__).resolve().parent.parent / "hooks" / "hooks.json"
    out["hook_active"] = plugin_hooks.exists()

    # ── Profile (via load_profile — same merge logic as guard.py) ──
    profile_path = cwd / ".claude" / "security" / "profile.json"
    out["profile_exists"] = profile_path.exists()
    p = load_profile(str(cwd))
    out["enabled"] = p.get("enabled", False)
    out["security_level"] = p.get("security_level", "normal")
    out["llm_enabled"] = p.get("llm", {}).get("enabled", False)
    out["memory_enabled"] = p.get("memory", {}).get("enabled", True)
    out["custom_rules"] = len(p.get("custom_rules", []))
    out["project_types"] = p.get("project_types", ["generic"])

    # ── Decision stats ──
    log_path = cwd / ".claude" / "security" / "decisions.jsonl"
    total = 0
    allowed = 0
    passthrough = 0
    llm_calls = 0
    memory_hits = 0
    by_tool = {}
    by_layer = {}
    last_ts = ""
    all_decisions = []

    if log_path.exists():
        try:
            with open(log_path, encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        total += 1
                        dec = d.get("decision", "?")
                        if dec == "allow":
                            allowed += 1
                        elif dec == "passthrough":
                            passthrough += 1
                        reason = d.get("reason", "")
                        if "[LLM]" in reason:
                            llm_calls += 1
                        if "[Memory]" in reason:
                            memory_hits += 1
                        tool = d.get("tool", "?")
                        by_tool[tool] = by_tool.get(tool, 0) + 1
                        last_ts = d.get("ts", last_ts)

                        layer = d.get("layer", "unknown")
                        if layer not in by_layer:
                            by_layer[layer] = {"allowed": 0, "passthrough": 0}
                        if dec == "allow":
                            by_layer[layer]["allowed"] += 1
                        elif dec == "passthrough":
                            by_layer[layer]["passthrough"] += 1

                        all_decisions.append(d)
                    except (json.JSONDecodeError, KeyError):
                        pass
        except OSError:
            pass

    out["total"] = total
    out["allowed"] = allowed
    out["passthrough"] = passthrough
    out["llm_calls"] = llm_calls
    out["memory_hits"] = memory_hits
    out["last_ts"] = last_ts
    out["by_tool"] = by_tool
    out["by_layer"] = by_layer

    # ── Memory stats ──
    mem_path = cwd / ".claude" / "security" / "memory.jsonl"
    memory_count = 0
    mem_latest_cmd = ""
    mem_latest_date = ""
    all_memory = []

    if mem_path.exists():
        try:
            with open(mem_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    memory_count += 1
                    try:
                        rec = json.loads(line)
                        mem_latest_date = rec.get("last_hit", mem_latest_date)
                        if not mem_latest_cmd:
                            mem_latest_cmd = rec.get("cmd", "")[:60]
                        all_memory.append(rec)
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass

    out["memory_count"] = memory_count
    out["memory_latest"] = mem_latest_date

    # ── --tail mode: pretty-print recent entries ──
    if tail:
        print("=" * 70)
        print("  Recent Decisions (last %d)" % tail)
        print("=" * 70)
        for d in all_decisions[-tail:]:
            print(json.dumps(d, indent=2, ensure_ascii=False))
            print("-" * 40)

        print("\n" + "=" * 70)
        print("  Recent Memory (last %d)" % tail)
        print("=" * 70)
        for m in all_memory[-tail:]:
            print(json.dumps(m, indent=2, ensure_ascii=False))
            print("-" * 40)
        return

    # ── Normal mode: JSON stats output ──
    print(json.dumps(out, indent=2, ensure_ascii=False))

    # ── Summary hints ──
    hints = []
    if total > 0:
        auto_rate = allowed * 100 // max(total, 1)
        hints.append("%d%% auto-allowed (%d/%d)." % (auto_rate, allowed, total))
        if passthrough > 0:
            hints.append("%d passthrough → delegated to native permissions." % passthrough)
    if memory_hits > 0:
        hints.append("Memory saved %d LLM call(s)." % memory_hits)
    if llm_calls > 10:
        hints.append("%d LLM calls — check costs if using paid API." % llm_calls)
    if not out.get("hook_active"):
        hints.append("Hook not registered — run /safe-yes:setup first.")
    if not out.get("profile_exists"):
        hints.append("No profile — run /safe-yes:setup to create one.")
    if out.get("profile_exists") and not out.get("enabled", True):
        hints.append("Guard is disabled — run /safe-yes:enable to activate.")

    # ── Layer breakdown ──
    if total > 0 and by_layer:
        parts = []
        for layer_name in ("rules", "memory", "llm", "file_check", "passthrough", "error"):
            if layer_name in by_layer:
                stats = by_layer[layer_name]
                layer_total = stats["allowed"] + stats["passthrough"]
                pct = layer_total * 100 // total
                if pct > 0:
                    parts.append("%d%% %s" % (pct, layer_name))
        if parts:
            hints.append("Layer breakdown: %s." % ", ".join(parts))

    for h in hints:
        print("HINT: %s" % h)


if __name__ == "__main__":
    tail = None
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "--tail":
        try:
            tail = int(args[1])
        except ValueError:
            print("ERROR: --tail requires a number", file=sys.stderr)
            sys.exit(1)
    elif args:
        print("Usage: status.py [--tail N]", file=sys.stderr)
        sys.exit(1)
    status(tail)
