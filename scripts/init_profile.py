#!/usr/bin/env python3
"""
Safe-Yes — Project Setup (v2).

Modes:
  --detect          Print detected settings as JSON (no writes)
  --apply <json>    Apply settings from JSON passed via stdin or env SAFE_YES_INIT

Auto-detects project root and type.
User choices (security_level, enabled, custom_prompt) are passed in via --apply.

Hooks are now defined in the plugin's hooks/hooks.json and loaded automatically.
setup only writes profile.json — no settings.local.json manipulation.
"""

import json
import os
import sys
from pathlib import Path


def detect_project_root(start_path: str = ".") -> str:
    markers = [
        ".git", "package.json", "pyproject.toml", "Cargo.toml",
        "go.mod", "pom.xml", "build.gradle", "Makefile", "CMakeLists.txt",
        ".claude", "setup.py", "setup.cfg", "composer.json",
    ]
    current = Path(start_path).resolve()
    while True:
        for marker in markers:
            if (current / marker).exists():
                return str(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return str(Path(start_path).resolve())


def detect_project_type(project_root: str) -> list:
    root = Path(project_root)
    types = []
    if (root / "pyproject.toml").exists() or (root / "setup.py").exists() or (root / "requirements.txt").exists():
        types.append("python")
    if (root / "package.json").exists():
        types.append("node")
    if (root / "go.mod").exists():
        types.append("go")
    if (root / "Cargo.toml").exists():
        types.append("rust")
    if (root / "pom.xml").exists() or (root / "build.gradle").exists():
        types.append("java")
    if not types:
        types.append("generic")
    return types


def generate_profile(project_root: str, project_types: list,
                     security_level: str = "normal",
                     custom_prompt: str = "",
                     enabled: bool = True) -> dict:
    return {
        "version": 2,
        "enabled": enabled,
        "security_level": security_level,
        "project_root": project_root,
        "project_types": project_types,
        "created_by": "safe-yes/setup",
        "llm": {
            "enabled": True,
            "custom_prompt": custom_prompt,
        },
        "memory": {
            "enabled": True,
            "max_entries": 5000,
            "ttl_days": 30,
            "similarity_threshold": 0.8,
        },
        "audit": {
            "central_log": False,
            "central_log_path": "",
        },
        "custom_rules": [],
        "network_allowed_domains": [],
    }


def cmd_detect(target_dir=None):
    """Print detected settings as JSON. target_dir overrides start path."""
    start = target_dir or "."
    project_root = detect_project_root(start)
    project_types = detect_project_type(project_root)

    result = {
        "project_root": project_root,
        "project_types": project_types,
    }
    print(json.dumps(result, indent=2))


def cmd_apply():
    """Apply settings: write profile.json (hooks are in plugin's hooks/hooks.json)."""
    raw = os.environ.get("SAFE_YES_INIT", "")
    if not raw:
        raw = sys.stdin.read()

    try:
        config = json.loads(raw)
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON input", file=sys.stderr)
        sys.exit(1)

    project_root = config.get("project_root") or detect_project_root()
    project_types = config.get("project_types") or detect_project_type(project_root)
    security_level = config.get("security_level", "normal")
    custom_prompt = config.get("custom_prompt", "")
    enabled = config.get("enabled", True)

    security_dir = Path(project_root) / ".claude" / "security"
    security_dir.mkdir(parents=True, exist_ok=True)
    profile_path = security_dir / "profile.json"

    if profile_path.exists():
        # Merge with existing — preserve user customizations
        try:
            existing = json.loads(profile_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}
        new_profile = generate_profile(project_root, project_types, security_level, custom_prompt, enabled)
        # Don't overwrite custom_rules or llm settings user may have added
        if "custom_rules" in existing and existing["custom_rules"]:
            new_profile["custom_rules"] = existing["custom_rules"]
        if "llm" in existing and existing.get("llm", {}).get("api_key"):
            new_profile["llm"]["api_key"] = existing["llm"]["api_key"]
        if "llm" in existing and existing.get("llm", {}).get("model"):
            new_profile["llm"]["model"] = existing["llm"]["model"]
        profile = new_profile
    else:
        profile = generate_profile(project_root, project_types, security_level, custom_prompt, enabled)

    profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "project_root": project_root,
        "project_types": project_types,
        "security_level": security_level,
        "enabled": enabled,
        "profile": str(profile_path),
    }, indent=2))


if __name__ == "__main__":
    target_dir = None
    if len(sys.argv) > 2 and sys.argv[2] == "--dir":
        target_dir = sys.argv[3] if len(sys.argv) > 3 else None

    if len(sys.argv) > 1 and sys.argv[1] == "--detect":
        cmd_detect(target_dir)
    elif len(sys.argv) > 1 and sys.argv[1] == "--apply":
        cmd_apply()
    else:
        print("Usage: init_profile.py --detect [--dir <path>] | --apply", file=sys.stderr)
        sys.exit(1)
