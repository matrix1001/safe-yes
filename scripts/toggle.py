#!/usr/bin/env python3
"""Safe-Yes — enable/disable toggle for profile.json."""

import json
import sys
from pathlib import Path

def toggle(enable: bool, cwd: Path):
    profile_path = cwd.resolve() / ".claude" / "security" / "profile.json"

    if profile_path.exists():
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            print("ERROR: profile.json is corrupt", file=sys.stderr)
            sys.exit(1)
    else:
        # No profile yet — create minimal one (load_profile() fills DEFAULT_PROFILE at runtime)
        profile = {
            "version": 2,
            "enabled": enable,
            "project_root": str(cwd.resolve()),
            "project_types": ["generic"],
            "created_by": "safe-yes/toggle",
        }

    profile["enabled"] = enable
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")

    state = "enabled" if enable else "disabled"
    print(json.dumps({
        "status": "ok",
        "enabled": enable,
        "message": f"safe-yes is now {state}",
        "profile": str(profile_path),
    }, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("--enable", "--disable"):
        print("Usage: toggle.py --enable | --disable", file=sys.stderr)
        sys.exit(1)

    enable = sys.argv[1] == "--enable"
    toggle(enable, Path.cwd())
