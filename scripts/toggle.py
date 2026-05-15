#!/usr/bin/env python3
"""Safe-Yes — enable/disable toggle for profile.json."""

import json
import sys
from pathlib import Path

_script_dir = str(Path(__file__).resolve().parent)
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from config import DEFAULT_PROFILE


def toggle(enable: bool, cwd: Path):
    profile_path = cwd.resolve() / ".claude" / "security" / "profile.json"

    if profile_path.exists():
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            print("ERROR: profile.json is corrupt", file=sys.stderr)
            sys.exit(1)
    else:
        # No profile yet — create from defaults
        profile = dict(DEFAULT_PROFILE)
        profile["project_root"] = str(cwd.resolve())
        profile["created_by"] = "safe-yes/toggle"

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
