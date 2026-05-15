"""Safe-Yes config — load project-level profile.json with v2 migration and caching.

LLM credentials auto-resolve from Claude Code's ANTHROPIC_AUTH_TOKEN
and ANTHROPIC_BASE_URL env vars if not explicitly set in profile.
"""

import json
import os
from pathlib import Path

DEFAULT_PROFILE = {
    "version": 2,
    "enabled": False,
    "security_level": "normal",
    "project_types": ["generic"],
    "llm": {
        "enabled": True,
        "api_key": "",       # Falls back to ANTHROPIC_AUTH_TOKEN
        "base_url": "",      # Falls back to ANTHROPIC_BASE_URL
        "model": "",         # Falls back to ANTHROPIC_DEFAULT_HAIKU_MODEL
        "custom_prompt": "",
    },
    "custom_rules": [],
    "network_allowed_domains": [],
    "audit": {
        "central_log": False,
        "central_log_path": "",
    },
    "memory": {
        "enabled": True,
        "max_entries": 5000,
        "ttl_days": 30,
        "similarity_threshold": 0.8,
    },
}

# Module-level cache indexed by (cwd_path, profile_path, mtime) tuple.
# Each guard.py invocation is a fresh process so there is normally only one call
# to load_profile() per run; the cache pays off in test suites and when guard.py
# is imported as a library for batch analysis.
_cache = {}


def migrate_v1(profile: dict) -> dict:
    """Migrate v1 profile to v2 format."""
    if profile.get("version", 1) >= 2:
        return profile

    custom_rules = []
    for pat in profile.get("custom_allowed_commands", []):
        custom_rules.append({"priority": 205, "pattern": pat, "decision": "yes",
                             "reason": f"Custom allowed: {pat}"})
    for pat in profile.get("custom_blocked_commands", []):
        custom_rules.append({"priority": 5, "pattern": pat, "decision": "no",
                             "reason": f"Custom blocked: {pat}"})
    for pat in profile.get("custom_warn_commands", []):
        custom_rules.append({"priority": 95, "pattern": pat, "decision": "uncertain",
                             "reason": f"Custom warn: {pat}"})

    llm = profile.get("llm", {})
    if "custom_prompt" not in llm:
        llm["custom_prompt"] = ""

    return {
        "version": 2,
        "security_level": profile.get("security_level", "normal"),
        "project_root": profile.get("project_root", ""),
        "project_types": profile.get("project_types", ["generic"]),
        "llm": {
            "enabled": llm.get("enabled", False),
            "api_key": llm.get("api_key", ""),
            "base_url": llm.get("base_url", ""),
            "model": llm.get("model", ""),
            "custom_prompt": llm.get("custom_prompt", ""),
        },
        "custom_rules": custom_rules,
        "network_allowed_domains": profile.get("network_allowed_domains", []),
    }


def load_profile(cwd: str) -> dict:
    """Load project-level profile, merged with hardcoded defaults.

    Only reads .claude/security/profile.json from the project root.
    Global ~/.claude/security/profile.json is deliberately ignored —
    safe-yes is a per-project opt-in tool.

    Cached by (cwd_path, profile_path, mtime) to avoid repeated disk I/O.
    """
    global _cache
    cwd_path = Path(cwd).resolve()
    profile_path = cwd_path / ".claude" / "security" / "profile.json"

    # Build cache key from cwd + profile path + mtime
    cache_key = None
    if profile_path.exists():
        try:
            cache_key = (str(cwd_path), str(profile_path), profile_path.stat().st_mtime)
        except OSError:
            pass

    if cache_key and _cache.get("key") == cache_key:
        return _cache["profile"]

    # Load: DEFAULT_PROFILE as base, project-level on top
    profile = dict(DEFAULT_PROFILE)
    if profile_path.exists():
        try:
            overlay = json.loads(profile_path.read_text(encoding='utf-8'))
            overlay = migrate_v1(overlay)
            profile = deep_merge(profile, overlay)
        except (json.JSONDecodeError, OSError):
            pass

    if not profile.get("project_root"):
        profile["project_root"] = str(cwd_path)

    if cache_key:
        _cache["profile"] = profile
        _cache["key"] = cache_key

    return profile


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Nested dicts are merged; everything else is replaced."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def is_llm_configured(profile: dict) -> bool:
    """Check if LLM is usable — enabled and has credentials (profile or env)."""
    llm = profile.get("llm", {})
    if not llm.get("enabled", False):
        return False

    api_key = llm.get("api_key", "").strip()
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()

    model = llm.get("model", "").strip()
    if not model:
        model = os.environ.get("ANTHROPIC_DEFAULT_HAIKU_MODEL", "").strip()
    if not model:
        model = "claude-haiku-4-5-20251001"

    return bool(api_key and model)
