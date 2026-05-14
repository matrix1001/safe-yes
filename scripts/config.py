"""Safe-Yes config — load profile.json with v2 migration, deep merge, and caching.

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

# Module-level cache indexed by (path, mtime) tuples of all loaded profile files.
# Each guard.py invocation is a fresh process so there is normally only one call
# to load_profile() per run; the cache pays off in test suites and when guard.py
# is imported as a library for batch analysis.
_cache = {}


def _migrate_v1(profile: dict) -> dict:
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
            "base_url": llm.get("base_url", "https://api.openai.com/v1"),
            "model": llm.get("model", "gpt-4o-mini"),
            "custom_prompt": llm.get("custom_prompt", ""),
        },
        "custom_rules": custom_rules,
        "network_allowed_domains": profile.get("network_allowed_domains", []),
    }


def load_profile(cwd: str) -> dict:
    """Load merged profile: user-level as base, project-level overrides.

    Search order:
      1. User-level ~/.claude/security/profile.json — base defaults
      2. Project-level .claude/security/profile.json — overrides on top

    Deep-merge means LLM config from user-level flows into all projects.
    Cached by (project_path, user_path) + mtime to avoid repeated disk I/O.
    """
    global _cache
    cwd_path = Path(cwd).resolve()

    user_path = Path.home() / ".claude" / "security" / "profile.json"
    project_path = cwd_path / ".claude" / "security" / "profile.json"

    # Determine effective paths
    paths = []
    if user_path.exists():
        paths.append(user_path)
    if project_path.exists() and project_path != user_path:
        paths.append(project_path)

    # Build cache key from all paths + their mtimes
    cache_key = None
    if paths:
        try:
            key_parts = []
            for p in paths:
                key_parts.append((str(p), p.stat().st_mtime))
            cache_key = tuple(key_parts)
        except OSError:
            pass

    if cache_key and _cache.get("key") == cache_key:
        return _cache["profile"]

    # Load and merge
    profile = _load_merged(paths, cwd_path)

    if cache_key:
        _cache["profile"] = profile
        _cache["key"] = cache_key

    return profile


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Nested dicts are merged; everything else is replaced."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_merged(paths, cwd_path: Path) -> dict:
    """Load base (user) and overlay (project), deep-merging in order."""
    profile = dict(DEFAULT_PROFILE)

    for p in paths:
        try:
            overlay = json.loads(p.read_text(encoding='utf-8'))
            overlay = _migrate_v1(overlay)
            profile = _deep_merge(profile, overlay)
        except (json.JSONDecodeError, OSError):
            pass

    if not profile.get("project_root"):
        profile["project_root"] = str(cwd_path)

    return profile


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
