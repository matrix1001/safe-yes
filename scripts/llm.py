"""Safe-Yes LLM — review uncertain commands via Anthropic Messages API.

API credentials are auto-resolved from Claude Code's environment variables
(ANTHROPIC_AUTH_TOKEN, ANTHROPIC_BASE_URL) — no separate key needed.
"""

import json
import os
import re
import socket

# Tight DNS/connect timeout so LLM review never blocks the hook pipeline.
# Set once at import time; the guard process exits immediately after printing
# its single decision, so the global side-effect is harmless.
socket.setdefaulttimeout(8)

# Lone surrogates (U+D800–U+DFFF) are invalid Unicode — they arise from
# malformed JSON, corrupted stdin, or escaped surrogate pairs in profile data.
# json.dumps(ensure_ascii=True) will faithfully encode them as \uDXXX hex
# escapes, but many JSON parsers (including DeepSeek's) reject lone surrogates
# as invalid JSON.  Scrub them before they reach the request body.
_SURROGATE_RE = re.compile('[\ud800-\udfff]')


def _scrub(s):
    """Replace lone surrogate code points with U+FFFD (replacement character)."""
    if not isinstance(s, str):
        return s
    return _SURROGATE_RE.sub('�', s)

LLM_SYSTEM_PROMPT = """\
You are a command security auditor. Analyze shell commands for safety only.
Never judge correctness or code quality — only safety.

Return ONLY this JSON (no markdown, no extra text):
{"decision": "yes|no|uncertain", "reason": "one sentence safety assessment"}

Decision rules:

"yes" — clearly safe:
  - Read-only: ls, cat, head, tail, find, grep, diff, stat, wc, du, df, which, type, pwd, whoami, env, date, hostname
  - Safe mutations in project: mkdir, touch, cp, mv, rm (single files), npm/pip/cargo install, git add/commit/checkout/pull/fetch/stash, make, pytest, cargo build/test
  - Package queries: pip list, npm list, conda list
  - URL fetches to trusted hosts: curl/wget GET to github.com, pypi.org, npmjs.org, localhost
  - Python/Node scripts within project directory
  - Process listing: ps, tasklist, pgrep, pidof

"no" — clearly dangerous (system destruction or credential theft):
  - Raw disk writes: dd to /dev/sd*, mkfs, fdisk
  - System root deletion: rm -rf /, rm -rf /etc, rm -rf /usr, del C:\\Windows
  - Credential exfiltration: cat ~/.ssh/id_rsa, cat ~/.aws/credentials, base64 encode then pipe to remote
  - Fork bombs, eval with remote input, curl | sh from untrusted URLs

"uncertain" — ambiguous (use for everything else):
  - Process management: kill, killall, pkill, taskkill, supervisorctl stop/restart
  - Service control: systemctl, service, docker stop/rm/restart, docker compose down/restart
  - Permission changes: chmod, chown, icacls, attrib
  - Git destructive: reset --hard, clean -f, push --force, branch -D
  - Recursive deletion: rm -rf (project paths), del /s
  - Network listeners: nc -l, python -m http.server, npx serve
  - Any command with sudo, or operating outside the project working directory
  - Any command whose safety depends entirely on context you cannot see (target files, running processes, environment state)
"""


def _build_prompt(command, cwd, profile):
    """Build user prompt for LLM including project context.

    Commands longer than 2000 chars are truncated (with marker) to keep
    the request body small and avoid 400 errors from large payloads.
    """
    project_types = profile.get("project_types", ["unknown"])
    project_root = profile.get("project_root", cwd)
    level = profile.get("security_level", "normal")

    cmd_display = command
    if len(command) > 2000:
        cmd_display = command[:1900] + "\n... [truncated, total " + str(len(command)) + " chars]"

    return _scrub(
        f"Command: {cmd_display}\n"
        f"Working directory: {cwd}\n"
        f"Project root: {project_root}\n"
        f"Project type: {', '.join(project_types)}\n"
        f"Security level: {level}"
    )


def _parse_response(content):
    """Extract decision from LLM response. Returns (decision, reason)."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r'^```\w*\n?', '', text)
        text = re.sub(r'\n?```$', '', text)

    try:
        result = json.loads(text)
        decision = result.get("decision", "uncertain")
        reason = result.get("reason", "No reason given")
        if decision not in ("yes", "no", "uncertain"):
            decision = "uncertain"
        return (decision, reason)
    except json.JSONDecodeError:
        m = re.search(r'"decision"\s*:\s*"(yes|no|uncertain)"', text)
        if m:
            return (m.group(1), text[:200])
        lower = text.lower()
        yes_words = ("safe", "harmless", "benign", "read-only", "no risk", "not dangerous")
        no_words = ("danger", "risk", "destructive", "malicious", "data loss",
                    "privilege", "unsafe", "harmful", "exfiltration")
        if any(w in lower for w in yes_words):
            return ("yes", text[:200])
        if any(w in lower for w in no_words):
            return ("no", text[:200])
        return ("uncertain", text[:200])


def _resolve_credentials(profile):
    """Get api_key, base_url, model — falling back to Claude Code env vars."""
    llm_config = profile.get("llm", {})

    api_key = llm_config.get("api_key", "").strip()
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()

    base_url = llm_config.get("base_url", "").strip().rstrip('/')
    if not base_url:
        base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip().rstrip('/')
    if not base_url:
        base_url = "https://api.anthropic.com"

    model = llm_config.get("model", "").strip()
    if not model:
        model = os.environ.get("ANTHROPIC_DEFAULT_HAIKU_MODEL", "").strip()
    if not model:
        model = "claude-haiku-4-5-20251001"

    return api_key, base_url, model


def _call_api(command, cwd, profile):
    """Call LLM via Anthropic Messages API. Retries once on transient failure."""
    api_key, base_url, model = _resolve_credentials(profile)

    if not api_key or not model:
        return None

    user_prompt = _build_prompt(command, cwd, profile)

    system_prompt = _scrub(LLM_SYSTEM_PROMPT)
    custom = profile.get("llm", {}).get("custom_prompt", "").strip()
    if custom:
        system_prompt += _scrub(f"\n\nAdditional project-specific security concerns:\n{custom}")

    body = {
        "model": model,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
        "temperature": 0,
        "max_tokens": 256,
        "thinking": {"type": "disabled"},
    }

    import urllib.request
    import urllib.error

    last_error = ""
    for attempt in (1, 2):
        try:
            body_data = json.dumps(body).encode("utf-8")

            req = urllib.request.Request(
                f"{base_url}/messages",
                data=body_data,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            resp = urllib.request.urlopen(req, timeout=10)
            resp_body = json.loads(resp.read())
            text = ""
            for block in resp_body.get("content", []):
                if block.get("type") == "text":
                    text = block.get("text", "")
                    break
            if not text:
                last_error = "No text block in response"
                if attempt == 1:
                    import time
                    time.sleep(0.3)
                continue
            dec, reason = _parse_response(text)
            return (dec, f"[LLM] {reason}")
        except urllib.error.HTTPError as e:
            # Read the error response body for diagnostics
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                err_body = "(could not read error body)"
            last_error = f"HTTP {e.code}: {err_body}"
            if attempt == 1:
                import time
                time.sleep(0.5)
        except Exception as e:
            last_error = f"{type(e).__name__}: {e}"
            if attempt == 1:
                import time
                time.sleep(0.3)
    return None, last_error


def llm_review(command, cwd, profile):
    """
    Call LLM API for safety review.
    Returns (decision, reason) — decision: "yes", "no", "uncertain".
    Falls back based on security_level when LLM unavailable.
    """
    if not profile.get("llm", {}).get("enabled", False):
        return ("uncertain", "LLM review disabled")

    api_key, _base_url, _model = _resolve_credentials(profile)
    if not api_key:
        return ("uncertain", "No API key configured — set ANTHROPIC_AUTH_TOKEN or llm.api_key")

    result, error = _call_api(command, cwd, profile)
    if result is not None:
        return (result, error)

    return ("uncertain", f"LLM API call failed: {error}")
