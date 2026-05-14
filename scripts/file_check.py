"""Safe-Yes file check — path-based safety for Write/Edit/Read."""

import os
import re
from pathlib import Path

# Files with actual secrets — passthrough to native for read or write
_SECRET_FILES = [re.compile(pat, re.IGNORECASE) for pat in [
    r'(?:^|[/\\])\.env(?:\.\w+)?$',                      # Environment secrets
    r'(?:^|[/\\])\.env\.local$',                          # Local secrets
    r'(?:^|[/\\])\.git[/\\]config$',                      # Repo config (may contain credentials)
]]

# Config files — passthrough to native on write, allow read
_CONFIG_FILES = [re.compile(pat, re.IGNORECASE) for pat in [
    r'(?:^|[/\\])\.claude[/\\]settings\.json$',          # Hook/permission config
    r'(?:^|[/\\])\.claude[/\\]settings\.local\.json$',   # Hook/permission config
    r'(?:^|[/\\])\.claude[/\\]security[/\\]profile\.json$',  # Security policy
    r'(?:^|[/\\])\.git[/\\]hooks[/\\]',                   # Executable git hooks
]]

# System paths — passthrough to native
SYSTEM_PATHS = [
    '/etc/', '~/.ssh', '~/.aws',
    # Windows
    'C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\',
    'C:\\Windows\\System32\\drivers\\', 'C:\\Windows\\System32\\config\\',
    'C:\\Program Files\\', 'C:\\Program Files (x86)\\',
    'C:\\ProgramData\\',
    '/Windows/System32/', '/Windows/SysWOW64/',  # MSYS2 style
]

CREDENTIAL_EXTS = {'.pem', '.key', 'credentials', 'id_rsa', '.secrets'}

_RE_MSYS_DRIVE = re.compile(r'^/([a-zA-Z])(?:/|$)(.*)')


def _norm(p):
    """Normalize path separators and MSYS2 drives for reliable matching."""
    s = str(p).replace('\\', '/')
    m = _RE_MSYS_DRIVE.match(s)
    if m and os.name == 'nt':
        s = f"{m.group(1).upper()}:/{m.group(2)}"
    return s


def _in_project(file_path: str, project_root: str) -> bool:
    """Check if file_path is within project_root."""
    try:
        fp = Path(_norm(file_path))
        pr = Path(_norm(project_root)).resolve()
        if not fp.is_absolute():
            fp = pr / fp
        resolved = fp.resolve(strict=False)
        resolved.relative_to(pr)
        return True
    except (ValueError, OSError):
        return False


def check_file_safety(file_path: str, tool_name: str,
                     project_root: str = None) -> tuple:
    """Check file safety. Returns (decision, reason) — decision: yes/no."""
    sp = str(file_path)
    sp_norm = _norm(sp)

    # Check system paths (normalize both sides so \\ and / both match)
    for sys_path in SYSTEM_PATHS:
        sys_norm = _norm(sys_path)
        if sp_norm.startswith(sys_norm) or sp_norm.lower().startswith(sys_norm.lower()):
            verb = {"Write": "Writing to", "Edit": "Editing", "Read": "Reading"}.get(
                tool_name, "Accessing"
            )
            return ("no", f"{verb} system/sensitive path: {sp}")

    # Secret files — passthrough to native (read or write)
    for pat in _SECRET_FILES:
        if pat.search(sp):
            verb = {"Write": "Writing to", "Edit": "Editing", "Read": "Reading"}.get(
                tool_name, "Accessing"
            )
            return ("no", f"{verb} secret file: {sp}")

    # Config files — passthrough on write/edit, allow read
    if tool_name in ("Write", "Edit"):
        for pat in _CONFIG_FILES:
            if pat.search(sp):
                verb = {"Write": "Writing to", "Edit": "Editing"}.get(
                    tool_name, "Accessing"
                )
                return ("no", f"{verb} sensitive config: {sp}")

    # Check credential-like files for Write
    if tool_name == "Write":
        lower = sp.lower()
        for ext in CREDENTIAL_EXTS:
            if lower.endswith(ext.lower()):
                return ("no", f"Writing to credential-like file: {sp}")

    # Check project scope for Write/Edit (outside project → passthrough)
    if tool_name in ("Write", "Edit") and project_root:
        if not _in_project(sp, project_root):
            return ("no", f"{tool_name} outside project scope: {sp}")

    return ("yes", f"{tool_name} within project scope")
