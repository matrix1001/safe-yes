"""Safe-Yes validators — return ("yes", reason) or None to defer to LLM."""

import os
import re
from pathlib import Path

# Pre-compiled regex patterns (module load time)
_RE_MSYS_DRIVE = re.compile(r'^/([a-zA-Z])(?:/|$)(.*)')
_RE_PATH_CANDIDATE = re.compile(r'(?:^|\s)((?:\.{0,2}/|[a-zA-Z]:[\\/])?[^\s|;&]+)')
_RE_ABSOLUTE_PATH = re.compile(r'^(?:[a-zA-Z]:[\\/]|[a-zA-Z]:\\|/)')
_RE_FLAG_LIKE = re.compile(r'^[-/][a-zA-Z]')
_RE_RM_FLAG_RECURSIVE = re.compile(r'-[-\w]*r[-\w]*')
_RE_RM_FLAG_FORCE = re.compile(r'-[-\w]*f[-\w]*')
_RE_RM_ARGS = re.compile(r'\brm\b(.*)')
_RE_GIT_FORCE_FLAG = re.compile(r'-f')
_RE_PRIMARY_BRANCH = re.compile(r'\b(?:main|master)\b')
_RE_NETWORK_DATA = re.compile(
    r'-[Fd].*@|--data|--upload-file|-T\s+\S|--post|-X\s+(?:POST|PUT|DELETE|PATCH)'
)
_RE_INLINE_CODE = re.compile(
    r'(?:python\d*|node|sh|bash|perl|ruby)\s+(?:-c|--eval|-e)\s+[\'"](.+?)[\'"]'
)
_RE_DANGEROUS_INLINE = re.compile(
    r'os\.system|subprocess|__import__|eval\s*\(|exec\s*\(|rm\s+-rf|/etc/passwd|/etc/shadow'
)


def _npath(path_str):
    """Convert MSYS2/Cygwin paths (/d/...) to Windows native (D:/...)."""
    m = _RE_MSYS_DRIVE.match(path_str)
    if m and os.name == 'nt':
        return f"{m.group(1).upper()}:/{m.group(2)}"
    return path_str


def _in_project(command, project_root):
    """Check if absolute paths in command are within project root."""
    project_path = Path(_npath(project_root)).resolve()
    path_candidates = _RE_PATH_CANDIDATE.findall(command)
    for path_str in path_candidates:
        if not _RE_ABSOLUTE_PATH.match(path_str):
            continue  # skip relative paths and flags
        # Skip flag-like patterns (e.g. -r, --force, /Q)
        if _RE_FLAG_LIKE.match(path_str.strip('\'"')):
            continue
        clean = _npath(path_str.strip('\'"'))
        try:
            resolved = Path(clean).resolve(strict=False)
        except OSError:
            return False  # Permission error etc. — can't verify, treat as outside
        try:
            resolved.relative_to(project_path)
        except ValueError:
            return False  # Outside project
    return True


# ═══════════════════════════════════════════════════════════════════════════
#  Validators — each returns ("yes", reason) or None
# ═══════════════════════════════════════════════════════════════════════════

def v_docker_rm(command, cwd, profile):
    # Docker rm is too context-sensitive for simple validation (--force, --volumes,
    # container IDs vs names, running vs stopped). Always defer to LLM.
    return None


def v_rm(command, cwd, profile):
    """Quick check: simple rm without recursive/force → yes. Otherwise → LLM."""
    has_recursive = bool(_RE_RM_FLAG_RECURSIVE.search(command))
    has_force = bool(_RE_RM_FLAG_FORCE.search(command))

    if not has_recursive and not has_force:
        # Simple deletion — check it's within project
        project_root = profile.get("project_root", cwd)
        rm_match = _RE_RM_ARGS.search(command)
        if rm_match:
            rm_args = rm_match.group(1)
            paths = _RE_PATH_CANDIDATE.findall(rm_args)
            for p in paths:
                p = p.strip('\'"')
                if not p or p.startswith('-'):
                    continue
                if _RE_FLAG_LIKE.match(p):
                    continue
                # If absolute and outside project, defer to LLM
                if os.path.isabs(p) or p.startswith('/'):
                    if not _in_project(f"rm {p}", project_root):
                        return None
            return ("yes", "Simple file deletion — project scoped")
    return None  # Recursive or force — LLM decides


def v_find_delete(command, cwd, profile):
    # find -delete can match unpredictable sets of files. Always defer to LLM.
    return None


def v_git_clean(command, cwd, profile):
    if not _RE_GIT_FORCE_FLAG.search(command):
        return ("yes", "Git clean dry-run — safe")
    return None  # -f flag — LLM decides


def v_git_force_push(command, cwd, profile):
    if not _RE_PRIMARY_BRANCH.search(command):
        return ("yes", "Force push to non-primary branch")
    return None  # Force push to main/master — LLM decides


def v_chmod(command, cwd, profile):
    # chmod permission changes are too context-sensitive (setuid, world-writable,
    # system files vs project files). Always defer to LLM.
    return None


def v_network(command, cwd, profile):
    """curl/wget: GET → yes, upload/data → LLM."""
    if _RE_NETWORK_DATA.search(command):
        return None  # Upload — LLM decides
    return ("yes", "Network GET/download — read-only")


def v_inline(command, cwd, profile):
    """Inline interpreter code: quick dangerous pattern check."""
    m = _RE_INLINE_CODE.search(command)
    if not m:
        return None
    code = m.group(1)
    if _RE_DANGEROUS_INLINE.search(code):
        return None  # Dangerous patterns found — defer to LLM
    return None  # Let LLM review the inline code


def v_project_scope(command, cwd, profile):
    """mkdir/touch/cp/mv: yes if within project, otherwise let LLM decide."""
    project_root = profile.get("project_root", cwd)
    if _in_project(command, project_root):
        return ("yes", "Operation within project scope")
    return None  # Outside project — LLM decides
