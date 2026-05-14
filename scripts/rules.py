"""Safe-Yes rules — YES/NO rule matching engine."""

import re
from validators import (
    v_docker_rm, v_rm, v_find_delete, v_git_clean, v_git_force_push,
    v_chmod, v_network, v_inline, v_project_scope,
)


def _compile_rule(priority, pattern, decision, reason, validator=None):
    return (priority, re.compile(pattern, re.IGNORECASE), decision, reason, validator)


# Interpreter flags whose quoted argument IS executable code — do NOT mask these
_INTERP_EXEC_RE = re.compile(
    r'\b(?:bash|sh|zsh|dash|ksh|python\d*|node|perl|ruby|php)\s+'
    r'(?:-c|--eval|--execute|-e)\s*',
    re.IGNORECASE
)


def _mask_quoted_content(command):
    """Replace quoted string content with spaces, except for interpreter -c/-e args.

    Prevents NO rules from matching patterns that appear only inside string
    arguments (e.g. echo "rm -rf /etc"). Quoted content following interpreter
    flags (bash -c "...") is preserved since it IS the executable command.
    """
    # Find quote ranges that follow interpreter flags — preserve these
    preserve_set = set()
    for m in _INTERP_EXEC_RE.finditer(command):
        pos = m.end()
        if pos >= len(command):
            continue
        if command[pos] in ('"', "'"):
            quote = command[pos]
            end = command.find(quote, pos + 1)
            if end != -1:
                preserve_set.update(range(pos + 1, end))
        elif command[pos] == '$' and pos + 1 < len(command) and command[pos + 1] in ("'", '"'):
            quote = command[pos + 1]
            end = command.find(quote, pos + 2)
            if end != -1:
                preserve_set.update(range(pos + 2, end))

    # Walk the command, masking non-preserved quoted content
    result = list(command)
    i = 0
    in_single = False
    in_double = False
    single_start = -1
    double_start = -1

    while i < len(command):
        c = command[i]

        if not in_single and not in_double:
            if c == "'":
                in_single = True
                single_start = i
            elif c == '"':
                in_double = True
                double_start = i
        elif in_single:
            if c == "'":
                for k in range(single_start + 1, i):
                    if k not in preserve_set:
                        result[k] = ' '
                in_single = False
        elif in_double:
            if c == '"' and (i == 0 or command[i - 1] != '\\'):
                for k in range(double_start + 1, i):
                    if k not in preserve_set:
                        result[k] = ' '
                in_double = False

        i += 1

    # Handle unclosed quotes
    if in_single:
        for k in range(single_start + 1, len(command)):
            if k not in preserve_set:
                result[k] = ' '
    if in_double:
        for k in range(double_start + 1, len(command)):
            if k not in preserve_set:
                result[k] = ' '

    return ''.join(result)


# ═══════════════════════════════════════════════════════════════════════════
#  System Rules — (priority, pattern, decision, reason, validator)
#  decision: "yes" or "no"
#  unmatched → "uncertain" → LLM
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_RULES = [
    # ── P10: System destruction (no — skip LLM) ─────────────────────
    _compile_rule(10, r'\bdd\s+if=.*\bof=/dev/sd', "no", "Raw write to block device"),
    _compile_rule(10, r'\bfdisk\s+/dev/', "no", "Disk partition table modification"),
    _compile_rule(10, r'\bmkfs\b', "no", "Filesystem format"),
    _compile_rule(10, r'>\s*/dev/sd[a-z]', "no", "Redirect to block device"),
    _compile_rule(10, r'\brm\s+(?:-[-\w]*r[-\w]*\s+)*/(?:\s|$)', "no", "Recursive deletion of root filesystem (rm -rf /)"),
    _compile_rule(10, r'\brm\s+(?:-[-\w]*r[-\w]*\s+)*/\*', "no", "Recursive deletion of root filesystem (rm -rf /*)"),

    # ── P15: Fork bombs (no) ────────────────────────────────────────
    _compile_rule(15, r':\(\)\s*\{.*:\|:&\s*\};:', "no", "Fork bomb detected"),
    _compile_rule(15, r'\(\$_\)\s*\{\s*\$_|\$_&\s*\};', "no", "Fork bomb variant"),

    # ── P30: Credential exfiltration / RCE (no) ─────────────────────
    _compile_rule(30, r'\bcat\s+~/.ssh/', "no", "Reading SSH private keys"),
    _compile_rule(30, r'\bcat\s+~/.aws/', "no", "Reading AWS credentials"),
    _compile_rule(30, r'\bbase64\s+(?:-d|--decode)\s*\|.*(?:ba)?sh', "no",
     "Base64-decoded payload piped to shell"),
    _compile_rule(30, r'\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b', "no",
     "Network download piped to shell interpreter"),
    _compile_rule(30, r'\beval\s+.*\$', "no", "eval with variable expansion"),

    # ── P50: Recursive deletion of system paths (no) ────────────────
    _compile_rule(50, r'\brm\s+(?:-[-\w]*r[-\w]*\s+)*/(?:etc|usr|boot|var|opt|bin|dev|sys|proc)(?:/\S*)?(?:\s|$)',
     "no", "Recursive deletion of system directory"),
    _compile_rule(50, r'\brm\s+(?:-[-\w]*r[-\w]*\s+)*~(?:\s|$)', "no",
     "Recursive deletion of home directory"),
    _compile_rule(50, r'\brm\s+(?:-[-\w]*r[-\w]*\s+)*\$HOME(?:\s|$)', "no",
     "Recursive deletion of $HOME"),

    # ═══════════════════════════════════════════════════════════════════
    # P200: Safe operations — yes (auto-allow)
    # ═══════════════════════════════════════════════════════════════════

    # ── Read-only filesystem ─────────────────────────────────────────
    _compile_rule(200, r'^ls\b', "yes", "List directory"),
    _compile_rule(200, r'^dir\b', "yes", "List directory"),
    _compile_rule(200, r'^cat\s+\S', "yes", "Read file"),
    _compile_rule(200, r'^head\b', "yes", "Read file head"),
    _compile_rule(200, r'^tail\b', "yes", "Read file tail"),
    _compile_rule(200, r'^less\b', "yes", "Read file with pager"),
    _compile_rule(200, r'^more\b', "yes", "Read file with pager"),
    _compile_rule(200, r'^find\s+(?!.*-delete)', "yes", "Find files"),
    _compile_rule(200, r'^tree\b', "yes", "Tree view"),
    _compile_rule(200, r'^stat\s', "yes", "File stat"),
    _compile_rule(200, r'^file\s', "yes", "Check file type"),
    _compile_rule(200, r'^wc\s', "yes", "Word count"),
    _compile_rule(200, r'^du\s', "yes", "Disk usage"),
    _compile_rule(200, r'^df\b', "yes", "Disk free"),
    _compile_rule(200, r'^locate\b', "yes", "Locate file"),
    _compile_rule(200, r'^which\s', "yes", "Find executable"),
    _compile_rule(200, r'^where\b', "yes", "Find executable"),
    _compile_rule(200, r'^whereis\b', "yes", "Find executable"),
    _compile_rule(200, r'^type\s', "yes", "Command type"),
    _compile_rule(200, r'^command\s+-v', "yes", "Command check"),
    _compile_rule(200, r'^realpath\b', "yes", "Real path"),
    _compile_rule(200, r'^readlink\b', "yes", "Read symlink"),
    _compile_rule(200, r'^dirname\b', "yes", "Directory name"),
    _compile_rule(200, r'^basename\b', "yes", "Base name"),

    # ── Info / util ──────────────────────────────────────────────────
    _compile_rule(200, r'^echo\b', "yes", "Print text"),
    _compile_rule(200, r'^printf\b', "yes", "Formatted print"),
    _compile_rule(200, r'^curl\b', "yes", "Network transfer", v_network),
    _compile_rule(200, r'^wget\b', "yes", "Network transfer", v_network),
    _compile_rule(200, r'^pwd\b', "yes", "Current directory"),
    _compile_rule(200, r'^whoami\b', "yes", "Current user"),
    _compile_rule(200, r'^uname\b', "yes", "System info"),
    _compile_rule(200, r'^hostname\b', "yes", "Hostname"),
    _compile_rule(200, r'^date\b', "yes", "Current date"),
    _compile_rule(200, r'^env\b', "yes", "Environment variables"),
    _compile_rule(200, r'^printenv\b', "yes", "Print environment"),

    # ── Read-only git ────────────────────────────────────────────────
    _compile_rule(200, r'^git\s+status\b', "yes", "Git status"),
    _compile_rule(200, r'^git\s+log\b', "yes", "Git log"),
    _compile_rule(200, r'^git\s+diff\b', "yes", "Git diff"),
    _compile_rule(200, r'^git\s+show\b', "yes", "Git show"),
    _compile_rule(200, r'^git\s+branch\s(?!.*-[dD])', "yes", "Git branch list"),
    _compile_rule(200, r'^git\s+remote\s+-v\b', "yes", "Git remote list"),
    _compile_rule(200, r'^git\s+stash\s+list\b', "yes", "Git stash list"),
    _compile_rule(200, r'^git\s+tag\b', "yes", "Git tag list"),
    _compile_rule(200, r'^git\s+rev-parse\b', "yes", "Git rev-parse"),
    _compile_rule(200, r'^git\s+config\s+--get\b', "yes", "Git config read"),
    _compile_rule(200, r'^git\s+ls-files\b', "yes", "Git ls-files"),
    _compile_rule(200, r'^git\s+grep\b', "yes", "Git grep"),
    _compile_rule(200, r'^git\s+blame\b', "yes", "Git blame"),
    _compile_rule(200, r'^git\s+--version\b', "yes", "Git version"),

    # ── Version checks ───────────────────────────────────────────────
    _compile_rule(200, r'^python\d*\s+(?:--version|-V)$', "yes", "Python version"),
    _compile_rule(200, r'^node\s+(?:--version|-v)$', "yes", "Node version"),
    _compile_rule(200, r'^npm\s+(?:--version|-v)$', "yes", "npm version"),
    _compile_rule(200, r'^yarn\s+(?:--version|-v)$', "yes", "Yarn version"),
    _compile_rule(200, r'^pnpm\s+(?:--version|-v)$', "yes", "pnpm version"),
    _compile_rule(200, r'^cargo\s+(?:--version|-V)$', "yes", "Cargo version"),
    _compile_rule(200, r'^rustc\s+(?:--version|-V)$', "yes", "Rustc version"),
    _compile_rule(200, r'^go\s+version\b', "yes", "Go version"),

    # ── Package queries ──────────────────────────────────────────────
    _compile_rule(200, r'^pip\s+(?:list|show|freeze)\b', "yes", "Pip query"),
    _compile_rule(200, r'^python\d*\s+-m\s+pip\s+(?:list|show|freeze)\b', "yes", "Pip query"),
    _compile_rule(200, r'^npm\s+(?:list|ls|outdated|view)\b', "yes", "npm query"),
    _compile_rule(200, r'^yarn\s+(?:list|outdated|info)\b', "yes", "Yarn query"),
    _compile_rule(200, r'^pnpm\s+(?:list|outdated)\b', "yes", "pnpm query"),
    _compile_rule(200, r'^conda\s+(?:list|info|env\s+list)\b', "yes", "Conda query"),
    _compile_rule(200, r'^cargo\s+tree\b', "yes", "Cargo tree"),
    _compile_rule(200, r'^poetry\s+show\b', "yes", "Poetry show"),

    # ── Lint / type-check ────────────────────────────────────────────
    _compile_rule(200, r'^(?:python\d*\s+-m\s+)?pylint\b', "yes", "Pylint"),
    _compile_rule(200, r'^(?:python\d*\s+-m\s+)?flake8\b', "yes", "Flake8"),
    _compile_rule(200, r'^(?:python\d*\s+-m\s+)?mypy\b', "yes", "Mypy"),
    _compile_rule(200, r'^(?:python\d*\s+-m\s+)?ruff\s+check\b', "yes", "Ruff check"),
    _compile_rule(200, r'^(?:python\d*\s+-m\s+)?bandit\b', "yes", "Bandit"),
    _compile_rule(200, r'^black\s+--check\b', "yes", "Black check"),
    _compile_rule(200, r'^isort\s+--check\b', "yes", "isort check"),
    _compile_rule(200, r'^npx\s+eslint\b', "yes", "ESLint"),
    _compile_rule(200, r'^npx\s+prettier\s+--check\b', "yes", "Prettier check"),
    _compile_rule(200, r'^npx\s+tsc\s+--noEmit\b', "yes", "TypeScript check"),

    # ── mkdir / touch / cp / mv / rm ──────────────────────────────────
    _compile_rule(200, r'^mkdir\b', "yes", "Create directory", v_project_scope),
    _compile_rule(200, r'^touch\b', "yes", "Create file", v_project_scope),
    _compile_rule(200, r'^cp\s', "yes", "Copy file", v_project_scope),
    _compile_rule(200, r'^mv\s', "yes", "Move file", v_project_scope),
    _compile_rule(200, r'^rm\s', "yes", "Remove file", v_rm),

    # ── Build / test / run ───────────────────────────────────────────
    _compile_rule(200, r'^(?:python\d*\s+-m\s+)?pytest\b', "yes", "Run tests"),
    _compile_rule(200, r'^npm\s+(?:test|run\s+\w+|start|build|dev)\b', "yes", "npm script"),
    _compile_rule(200, r'^npx\s+(?:jest|vitest|mocha|ava)\b', "yes", "Test runner"),
    _compile_rule(200, r'^yarn\s+(?:test|build|dev|start)\b', "yes", "Yarn script"),
    _compile_rule(200, r'^pnpm\s+(?:test|build|dev|start)\b', "yes", "pnpm script"),
    _compile_rule(200, r'^cargo\s+(?:test|build|check|run|clippy)\b', "yes", "Cargo"),
    _compile_rule(200, r'^go\s+(?:test|build|run|vet|fmt)\b', "yes", "Go"),
    _compile_rule(200, r'^make\b', "yes", "Make"),

    # ── Package install ──────────────────────────────────────────────
    _compile_rule(200, r'^pip\s+install\b', "yes", "pip install"),
    _compile_rule(200, r'^python\d*\s+-m\s+pip\s+install\b', "yes", "pip install"),
    _compile_rule(200, r'^npm\s+(?:install|i|ci)\b(?!\s+-g\b)', "yes", "npm install"),
    _compile_rule(200, r'^yarn\s+(?:install|add)\b', "yes", "Yarn install"),
    _compile_rule(200, r'^pnpm\s+(?:install|add|i)\b', "yes", "pnpm install"),
    _compile_rule(200, r'^cargo\s+(?:add|install)\b', "yes", "Cargo install"),
    _compile_rule(200, r'^conda\s+install\b', "yes", "Conda install"),
    _compile_rule(200, r'^poetry\s+(?:install|add)\b', "yes", "Poetry install"),
    _compile_rule(200, r'^go\s+(?:get|install)\b', "yes", "Go install"),

    # ── Env management ───────────────────────────────────────────────
    _compile_rule(200, r'^conda\s+(?:create|activate|deactivate|remove)\b', "yes", "Conda env"),
    _compile_rule(200, r'^python\d*\s+-m\s+venv\b', "yes", "Create venv"),
    _compile_rule(200, r'^virtualenv\b', "yes", "Create virtualenv"),

    # ── Git safe mutations ───────────────────────────────────────────
    _compile_rule(200, r'^git\s+add\s', "yes", "Git add"),
    _compile_rule(200, r'^git\s+commit\b', "yes", "Git commit"),
    _compile_rule(200, r'^git\s+checkout\s(?!.*--)', "yes", "Git checkout branch"),
    _compile_rule(200, r'^git\s+switch\b', "yes", "Git switch"),
    _compile_rule(200, r'^git\s+merge\b', "yes", "Git merge"),
    _compile_rule(200, r'^git\s+rebase\b(?!.*--continue|--abort)', "yes", "Git rebase"),
    _compile_rule(200, r'^git\s+pull\b', "yes", "Git pull"),
    _compile_rule(200, r'^git\s+push\b(?!\s+(?:--force|-f)\b)', "yes", "Git push"),
    _compile_rule(200, r'^git\s+fetch\b', "yes", "Git fetch"),
    _compile_rule(200, r'^git\s+stash\b(?!\s+(?:drop|clear)\b)', "yes", "Git stash save"),
    _compile_rule(200, r'^git\s+init\b', "yes", "Git init"),
    _compile_rule(200, r'^git\s+clone\b', "yes", "Git clone"),
]

# Verify SYSTEM_RULES is sorted by priority (ascending)
assert all(SYSTEM_RULES[i][0] <= SYSTEM_RULES[i + 1][0]
           for i in range(len(SYSTEM_RULES) - 1)), \
    "SYSTEM_RULES must be sorted by priority"


def load_custom_rules(profile):
    """Convert profile custom_rules to internal rule tuples with compiled regex."""
    rules = []
    for entry in profile.get("custom_rules", []):
        if not isinstance(entry, dict):
            continue
        priority = entry.get("priority", 100)
        pattern = entry.get("pattern", "")
        decision = entry.get("decision", "uncertain")
        reason = entry.get("reason", f"Custom rule: {pattern}")
        if pattern and decision in ("yes", "no", "uncertain"):
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue  # Skip invalid regex from user config
            rules.append((priority, compiled, decision, reason, None))
    return rules


def match_rules(command, cwd, profile):
    """Match command against unified rule list.

    Returns (decision, reason) — decision: "yes", "no", or "uncertain".
    NO rules are matched against a masked version of the command to
    prevent false positives from quoted strings (e.g. echo "rm -rf /").
    """
    custom = load_custom_rules(profile)

    if custom:
        all_rules = custom + list(SYSTEM_RULES)
        all_rules.sort(key=lambda r: r[0])
    else:
        all_rules = SYSTEM_RULES  # Already sorted by priority

    masked_command = None

    for entry in all_rules:
        _pri, pattern, decision, reason = entry[:4]
        validator = entry[4] if len(entry) > 4 else None

        # NO rules use masked command to avoid false positives
        # from patterns inside quoted strings
        if decision == "no":
            if masked_command is None:
                masked_command = _mask_quoted_content(command)
            target = masked_command
        else:
            target = command

        if not pattern.search(target):
            continue

        # If rule has a validator that confirms "yes", use it
        # Otherwise use the rule's default decision
        if validator and decision == "yes":
            override = validator(command, cwd, profile)
            if override is not None:
                return override  # validator says yes
            continue  # validator says no → keep searching

        return (decision, reason)

    return ("uncertain", "No matching rule — LLM review needed")
