# safe-yes

<p align="center">
  <b>Smart Command Auto-Approval for Claude Code</b><br>
  Auto-allow safe operations · Flag dangerous commands · Only prompt you when it matters<br>
  <sub>2.1.1 · MIT · Python 3.12+</sub>
</p>

<p align="center">
  <a href="README.md">:cn: 中文</a>
</p>

---

## Why safe-yes?

Claude Code's permission dialog is secure, but **too frequent**. Every `ls`, `git status`, or `npm test` demands a click — breaking your flow. safe-yes automatically approves commands that are obviously safe, so you only deal with the ones that actually need judgment.

**Core design principle: never interfere with the native permission system.** safe-yes is a "yes-only accelerator" — it only auto-allows clearly safe commands. Anything uncertain passes through to Claude Code's native dialog. You will never miss a manual approval because of a safe-yes misjudgment.

## How It Works

safe-yes intercepts every Bash tool call through Claude Code's **PreToolUse / PostToolUse Hook**:

```
Bash command
    │
    ▼
┌──────────────────────────┐
│  Layer 1: Code Rules     │  60+ compiled regex, priority-ordered
│  Latency: < 1ms          │  ├─ yes → allow ✅
│  Covers: git/npm/pip/    │  ├─ no  → passthrough ⏳
│  docker/file ops/build   │  └─ maybe ↓
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│  Layer 2: Decision Memory│  Jaccard similarity against history
│  Latency: < 1ms          │  ├─ match → reuse your past choice 🔄
│  Capacity: 5000 entries  │  └─ miss ↓
│  TTL: 30 days            │
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│  Layer 3: LLM Review     │  Anthropic API safety analysis
│  Model: Claude Haiku     │  ├─ yes/no → decide & write memory 🤖
│  Optional, auto-skipped  │  └─ unavailable ↓
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│  Layer 4: Passthrough    │  Claude Code native dialog
│  tolerant: auto-allow    │  → Your manual judgment 👤
│  normal: show dialog      │
└──────────────────────────┘
```

### Hook Mechanism

safe-yes registers two hooks:

| Hook | When | Purpose |
|------|------|---------|
| **PreToolUse** | Before tool execution | Analyze command, return allow or passthrough |
| **PostToolUse** | After Bash execution | Detect user-approved commands, write to memory |

**Critical: safe-yes always returns `continue: true`.** Even a "no" decision merely means passthrough to the native permission system — the hook itself never blocks any operation. That's what "yes-only accelerator" means.

Tool coverage:

| Tool | Handling |
|------|---------|
| **Bash** | Full 4-layer pipeline analysis |
| **Write / Edit / Read** | Path safety check (system paths, secrets, project scope) |
| **WebSearch / WebFetch** | Always allow (read-only) |
| **mcp__\*** | Always allow (MCP tools) |
| **Others** | Always allow |

## Why safe-yes?

### vs. Default Claude Code

- Every safe command triggers a dialog → safe-yes auto-allows 80%+ daily operations
- No memory of your choices → safe-yes learns your habits, fewer prompts over time

### vs. Built-in `/permission`

Claude Code's `/permission` only does simple prefix matching:

| Capability | `/permission` | safe-yes |
|------|:---:|:---:|
| Prefix matching | ✅ | ✅ |
| Regex pattern matching | ❌ | ✅ 60+ |
| Context-aware (paths/args) | ❌ | ✅ |
| Decision memory | ❌ | ✅ |
| AI safety review | ❌ | ✅ |
| File path safety check | ❌ | ✅ |
| Quoted content masking | ❌ | ✅ |
| Interpreter body detection | ❌ | ✅ |

### Standout Features

**Quoted content masking** — `echo "rm -rf /etc"` won't be flagged as dangerous. The quoted string is just an echo argument, not a command to execute.

**Interpreter body detection** — `bash -c "rm -rf /etc"` **will** be correctly flagged. The argument to `-c` is executable code.

**Validator pipeline** — `rm *.log` auto-allowed, `rm -rf /etc` passed to dialog, `git push` auto-allowed, `git push --force main` escalated to LLM review.

## Installation

> **Important: you must run `/safe-yes:setup` after installation to activate.** The plugin installs in a disabled state so it never intercepts commands without your knowledge.

### Option A: Marketplace (Recommended)

```bash
# 1. Create marketplace directory
mkdir -p ~/safe-yes-marketplace/.claude-plugin ~/safe-yes-marketplace/plugins

# 2. Clone the plugin
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes-marketplace/plugins/safe-yes

# 3. Create marketplace manifest
cat > ~/safe-yes-marketplace/.claude-plugin/marketplace.json << 'EOF'
{
  "name": "safe-yes-marketplace",
  "owner": {},
  "plugins": [{
    "name": "safe-yes",
    "source": "./plugins/safe-yes",
    "description": "Smart command auto-approval for Claude Code. Auto-allows safe operations, blocks truly dangerous commands, and only prompts you for genuinely ambiguous cases.",
    "version": "2.1.1",
    "category": "productivity",
    "tags": ["safe-yes", "auto-approve", "security", "permission", "hook"]
  }]
}
EOF

# 4. Register and install
claude plugin marketplace add ~/safe-yes-marketplace
claude plugin install safe-yes@safe-yes-marketplace

# 5. Activate — in Claude Code, run:
# /safe-yes:setup
```

### Option B: Quick Try

```bash
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes
claude --plugin-dir ~/safe-yes
# In Claude Code, run /safe-yes:setup
```

## Commands

| Command | Description |
|---------|-------------|
| `/safe-yes:setup` | Initialize project config, detect project type, activate guard |
| `/safe-yes:enable` | Enable auto-approval |
| `/safe-yes:disable` | Disable auto-approval (back to native dialogs) |
| `/safe-yes:status` | Show stats: total decisions, memory entries, hit rate |

## Configuration

Config is stored at `.claude/security/profile.json` in your project, auto-generated by `/safe-yes:setup`. Full options:

```json
{
  "enabled": true,
  "security_level": "tolerant",
  "llm": {
    "enabled": true,
    "api_key": "",
    "base_url": "",
    "model": "",
    "custom_prompt": ""
  },
  "memory": {
    "enabled": true,
    "max_entries": 5000,
    "ttl_days": 30,
    "similarity_threshold": 0.8
  },
  "audit": {
    "central_log": false,
    "central_log_path": ""
  },
  "custom_rules": [],
  "network_allowed_domains": []
}
```

### security_level

| Value | Behavior | Use Case |
|-------|---------|---------|
| `tolerant` | Auto-allow when rules can't decide (default) | Daily development, trust in Claude |
| `normal` | Pass to native dialog when uncertain | Production, need manual oversight |

### LLM Review (Independent API Call)

**Important: LLM review is a completely separate API call from your current Claude Code session.**

safe-yes runs as a Hook script in a subprocess, calling the Anthropic Messages API directly over HTTP. Each review is a **fresh, stateless request** — it cannot see your conversation history, doesn't know what task you're working on, and only receives a fixed system prompt + the current command context.

```
Your Bash command
    │
    ▼
guard.py (subprocess)
    │
    ▼
HTTP POST /v1/messages ──────► Anthropic API
    │                              │
    │   system prompt (fixed)       │
    │   + user message (context)    │
    │                              │
    ◄──── {"decision": "yes"} ────┘
    │
    ▼
allow / passthrough
```

#### What gets sent to the LLM

**System Prompt** (identical for every request):

<details>
<summary>Click to expand full system prompt</summary>

```
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
  - Any command whose safety depends entirely on context you cannot see
```

</details>

**User Message** (varies per request, carries command context):

```
Command: rm -rf ./node_modules/
Working directory: /home/user/my-project
Project root: /home/user/my-project
Project type: node
Security level: tolerant
```

**API parameters**: `temperature: 0`, `max_tokens: 256`, `thinking: disabled` (no deep reasoning needed, just fast classification). Default model is `claude-haiku-4-5-20251001`. Credentials are auto-resolved from Claude Code's `ANTHROPIC_AUTH_TOKEN` environment variable.

#### custom_prompt — Project-Specific Safety Rules

The `custom_prompt` field lets you append project-specific safety context. It's **appended to the end** of the system prompt:

**Example 1 — Microservice project, prevent manual pod deletion**:

```json
{
  "llm": {
    "enabled": true,
    "custom_prompt": "This project runs in production Kubernetes. NEVER allow kubectl delete pod, helm uninstall, or terraform destroy without manual review — classify these as 'no'. Database migration commands (alembic upgrade, python manage.py migrate) should be 'yes' when run in the project root."
  }
}
```

**Example 2 — Data science project, protect raw data**:

```json
{
  "llm": {
    "enabled": true,
    "custom_prompt": "The ./data/raw/ directory contains irreplaceable research data. Any command that writes to or deletes from ./data/raw/ must be classified as 'no'. Jupyter notebook operations and pip install are 'yes'."
  }
}
```

**Example 3 — Frontend project, relax build tooling**:

```json
{
  "llm": {
    "enabled": true,
    "custom_prompt": "This is a Next.js frontend project. Commands like npx create, npx add, npm init, and yarn create are normal development operations — classify as 'yes'. However, any command that modifies .env.local or next.config.js should be 'uncertain'."
  }
}
```

Graceful fallback when LLM is unavailable: `tolerant` → allow, `normal` → dialog.

### Custom Rules

```json
{
  "custom_rules": [
    {
      "priority": 210,
      "pattern": "docker exec.*",
      "decision": "no",
      "reason": "Docker exec needs manual review"
    }
  ]
}
```

| Priority Range | Purpose |
|----------------|---------|
| 1–99 | Custom "untrusted" rules |
| 200–299 | Custom "trusted" rules |

## Built-in Rules

60+ rules across two priority bands:

### Dangerous (P10–P50, passthrough to dialog)

`dd` to block devices, fork bombs, credential exfiltration, recursive system-path deletion, curl-to-shell pipelines, etc.

### Safe (P200, auto-allow)

- **Read-only system tools**: `ls`, `cat`, `head`, `tail`, `find`, `grep`, `wc`, `du`, `which`, etc.
- **Git queries**: `git status`, `git log`, `git diff`, `git branch`, etc.
- **Git safe writes**: `git add`, `git commit`, `git stash`, `git pull`, etc.
- **Lint / Test / Build**: `npm test`, `pytest`, `make`, `cargo build`, etc.
- **Package management**: `npm install`, `pip install`, `cargo add`, etc.

Full list: `scripts/rules.py`.

## Decision Memory

safe-yes remembers your past decisions. When you manually approve a command, the PostToolUse hook writes it to memory. Similar future commands (keyword Jaccard similarity ≥ 80%) reuse your choice automatically.

- Commands with dangerous words (`--force`, `rm -rf`, `drop`, etc.) skip memory and are always re-evaluated
- TTL of 30 days — stale decisions expire
- All data stored **locally** in `.claude/security/memory.jsonl`, never uploaded

## Audit Trail

Every decision is logged to `.claude/security/decisions.jsonl` (JSONL, one line per entry):

```json
{
  "timestamp": "2026-05-14T10:30:00.000Z",
  "command": "git push origin main",
  "decision": "allow",
  "reason": "Git push is safe",
  "layer": "rules",
  "cwd": "/project",
  "sid": "abc123"
}
```

Optional centralized log path for team security audits.

## Requirements

- **Claude Code** (any version)
- **Python 3.12+**

LLM review is optional. Requires an Anthropic API key (reuses Claude Code's existing env vars).

## License

MIT

---

<p align="center">
  <a href="README.md">:cn: 读中文版</a>
</p>
