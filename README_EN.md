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

### LLM Review

Enable LLM review and safe-yes reads `ANTHROPIC_AUTH_TOKEN` from Claude Code's environment automatically — zero config. Or specify manually:

```json
{
  "llm": {
    "enabled": true,
    "model": "claude-haiku-4-5-20251001"
  }
}
```

Uses Claude Haiku by default (fast, low cost). Graceful fallback when unavailable: `tolerant` → allow, `normal` → dialog.

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
