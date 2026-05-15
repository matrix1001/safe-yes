# safe-yes

<p align="center">
  <b>Claude Code 智能命令审批插件</b><br>
  自动放行安全操作 · 拦截危险命令 · 只把真正需要判断的交给权限弹窗<br>
  <sub>2.1.1 · MIT · Python 3.12+</sub>
</p>

<p align="center">
  <a href="README_EN.md">:us: English</a>
</p>

---

## 为什么需要 safe-yes？

Claude Code 的权限弹窗很安全，但**太频繁了**。每次 `ls`、`git status`、`npm test` 都要点一次 Allow，打断心流。safe-yes 帮你自动审批那些"显然安全"的命令，让你只关注真正需要判断的操作。

**核心设计原则：不影响原生权限系统。** safe-yes 是一个"只放行不拦截"的插件——它只会 auto-allow 明显安全的命令，拿不准的统统交给 Claude Code 原生弹窗。你永远不会因为 safe-yes 误判而错失手动审批的机会。

## 如何工作

safe-yes 通过 Claude Code 的 **PreToolUse / PostToolUse Hook** 拦截每一次 Bash 工具调用：

```
Bash 命令
    │
    ▼
┌──────────────────────────┐
│  Layer 1: Code Rules     │  60+ 条编译正则，优先级匹配
│  速度: < 1ms             │  ├─ yes → 直接放行 ✅
│  覆盖: git/npm/pip/docker│  ├─ no  → 交给弹窗 ⏳
│  文件读写/包管理/构建测试│  └─ maybe ↓
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│  Layer 2: Decision Memory│  Jaccard 相似度匹配历史决策
│  速度: < 1ms             │  ├─ 匹配 → 复用你的历史选择 🔄
│  容量: 最多 5000 条      │  └─ 未命中 ↓
│  TTL: 默认 30 天         │
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│  Layer 3: LLM Review     │  Anthropic API 安全审查
│  模型: Claude Haiku      │  ├─ yes/no → 决策并写回记忆 🤖
│  可关闭，无 key 自动跳过  │  └─ 失败/不可用 ↓
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│  Layer 4: Passthrough    │  交给 Claude Code 原生弹窗
│  tolerant: 自动放行      │  → 你手动判断 👤
│  normal: 弹出原生对话框   │
└──────────────────────────┘
```

### Hook 机制说明

safe-yes 注册了两种 hook：

| Hook | 触发时机 | 作用 |
|------|---------|------|
| **PreToolUse** | 工具执行前 | 分析命令，返回 allow 或 passthrough |
| **PostToolUse** | Bash 执行后 | 检测你手动放行的命令，写入决策记忆 |

**关键：safe-yes 永远只返回 `continue: true`。** 即使判定为危险命令，也只是 passthrough 给原生权限系统——Hook 本身不拒绝任何操作。这就是"yes-only accelerator"的含义。

工具覆盖：

| 工具 | 处理方式 |
|------|---------|
| **Bash** | 完整四层管道分析 |
| **Write / Edit / Read** | 路径安全检查（系统路径、密钥文件、项目范围） |
| **WebSearch / WebFetch** | 直接放行（只读网络操作） |
| **mcp__\*** | 直接放行（MCP 工具） |
| **其他** | 直接放行 |

## 为什么选择 safe-yes？

### vs. 什么都不装

- Claude Code 每次安全的命令都要弹窗 → safe-yes 自动放行 80%+ 的日常操作
- 没有记忆功能 → safe-yes 学习你的习惯，越用越少弹窗

### vs. 直接配 allowlist

Claude Code 的 `/permission` 只能做简单的命令前缀匹配：

| 能力 | `/permission` | safe-yes |
|------|:---:|:---:|
| 命令前缀匹配 | ✅ | ✅ |
| 正则模式匹配 | ❌ | ✅ 60+ |
| 上下文感知（路径/参数） | ❌ | ✅ |
| 历史决策记忆 | ❌ | ✅ |
| AI 安全审查 | ❌ | ✅ |
| 文件路径安全检查 | ❌ | ✅ |
| 引号内容遮蔽 | ❌ | ✅ |
| 解释器执行体检测 | ❌ | ✅ |

### 特色能力

**引号内容遮蔽** —— `echo "rm -rf /etc"` 不会被误判为危险命令，因为引号内的 `rm -rf /etc` 只是字符串，并非要执行的命令。

**解释器执行体检测** —— `bash -c "rm -rf /etc"` **会被正确识别**为危险命令，因为 `-c` 后面的参数是需要执行的代码。

**Validator 机制** —— `rm *.log` 自动放行，`rm -rf /etc` 转交弹窗，`git push` 自动放行，`git push --force main` 升级到 LLM 审查。

## 安装

> **注意：安装后需要运行 `/safe-yes:setup` 才能激活。** 默认状态为禁用，避免你不知情的情况下被接管。

### 方案 A：Marketplace 安装（推荐）

```bash
# 1. 创建 marketplace 目录
mkdir -p ~/safe-yes-marketplace/.claude-plugin ~/safe-yes-marketplace/plugins

# 2. 克隆插件
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes-marketplace/plugins/safe-yes

# 3. 创建 marketplace 注册文件
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

# 4. 注册 marketplace 并安装
claude plugin marketplace add ~/safe-yes-marketplace
claude plugin install safe-yes@safe-yes-marketplace

# 5. 激活
# 在 Claude Code 中运行 /safe-yes:setup
```

### 方案 B：快速试用

```bash
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes
claude --plugin-dir ~/safe-yes
# 在 Claude Code 中运行 /safe-yes:setup
```

## 使用

| 命令 | 说明 |
|------|------|
| `/safe-yes:setup` | 初始化配置，自动检测项目类型，启用 guard |
| `/safe-yes:enable` | 启用自动审批 |
| `/safe-yes:disable` | 禁用自动审批（恢复手动弹窗） |
| `/safe-yes:status` | 查看统计数据：决策总数、记忆条数、命中率 |

## 配置

配置文件位于项目 `.claude/security/profile.json`，由 `/safe-yes:setup` 自动生成。完整选项：

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

| 值 | 行为 | 适用场景 |
|----|------|---------|
| `tolerant` | 规则无法判断时自动放行（默认） | 日常开发，信任 Claude |
| `normal` | 规则无法判断时交给弹窗 | 生产环境，需要手动把关 |

### LLM 审查（独立 API 调用）

**重要：LLM 审查是与当前 Claude Code 会话完全独立的 API 调用。**

safe-yes 作为 Hook 脚本在子进程中运行，通过 HTTP 直接调用 Anthropic Messages API。每次审查都是一个**全新的、无状态的请求**——它看不到你的对话历史，不知道你在做什么任务，只接收固定的 system prompt + 当前命令上下文。

```
你的 Bash 命令
    │
    ▼
guard.py（子进程）
    │
    ▼
HTTP POST /v1/messages ──────► Anthropic API
    │                              │
    │   system prompt（固定指令）    │
    │   + user message（命令上下文）  │
    │                              │
    ◄──── {"decision": "yes"} ────┘
    │
    ▼
allow / passthrough
```

#### 发送给 LLM 的完整内容

**System Prompt**（每次相同的固定指令）：

<details>
<summary>点击展开完整 system prompt</summary>

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

**User Message**（每次不同，包含当前命令上下文）：

```
Command: rm -rf ./node_modules/
Working directory: /home/user/my-project
Project root: /home/user/my-project
Project type: node
Security level: tolerant
```

**API 参数**：`temperature: 0`，`max_tokens: 256`，`thinking: disabled`（不需要深度思考，只需要快速分类）。默认模型为 `claude-haiku-4-5-20251001`，可自动复用 Claude Code 已有的 `ANTHROPIC_AUTH_TOKEN` 环境变量。

#### custom_prompt — 项目级安全规则

通过 `custom_prompt` 字段，你可以给 LLM 追加项目特有的安全上下文。这段文本会**追加到 system prompt 末尾**：

**示例 1 — 微服务项目，禁止手动重启 Pod**：

```json
{
  "llm": {
    "enabled": true,
    "custom_prompt": "This project runs in production Kubernetes. NEVER allow kubectl delete pod, helm uninstall, or terraform destroy without manual review — classify these as 'no'. Database migration commands (alembic upgrade, python manage.py migrate) should be 'yes' when run in the project root."
  }
}
```

**示例 2 — 数据科学项目，保护原始数据**：

```json
{
  "llm": {
    "enabled": true,
    "custom_prompt": "The ./data/raw/ directory contains irreplaceable research data. Any command that writes to or deletes from ./data/raw/ must be classified as 'no'. Jupyter notebook operations and pip install are 'yes'."
  }
}
```

**示例 3 — 前端项目，放宽构建工具**：

```json
{
  "llm": {
    "enabled": true,
    "custom_prompt": "This is a Next.js frontend project. Commands like npx create, npx add, npm init, and yarn create are normal development operations — classify as 'yes'. However, any command that modifies .env.local or next.config.js should be 'uncertain'."
  }
}
```

LLM 不可用时自动降级：`tolerant` → 放行，`normal` → 弹窗。

### 自定义规则

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

| priority 范围 | 用途 |
|--------------|------|
| 1–99 | 自定义"不信任"规则 |
| 200–299 | 自定义"信任"规则 |

## 规则清单

safe-yes 内置 60+ 条规则，分两个优先级段：

### 危险操作（P10–P50，匹配后 passthrough 给弹窗）

`dd` 写块设备、进程炸弹、凭证窃取、系统路径递归删除、网络到 shell 管道等。

### 安全操作（P200，匹配后自动放行）

- **只读系统工具**：`ls`、`cat`、`head`、`tail`、`find`、`grep`、`wc`、`du`、`which` 等
- **Git 查询**：`git status`、`git log`、`git diff`、`git branch` 等
- **Git 安全写入**：`git add`、`git commit`、`git stash`、`git pull` 等
- **Lint / Test / Build**：`npm test`、`pytest`、`make`、`cargo build` 等
- **包管理**：`npm install`、`pip install`、`cargo add` 等

完整列表见 `scripts/rules.py`。

## 决策记忆

safe-yes 会记住你的历史决策。当你手动放行一条命令后，PostToolUse hook 自动将其写入记忆。下次遇到相似命令（关键词 Jaccard 相似度 ≥ 80%），直接复用你的历史选择。

- 含危险词汇（`--force`、`rm -rf`、`drop` 等）的命令不会走记忆层，始终重新判断
- TTL 30 天自动过期，过期决策不再复用
- 所有数据存储在**本地** `.claude/security/memory.jsonl`，不上传

## 审计

所有决策记录到 `.claude/security/decisions.jsonl`（JSONL 格式，每行一条）：

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

可选配置集中日志路径，方便团队安全审计。

## 要求

- **Claude Code**（任意版本）
- **Python 3.12+**

LLM 审查为可选功能，需要 Anthropic API key（可使用 Claude Code 已有的环境变量）。

## 许可证

MIT

---

<p align="center">
  <a href="README_EN.md">:us: Read this in English</a>
</p>
