# safe-yes

Claude Code 智能命令自动审批插件。自动放行安全操作，拦截危险命令，只把真正需要判断的交给权限弹窗。

[:us: English](#english)

## 特性

- **四层管道**：Code Rules → Decision Memory → LLM Review → Passthrough，层层过滤
- **60+ 内置规则**：覆盖常见开发操作（git、npm、pip、docker、文件读写等）
- **决策记忆**：学习你的审批习惯，相似命令自动复用历史决策
- **LLM 审查**：不确定的命令交给 AI 判断（可选，需 Anthropic API key）
- **非侵入式**：只做 auto-allow，不 deny。拿不准的交给 Claude Code 原生权限系统

## 架构

```
命令 → Code Rules（60+ 正则规则，<1ms）
         ├─ yes → 放行
         ├─ no  → 转给原生权限弹窗
         └─ maybe ↓
       Decision Memory（Jaccard 相似度匹配）
         ├─ match → 复用历史决策
         └─ miss ↓
       LLM Review（Anthropic API）
         ├─ yes/no → 决策 + 写回记忆
         └─ error ↓
       Passthrough → 原生权限弹窗
```

## 安装

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
```

### 方案 B：快速试用

```bash
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes
claude --plugin-dir ~/safe-yes
```

安装后运行 `/safe-yes:setup` 初始化项目配置。

## 使用

| 命令 | 说明 |
|------|------|
| `/safe-yes:setup` | 初始化项目配置，自动检测项目类型 |
| `/safe-yes:enable` | 启用 guard（开始自动审批） |
| `/safe-yes:disable` | 禁用 guard（恢复手动审批） |
| `/safe-yes:status` | 查看统计：决策数、记忆条数、命中率 |

## 配置

配置保存在项目 `.claude/security/profile.json`，由 `/safe-yes:setup` 自动生成。

```json
{
  "enabled": true,
  "security_level": "tolerant",
  "llm": {
    "enabled": true
  },
  "memory": {
    "enabled": true,
    "max_entries": 5000,
    "ttl_days": 30,
    "similarity_threshold": 0.8
  }
}
```

### security_level

| 值 | 行为 |
|----|------|
| `tolerant` | 规则无法判断时自动放行（默认） |
| `normal` | 规则无法判断时交给 Claude Code 弹窗 |

### LLM

启用 LLM 审查后，需要配置 API key。safe-yes 会自动读取 Claude Code 的 `ANTHROPIC_AUTH_TOKEN` 环境变量，无需额外配置。也可以手动指定：

```json
{
  "llm": {
    "enabled": true,
    "api_key": "sk-ant-...",
    "base_url": "https://api.anthropic.com",
    "model": "claude-haiku-4-5-20251001"
  }
}
```

## 要求

- Claude Code（任意版本）
- Python 3.12+

---

## English

[:cn: 中文](#safe-yes)

**safe-yes** is a Claude Code plugin for smart command auto-approval. It silently allows safe operations (git, npm, pip, file reads), blocks dangerous commands (rm -rf /, dd to block devices, credential exfiltration), and only prompts you for genuinely ambiguous cases.

### How It Works

A four-tier pipeline processes every Bash command before execution:

1. **Code Rules** — 60+ compiled regex rules, matched in priority order (<1ms)
2. **Decision Memory** — Jaccard similarity matching against your past decisions
3. **LLM Review** — Optional AI safety review via Anthropic API
4. **Passthrough** — Falls back to Claude Code's native permission dialog

safe-yes only auto-allows — it never blocks commands on its own. Anything deemed dangerous is passed through to Claude Code's permission system for your manual approval.

### Installation

**Option A: Marketplace (recommended)**

```bash
mkdir -p ~/safe-yes-marketplace/.claude-plugin ~/safe-yes-marketplace/plugins
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes-marketplace/plugins/safe-yes
cat > ~/safe-yes-marketplace/.claude-plugin/marketplace.json << 'EOF'
{
  "name": "safe-yes-marketplace",
  "owner": {},
  "plugins": [{
    "name": "safe-yes",
    "source": "./plugins/safe-yes",
    "description": "Smart command auto-approval for Claude Code.",
    "version": "2.1.1",
    "category": "productivity",
    "tags": ["safe-yes", "auto-approve", "security", "permission", "hook"]
  }]
}
EOF
claude plugin marketplace add ~/safe-yes-marketplace
claude plugin install safe-yes@safe-yes-marketplace
```

**Option B: Quick try**

```bash
git clone https://github.com/matrix1001/safe-yes.git ~/safe-yes
claude --plugin-dir ~/safe-yes
```

Run `/safe-yes:setup` after installation to initialize project configuration.

### Commands

| Command | Description |
|---------|-------------|
| `/safe-yes:setup` | Initialize project profile |
| `/safe-yes:enable` | Enable auto-approval |
| `/safe-yes:disable` | Disable auto-approval |
| `/safe-yes:status` | Show statistics and status |

### Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `security_level` | `tolerant` | `tolerant` = auto-allow ambiguous; `normal` = ask |
| `llm.enabled` | `true` | Enable LLM safety review |
| `memory.max_entries` | `5000` | Max decision memory entries |
| `memory.ttl_days` | `30` | Decision memory TTL in days |

### Requirements

- Claude Code
- Python 3.12+

### License

MIT
