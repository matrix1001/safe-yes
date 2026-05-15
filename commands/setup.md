---
description: Setup safe-yes for current project — profile + enable/disable
allowed-tools: Bash, Read, AskUserQuestion
---

# Setup safe-yes for this Project

Creates `.claude/security/profile.json`. Hooks are shipped in the plugin's `hooks/hooks.json` and loaded automatically — no settings.local.json changes needed.

## Step 1: Confirm Project Root

Run `pwd` to get the current working directory. This is the project root where `.claude/security/profile.json` will be created. Claude Code's cwd IS the project root — do NOT walk up directories or try to auto-detect it. Just show it to the user:

> Project root: `(pwd output)`
>
> Profile will be written to `.claude/security/profile.json` here.

No need to ask for confirmation — Claude Code always sets cwd correctly.

## Step 2: Read Profile & Ask Questions

Read `./.claude/security/profile.json` to check for existing config.

Ask using AskUserQuestion (all questions together):

**Enable safe-yes?** (header: "Enable"):
- `yes` — Enable the guard (recommended)
- `no` — Create profile but leave guard disabled
- `quit` — Exit without changes

**Security level** (header: "Security"):
- `normal` — LLM uncertain → native permission handles it
- `tolerant` — LLM uncertain → auto-allow (fewer prompts)
- `quit` — Exit without changes

**Custom prompt** (header: "Custom"):
- `none` — Use default safety rules, no custom prompt
- `keep current` — (only if existing profile has a custom_prompt) Keep it unchanged
- `quit` — Exit without changes

If user picks `quit` on any question, stop.

**Constraints**: each question MUST have >=2 options in the `options` array. "quit" always counts. For the Custom question: when no existing profile, use `["none", "quit"]`; when existing has custom_prompt, use `["none", "keep current", "quit"]`. Users can always type a custom value via the "Other" input — never add "custom text" as a literal option.

## Step 3: Apply & Done

```bash
echo '{"project_root":"(pwd)","security_level":"<level>","custom_prompt":"<prompt>","enabled":<true|false>}' | python ${CLAUDE_PLUGIN_ROOT}/scripts/init_profile.py --apply
```

Then:

> safe-yes is active!
>
> - Status: `enabled` (guard active) or `disabled` (pass-through)
> - Level: `normal` (passthrough to native when unsure) or `tolerant` (auto-allow when unsure)
> - Profile: `.claude/security/profile.json` · Hooks: in plugin
>
> Run `/reload-plugins` to activate · `/safe-yes:status` for statistics
