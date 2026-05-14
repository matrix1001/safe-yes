---
description: Disable safe-yes guard
allowed-tools: Bash
---

# Disable safe-yes

Temporarily disables the guard. Hooks stay registered but all commands pass through unchecked.

```bash
python ${CLAUDE_PLUGIN_ROOT}/scripts/toggle.py --disable
```

Print the JSON output's `message` field, then:

> Run `/safe-yes:enable` to re-enable.
