---
description: Enable safe-yes guard
allowed-tools: Bash
---

# Enable safe-yes

```bash
python ${CLAUDE_PLUGIN_ROOT}/scripts/toggle.py --enable
```

Print the JSON output's `message` field, then:

> Run `/reload-plugins` if hooks were just registered.
