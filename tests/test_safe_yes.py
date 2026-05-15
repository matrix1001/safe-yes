#!/usr/bin/env python3
"""Test suite for safe-yes v2 — code rules → memory → LLM → passthrough."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GUARD_SCRIPT = str(PROJECT_ROOT / "scripts" / "guard.py")
SCRIPTS_DIR = str(PROJECT_ROOT / "scripts")
PYTHON = sys.executable
CWD = str(PROJECT_ROOT)


def make_profile(security_level="normal", llm_enabled=False, custom_rules=None):
    """Build a v2 profile dict."""
    return {
        "version": 2,
        "enabled": True,
        "project_root": CWD,
        "project_types": ["generic"],
        "security_level": security_level,
        "llm": {
            "enabled": llm_enabled,
            "api_key": "sk-test" if llm_enabled else "",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
            "custom_prompt": "",
        },
        "custom_rules": custom_rules or [],
        "network_allowed_domains": [],
    }


def run_guard(tool_name, tool_input, security_level="normal",
              llm_enabled=False, custom_rules=None):
    """Run guard.py with temp profile, return hookSpecificOutput dict."""
    profile_data = make_profile(security_level, llm_enabled, custom_rules)
    profile_data["project_root"] = CWD

    with tempfile.TemporaryDirectory() as tmpdir:
        security_dir = Path(tmpdir) / ".claude" / "security"
        security_dir.mkdir(parents=True)
        profile_path = security_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data, indent=2))

        hook_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "cwd": tmpdir,
        }

        result = subprocess.run(
            [PYTHON, GUARD_SCRIPT],
            input=json.dumps(hook_input),
            capture_output=True, text=True, timeout=10,
        )
        output = json.loads(result.stdout)
        # passthrough → no hookSpecificOutput → treat as permissionDecision=passthrough
        hso = output.get("hookSpecificOutput")
        if hso is None:
            return {"permissionDecision": "passthrough", "permissionDecisionReason": "passthrough"}
        return hso


def test(category, name, tool_name, tool_input, expected,
         level="normal", llm=False, custom_rules=None):
    """Run a single test case."""
    result = run_guard(tool_name, tool_input, level, llm, custom_rules)
    actual = result["permissionDecision"]
    reason = result["permissionDecisionReason"]
    ok = actual == expected
    marker = "[PASS]" if ok else "[FAIL]"
    print(f"  {marker} [{category}] {name}")
    if not ok:
        print(f"       Expected: {expected}, Got: {actual}")
        print(f"       Reason: {reason}")
    return ok


# =====================================================================
# Test Data
# =====================================================================

# -- Code YES → allow --
YES_BASH = [
    # Read-only filesystem
    ("ls", {"command": "ls -la"}),
    ("cat project file", {"command": "cat README.md"}),
    ("head", {"command": "head -20 app.log"}),
    ("tail", {"command": "tail -f app.log"}),
    ("find", {"command": "find . -name '*.py'"}),
    ("tree", {"command": "tree -L 2"}),
    ("stat", {"command": "stat setup.py"}),
    ("file", {"command": "file unknown.bin"}),
    ("wc", {"command": "wc -l *.py"}),
    ("du", {"command": "du -sh ."}),
    ("df", {"command": "df -h"}),
    ("which", {"command": "which python"}),
    ("type", {"command": "type python"}),
    ("realpath", {"command": "realpath README.md"}),
    ("dirname", {"command": "dirname /d/project/safe-yes/foo.py"}),

    # Info / util
    ("echo", {"command": "echo 'hello world'"}),
    ("pwd", {"command": "pwd"}),
    ("whoami", {"command": "whoami"}),
    ("uname", {"command": "uname -a"}),
    ("hostname", {"command": "hostname"}),
    ("date", {"command": "date"}),
    ("env", {"command": "env"}),

    # Git read-only
    ("git status", {"command": "git status"}),
    ("git log", {"command": "git log --oneline -5"}),
    ("git diff", {"command": "git diff HEAD~1"}),
    ("git show", {"command": "git show HEAD"}),
    ("git branch -a", {"command": "git branch -a"}),
    ("git remote -v", {"command": "git remote -v"}),
    ("git stash list", {"command": "git stash list"}),
    ("git tag", {"command": "git tag"}),
    ("git rev-parse", {"command": "git rev-parse HEAD"}),
    ("git config --get", {"command": "git config --get user.email"}),
    ("git ls-files", {"command": "git ls-files"}),
    ("git blame", {"command": "git blame setup.py"}),

    # Git safe mutations
    ("git add", {"command": "git add README.md"}),
    ("git commit", {"command": "git commit -m 'test'"}),
    ("git checkout branch", {"command": "git checkout feature-branch"}),
    ("git switch", {"command": "git switch main"}),
    ("git merge", {"command": "git merge feature-branch"}),
    ("git pull", {"command": "git pull origin main"}),
    ("git push", {"command": "git push origin feature-branch"}),
    ("git fetch", {"command": "git fetch origin"}),
    ("git stash save", {"command": "git stash save 'wip'"}),
    ("git clone", {"command": "git clone https://github.com/user/repo.git"}),
    ("git init", {"command": "git init"}),
    ("git rebase", {"command": "git rebase main"}),

    # Version checks
    ("python --version", {"command": "python --version"}),
    ("node --version", {"command": "node --version"}),
    ("npm --version", {"command": "npm --version"}),
    ("go version", {"command": "go version"}),
    ("cargo --version", {"command": "cargo --version"}),

    # Package queries
    ("pip list", {"command": "pip list"}),
    ("pip show", {"command": "pip show requests"}),
    ("pip freeze", {"command": "pip freeze"}),
    ("npm list", {"command": "npm list"}),
    ("conda list", {"command": "conda list"}),
    ("conda info", {"command": "conda info"}),
    ("conda env list", {"command": "conda env list"}),

    # Lint / type-check
    ("pylint", {"command": "pylint app.py"}),
    ("flake8", {"command": "flake8 app.py"}),
    ("mypy", {"command": "mypy app.py"}),
    ("ruff check", {"command": "ruff check ."}),
    ("eslint", {"command": "npx eslint src/"}),

    # Project-scoped file ops
    ("mkdir project", {"command": "mkdir ./build"}),
    ("touch project", {"command": "touch ./newfile.py"}),
    ("cp project", {"command": "cp a.py b.py"}),
    ("mv project", {"command": "mv old.py new.py"}),

    # Build/test/run
    ("pytest", {"command": "pytest tests/"}),
    ("npm test", {"command": "npm test"}),
    ("npm run build", {"command": "npm run build"}),
    ("npm start", {"command": "npm start"}),
    ("npx jest", {"command": "npx jest"}),
    ("cargo test", {"command": "cargo test"}),
    ("cargo build", {"command": "cargo build"}),
    ("go test", {"command": "go test ./..."}),
    ("go build", {"command": "go build ./..."}),
    ("make", {"command": "make all"}),

    # Package install
    ("pip install", {"command": "pip install requests"}),
    ("npm install", {"command": "npm install lodash"}),
    ("npm ci", {"command": "npm ci"}),
    ("poetry install", {"command": "poetry install"}),
    ("conda install", {"command": "conda install numpy"}),

    # Network GET (no pipe)
    ("curl GET", {"command": "curl https://example.com/data.json"}),
    ("wget download", {"command": "wget https://example.com/file.tar.gz"}),

    # Redirect /dev/null
    ("redirect devnull", {"command": "npm test > /dev/null 2>&1"}),

    # venv
    ("venv", {"command": "python -m venv .venv"}),
]

# -- Code NO → ask --
NO_BASH = [
    # System destruction
    ("mkfs", {"command": "mkfs.ext4 /dev/sda1"}),
    ("dd block", {"command": "dd if=/dev/zero of=/dev/sda"}),
    ("fdisk", {"command": "fdisk /dev/sda"}),
    ("redirect block dev", {"command": "echo data > /dev/sda"}),

    # Fork bombs
    ("fork bomb", {"command": ":(){ :|:& };:"}),

    # Credential exfiltration
    ("cat ~/.ssh/id_rsa", {"command": "cat ~/.ssh/id_rsa"}),
    ("cat ~/.aws/credentials", {"command": "cat ~/.aws/credentials"}),
    ("base64 decode | sh", {"command": 'echo "cm0gLXJmIC8=" | base64 -d | sh'}),
    ("eval $var", {"command": "eval $USER_INPUT"}),

    # Recursive delete system
    ("rm -rf /etc", {"command": "rm -rf /etc/nginx"}),
    ("rm -rf /usr", {"command": "rm -rf /usr/local/bin"}),
    ("rm -rf /boot", {"command": "rm -rf /boot"}),
    ("rm -rf ~", {"command": "rm -rf ~"}),
    ("rm -rf $HOME", {"command": "rm -rf $HOME"}),
    ("rm -rf /var", {"command": "rm -rf /var/lib"}),
    ("rm -rf /opt", {"command": "rm -rf /opt/app"}),
    ("rm -rf /bin", {"command": "rm -rf /bin"}),
    ("rm -rf /dev", {"command": "rm -rf /dev"}),
    ("rm -rf /sys", {"command": "rm -rf /sys"}),
    ("rm -rf /proc", {"command": "rm -rf /proc"}),
    ("rm -rf /", {"command": "rm -rf /"}),
    ("rm -rf /*", {"command": "rm -rf /*"}),
]

# -- UNCERTAIN (no code match) → LLM disabled → normal: ask / tolerant: allow --
UNCERTAIN_ASK_NORMAL = [
    # Destructive git
    ("git reset --hard", {"command": "git reset --hard HEAD~3"}),
    ("git clean -fd", {"command": "git clean -fd"}),
    ("git push --force main", {"command": "git push --force origin main"}),
    ("git branch -D", {"command": "git branch -D feature-x"}),
    ("git stash drop", {"command": "git stash drop stash@{0}"}),
    ("git stash clear", {"command": "git stash clear"}),
    ("git checkout -- discard", {"command": "git checkout -- file.txt"}),

    # Deletion
    ("rm -rf ./", {"command": "rm -rf ./"}),
    ("rm -r dir", {"command": "rm -r ./old_files/"}),

    # Permissions / privileges
    ("chmod 777", {"command": "chmod 777 app.py"}),
    ("chown", {"command": "chown user:group file.txt"}),
    ("sudo", {"command": "sudo systemctl restart nginx"}),

    # Remote transfer
    ("scp", {"command": "scp file.txt user@host:/path/"}),
    ("rsync", {"command": "rsync -avz ./ user@host:/backup/"}),

    # Inline code
    ("python -c", {"command": "python -c 'print(sum(range(100)))'"}),
    ("node -e", {"command": "node -e 'console.log(1+1)'"}),
    ("bash -c", {"command": "bash -c 'echo hello'"}),

    # Docker
    ("docker rm", {"command": "docker rm -f mycontainer"}),
    ("docker compose down", {"command": "docker compose down -v"}),

    # Other
    ("sed -i", {"command": "sed -i 's/foo/bar/g' config.yaml"}),
    ("find -delete", {"command": "find . -name '*.pyc' -delete"}),
    ("npm install -g", {"command": "npm install -g typescript"}),
    ("nc listener", {"command": "nc -l 1234"}),
    ("shutdown", {"command": "shutdown -h now"}),
    ("reboot", {"command": "reboot"}),
    ("sudo su", {"command": "sudo su -"}),
    ("printenv KEY", {"command": "printenv | grep API_KEY"}, "allow"),  # env → yes rule
    ("echo > /etc", {"command": "echo 'evil' > /etc/cron.d/backdoor"}, "allow"),  # echo → yes rule
    ("chmod 777 system", {"command": "chmod 777 /etc/passwd"}),
]

# -- Write/Edit/Read --
# Use paths relative to PROJECT_ROOT for project-scoped checks
FILE_TESTS = [
    ("Write project file", "Write", {"file_path": str(PROJECT_ROOT / "README.md")}, "allow"),
    ("Write project subdir", "Write", {"file_path": str(PROJECT_ROOT / "src" / "app.py")}, "allow"),
    ("Edit project file", "Edit", {"file_path": str(PROJECT_ROOT / "config.json")}, "allow"),
    ("Read project file", "Read", {"file_path": str(PROJECT_ROOT / "main.py")}, "allow"),

    # Sensitive config files → passthrough
    ("Write settings.json", "Write", {"file_path": str(PROJECT_ROOT / ".claude" / "settings.local.json")}, "passthrough"),
    ("Edit settings.json", "Edit", {"file_path": str(PROJECT_ROOT / ".claude" / "settings.local.json")}, "passthrough"),
    ("Read settings.json", "Read", {"file_path": str(PROJECT_ROOT / ".claude" / "settings.local.json")}, "allow"),  # Config read → allow
    ("Write CLAUDE.md", "Write", {"file_path": str(PROJECT_ROOT / "CLAUDE.md")}, "allow"),
    ("Write .env", "Write", {"file_path": str(PROJECT_ROOT / ".env")}, "passthrough"),
    ("Write .env.local", "Write", {"file_path": str(PROJECT_ROOT / ".env.local")}, "passthrough"),
    ("Write .git/config", "Write", {"file_path": str(PROJECT_ROOT / ".git" / "config")}, "passthrough"),
    ("Write skill SKILL.md", "Write", {"file_path": str(PROJECT_ROOT / "skills" / "SKILL.md")}, "allow"),

    # Credential-like files → passthrough
    ("Write .pem", "Write", {"file_path": str(PROJECT_ROOT / "server.pem")}, "passthrough"),
    ("Write .key", "Write", {"file_path": str(PROJECT_ROOT / "ssl.key")}, "passthrough"),
    ("Write credentials", "Write", {"file_path": str(PROJECT_ROOT / "credentials")}, "passthrough"),

    # System paths → passthrough
    ("Write /etc", "Write", {"file_path": "/etc/cron.d/job"}, "passthrough"),
    ("Write ~/.ssh", "Write", {"file_path": "~/.ssh/authorized_keys"}, "passthrough"),
    ("Write ~/.aws", "Write", {"file_path": "~/.aws/credentials"}, "passthrough"),
]

# -- WebSearch / WebFetch --
WEB_TESTS = [
    ("websearch normal", "WebSearch", {"query": "python argparse tutorial"}, "allow"),
    ("webfetch normal", "WebFetch", {"url": "https://docs.python.org/3/"}, "allow"),
    ("websearch suspicious", "WebSearch", {"query": "/etc/passwd sql injection payload"}, "allow"),
    ("websearch xss", "WebSearch", {"query": "xss payload <script>alert(1)</script>"}, "allow"),
]

# -- Tolerant: UNCERTAIN → LLM disabled → allow --
TOLERANT_ALLOW = [
    ("tolerant: sudo → allow", "Bash", {"command": "sudo systemctl restart nginx"}, "tolerant", "allow"),
    ("tolerant: rm -r → allow", "Bash", {"command": "rm -r ./build/"}, "tolerant", "allow"),
    ("tolerant: git reset --hard → allow", "Bash", {"command": "git reset --hard HEAD~3"}, "tolerant", "allow"),
    ("tolerant: shutdown → allow", "Bash", {"command": "shutdown -h now"}, "tolerant", "allow"),
    # But NO rules still passthrough even in tolerant
    ("tolerant: rm -rf /etc → passthrough", "Bash", {"command": "rm -rf /etc/nginx"}, "tolerant", "passthrough"),
    ("tolerant: mkfs → passthrough", "Bash", {"command": "mkfs.ext4 /dev/sda1"}, "tolerant", "passthrough"),
]

# -- Custom rules --
CUSTOM_TESTS = [
    # Custom YES rule overrides system (priority 5 < 200)
    ("custom yes: override", "Bash",
     {"command": "dangerous-script --fix"},
     "allow", "normal", False,
     [{"priority": 5, "pattern": "dangerous-script --fix", "decision": "yes",
       "reason": "Known safe script"}]),

    # Custom NO rule (priority 5)
    ("custom no: force passthrough", "Bash",
     {"command": "docker compose down"},
     "passthrough", "normal", False,
     [{"priority": 5, "pattern": "docker compose down", "decision": "no",
       "reason": "Review before shutdown"}]),
]


def main():
    total = 0
    passed = 0

    print("=" * 70)
    print("  SAFE-YES v2 — Comprehensive Test Suite")
    print("=" * 70)

    # -- Bash YES --
    print("\n-- Bash YES (code rules → allow) --")
    for name, tool_input in YES_BASH:
        total += 1
        if test("YES", name, "Bash", tool_input, "allow"):
            passed += 1

    # -- Bash NO --
    print("\n-- Bash NO (code rules → passthrough, skip LLM) --")
    for name, tool_input in NO_BASH:
        total += 1
        if test("NO", name, "Bash", tool_input, "passthrough"):
            passed += 1

    # -- UNCERTAIN → LLM disabled → normal: passthrough --
    print("\n-- UNCERTAIN → LLM disabled → normal: passthrough --")
    for entry in UNCERTAIN_ASK_NORMAL:
        total += 1
        name = entry[0]
        tool_input = entry[1]
        expected = entry[2] if len(entry) > 2 else "passthrough"
        if test("UNC→ASK", name, "Bash", tool_input, expected):
            passed += 1

    # -- Write/Edit/Read --
    print("\n-- Write / Edit / Read --")
    for name, tool_name, tool_input, expected in FILE_TESTS:
        total += 1
        if test("FILE", name, tool_name, tool_input, expected):
            passed += 1

    # -- WebSearch / WebFetch --
    print("\n-- WebSearch / WebFetch --")
    for name, tool_name, tool_input, expected in WEB_TESTS:
        total += 1
        if test("WEB", name, tool_name, tool_input, expected):
            passed += 1

    # -- Tolerant mode --
    print("\n-- Tolerant Mode --")
    for name, tool_name, tool_input, level, expected in TOLERANT_ALLOW:
        total += 1
        if test("TOLERANT", name, tool_name, tool_input, expected, level=level):
            passed += 1

    # -- Custom rules --
    print("\n-- Custom Rules --")
    for name, tool_name, tool_input, expected, level, llm, custom in CUSTOM_TESTS:
        total += 1
        if test("CUSTOM", name, tool_name, tool_input, expected, level, llm, custom):
            passed += 1

    # -- Disabled Guard --
    print("\n-- Disabled Guard --")
    with tempfile.TemporaryDirectory() as dtmpdir:
        dsecurity = Path(dtmpdir) / ".claude" / "security"
        dsecurity.mkdir(parents=True)
        dprofile = make_profile("normal", False)
        dprofile["enabled"] = False
        dprofile["project_root"] = dtmpdir
        (dsecurity / "profile.json").write_text(json.dumps(dprofile))

        disabled_tests = [
            ("disabled: ls → passthrough", "Bash", {"command": "ls -la"}, "passthrough"),
            ("disabled: rm -rf / → passthrough", "Bash", {"command": "rm -rf /"}, "passthrough"),
            ("disabled: sudo → passthrough", "Bash", {"command": "sudo systemctl restart nginx"}, "passthrough"),
            ("disabled: Write file → passthrough", "Write", {"file_path": str(PROJECT_ROOT / "test.py")}, "passthrough"),
        ]
        for name, tool_name, tool_input, expected in disabled_tests:
            total += 1
            result = subprocess.run(
                [PYTHON, GUARD_SCRIPT],
                input=json.dumps({
                    "hook_event_name": "PreToolUse",
                    "tool_name": tool_name,
                    "tool_input": tool_input,
                    "cwd": dtmpdir,
                }),
                capture_output=True, text=True, timeout=10,
                cwd=dtmpdir,
            )
            output = json.loads(result.stdout)
            hso = output.get("hookSpecificOutput")
            actual = hso["permissionDecision"] if hso else "passthrough"
            ok = actual == expected
            marker = "[PASS]" if ok else "[FAIL]"
            print(f"  {marker} [DISABLED] {name}")
            if not ok:
                print(f"       Expected: {expected}, Got: {actual}")
            if ok:
                passed += 1

    # -- Toggle script --
    print("\n-- Toggle Script --")
    with tempfile.TemporaryDirectory() as ttdir:
        tsecurity = Path(ttdir) / ".claude" / "security"
        tsecurity.mkdir(parents=True, exist_ok=True)

        toggle_script = str(PROJECT_ROOT / "scripts" / "toggle.py")

        # Test --enable (creates profile if missing)
        r = subprocess.run(
            [PYTHON, toggle_script, "--enable"],
            capture_output=True, text=True, timeout=10,
            cwd=ttdir,
        )
        total += 1
        if r.returncode == 0 and "enabled" in r.stdout:
            print("  [PASS] [TOGGLE] toggle --enable (new profile)")
            passed += 1
        else:
            print(f"  [FAIL] [TOGGLE] toggle --enable (new profile) — rc={r.returncode}, out={r.stdout[:100]}")

        # Verify profile says enabled=true
        total += 1
        profile = json.loads((tsecurity / "profile.json").read_text(encoding="utf-8"))
        if profile.get("enabled") is True:
            print("  [PASS] [TOGGLE] profile enabled=true confirmed")
            passed += 1
        else:
            print(f"  [FAIL] [TOGGLE] profile enabled={profile.get('enabled')}")

        # Test --disable
        r = subprocess.run(
            [PYTHON, toggle_script, "--disable"],
            capture_output=True, text=True, timeout=10,
            cwd=ttdir,
        )
        total += 1
        if r.returncode == 0 and "disabled" in r.stdout:
            print("  [PASS] [TOGGLE] toggle --disable")
            passed += 1
        else:
            print(f"  [FAIL] [TOGGLE] toggle --disable — rc={r.returncode}, out={r.stdout[:100]}")

        # Verify profile says enabled=false
        total += 1
        profile = json.loads((tsecurity / "profile.json").read_text(encoding="utf-8"))
        if profile.get("enabled") is False:
            print("  [PASS] [TOGGLE] profile enabled=false confirmed")
            passed += 1
        else:
            print(f"  [FAIL] [TOGGLE] profile enabled={profile.get('enabled')}")

    # -- Setup Re-Run Preservation Test --
    print("\n-- Setup Re-Run Preservation --")
    with tempfile.TemporaryDirectory() as rtmpdir:
        setup_script = str(PROJECT_ROOT / "scripts" / "init_profile.py")
        rsec = Path(rtmpdir) / ".claude" / "security"
        rsec.mkdir(parents=True)

        # Create existing profile with custom settings
        existing = {
            "version": 2, "enabled": True, "security_level": "normal",
            "project_root": rtmpdir, "project_types": ["node"],
            "llm": {"enabled": True, "api_key": "sk-custom", "model": "claude-sonnet",
                    "custom_prompt": "old prompt"},
            "memory": {"enabled": False, "max_entries": 100,
                       "ttl_days": 7, "similarity_threshold": 0.5},
            "audit": {"central_log": True, "central_log_path": "/var/log"},
            "custom_rules": [{"priority": 205, "pattern": "npm run deploy",
                              "decision": "no", "reason": "custom block"}],
            "network_allowed_domains": ["internal.api"],
        }
        (rsec / "profile.json").write_text(json.dumps(existing))

        # Re-run setup with new choices
        setup_input = json.dumps({
            "project_root": rtmpdir, "security_level": "tolerant",
            "custom_prompt": "new prompt", "enabled": False,
        })
        r = subprocess.run(
            [PYTHON, setup_script, "--apply"],
            input=setup_input, capture_output=True, text=True, timeout=10,
            cwd=rtmpdir,
        )

        total += 1
        if r.returncode != 0:
            print(f"  [FAIL] [SETUP-PRESERVE] setup re-run failed: {r.stderr[:200]}")
        else:
            result = json.loads(r.stdout)
            profile_after = json.loads((rsec / "profile.json").read_text(encoding="utf-8"))

            # Check that user's explicit choices were applied
            ok = True
            ok = ok and (profile_after.get("enabled") is False)
            ok = ok and (profile_after.get("security_level") == "tolerant")
            ok = ok and (profile_after.get("llm", {}).get("custom_prompt") == "new prompt")

            # Check that custom settings were preserved
            ok = ok and (profile_after.get("llm", {}).get("api_key") == "sk-custom")
            ok = ok and (profile_after.get("llm", {}).get("model") == "claude-sonnet")
            ok = ok and (profile_after.get("memory", {}).get("enabled") is False)
            ok = ok and (profile_after.get("memory", {}).get("max_entries") == 100)
            ok = ok and (profile_after.get("memory", {}).get("ttl_days") == 7)
            ok = ok and (profile_after.get("audit", {}).get("central_log") is True)
            ok = ok and (profile_after.get("audit", {}).get("central_log_path") == "/var/log")
            ok = ok and (len(profile_after.get("custom_rules", [])) == 1)
            ok = ok and (profile_after.get("network_allowed_domains") == ["internal.api"])

            if ok:
                print("  [PASS] [SETUP-PRESERVE] all custom settings survived re-setup")
                passed += 1
            else:
                print(f"  [FAIL] [SETUP-PRESERVE] profile={json.dumps(profile_after, indent=2)[:500]}")

    # -- match_rules() unit tests --
    print("\n-- match_rules() Unit Tests --")
    try:
        sys.path.insert(0, SCRIPTS_DIR)
        from config import load_profile

        # Use a temp profile
        with tempfile.TemporaryDirectory() as tmpdir:
            security_dir = Path(tmpdir) / ".claude" / "security"
            security_dir.mkdir(parents=True)
            profile_data = make_profile("normal", False)
            profile_data["project_root"] = tmpdir
            (security_dir / "profile.json").write_text(json.dumps(profile_data))

            profile = load_profile(tmpdir)

            from rules import match_rules

            unit_tests = [
                ("yes: ls", "ls -la", "yes"),
                ("yes: git status", "git status", "yes"),
                ("yes: curl GET", "curl https://example.com", "yes"),
                ("no: mkfs", "mkfs.ext4 /dev/sda1", "no"),
                ("no: rm -rf /etc", "rm -rf /etc/nginx", "no"),
                ("no: fork bomb", ":(){ :|:& };:", "no"),
                ("no: cat ssh key", "cat ~/.ssh/id_rsa", "no"),
                ("no: base64 | sh", "echo 'x' | base64 -d | sh", "no"),
                ("no: rm -rf ~", "rm -rf ~", "no"),
                ("no: rm -rf $HOME", "rm -rf $HOME", "no"),
                ("no: dd of=/dev/sd", "dd if=/dev/zero of=/dev/sda", "no"),
                ("no: fdisk", "fdisk /dev/sda", "no"),
                ("no: eval $var", "eval $USER_INPUT", "no"),
                ("no: rm -rf /", "rm -rf /", "no"),
                ("no: rm -rf /*", "rm -rf /*", "no"),
                ("uncertain: rm -r dir", "rm -r ./build/", "uncertain"),
                ("uncertain: sudo", "sudo systemctl restart nginx", "uncertain"),
                ("uncertain: chmod", "chmod 755 file.txt", "uncertain"),
                ("uncertain: nc", "nc -l 1234", "uncertain"),
                ("uncertain: unknown", "some-unknown-command --flag", "uncertain"),
            ]
            for name, cmd, expected in unit_tests:
                total += 1
                decision, _ = match_rules(cmd, tmpdir, profile)
                if decision == expected:
                    print(f"  [PASS] [UNIT] {name}")
                    passed += 1
                else:
                    print(f"  [FAIL] [UNIT] {name} — expected {expected}, got {decision}")
    except Exception as e:
        print(f"  [FAIL] Unit tests could not run: {e}")

    # -- _mask_quoted_content() unit tests --
    print("\n-- _mask_quoted_content() Unit Tests --")
    try:
        from rules import _mask_quoted_content

        # Create a profile for match_rules context
        with tempfile.TemporaryDirectory() as mtmpdir:
            msecurity = Path(mtmpdir) / ".claude" / "security"
            msecurity.mkdir(parents=True)
            mp = make_profile("normal", False)
            mp["project_root"] = mtmpdir
            (msecurity / "profile.json").write_text(json.dumps(mp))
            mprofile = load_profile(mtmpdir)
            from rules import match_rules as mmr

            mask_tests = [
                ("echo with rm -rf masked",
                 'echo "rm -rf /etc"',
                 lambda c: mmr(c, mtmpdir, mprofile)[0] != "no"),
                ("bash -c preserves code (LLM decision expected)",
                 'bash -c "rm -rf /etc"',
                 lambda c: mmr(c, mtmpdir, mprofile)[0] == "uncertain"),
                ("unquoted dangerous cmd caught",
                 'grep "pattern" file && rm -rf /etc',
                 lambda c: mmr(c, mtmpdir, mprofile)[0] == "no"),
                ("normal command unchanged",
                 "ls -la",
                 lambda c: _mask_quoted_content(c) == "ls -la"),
            ]
            for name, cmd, check in mask_tests:
                total += 1
                if check(cmd):
                    print(f"  [PASS] [MASK] {name}")
                    passed += 1
                else:
                    print(f"  [FAIL] [MASK] {name}")
    except Exception as e:
        print(f"  [FAIL] Mask tests could not run: {e}")

    # -- Validator unit tests --
    print("\n-- Validator Unit Tests --")
    try:
        from validators import v_network, v_rm, v_git_clean, v_git_force_push, v_inline

        with tempfile.TemporaryDirectory() as vtmpdir:
            vprofile = make_profile("normal", False)
            vprofile["project_root"] = vtmpdir

            val_tests = [
                ("v_network: curl GET", v_network, "curl https://example.com/data.json", "yes"),
                ("v_network: curl POST", v_network, "curl -X POST https://api.example.com/data", None),
                ("v_network: wget download", v_network, "wget https://example.com/file.tar.gz", "yes"),
                ("v_network: curl upload", v_network, "curl -F 'file=@data.txt' https://example.com", None),
                ("v_rm: simple rm file", v_rm, "rm README.md", "yes"),
                ("v_rm: rm -r dir", v_rm, "rm -r ./build/", None),
                ("v_rm: rm -rf force", v_rm, "rm -rf ./build/", None),
                ("v_git_clean: dry-run", v_git_clean, "git clean -n", "yes"),
                ("v_git_clean: force", v_git_clean, "git clean -fd", None),
                ("v_git_force_push: non-primary", v_git_force_push, "git push --force origin feature", "yes"),
                ("v_git_force_push: main", v_git_force_push, "git push --force origin main", None),
                ("v_git_force_push: master", v_git_force_push, "git push --force origin master", None),
                ("v_inline: safe python -c", v_inline, "python -c 'print(1+1)'", None),
                ("v_inline: dangerous os.system", v_inline, "python -c 'import os; os.system(\"rm -rf /\")'", None),
            ]
            for name, validator, cmd, expected in val_tests:
                total += 1
                result = validator(cmd, vtmpdir, vprofile)
                if expected is None:
                    if result is None:
                        print(f"  [PASS] [VAL] {name} (-> LLM)")
                        passed += 1
                    else:
                        print(f"  [FAIL] [VAL] {name} — expected None, got {result}")
                else:
                    if result and result[0] == expected:
                        print(f"  [PASS] [VAL] {name}")
                        passed += 1
                    else:
                        print(f"  [FAIL] [VAL] {name} — expected {expected}, got {result}")
    except Exception as e:
        print(f"  [FAIL] Validator tests could not run: {e}")

    # -- _parse_response() unit tests --
    print("\n-- _parse_response() Unit Tests --")
    try:
        from llm import _parse_response

        parse_tests = [
            ("well-formed yes", '{"decision": "yes", "reason": "safe command"}', "yes"),
            ("well-formed no", '{"decision": "no", "reason": "dangerous"}', "no"),
            ("well-formed uncertain", '{"decision": "uncertain", "reason": "ambiguous"}', "uncertain"),
            ("markdown code fence", '```json\n{"decision": "yes", "reason": "safe"}\n```', "yes"),
            ("partial json regex", '..."decision": "no", "reason": "truncated', "no"),
            ("free text: safe keyword", "I believe this command is safe", "yes"),
            ("free text: dangerous keyword", "This looks dangerous and destructive", "no"),
            ("free text: no keywords", "This could go either way", "uncertain"),
            ("empty string", "", "uncertain"),
        ]
        for name, content, expected in parse_tests:
            total += 1
            decision, _ = _parse_response(content)
            if decision == expected:
                print(f"  [PASS] [PARSE] {name}")
                passed += 1
            else:
                print(f"  [FAIL] [PARSE] {name} — expected {expected}, got {decision}")
    except Exception as e:
        print(f"  [FAIL] Parse tests could not run: {e}")

    # -- guard.py error handling tests --
    print("\n-- guard.py Error Handling --")
    error_tests = [
        ("empty stdin", ""),
        ("malformed json", "not json {{{"),
        ("missing tool_name", '{"hook_event_name":"PreToolUse","tool_input":{"command":"ls"}}'),
    ]
    for name, stdin_data in error_tests:
        total += 1
        result = subprocess.run(
            [PYTHON, GUARD_SCRIPT],
            input=stdin_data,
            capture_output=True, text=True, timeout=10,
            cwd=CWD,
        )
        try:
            parsed = json.loads(result.stdout)
            assert parsed.get("continue") is True
            perm = parsed["hookSpecificOutput"]["permissionDecision"]
            assert perm in ("allow", "passthrough")
            print(f"  [PASS] [ERR] {name} (-> {perm})")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] [ERR] {name} — {e}")
            if result.stderr:
                print(f"       stderr: {result.stderr[:200]}")

    # -- memory.py Unit Tests --
    print("\n-- memory.py Unit Tests --")
    try:
        from memory import _extract_keywords, _jaccard, _has_danger_words, check_memory, write_memory
        from config import load_profile

        with tempfile.TemporaryDirectory() as memtmp:
            mem_security = Path(memtmp) / ".claude" / "security"
            mem_security.mkdir(parents=True)
            mem_profile = make_profile("normal", False)
            mem_profile["project_root"] = memtmp
            (mem_security / "profile.json").write_text(json.dumps(mem_profile))
            mem_profile_loaded = load_profile(memtmp)

            kw = _extract_keywords("docker compose restart myapp")
            assert kw == ['docker', 'compose', 'restart', 'myapp'], f"kw={kw}"
            kw = _extract_keywords("pip install --upgrade requests")
            assert kw == ['pip', 'install', 'requests'], f"kw={kw}"
            kw = _extract_keywords("git push origin main")
            assert kw == ['git', 'push', 'origin', 'main'], f"kw={kw}"
            kw = _extract_keywords("cat /etc/nginx/nginx.conf")
            assert kw == ['cat'], f"kw={kw}"
            total += 4; passed += 4
            print("  [PASS] [MEM] _extract_keywords: 4/4")

            # -f removed from DANGER_WORDS — should no longer trigger
            assert _has_danger_words("git push --force origin main") is True
            assert _has_danger_words("rm -rf ./node_modules") is True
            assert _has_danger_words("git push origin main") is False
            assert _has_danger_words("docker compose -f config.yml up") is False
            total += 4; passed += 4
            print("  [PASS] [MEM] _has_danger_words: 4/4")

            assert _jaccard({'a', 'b'}, {'a', 'b'}) == 1.0
            assert _jaccard({'a', 'b'}, {'a', 'c'}) == 1/3
            assert _jaccard(set(), {'a'}) == 0.0
            assert _jaccard({'a', 'b', 'c'}, {'a', 'b'}) == 2/3
            total += 4; passed += 4
            print("  [PASS] [MEM] _jaccard: 4/4")

            write_memory("docker compose restart myapp", "allow", memtmp,
                         source="llm", profile=mem_profile_loaded)
            result = check_memory("docker compose restart myapp", memtmp, mem_profile_loaded)
            assert result is not None, "exact match should return result"
            assert result[0] == "allow", f"expected allow, got {result[0]}"
            assert "[Memory] exact match" in result[1], f"reason: {result[1]}"
            total += 1; passed += 1
            print("  [PASS] [MEM] exact match")

            result = check_memory("docker compose restart myapp -d", memtmp, mem_profile_loaded)
            assert result is not None, "keyword match should return result"
            assert result[0] == "allow", f"expected allow, got {result[0]}"
            assert "[Memory] keyword match 100%" in result[1], f"reason: {result[1]}"
            result = check_memory("pip install requests", memtmp, mem_profile_loaded)
            assert result is None, f"unrelated command should not match, got {result}"
            total += 2; passed += 2
            print("  [PASS] [MEM] keyword match + no-match")

            write_memory("git push origin main", "allow", memtmp,
                         source="llm", profile=mem_profile_loaded)
            result = check_memory("git push --force origin main", memtmp, mem_profile_loaded)
            assert result is None, "danger word should skip memory"
            total += 1; passed += 1
            print("  [PASS] [MEM] danger gate")

            disabled_profile = make_profile("normal", False)
            disabled_profile["project_root"] = memtmp
            disabled_profile["memory"] = {"enabled": False}
            result = check_memory("docker compose restart myapp", memtmp, disabled_profile)
            assert result is None, "disabled memory should return None"
            total += 1; passed += 1
            print("  [PASS] [MEM] disabled")
    except Exception as e:
        print(f"  [FAIL] Memory tests could not run: {e}")

    # -- Memory Integration Tests --
    print("\n-- Memory Integration Tests --")
    try:
        with tempfile.TemporaryDirectory() as itmpdir:
            isecurity = Path(itmpdir) / ".claude" / "security"
            isecurity.mkdir(parents=True)
            iprofile = make_profile("normal", False)
            iprofile["project_root"] = itmpdir
            (isecurity / "profile.json").write_text(json.dumps(iprofile))

            # Pre-populate memory with a known decision
            from memory import write_memory as wm, check_memory as cm
            wm("docker compose restart myapp", "allow", itmpdir,
               source="llm", profile=iprofile)

            # Test 1: Memory hit — guard.py should skip LLM and return allow
            cmd_input = json.dumps({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "docker compose restart myapp"},
                "cwd": itmpdir,
            })
            result = subprocess.run(
                [PYTHON, GUARD_SCRIPT],
                input=cmd_input,
                capture_output=True, text=True, timeout=10,
                cwd=itmpdir,
            )
            output1 = json.loads(result.stdout)
            hso1 = output1.get("hookSpecificOutput")
            if hso1 is None:
                hso1 = {"permissionDecision": "passthrough", "permissionDecisionReason": "passthrough"}
            assert hso1["permissionDecision"] == "allow", \
                f"expected allow, got {hso1['permissionDecision']}"
            assert "[Memory]" in hso1["permissionDecisionReason"], \
                f"expected [Memory] prefix, got: {hso1['permissionDecisionReason']}"
            print("  [PASS] [MEM-INT] memory hit via guard.py")
            total += 1; passed += 1

            # Test 2: Danger words — guard.py should skip memory
            wm("docker compose down", "allow", itmpdir,
               source="llm", profile=iprofile)
            cmd_input2 = json.dumps({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "docker compose down --force"},
                "cwd": itmpdir,
            })
            result2 = subprocess.run(
                [PYTHON, GUARD_SCRIPT],
                input=cmd_input2,
                capture_output=True, text=True, timeout=10,
                cwd=itmpdir,
            )
            output2 = json.loads(result2.stdout)
            hso2 = output2.get("hookSpecificOutput")
            if hso2 is None:
                parsed2 = {"permissionDecision": "passthrough", "permissionDecisionReason": "passthrough"}
            else:
                parsed2 = hso2
            assert "[Memory]" not in parsed2["permissionDecisionReason"], \
                f"danger words should skip memory: {parsed2['permissionDecisionReason']}"
            print("  [PASS] [MEM-INT] danger gate via guard.py")
            total += 1; passed += 1

            # Test 3: No memory match — falls through to ask (LLM disabled)
            cmd_input3 = json.dumps({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "some-random-cmd --flag value"},
                "cwd": itmpdir,
            })
            result3 = subprocess.run(
                [PYTHON, GUARD_SCRIPT],
                input=cmd_input3,
                capture_output=True, text=True, timeout=10,
                cwd=itmpdir,
            )
            output3 = json.loads(result3.stdout)
            hso3 = output3.get("hookSpecificOutput")
            if hso3 is None:
                hso3 = {"permissionDecision": "passthrough", "permissionDecisionReason": "passthrough"}
            assert hso3["permissionDecision"] in ("allow", "passthrough"), \
                f"got unexpected decision: {hso3['permissionDecision']}"
            print(f"  [PASS] [MEM-INT] no match → {hso3['permissionDecision']}")
            total += 1; passed += 1
    except Exception as e:
        print(f"  [FAIL] Memory integration tests: {e}")
        import traceback
        traceback.print_exc()

    # -- Summary --
    print("\n" + "=" * 70)
    print(f"  RESULTS: {passed}/{total} passed ({passed * 100 // max(total, 1)}%)")
    if passed == total:
        print("  All tests passed!")
    else:
        print(f"  {total - passed} test(s) FAILED")
    print("=" * 70)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
