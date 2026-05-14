"""Safe-Yes Decision Memory — stores and reuses historical command decisions."""
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

DANGER_WORDS = (
    '--force', '--delete', '-delete', '--hard',
    'rm -rf', 'drop', 'clear', '--purge', 'chmod 777',
)

_KEYWORD_STRIP_RE = re.compile(r'^[\d.]+$')
_PATH_RE = re.compile(r'[/\\]')


def _extract_keywords(command):
    """Extract normalized keywords from a command string.
    Keeps: command names, subcommands, non-path arguments.
    Drops: flags (-x/--flag), file paths, IPs, numbers."""
    tokens = command.split()
    keywords = []
    for t in tokens:
        if t.startswith('-'):
            continue
        if _KEYWORD_STRIP_RE.match(t):
            continue
        if _PATH_RE.search(t):
            continue
        if '@' in t:
            continue
        keywords.append(t.lower())
    return keywords


def _jaccard(set1, set2):
    if not set1 or not set2:
        return 0.0
    return len(set1 & set2) / len(set1 | set2)


def _has_danger_words(command):
    cmd_lower = command.lower()
    return any(w in cmd_lower for w in DANGER_WORDS)


def _load_memory(memory_path, ttl_days=30):
    """Load memory.jsonl entries, filtering out expired ones. Always returns a list."""
    records = []
    cutoff = datetime.now() - timedelta(days=ttl_days)
    if not memory_path.exists():
        return records
    try:
        with open(memory_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    last_hit = datetime.strptime(
                        rec.get('last_hit', '2000-01-01'), '%Y-%m-%d'
                    )
                    if last_hit >= cutoff:
                        records.append(rec)
                except (json.JSONDecodeError, ValueError, KeyError):
                    pass
    except OSError:
        pass
    return records


def _save_records(memory_path, records, max_entries=5000):
    """Save records to memory.jsonl. Evicts oldest (by last_hit) if over max_entries."""
    records.sort(key=lambda r: r.get('last_hit', '2000-01-01'), reverse=True)
    if len(records) > max_entries:
        records = records[:max_entries]
    try:
        memory_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = memory_path.with_suffix('.jsonl.tmp')
        with open(tmp_path, 'w', encoding='utf-8') as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        os.replace(tmp_path, memory_path)
    except OSError:
        pass


def check_memory(command, cwd, profile):
    """Check if command matches a historical decision.
    Returns ('allow', reason) if matched, None if no match or memory disabled."""
    mem_cfg = profile.get('memory', {})
    if not mem_cfg.get('enabled', True):
        return None
    if _has_danger_words(command):
        return None

    memory_path = Path(cwd).resolve() / '.claude' / 'security' / 'memory.jsonl'
    ttl_days = mem_cfg.get('ttl_days', 30)
    threshold = mem_cfg.get('similarity_threshold', 0.8)
    max_entries = mem_cfg.get('max_entries', 5000)

    records = _load_memory(memory_path, ttl_days)
    if not records:
        return None

    new_keywords = set(_extract_keywords(command))

    # Layer 1: exact match
    for rec in records:
        if rec.get('cmd') == command:
            rec['hit_count'] = rec.get('hit_count', 0) + 1
            rec['last_hit'] = datetime.now().strftime('%Y-%m-%d')
            _save_records(memory_path, records, max_entries)
            if rec['hit_count'] >= AUTO_PROMOTE_THRESHOLD:
                _auto_promote_to_rules(command, cwd)
            return ('allow', f"[Memory] exact match: {command[:60]}, hits={rec['hit_count']}")

    # Layer 2: keyword overlap
    best_score = 0.0
    best_rec = None
    for rec in records:
        rec_keywords = set(rec.get('keywords', []))
        score = _jaccard(new_keywords, rec_keywords)
        if score > best_score:
            best_score = score
            best_rec = rec

    if best_score >= threshold and best_rec:
        best_rec['hit_count'] = best_rec.get('hit_count', 0) + 1
        best_rec['last_hit'] = datetime.now().strftime('%Y-%m-%d')
        _save_records(memory_path, records, max_entries)
        if best_rec['hit_count'] >= AUTO_PROMOTE_THRESHOLD:
            _auto_promote_to_rules(command, cwd)
        return ('allow', f"[Memory] keyword match {int(best_score * 100)}%: {best_rec['cmd'][:40]}, hits={best_rec['hit_count']}")

    return None


def write_memory(command, decision, cwd, source='llm', profile=None):
    """Write a new decision to memory.jsonl. Updates hit_count if duplicate exists."""
    mem_cfg = (profile or {}).get('memory', {})
    max_entries = mem_cfg.get('max_entries', 5000)
    memory_path = Path(cwd).resolve() / '.claude' / 'security' / 'memory.jsonl'

    # ttl_days=36500 (≈100 years) — load full history for deduplication, not TTL filtering
    existing = _load_memory(memory_path, ttl_days=36500)

    for rec in existing:
        if rec.get('cmd') == command:
            rec['hit_count'] = rec.get('hit_count', 0) + 1
            rec['last_hit'] = datetime.now().strftime('%Y-%m-%d')
            if source == 'user':
                rec['source'] = 'user'
            _save_records(memory_path, existing, max_entries)
            if rec['hit_count'] >= AUTO_PROMOTE_THRESHOLD:
                _auto_promote_to_rules(command, cwd)
            return

    record = {
        'cmd': command,
        'keywords': _extract_keywords(command),
        'decision': decision,
        'source': source,
        'hit_count': 0,
        'last_hit': datetime.now().strftime('%Y-%m-%d'),
    }
    existing.append(record)
    _save_records(memory_path, existing, max_entries)


def add_pending(command, cwd):
    """Record a command passed through to the user for approval (pending.jsonl)."""
    pending_path = Path(cwd).resolve() / '.claude' / 'security' / 'pending.jsonl'
    try:
        pending_path.parent.mkdir(parents=True, exist_ok=True)
        with open(pending_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps({
                "cmd": command,
                "ts": datetime.now().strftime('%H:%M:%S'),
            }, ensure_ascii=False) + '\n')
    except OSError:
        pass


def consume_pending(command, cwd):
    """Check if command was pending user approval and remove it from pending.
    Returns True if found (user approved), False otherwise."""
    pending_path = Path(cwd).resolve() / '.claude' / 'security' / 'pending.jsonl'
    if not pending_path.exists():
        return False
    records = []
    found = False
    try:
        with open(pending_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get('cmd') == command and not found:
                        found = True
                    else:
                        records.append(rec)
                except json.JSONDecodeError:
                    pass
        tmp = pending_path.with_suffix('.jsonl.tmp')
        with open(tmp, 'w', encoding='utf-8') as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        os.replace(tmp, pending_path)
    except OSError:
        pass
    return found


AUTO_PROMOTE_THRESHOLD = 5
_AUTO_PROMOTE_PRIORITY = 210


def _auto_promote_to_rules(command, cwd):
    """Add a frequently-hit command as a custom YES rule in profile.json.
    Idempotent — skips if an identical pattern already exists."""
    profile_path = Path(cwd).resolve() / '.claude' / 'security' / 'profile.json'
    if not profile_path.exists():
        return

    keywords = _extract_keywords(command)
    if not keywords:
        return
    escaped = [re.escape(k) for k in keywords if len(k) >= 3]
    if not escaped:
        return
    pattern = '.*'.join(escaped)

    try:
        profile_data = json.loads(profile_path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return

    custom_rules = profile_data.get('custom_rules', [])
    for rule in custom_rules:
        if rule.get('pattern') == pattern:
            return

    custom_rules.append({
        'priority': _AUTO_PROMOTE_PRIORITY,
        'pattern': pattern,
        'decision': 'yes',
        'reason': f'Auto-promoted: {command[:80]}',
    })
    profile_data['custom_rules'] = custom_rules

    tmp = profile_path.with_suffix('.json.tmp')
    try:
        tmp.write_text(json.dumps(profile_data, indent=2, ensure_ascii=False),
                       encoding='utf-8')
        os.replace(str(tmp), str(profile_path))
    except OSError:
        pass
