# Claude Code Security Hooks

Drop-in security policy for [Claude Code](https://code.claude.com/) using the hooks system. Blocks dangerous commands, protects sensitive files, detects secret leaks, and logs everything.

## What It Does

| Check | Action | Examples |
|-------|--------|---------|
| Destructive shell commands | **Block** | `rm -rf /`, `dd if=`, `git push --force main` |
| Data exfiltration patterns | **Block** | `curl -d @secrets.json`, `nc < /etc/passwd` |
| Pipe-to-shell installs | **Block** | `curl ... \| bash`, `wget ... \| sh` |
| Secret content in writes | **Block** | Writing `sk-...` API keys, private keys to files |
| Private key reads | **Block** | Reading `id_rsa`, `.pem`, `.key` files |
| Protected system files | **Block** | Writing to `/etc/passwd`, `/etc/shadow`, `.ssh/authorized_keys` |
| Sensitive file access | **Escalate** | `.env`, `credentials`, `.aws/`, `.ssh/` — asks user to confirm |
| Network data sends | **Escalate** | `curl -X POST`, `wget --post` — asks user to confirm |
| Package installs | **Escalate** | `npm install`, `pip install`, `brew install` — asks user to confirm |
| All tool calls | **Log** | Every Bash, Write, Edit, Read call → `~/.claude/security-audit.log` |

**Block** = denied immediately, Claude gets feedback.
**Escalate** = normal permission prompt shown to user.

## Install

### Option 1: Copy to your project

```bash
# From your project root:
cp -r /path/to/claude-code-security-hooks/.claude .
```

### Option 2: Clone and symlink

```bash
git clone https://github.com/echo-lumen/claude-code-security-hooks.git ~/.claude-security-hooks
ln -s ~/.claude-security-hooks/.claude/hooks .claude/hooks
```

Then merge the hook config into your existing `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/security-gate.sh", "timeout": 10 }]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [{ "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/security-gate.sh", "timeout": 10 }]
      },
      {
        "matcher": "Read",
        "hooks": [{ "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/security-gate.sh", "timeout": 10 }]
      }
    ]
  }
}
```

### Option 3: Global install

Copy the hook to `~/.claude/hooks/` and update `~/.claude/settings.json` to apply across all projects.

## Configuration

Edit the policy variables at the top of `security-gate.sh`:

```bash
# Shell commands that are always blocked
BLOCKED_COMMANDS='(rm\s+-rf\s+[/~]|dd\s+if=|...)'

# File patterns that require user confirmation
SENSITIVE_FILE_PATTERNS='(.env|credentials|\.ssh/|...)'

# File patterns that are always denied
BLOCKED_FILE_PATTERNS='(/etc/passwd|/etc/shadow|...)'

# Enable/disable audit logging
AUDIT_LOG="true"
AUDIT_LOG_FILE="${HOME}/.claude/security-audit.log"
```

Environment variable overrides:
- `CLAUDE_SECURITY_AUDIT_LOG=false` — disable logging
- `CLAUDE_SECURITY_LOG_FILE=/path/to/log` — custom log location

## How It Works

The hook runs as a `PreToolUse` handler. Claude Code calls it before executing any Bash, Write, Edit, or Read operation. The hook receives the tool name and arguments on stdin as JSON, evaluates them against the security policy, and returns one of:

- **Allow** (exit 0, no output) — tool proceeds normally
- **Deny** (exit 0, JSON with `permissionDecision: "deny"`) — tool blocked, Claude gets the reason
- **Ask** (exit 0, JSON with `permissionDecision: "ask"`) — user sees the normal confirmation prompt

This means the hook never silently drops operations — blocked actions produce visible feedback that Claude adjusts to.

## Audit Log

When enabled, every tool call is logged to `~/.claude/security-audit.log`:

```
[2026-03-10T15:30:00Z] [session123] Bash: npm test
[2026-03-10T15:30:05Z] [session123] Write: src/index.ts
[2026-03-10T15:30:10Z] [session123] Bash: rm -rf /tmp/build
```

## What It Doesn't Do

- **No network monitoring.** It checks command patterns, not actual traffic.
- **No runtime sandboxing.** It's a gate, not a jail. If you allow a command, it runs with full permissions.
- **No MCP tool coverage.** It gates built-in tools (Bash, Write, Edit, Read). MCP tool calls need separate matchers — add `mcp__.*` matchers if needed.

For MCP server security, see [mcp-security-scan](https://github.com/echo-lumen/mcp-security-scan).

## Requirements

- Claude Code with hooks support
- `jq` (for JSON output)
- `bash` (macOS/Linux)

## License

MIT
