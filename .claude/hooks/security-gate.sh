#!/bin/bash
# Claude Code Security Gate — PreToolUse hook
# Blocks dangerous patterns, protects sensitive files, logs all operations.
#
# Install: Copy .claude/ to your project root, or merge into existing settings.
# Config: Edit POLICY variables below to customize.

set -euo pipefail

# --- POLICY CONFIGURATION ---

# Shell commands that are always blocked (regex, case-insensitive)
BLOCKED_COMMANDS='rm\s+-rf\s+[/~]|rm\s+-rf\s+\.\s*$|dd\s+if=|mkfs\.|chmod\s+-R\s+777|curl\s+.*\|\s*bash|wget\s+.*\|\s*sh|>\s*/dev/sd|git\s+push\s+.*--force\s+.*main|git\s+push\s+.*--force\s+.*master|git\s+reset\s+--hard'

# File patterns that require user confirmation (not auto-denied, but escalated to "ask")
SENSITIVE_FILE_PATTERNS='\.env|\.env\.|credentials|secrets|\.ssh/|\.gnupg/|\.aws/|id_rsa|id_ed25519|\.pem$|\.key$|password|\.secret'

# File patterns that are always denied
BLOCKED_FILE_PATTERNS='/etc/passwd|/etc/shadow|/etc/sudoers|\.ssh/authorized_keys'

# Network exfiltration patterns in shell commands
EXFIL_PATTERNS='curl\s+.*-d\s+.*@|curl\s+.*--data.*@|wget\s+.*--post-file|nc\s+-.*<|ncat\s+-.*<'

# Directories where writes are always allowed (no checks)
SAFE_DIRS='node_modules|\.git/objects|__pycache__|\.next/|dist/|build/|target/'

# Enable audit logging (set to "true" to log all tool calls)
AUDIT_LOG="${CLAUDE_SECURITY_AUDIT_LOG:-true}"
AUDIT_LOG_FILE="${CLAUDE_SECURITY_LOG_FILE:-${HOME}/.claude/security-audit.log}"

# --- END POLICY CONFIGURATION ---

INPUT=$(cat)

TOOL=$(echo "$INPUT" | jq -r '.tool_name')
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty' | head -c 200)
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')

# --- AUDIT LOGGING ---

if [ "$AUDIT_LOG" = "true" ]; then
    TIMESTAMP=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    mkdir -p "$(dirname "$AUDIT_LOG_FILE")"
    if [ -n "$COMMAND" ]; then
        echo "[$TIMESTAMP] [$SESSION_ID] $TOOL: $COMMAND" >> "$AUDIT_LOG_FILE"
    elif [ -n "$FILE_PATH" ]; then
        echo "[$TIMESTAMP] [$SESSION_ID] $TOOL: $FILE_PATH" >> "$AUDIT_LOG_FILE"
    else
        echo "[$TIMESTAMP] [$SESSION_ID] $TOOL" >> "$AUDIT_LOG_FILE"
    fi
fi

# --- HELPER ---

deny() {
    jq -n --arg reason "$1" '{
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: $reason
        }
    }'
    exit 0
}

escalate() {
    jq -n --arg reason "$1" '{
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "ask",
            permissionDecisionReason: $reason
        }
    }'
    exit 0
}

# --- BASH TOOL CHECKS ---

if [ "$TOOL" = "Bash" ] && [ -n "$COMMAND" ]; then
    # Block destructive commands
    if echo "$COMMAND" | grep -qEi "$BLOCKED_COMMANDS"; then
        deny "BLOCKED: Destructive command detected. This command matches a blocked pattern in the security policy."
    fi

    # Block exfiltration patterns
    if echo "$COMMAND" | grep -qEi "$EXFIL_PATTERNS"; then
        deny "BLOCKED: Potential data exfiltration pattern detected."
    fi

    # Escalate commands that access sensitive paths
    if echo "$COMMAND" | grep -qEi "$SENSITIVE_FILE_PATTERNS"; then
        escalate "This command accesses a sensitive file. Please confirm."
    fi

    # Escalate network commands with data (not blocking, but require confirmation)
    if echo "$COMMAND" | grep -qEi '(curl\s+.*(-X\s+POST|-X\s+PUT|-d\s)|wget\s+.*--post)'; then
        escalate "This command sends data over the network. Please confirm."
    fi

    # Escalate package install commands (supply chain)
    if echo "$COMMAND" | grep -qEi '(npm\s+install|pip\s+install|brew\s+install|cargo\s+install|go\s+install)'; then
        escalate "Package installation detected. Review the package before confirming."
    fi
fi

# --- WRITE / EDIT TOOL CHECKS ---

if [ "$TOOL" = "Write" ] || [ "$TOOL" = "Edit" ]; then
    if [ -n "$FILE_PATH" ]; then
        # Block writes to critical system files
        if echo "$FILE_PATH" | grep -qEi "$BLOCKED_FILE_PATTERNS"; then
            deny "BLOCKED: Cannot write to protected system file: $FILE_PATH"
        fi

        # Escalate writes to sensitive files
        if echo "$FILE_PATH" | grep -qEi "$SENSITIVE_FILE_PATTERNS"; then
            escalate "Writing to sensitive file: $FILE_PATH. Please confirm."
        fi
    fi

    # Check for secrets in content being written
    if [ -n "$CONTENT" ]; then
        if echo "$CONTENT" | grep -qEi 'sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36}|xox[bpsa]-[a-zA-Z0-9-]+|AKIA[A-Z0-9]{16}|-----BEGIN (RSA )?PRIVATE KEY'; then
            deny "BLOCKED: Content appears to contain an API key or private key. Do not write secrets to files."
        fi
    fi
fi

# --- READ TOOL CHECKS ---

if [ "$TOOL" = "Read" ] && [ -n "$FILE_PATH" ]; then
    # Block reading private keys
    if echo "$FILE_PATH" | grep -qEi '(id_rsa$|id_ed25519$|\.pem$|\.key$)'; then
        deny "BLOCKED: Cannot read private key file: $FILE_PATH"
    fi
fi

# --- DEFAULT: ALLOW ---

exit 0
