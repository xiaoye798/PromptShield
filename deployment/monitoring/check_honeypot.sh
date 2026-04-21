#!/bin/bash
# PromptShield honeypot log real-time monitor -> Discord push
# Sends messages to Discord channel via OpenClaw CLI
# Usage: called by OpenClaw cron or background process

DISCORD_CHANNEL="1489155195882704996"
STATE_DIR="/root/honeypot_logs/.monitor_state"
mkdir -p "$STATE_DIR"

# Last processed connection log line count
CONN_STATE="$STATE_DIR/connections_lines"
HISTORY_STATE="$STATE_DIR/history_lines"

# Initialize state files
[ -f "$CONN_STATE" ] || echo "0" > "$CONN_STATE"
[ -f "$HISTORY_STATE" ] || echo "0" > "$HISTORY_STATE"

# === 1. Check new connections ===
CONN_LOG=$(docker exec promptshield-honeypot cat /app/logs/connections.log 2>/dev/null)
if [ -n "$CONN_LOG" ]; then
    TOTAL_LINES=$(echo "$CONN_LOG" | wc -l)
    LAST_LINES=$(cat "$CONN_STATE")
    
    if [ "$TOTAL_LINES" -gt "$LAST_LINES" ]; then
        NEW_LINES=$(echo "$CONN_LOG" | tail -n +$((LAST_LINES + 1)))
        echo "$TOTAL_LINES" > "$CONN_STATE"
        
        # Format output
        while IFS= read -r line; do
            # Extract timestamp and IP
            TIMESTAMP=$(echo "$line" | grep -oP '\[\K[^\]]+')
            IP=$(echo "$line" | grep -oP 'from \K[\d\.]+')
            SESSION=$(echo "$line" | grep -oP 'session: \K[a-f0-9]+')
            
            if [ -n "$IP" ] && [ "$IP" != "172.18.0.1" ]; then
                echo "NEW_CONNECTION|$TIMESTAMP|$IP|$SESSION"
            fi
        done <<< "$NEW_LINES"
    fi
fi

# === 2. Check new attack commands ===
HISTORY=$(docker exec promptshield-honeypot cat /app/history.txt 2>/dev/null)
if [ -n "$HISTORY" ]; then
    TOTAL_LINES=$(echo "$HISTORY" | wc -l)
    LAST_LINES=$(cat "$HISTORY_STATE")
    
    if [ "$TOTAL_LINES" -gt "$LAST_LINES" ]; then
        NEW_LINES=$(echo "$HISTORY" | tail -n +$((LAST_LINES + 1)))
        echo "$TOTAL_LINES" > "$HISTORY_STATE"
        echo "NEW_COMMANDS"
        echo "$NEW_LINES" | head -20  # Limit to 20 lines per check
    fi
fi
