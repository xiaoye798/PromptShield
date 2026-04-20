#!/bin/bash
# PromptShield 蜜罐日志实时监控 → Discord 推送
# 通过 OpenClaw CLI 发送消息到 Discord 频道
# 用法: 由 OpenClaw cron 或后台进程调用

DISCORD_CHANNEL="1489155195882704996"
STATE_DIR="/root/honeypot_logs/.monitor_state"
mkdir -p "$STATE_DIR"

# 上次处理的连接日志行数
CONN_STATE="$STATE_DIR/connections_lines"
HISTORY_STATE="$STATE_DIR/history_lines"

# 初始化状态文件
[ -f "$CONN_STATE" ] || echo "0" > "$CONN_STATE"
[ -f "$HISTORY_STATE" ] || echo "0" > "$HISTORY_STATE"

# === 1. 检查新连接 ===
CONN_LOG=$(docker exec promptshield-honeypot cat /app/logs/connections.log 2>/dev/null)
if [ -n "$CONN_LOG" ]; then
    TOTAL_LINES=$(echo "$CONN_LOG" | wc -l)
    LAST_LINES=$(cat "$CONN_STATE")
    
    if [ "$TOTAL_LINES" -gt "$LAST_LINES" ]; then
        NEW_LINES=$(echo "$CONN_LOG" | tail -n +$((LAST_LINES + 1)))
        echo "$TOTAL_LINES" > "$CONN_STATE"
        
        # 格式化输出
        while IFS= read -r line; do
            # 提取时间和 IP
            TIMESTAMP=$(echo "$line" | grep -oP '\[\K[^\]]+')
            IP=$(echo "$line" | grep -oP 'from \K[\d\.]+')
            SESSION=$(echo "$line" | grep -oP 'session: \K[a-f0-9]+')
            
            if [ -n "$IP" ] && [ "$IP" != "172.18.0.1" ]; then
                echo "NEW_CONNECTION|$TIMESTAMP|$IP|$SESSION"
            fi
        done <<< "$NEW_LINES"
    fi
fi

# === 2. 检查新的攻击命令 ===
HISTORY=$(docker exec promptshield-honeypot cat /app/history.txt 2>/dev/null)
if [ -n "$HISTORY" ]; then
    TOTAL_LINES=$(echo "$HISTORY" | wc -l)
    LAST_LINES=$(cat "$HISTORY_STATE")
    
    if [ "$TOTAL_LINES" -gt "$LAST_LINES" ]; then
        NEW_LINES=$(echo "$HISTORY" | tail -n +$((LAST_LINES + 1)))
        echo "$TOTAL_LINES" > "$HISTORY_STATE"
        echo "NEW_COMMANDS"
        echo "$NEW_LINES" | head -20  # 限制每次最多20行
    fi
fi
