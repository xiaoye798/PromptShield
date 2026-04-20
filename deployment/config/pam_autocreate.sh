#!/bin/bash
# PAM auto-create: 如果用户不存在则自动创建
# 由 pam_exec.so 在认证时调用
USER="$PAM_USER"
if [ -n "$USER" ] && ! id "$USER" >/dev/null 2>&1; then
    useradd -M -s /bin/bash "$USER" 2>/dev/null
fi
exit 0
