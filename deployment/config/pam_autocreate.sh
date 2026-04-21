#!/bin/bash
# PAM auto-create: automatically create user if not exists
# Called by pam_exec.so during authentication
USER="$PAM_USER"
if [ -n "$USER" ] && ! id "$USER" >/dev/null 2>&1; then
    useradd -M -s /bin/bash "$USER" 2>/dev/null
fi
exit 0
