import re
import os
import shlex
from typing import List, Dict, Any, Optional, Tuple
from .event_graph import EventType, EventStatus, StateChange

class CommandAnalyzer:
    """Analyze commands and output to determine state changes (Comprehensive Version for T2 Test Suite)"""
    
    def determine_event_type(self, command: str) -> EventType:
        """Determine event type"""
        command_lower = command.lower().strip()
        parts = command_lower.split()
        if not parts:
            return EventType.COMMAND_EXECUTION
            
        cmd = parts[0]
        
        file_ops = {
            "touch", "echo", "cat", "ls", "mkdir", "rm", "cp", "mv", 
            "nano", "vi", "vim", "sed", "awk", "chmod", "chown", "ln",
            "truncate", "dd", "tar", "gzip", "gunzip"
        }
        user_ops = {"useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd", "chage", "su", "sudo", "id", "whoami"}
        service_ops = {"systemctl", "service", "init.d", "update-rc.d", "journalctl", "supervisorctl", "pm2"}
        pkg_ops = {"apt", "apt-get", "yum", "dnf", "pip", "pip3", "npm", "git", "dpkg", "rpm", "cargo", "gem", "composer", "make", "wget", "curl"}
        net_ops = {"ifconfig", "ip", "route", "iptables", "ufw", "nft", "nc", "netstat", "ss", "ping", "dig", "nslookup", "ip6tables"}
        cron_ops = {"crontab", "at", "anacron"}
        kernel_ops = {"sysctl", "modprobe", "lsmod", "insmod", "rmmod", "ulimit", "dmesg", "setenforce", "getenforce"}
        db_ops = {"mysql", "psql", "sqlite3", "mongo", "redis-cli"}
        
        if cmd in file_ops: return EventType.FILE_OPERATION
        if cmd in user_ops: return EventType.USER_OPERATION
        if cmd in service_ops: return EventType.SERVICE_OPERATION
        if cmd in pkg_ops: return EventType.PACKAGE_OPERATION
        if cmd in cron_ops: return EventType.CRON_OPERATION
        if cmd in net_ops: return EventType.NETWORK_OPERATION
        if cmd in kernel_ops: return EventType.KERNEL_OPERATION # Need to add KERNEL_OPERATION to EventType enum if not exists, or map to closest
        if cmd in db_ops: return EventType.DB_OPERATION # Same here
        
        return EventType.COMMAND_EXECUTION
    
    def determine_status(self, command: str, output: str) -> EventStatus:
        """Determine execution status"""
        error_indicators = [
            "command not found", "permission denied", "no such file",
            "cannot create", "cannot access", "error", "failed",
            "is a directory", "not a directory", "syntax error",
            "invalid option", "usage:", "illegal option", "fatal:",
            "could not", "unable to", "doesn't exist"
        ]
        
        output_lower = output.lower()
        for indicator in error_indicators:
            if indicator in output_lower:
                return EventStatus.FAILED
        
        return EventStatus.SUCCESS

    def _resolve_path(self, path: str, cwd: str) -> str:
        """Resolve path to absolute path"""
        if not path:
            return cwd
        
        if path.startswith("~"):
            path = path.replace("~", "/root", 1)
        
        if os.path.isabs(path):
            return os.path.normpath(path).replace("\\", "/")
            
        full_path = os.path.join(cwd, path)
        return os.path.normpath(full_path).replace("\\", "/")

    def _parse_args(self, command: str) -> List[str]:
        """Use shlex to parse command line arguments, handling quotes"""
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    def _split_compound_commands(self, command_str: str) -> List[str]:
        """
        Quote-aware compound command splitting
        
        Find && or ; delimiters outside of quotes to split commands into multiple subcommands.
        Inside quotes, ; or && are not treated as delimiters.
        """
        commands = []
        current_cmd = []
        i = 0
        in_single_quote = False
        in_double_quote = False
        escape_next = False
        
        while i < len(command_str):
            char = command_str[i]
            
            # Handle escape
            if escape_next:
                current_cmd.append(char)
                escape_next = False
                i += 1
                continue
            
            if char == '\\':
                escape_next = True
                current_cmd.append(char)
                i += 1
                continue
            
            # Toggle quote status
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                current_cmd.append(char)
                i += 1
                continue
            
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                current_cmd.append(char)
                i += 1
                continue
            
            # Only check for delimiters outside of quotes
            if not in_single_quote and not in_double_quote:
                # Check ' && '
                if command_str[i:i+4] == ' && ':
                    cmd = ''.join(current_cmd).strip()
                    if cmd:
                        commands.append(cmd)
                    current_cmd = []
                    i += 4
                    continue
                
                # Check ' ; '
                if command_str[i:i+3] == ' ; ':
                    cmd = ''.join(current_cmd).strip()
                    if cmd:
                        commands.append(cmd)
                    current_cmd = []
                    i += 3
                    continue
                
                # Check single ';' (but not '; ' which is already handled)
                if char == ';':
                    cmd = ''.join(current_cmd).strip()
                    if cmd:
                        commands.append(cmd)
                    current_cmd = []
                    i += 1
                    continue
            
            current_cmd.append(char)
            i += 1
        
        # Add the last command
        cmd = ''.join(current_cmd).strip()
        if cmd:
            commands.append(cmd)
        
        return commands

    def analyze_state_changes(self, command: str, output: str, cwd: str = "/root", system_state: Any = None) -> List[StateChange]:
        """Comprehensive analysis of state changes caused by commands
        
        Note: For honeypot systems, we analyze state changes based on command intent,
        rather than relying on LLM output. This ensures that even if the LLM returns an error message,
        state changes are still correctly recorded (as the attacker's command "should have" succeeded).
        """
        changes = []
        command_str = command.strip()
        if not command_str:
            return changes
        
        # Handle compound commands using quote-aware splitting
        sub_commands = self._split_compound_commands(command_str)
        
        if len(sub_commands) > 1:
            # Multiple subcommands, analyzing one by one
            for sub_cmd in sub_commands:
                if sub_cmd:
                    sub_changes = self._analyze_single_command(sub_cmd, output, cwd, system_state)
                    changes.extend(sub_changes)
            return changes
        
        # 单个命令
        return self._analyze_single_command(command_str, output, cwd, system_state)
    
    def _analyze_single_command(self, command_str: str, output: str, cwd: str, system_state: Any) -> List[StateChange]:
        """Analyze state changes of a single command"""
        changes = []
        
        # Comment: No longer checking output status, as the honeypot needs to record command intent
        # status = self.determine_status(command, output)
        # if status == EventStatus.FAILED:
        #     return changes

        # Check for pipe/redirection first (simplified)
        # echo "..." | command -> handle complex
        # We process simple redirections here, complex pipes are hard
        
        # Special handling: Piping to crontab command
        if "| crontab" in command_str:
            # Extract crontab part
            crontab_part = command_str.split("|")[-1].strip()
            crontab_parts = self._parse_args(crontab_part)
            if crontab_parts and crontab_parts[0] == "crontab":
                return self._handle_cron_ops("crontab", crontab_parts, command_str)
        
        # Check for real redirections (using quote-aware parser)
        # This fixes the issue where > inside quotes was misidentified
        real_redirections = self._find_real_redirections(command_str)
        if real_redirections and "| crontab" not in command_str:
            return self._handle_redirection(command_str, cwd, system_state)
            
        parts = self._parse_args(command_str)
        if not parts:
            return changes
            
        cmd = parts[0]
        
        # Dispatchers
        if cmd in ["touch", "mkdir", "rm", "cp", "mv", "ln", "chmod", "chown", "truncate", "dd"]:
            changes.extend(self._handle_file_ops(cmd, parts, cwd, system_state))
        elif cmd == "sed":
            changes.extend(self._handle_sed(command_str, parts, cwd, system_state))
        elif cmd in ["useradd", "userdel", "usermod", "groupadd", "passwd", "chage"]:
            changes.extend(self._handle_user_ops(cmd, parts, system_state))
        elif cmd in ["systemctl", "service", "update-rc.d"]:
            changes.extend(self._handle_service_ops(cmd, parts, system_state))
        elif cmd in ["apt", "apt-get", "pip", "npm", "git", "dpkg", "cargo", "make", "wget", "curl"]:
            changes.extend(self._handle_package_ops(cmd, parts, command_str))
        elif cmd in ["ip", "iptables", "nft", "route"]:
            changes.extend(self._handle_network_ops(cmd, parts, command_str))
        elif cmd in ["crontab", "at"]:
            changes.extend(self._handle_cron_ops(cmd, parts, command_str))
        elif cmd in ["sysctl", "modprobe", "ulimit", "setenforce"]:
            changes.extend(self._handle_kernel_ops(cmd, parts, command_str))
            
        return changes

    def _find_real_redirections(self, command_str: str) -> List[Dict[str, Any]]:
        r"""
        Find real redirection operators in the command (ignoring those inside quotes)
        
        Parsing with a state machine, correctly handling:
        - > inside single quotes '...' is not a redirection
        - > inside double quotes "..." is not a redirection
        - File descriptor redirections like 2>/dev/null, 2>&1, >&2, etc.
        - Escaped character \> is not a redirection
        
        Return format: [{'type': '>' or '>>', 'position': int, 'target': str}]
        """
        redirections = []
        i = 0
        in_single_quote = False
        in_double_quote = False
        escape_next = False
        
        while i < len(command_str):
            char = command_str[i]
            
            # Handle escape characters
            if escape_next:
                escape_next = False
                i += 1
                continue
            
            if char == '\\' and not in_single_quote:
                escape_next = True
                i += 1
                continue
            
            # Handle quote status
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                i += 1
                continue
            
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                i += 1
                continue
            
            # Only check for redirections outside of quotes
            if not in_single_quote and not in_double_quote and char == '>':
                # Check if it is a file descriptor redirection
                
                # Check for >& pattern (e.g., >& /dev/tcp/... or >&2)
                if i + 1 < len(command_str) and command_str[i + 1] == '&':
                    # Skip >& pattern (file descriptor redirection)
                    i += 2
                    continue
                
                # Check for digit> pattern (e.g., 2>/dev/null)
                if i > 0 and command_str[i - 1].isdigit():
                    # This is stderr/other fd redirection, skip
                    i += 1
                    continue
                
                # Check >> (append) vs > (overwrite)
                if i + 1 < len(command_str) and command_str[i + 1] == '>':
                    # It is >> append redirection
                    target = self._extract_redirection_target(command_str, i + 2)
                    if target:
                        redirections.append({
                            'type': '>>',
                            'position': i,
                            'target': target
                        })
                    i += 2
                    continue
                else:
                    # It is > overwrite redirection
                    target = self._extract_redirection_target(command_str, i + 1)
                    if target:
                        redirections.append({
                            'type': '>',
                            'position': i,
                            'target': target
                        })
                    i += 1
                    continue
            
            i += 1
        
        return redirections

    def _extract_redirection_target(self, command_str: str, start_pos: int) -> Optional[str]:
        """Extract target path after the redirection operator"""
        rest = command_str[start_pos:].lstrip()
        if not rest:
            return None
        
        # If it is a file descriptor reference (e.g., &1, &2), return None
        if rest.startswith('&'):
            return None
        
        # Extract path (until space, pipe, semicolon, &&, etc.)
        target = []
        i = 0
        in_single_quote = False
        in_double_quote = False
        escape_next = False
        
        while i < len(rest):
            char = rest[i]
            
            if escape_next:
                target.append(char)
                escape_next = False
                i += 1
                continue
            
            if char == '\\':
                escape_next = True
                i += 1
                continue
            
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                i += 1
                continue
            
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                i += 1
                continue
            
            # Stop when meeting a delimiter outside of quotes
            if not in_single_quote and not in_double_quote:
                if char in ' \t|;&':
                    break
            
            target.append(char)
            i += 1
        
        result = ''.join(target).strip()
        return result if result else None

    def _extract_echo_content(self, command_str: str, redirect_pos: int) -> str:
        """
        Extract content to be written from echo command
        
        Handle various complex situations:
        - echo 'content' > file
        - echo "content with $var" > file
        - echo -e "content\n" > file
        - echo 'content with > inside' > file
        """
        # Get the part before redirection
        lhs = command_str[:redirect_pos].strip()
        
        # Handle pipe cases: cmd1 | cmd2 > file
        if '|' in lhs:
            lhs = lhs.split('|')[-1].strip()
        
        if not lhs.lower().startswith('echo'):
            return ""
        
        # Remove the echo command itself
        echo_part = lhs[4:].strip()
        
        # Handle echo options (-e, -n, -E)
        while echo_part.startswith('-'):
            space_idx = echo_part.find(' ')
            if space_idx == -1:
                return ""
            option = echo_part[:space_idx]
            if option in ['-e', '-n', '-E', '-en', '-ne', '-nE']:
                echo_part = echo_part[space_idx:].strip()
            else:
                break
        
        # Extract content within quotes
        content = self._extract_quoted_content(echo_part)
        return content

    def _extract_quoted_content(self, text: str) -> str:
        """
        提取引号内的内容，处理嵌套引号和转义
        
        Support:
        - 'single quoted content'
        - "double quoted content"
        - $'ansi-c quoting'
        - Mixed content 'part1' "part2"
        """
        text = text.strip()
        
        if not text:
            return ""
        
        result = []
        i = 0
        
        while i < len(text):
            char = text[i]
            
            # Handle single-quoted strings
            if char == "'":
                end_quote = text.find("'", i + 1)
                if end_quote != -1:
                    result.append(text[i + 1:end_quote])
                    i = end_quote + 1
                    continue
                else:
                    # No closing single quote, take the remaining part
                    result.append(text[i + 1:])
                    break
            
            # Handle double-quoted strings
            elif char == '"':
                # Need to handle escapes inside double quotes
                content = []
                i += 1
                escape_next = False
                while i < len(text):
                    c = text[i]
                    if escape_next:
                        content.append(c)
                        escape_next = False
                        i += 1
                        continue
                    if c == '\\':
                        escape_next = True
                        i += 1
                        continue
                    if c == '"':
                        i += 1
                        break
                    content.append(c)
                    i += 1
                result.append(''.join(content))
                continue
            
            # Handle $'...' format (ANSI-C quoting)
            elif char == '$' and i + 1 < len(text) and text[i + 1] == "'":
                end_quote = text.find("'", i + 2)
                if end_quote != -1:
                    result.append(text[i + 2:end_quote])
                    i = end_quote + 1
                    continue
            
            # Skip spaces
            elif char in ' \t':
                i += 1
                continue
            
            # Other characters (content without quotes)
            else:
                word = []
                while i < len(text) and text[i] not in ' \t\'"':
                    word.append(text[i])
                    i += 1
                if word:
                    result.append(''.join(word))
                continue
        
        return ''.join(result)

    def _extract_heredoc_content(self, command_str: str) -> str:
        """
        Extract content from heredoc syntax
        
        Supported formats:
        - cat > file << 'EOF'
        - cat > file << EOF
        - cat > file << "EOF"
        - cat > file <<-EOF (with tab stripping)
        """
        import re
        
        # Find heredoc marker
        # Match the delimiter after << (may have quotes)
        heredoc_match = re.search(r'<<-?\s*([\'"]?)(\w+)\1', command_str)
        if not heredoc_match:
            return ""
        
        delimiter = heredoc_match.group(2)  # 例如 'EOF'
        
        # Find content after the delimiter
        # heredoc content follows the delimiter until a standalone delimiter line is encountered
        start_pos = heredoc_match.end()
        
        # Skip potential newlines
        while start_pos < len(command_str) and command_str[start_pos] in ' \t':
            start_pos += 1
        if start_pos < len(command_str) and command_str[start_pos] == '\n':
            start_pos += 1
        
        # Find the end delimiter
        end_pattern = re.compile(r'^' + re.escape(delimiter) + r'\s*$', re.MULTILINE)
        end_match = end_pattern.search(command_str, start_pos)
        
        if end_match:
            content = command_str[start_pos:end_match.start()]
            # Remove trailing newline
            content = content.rstrip('\n')
            return content
        else:
            # End delimiter not found, take until the end of command
            return command_str[start_pos:].strip()

    def _handle_redirection(self, command_str: str, cwd: str, system_state: Any) -> List[StateChange]:
        """
        Handle redirection commands, correctly parsing quotes and special characters
        
        Refixed issues:
        1. > inside quotes is no longer misidentified as redirection
        2. File descriptor redirections (2>&1, >&, 2>/dev/null) are correctly skipped
        3. Complex escape characters are correctly handled
        4. Supports heredoc syntax (<< EOF)
        """
        changes = []
        
        # First check if it is heredoc syntax
        import re
        heredoc_match = re.search(r'<<-?\s*([\'"]?)(\w+)\1', command_str)
        if heredoc_match:
            # 是 heredoc 语法
            content = self._extract_heredoc_content(command_str)
            
            # Find the redirection target
            redirections = self._find_real_redirections(command_str)
            if redirections:
                redir = redirections[-1]
                target_path = self._resolve_path(redir['target'], cwd)
                mode = "append" if redir['type'] == '>>' else "overwrite"
                
                # Special handling for systemd service files
                if target_path.startswith('/etc/systemd/system/') and target_path.endswith('.service'):
                    service_name = os.path.basename(target_path).replace('.service', '')
                    changes.append(StateChange(
                        target=target_path, 
                        change_type="create",
                        new_value=content,
                        metadata={"op": "heredoc_create", "service": service_name}
                    ))
                    return changes
                
                # General files
                changes.append(StateChange(
                    target=target_path,
                    change_type="create" if mode == "overwrite" else "modify",
                    new_value=content,
                    metadata={"op": f"heredoc_{mode}"}
                ))
                return changes
        
        # Non-heredoc syntax, using original logic
        # Find all real redirection operations
        redirections = self._find_real_redirections(command_str)
        
        if not redirections:
            return changes
        
        # Handle the last valid redirection (usually the primary file redirection)
        redir = redirections[-1]
        
        mode = "append" if redir['type'] == '>>' else "overwrite"
        target_path = self._resolve_path(redir['target'], cwd)
        
        # 提取内容
        content = ""
        lhs = command_str[:redir['position']].strip()
        
        # 处理管道的情况: cmd1 | cmd2 > file
        if '|' in lhs:
            lhs = lhs.split('|')[-1].strip()
        
        # Parse the left-side command to extract content
        if lhs.lower().startswith('echo'):
            content = self._extract_echo_content(command_str, redir['position'])
        elif lhs.lower().startswith('cat'):
            cat_args = self._parse_args(lhs)
            if len(cat_args) > 1:
                src_file = self._resolve_path(cat_args[1], cwd)
                if system_state and hasattr(system_state, 'filesystem') and system_state.filesystem.file_exists(src_file):
                    content = system_state.filesystem.get_file_content(src_file) or ""
        elif lhs.lower().startswith('printf'):
            # Handle printf command
            try:
                args = self._parse_args(lhs)
                if len(args) > 1:
                    content = args[1]  # Simple handling: take the format string
            except:
                pass
        
        # Special file handling
        if target_path == "/etc/hosts":
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\w\.-]+)", content)
            if match:
                changes.append(StateChange(
                    target="network:hosts", change_type="modify",
                    new_value={match.group(2): match.group(1)},
                    metadata={"op": "hosts_add"}
                ))
                return changes
        
        if target_path.startswith("/etc/cron.d/"):
            changes.append(StateChange(
                target=f"cron:file:{os.path.basename(target_path)}",
                change_type="create",
                new_value=content,
                metadata={"op": "cron_d_add"}
            ))
            return changes
        
        # Handle append mode
        if mode == "append" and system_state and hasattr(system_state, 'filesystem'):
            existing = system_state.filesystem.get_file_content(target_path)
            if existing:
                content = existing + "\n" + content
        
        changes.append(StateChange(
            target=target_path,
            change_type="modify" if mode == "append" else "create",
            new_value=content,
            metadata={"op": f"redirect_{mode}"}
        ))
        
        return changes

    def _handle_file_ops(self, cmd: str, parts: List[str], cwd: str, system_state: Any) -> List[StateChange]:
        changes = []
        args = [p for p in parts[1:] if not p.startswith("-")]
        
        if cmd == "touch":
            # Check for -t flag
            if "-t" in parts:
                # P-FSM-13: touch -t 202501010000 file
                t_idx = parts.index("-t")
                if len(parts) > t_idx + 2:
                    timestamp = parts[t_idx+1]
                    target = self._resolve_path(parts[t_idx+2], cwd)
                    # We don't really store mtime in detailed format, but we record the op
                    changes.append(StateChange(target=target, change_type="modify_attr", new_value={"mtime": timestamp}, metadata={"op": "touch_t"}))
            else:
                for arg in args:
                    path = self._resolve_path(arg, cwd)
                    if not (system_state and system_state.filesystem.file_exists(path)):
                        changes.append(StateChange(target=path, change_type="create", new_value="", metadata={"op": "touch"}))

        elif cmd == "mkdir":
            for arg in args:
                path = self._resolve_path(arg, cwd)
                changes.append(StateChange(target=path, change_type="create", new_value=None, metadata={"op": "mkdir", "is_dir": True}))
                # If -p, creates parents? system state handles dir creation implicitly usually

        elif cmd == "rm":
            for arg in args:
                path = self._resolve_path(arg, cwd)
                changes.append(StateChange(target=path, change_type="delete", new_value=None, metadata={"op": "rm"}))

        elif cmd == "cp":
            if len(args) >= 2:
                src = self._resolve_path(args[0], cwd)
                dst = self._resolve_path(args[-1], cwd)
                content = "[Copied Content]"
                if system_state:
                    content = system_state.filesystem.get_file_content(src) or ""
                changes.append(StateChange(target=dst, change_type="create", new_value=content, metadata={"op": "cp"}))

        elif cmd == "mv":
            if len(args) >= 2:
                src = self._resolve_path(args[0], cwd)
                dst = self._resolve_path(args[-1], cwd)
                content = None
                if system_state:
                    content = system_state.filesystem.get_file_content(src)
                changes.append(StateChange(target=src, change_type="delete", new_value=None, metadata={"op": "mv_src"}))
                changes.append(StateChange(target=dst, change_type="create", new_value=content or "[Moved Content]", metadata={"op": "mv_dst"}))

        elif cmd == "ln":
            # ln -s target link_name
            if "-s" in parts:
                # find args not starting with -
                link_args = [p for p in parts if not p.startswith("-") and p != "ln"]
                if len(link_args) >= 2:
                    target = link_args[0] # The file being pointed to
                    link_name = self._resolve_path(link_args[1], cwd)
                    # We store links as files with special content or attributes?
                    # For now, just a file with content "-> target"
                    changes.append(StateChange(target=link_name, change_type="create", new_value=f"-> {target}", metadata={"op": "ln_s", "link_target": target}))
            else:
                # Hard link (P-FSM-10)
                link_args = [p for p in parts if not p.startswith("-") and p != "ln"]
                if len(link_args) >= 2:
                    target = self._resolve_path(link_args[0], cwd)
                    link_name = self._resolve_path(link_args[1], cwd)
                    changes.append(StateChange(target=link_name, change_type="create", new_value="[HardLink]", metadata={"op": "ln_hard", "link_target": target}))

        elif cmd == "chmod":
            if len(args) >= 2:
                mode = args[0]
                target = self._resolve_path(args[1], cwd)
                changes.append(StateChange(target=target, change_type="modify_attr", new_value={"permissions": mode}, metadata={"op": "chmod"}))

        elif cmd == "chown":
            if len(args) >= 2:
                owner = args[0]
                target = self._resolve_path(args[1], cwd)
                changes.append(StateChange(target=target, change_type="modify_attr", new_value={"owner": owner}, metadata={"op": "chown"}))

        elif cmd == "truncate":
            # truncate -s 10G file
            if "-s" in parts:
                s_idx = parts.index("-s")
                if len(parts) > s_idx + 1:
                    size = parts[s_idx+1]
                    target = self._resolve_path(parts[-1], cwd)
                    changes.append(StateChange(target=target, change_type="create", new_value=f"[Sparse File {size}]", metadata={"op": "truncate"}))
        
        elif cmd == "dd":
            # dd if=... of=...
            of_arg = next((p for p in parts if p.startswith("of=")), None)
            if of_arg:
                target = self._resolve_path(of_arg.split("=")[1], cwd)
                changes.append(StateChange(target=target, change_type="create", new_value="[DD Content]", metadata={"op": "dd"}))

        return changes

    def _handle_sed(self, command_str: str, parts: List[str], cwd: str, system_state: Any) -> List[StateChange]:
        changes = []
        if "-i" not in parts: return changes
        
        # Extract s/old/new/
        match = re.search(r"s/([^/]+)/([^/]*)/([g]?)", command_str)
        if match:
            old, new, flag = match.groups()
            target_file = self._resolve_path(parts[-1], cwd)
            if system_state and hasattr(system_state, 'filesystem') and system_state.filesystem.file_exists(target_file):
                content = system_state.filesystem.get_file_content(target_file) or ""
                count = 0 if flag == "g" else 1
                new_content = re.sub(old, new, content, count=count)
                changes.append(StateChange(target=target_file, change_type="modify", new_value=new_content, metadata={"op": "sed"}))
            else:
                # Blind edit: Record modification even without system_state
                # Use the replaced value as new content (assuming the file only contains the replaced content)
                # This is particularly useful for echo "old" > file && sed -i 's/old/new/' file
                new_content = new  # Assume the entire content is the result of replacement
                changes.append(StateChange(
                    target=target_file, 
                    change_type="modify", 
                    new_value=new_content, 
                    metadata={"op": "sed_blind", "pattern": f"{old}->{new}"})
                )
        return changes

    def _handle_user_ops(self, cmd: str, parts: List[str], system_state: Any) -> List[StateChange]:
        changes = []
        
        # Smarter argument parsing: skip option values
        # For example "useradd -m -s /bin/bash backdoor_user"
        # Need to skip "/bin/bash" after "-s"
        option_with_values = {"-s", "-u", "-g", "-d", "-c", "-G", "-aG", "-e", "-f", "-k", "-K", "-p"}
        args = []
        skip_next = False
        for i, p in enumerate(parts[1:], start=1):
            if skip_next:
                skip_next = False
                continue
            if p.startswith("-"):
                # Check if this option requires a value
                if p in option_with_values:
                    skip_next = True
                continue
            args.append(p)
        
        if cmd == "useradd":
            if args:
                # Username is the last non-option argument
                username = args[-1] if args else None
                if username:
                    # Check flags: -u uid, -g gid, -d home, -s shell
                    user_info = {"uid": 1001, "gid": 1001, "home": f"/home/{username}", "shell": "/bin/bash"}
                    if "-u" in parts: user_info["uid"] = int(parts[parts.index("-u")+1])
                    if "-s" in parts: user_info["shell"] = parts[parts.index("-s")+1]
                    if "-r" in parts: user_info["uid"] = 999 # System user
                    changes.append(StateChange(target=f"user:{username}", change_type="create", new_value=user_info, metadata={"op": "useradd"}))
        
        elif cmd == "userdel":
            if args:
                changes.append(StateChange(target=f"user:{args[0]}", change_type="delete", new_value=None, metadata={"op": "userdel"}))

        elif cmd == "groupadd":
            if args:
                changes.append(StateChange(target=f"group:{args[0]}", change_type="create", new_value={}, metadata={"op": "groupadd"}))

        elif cmd == "usermod":
            # usermod -aG group user   (add to group)
            # usermod -s shell user    (modify shell)
            # usermod -L user          (lock account)
            # usermod -U user          (unlock account)
            if not args: return changes
            username = args[-1]
            mod_info = {}
            
            # Handle shell modification
            if "-s" in parts: 
                mod_info["shell"] = parts[parts.index("-s")+1]
            
            # Handle locking/unlocking
            if "-L" in parts: 
                mod_info["locked"] = True
            if "-U" in parts:
                mod_info["locked"] = False
            
            # Handle -G or -aG (append group)
            g_idx = -1
            if "-G" in parts:
                g_idx = parts.index("-G")
            elif "-aG" in parts:
                g_idx = parts.index("-aG")
            
            if g_idx >= 0 and g_idx + 1 < len(parts):
                groups = parts[g_idx + 1].split(",")
                mod_info["groups_add"] = groups
            
            changes.append(StateChange(target=f"user:{username}", change_type="modify", new_value=mod_info, metadata={"op": "usermod"}))

        elif cmd == "passwd":
            # echo 'pass' | passwd --stdin user
            # We assume user is last arg if present, else current user
            username = args[-1] if args else "root"
            changes.append(StateChange(target=f"user:{username}", change_type="modify", new_value={"password_changed": True}, metadata={"op": "passwd"}))

        elif cmd == "chage":
            # chage -E date user
            if "-E" in parts and args:
                username = args[-1]
                date = parts[parts.index("-E")+1]
                changes.append(StateChange(target=f"user:{username}", change_type="modify", new_value={"expire_date": date}, metadata={"op": "chage"}))

        return changes

    def _handle_service_ops(self, cmd: str, parts: List[str], system_state: Any) -> List[StateChange]:
        changes = []
        if cmd == "systemctl":
            # systemctl enable|start|stop|disable service
            action = parts[1] if len(parts) > 1 else ""
            svc = parts[2] if len(parts) > 2 else ""
            if svc.endswith(".service"): svc = svc[:-8]
            
            target = f"service:{svc}"
            if action == "enable":
                changes.append(StateChange(target=target, change_type="create", new_value={"enabled": True}, metadata={"op": "systemctl_enable"}))
            elif action == "disable":
                changes.append(StateChange(target=target, change_type="modify", new_value={"enabled": False}, metadata={"op": "systemctl_disable"}))
            elif action == "start":
                changes.append(StateChange(target=target, change_type="create", new_value={"status": "active"}, metadata={"op": "systemctl_start"}))
            elif action == "stop":
                changes.append(StateChange(target=target, change_type="modify", new_value={"status": "inactive"}, metadata={"op": "systemctl_stop"}))
            elif action == "daemon-reload":
                 # Scan for new unit files? P-SVC-05
                 pass
        
        elif cmd == "service":
            # service name action
            if len(parts) >= 3:
                svc = parts[1]
                action = parts[2]
                target = f"service:{svc}"
                if action == "start":
                    changes.append(StateChange(target=target, change_type="create", new_value={"status": "active"}, metadata={"op": "service_start"}))
                elif action == "stop":
                    changes.append(StateChange(target=target, change_type="modify", new_value={"status": "inactive"}, metadata={"op": "service_stop"}))

        return changes

    def _handle_package_ops(self, cmd: str, parts: List[str], command_str: str) -> List[StateChange]:
        changes = []
        args = [p for p in parts if not p.startswith("-") and p != cmd]
        
        if cmd in ["apt", "apt-get"] and "install" in parts:
            pkgs = [p for p in args if p != "install"]
            for pkg in pkgs:
                changes.append(StateChange(target=f"package:{pkg}", change_type="install", new_value={"manager": "apt"}, metadata={"op": "apt_install"}))
        
        elif cmd == "pip" and "install" in parts:
            pkgs = [p for p in args if p != "install" and "." not in p] # simple filter
            for pkg in pkgs:
                changes.append(StateChange(target=f"package:{pkg}", change_type="install", new_value={"manager": "pip"}, metadata={"op": "pip_install"}))
        
        elif cmd == "npm" and "install" in parts:
            pkgs = [p for p in args if p not in ["install", "g", "global"]]
            for pkg in pkgs:
                changes.append(StateChange(target=f"package:{pkg}", change_type="install", new_value={"manager": "npm"}, metadata={"op": "npm_install"}))

        elif cmd == "git" and "clone" in parts:
            # git clone url [dir]
            url = next((p for p in args if "http" in p or "git@" in p), None)
            if url:
                repo_name = url.split("/")[-1].replace(".git", "")
                target_dir = args[-1] if len(args) > args.index(url) + 1 else repo_name
                # Treat as directory creation + content
                changes.append(StateChange(target=f"/root/{target_dir}/Makefile", change_type="create", new_value="[Git Content]", metadata={"op": "git_clone"}))

        elif cmd == "make" and "install" in parts:
            changes.append(StateChange(target="package:make_install", change_type="install", new_value={"manager": "source"}, metadata={"op": "make_install"}))

        elif cmd == "cargo" and "install" in parts:
            pkgs = [p for p in args if p != "install"]
            for pkg in pkgs:
                changes.append(StateChange(target=f"package:{pkg}", change_type="install", new_value={"manager": "cargo"}, metadata={"op": "cargo_install"}))
        
        elif cmd == "wget" or cmd == "curl":
            # wget url -> creates file
            url = next((p for p in parts if "http" in p), None)
            if url:
                filename = url.split("/")[-1] or "index.html"
                changes.append(StateChange(target=filename, change_type="create", new_value="[Downloaded]", metadata={"op": "download"}))

        elif cmd == "dpkg" and "-i" in parts:
             pkg_file = parts[-1]
             pkg_name = pkg_file.split("_")[0].split(".")[0] # Rough guess
             changes.append(StateChange(target=f"package:{pkg_name}", change_type="install", new_value={"manager": "dpkg"}, metadata={"op": "dpkg_install"}))

        return changes

    def _handle_network_ops(self, cmd: str, parts: List[str], command_str: str) -> List[StateChange]:
        changes = []
        if cmd == "ip":
            # ip route add ...
            if "route" in parts and "add" in parts:
                changes.append(StateChange(target="network:route", change_type="create", new_value=command_str, metadata={"op": "ip_route"}))
        
        elif cmd == "iptables" or cmd == "ip6tables":
            if "-A" in parts or "-I" in parts:
                changes.append(StateChange(target="network:iptables", change_type="create", new_value=command_str, metadata={"op": "iptables"}))

        elif cmd == "nft":
            if "add" in parts:
                changes.append(StateChange(target="network:iptables", change_type="create", new_value=command_str, metadata={"op": "nft"}))

        return changes

    def _handle_cron_ops(self, cmd: str, parts: List[str], command_str: str) -> List[StateChange]:
        changes = []
        if cmd == "crontab":
            # echo "..." | crontab -
            # Parsing piped input is handled in _handle_redirection mostly, but crontab - reads from stdin
            # For T2, P-CRON-01 is: (crontab -l; echo "...") | crontab -
            # This logic is hard to capture purely in single command analysis without pipe context.
            # But if we see "crontab -", we can assume it succeeded in adding cron.
            if "-" in parts:
                # Try to extract cron content from the command string
                cron_content = "[Stdin Cron Job]"
                
                # Extract echo content in a quote-aware manner
                # Find the starting position of the echo command
                echo_pos = command_str.lower().find('echo ')
                if echo_pos != -1:
                    # Extract content after echo
                    echo_part = command_str[echo_pos + 5:].strip()
                    
                    # Use _extract_quoted_content method to extract content within quotes
                    # But find the part before ) | crontab
                    pipe_pos = echo_part.rfind(') | crontab')
                    if pipe_pos == -1:
                        pipe_pos = echo_part.rfind('| crontab')
                    if pipe_pos == -1:
                        pipe_pos = echo_part.rfind('" |')
                    if pipe_pos == -1:
                        pipe_pos = echo_part.rfind("' |")
                    
                    if pipe_pos != -1:
                        echo_part = echo_part[:pipe_pos]
                    
                    # Extract quoted content
                    cron_content = self._extract_quoted_content(echo_part)
                    
                    # If no content is extracted, use the original echo part
                    if not cron_content:
                        cron_content = echo_part.strip().strip('"\'')
                
                changes.append(StateChange(target="cron:user:root", change_type="modify", new_value=cron_content, metadata={"op": "crontab_stdin"}))
        
        elif cmd == "at":
            # echo "..." | at now + 2 min
            changes.append(StateChange(target="cron:at", change_type="create", new_value="[At Job]", metadata={"op": "at_job"}))
        
        return changes

    def _handle_kernel_ops(self, cmd: str, parts: List[str], command_str: str) -> List[StateChange]:
        changes = []
        if cmd == "sysctl":
            # sysctl -w key=value or sysctl key=value
            args = [p for p in parts if "=" in p]
            for arg in args:
                key, val = arg.split("=", 1)
                changes.append(StateChange(target=f"sysctl:{key}", change_type="modify", new_value=val, metadata={"op": "sysctl"}))
        
        elif cmd == "modprobe":
            mod = parts[-1]
            changes.append(StateChange(target=f"module:{mod}", change_type="install", new_value="loaded", metadata={"op": "modprobe"}))
            
        elif cmd == "setenforce":
            val = parts[-1]
            # SELINUX
            changes.append(StateChange(target="sysctl:selinux", change_type="modify", new_value=val, metadata={"op": "setenforce"}))
            
        elif cmd == "ulimit":
            # ulimit -c unlimited
            if "-c" in parts:
                val = parts[parts.index("-c")+1] if len(parts) > parts.index("-c")+1 else "unlimited"
                changes.append(StateChange(target="sysctl:core_limit", change_type="modify", new_value=val, metadata={"op": "ulimit"}))
        
        return changes
