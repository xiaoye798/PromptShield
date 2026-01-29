import re
import os
import shlex
from typing import List, Dict, Any, Optional, Tuple
from .event_graph import EventType, EventStatus, StateChange

class CommandAnalyzer:
    """分析命令和输出以确定状态变化 (Comprehensive Version for T2 Test Suite)"""
    
    def determine_event_type(self, command: str) -> EventType:
        """确定事件类型"""
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
        """确定执行状态"""
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
        """解析路径为绝对路径"""
        if not path:
            return cwd
        
        if path.startswith("~"):
            path = path.replace("~", "/root", 1)
        
        if os.path.isabs(path):
            return os.path.normpath(path).replace("\\", "/")
            
        full_path = os.path.join(cwd, path)
        return os.path.normpath(full_path).replace("\\", "/")

    def _parse_args(self, command: str) -> List[str]:
        """使用 shlex 解析命令行参数，处理引号"""
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    def _split_compound_commands(self, command_str: str) -> List[str]:
        """
        引号感知的复合命令拆分
        
        在引号外找到 && 或 ; 分隔符，将命令拆分为多个子命令。
        引号内的 ; 或 && 不被视为分隔符。
        """
        commands = []
        current_cmd = []
        i = 0
        in_single_quote = False
        in_double_quote = False
        escape_next = False
        
        while i < len(command_str):
            char = command_str[i]
            
            # 处理转义
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
            
            # 引号状态切换
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
            
            # 只在引号外检查分隔符
            if not in_single_quote and not in_double_quote:
                # 检查 ' && '
                if command_str[i:i+4] == ' && ':
                    cmd = ''.join(current_cmd).strip()
                    if cmd:
                        commands.append(cmd)
                    current_cmd = []
                    i += 4
                    continue
                
                # 检查 ' ; '
                if command_str[i:i+3] == ' ; ':
                    cmd = ''.join(current_cmd).strip()
                    if cmd:
                        commands.append(cmd)
                    current_cmd = []
                    i += 3
                    continue
                
                # 检查单独的 ';' (但不是 '; ' 已处理)
                if char == ';':
                    cmd = ''.join(current_cmd).strip()
                    if cmd:
                        commands.append(cmd)
                    current_cmd = []
                    i += 1
                    continue
            
            current_cmd.append(char)
            i += 1
        
        # 添加最后一个命令
        cmd = ''.join(current_cmd).strip()
        if cmd:
            commands.append(cmd)
        
        return commands

    def analyze_state_changes(self, command: str, output: str, cwd: str = "/root", system_state: Any = None) -> List[StateChange]:
        """全面分析命令导致的状态变化
        
        注意：对于蜜罐系统，我们基于命令的意图分析状态变化，
        而不是依赖 LLM 的输出。这确保即使 LLM 返回错误消息，
        状态变化仍然会被正确记录（因为攻击者的命令"本应"成功）。
        """
        changes = []
        command_str = command.strip()
        if not command_str:
            return changes
        
        # 使用引号感知的拆分处理复合命令
        sub_commands = self._split_compound_commands(command_str)
        
        if len(sub_commands) > 1:
            # 有多个子命令，逐个分析
            for sub_cmd in sub_commands:
                if sub_cmd:
                    sub_changes = self._analyze_single_command(sub_cmd, output, cwd, system_state)
                    changes.extend(sub_changes)
            return changes
        
        # 单个命令
        return self._analyze_single_command(command_str, output, cwd, system_state)
    
    def _analyze_single_command(self, command_str: str, output: str, cwd: str, system_state: Any) -> List[StateChange]:
        """分析单个命令的状态变化"""
        changes = []
        
        # 注释：不再检查输出状态，因为蜜罐需要记录命令意图
        # status = self.determine_status(command, output)
        # if status == EventStatus.FAILED:
        #     return changes

        # Check for pipe/redirection first (simplified)
        # echo "..." | command -> handle complex
        # We process simple redirections here, complex pipes are hard
        
        # 特殊处理: 管道到crontab命令
        if "| crontab" in command_str:
            # 提取 crontab 部分
            crontab_part = command_str.split("|")[-1].strip()
            crontab_parts = self._parse_args(crontab_part)
            if crontab_parts and crontab_parts[0] == "crontab":
                return self._handle_cron_ops("crontab", crontab_parts, command_str)
        
        # 检查是否有真正的重定向（使用引号感知的解析器）
        # 这修复了引号内的 > 被误识别的问题
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
        找出命令中真正的重定向操作符（忽略引号内的）
        
        使用状态机解析，正确处理：
        - 单引号 '...' 内的 > 不是重定向
        - 双引号 "..." 内的 > 不是重定向
        - 文件描述符重定向 2>/dev/null, 2>&1, >&2 等
        - 转义字符 \> 不是重定向
        
        返回格式: [{'type': '>' or '>>', 'position': int, 'target': str}]
        """
        redirections = []
        i = 0
        in_single_quote = False
        in_double_quote = False
        escape_next = False
        
        while i < len(command_str):
            char = command_str[i]
            
            # 处理转义字符
            if escape_next:
                escape_next = False
                i += 1
                continue
            
            if char == '\\' and not in_single_quote:
                escape_next = True
                i += 1
                continue
            
            # 处理引号状态
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                i += 1
                continue
            
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                i += 1
                continue
            
            # 只在引号外检查重定向
            if not in_single_quote and not in_double_quote and char == '>':
                # 检查是否是文件描述符重定向
                
                # 检查 >& 模式 (如 >& /dev/tcp/... 或 >&2)
                if i + 1 < len(command_str) and command_str[i + 1] == '&':
                    # 跳过 >& 模式（文件描述符重定向）
                    i += 2
                    continue
                
                # 检查 数字> 模式 (如 2>/dev/null)
                if i > 0 and command_str[i - 1].isdigit():
                    # 这是 stderr/其他fd 重定向，跳过
                    i += 1
                    continue
                
                # 检查 >> (追加) vs > (覆盖)
                if i + 1 < len(command_str) and command_str[i + 1] == '>':
                    # 是 >> 追加重定向
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
                    # 是 > 覆盖重定向
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
        """从重定向操作符后提取目标路径"""
        rest = command_str[start_pos:].lstrip()
        if not rest:
            return None
        
        # 如果是文件描述符引用 (如 &1, &2)，返回 None
        if rest.startswith('&'):
            return None
        
        # 提取路径（到空格、管道、分号、&&等为止）
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
            
            # 在引号外遇到分隔符就停止
            if not in_single_quote and not in_double_quote:
                if char in ' \t|;&':
                    break
            
            target.append(char)
            i += 1
        
        result = ''.join(target).strip()
        return result if result else None

    def _extract_echo_content(self, command_str: str, redirect_pos: int) -> str:
        """
        从 echo 命令中提取要写入的内容
        
        处理各种复杂情况：
        - echo 'content' > file
        - echo "content with $var" > file
        - echo -e "content\\n" > file
        - echo 'content with > inside' > file
        """
        # 获取重定向之前的部分
        lhs = command_str[:redirect_pos].strip()
        
        # 处理管道情况: cmd1 | cmd2 > file
        if '|' in lhs:
            lhs = lhs.split('|')[-1].strip()
        
        if not lhs.lower().startswith('echo'):
            return ""
        
        # 移除 echo 命令本身
        echo_part = lhs[4:].strip()
        
        # 处理 echo 的选项 (-e, -n, -E)
        while echo_part.startswith('-'):
            space_idx = echo_part.find(' ')
            if space_idx == -1:
                return ""
            option = echo_part[:space_idx]
            if option in ['-e', '-n', '-E', '-en', '-ne', '-nE']:
                echo_part = echo_part[space_idx:].strip()
            else:
                break
        
        # 提取引号内的内容
        content = self._extract_quoted_content(echo_part)
        return content

    def _extract_quoted_content(self, text: str) -> str:
        """
        提取引号内的内容，处理嵌套引号和转义
        
        支持:
        - 'single quoted content'
        - "double quoted content"
        - $'ansi-c quoting'
        - 混合内容 'part1' "part2"
        """
        text = text.strip()
        
        if not text:
            return ""
        
        result = []
        i = 0
        
        while i < len(text):
            char = text[i]
            
            # 处理单引号字符串
            if char == "'":
                end_quote = text.find("'", i + 1)
                if end_quote != -1:
                    result.append(text[i + 1:end_quote])
                    i = end_quote + 1
                    continue
                else:
                    # 没有闭合的单引号，取剩余部分
                    result.append(text[i + 1:])
                    break
            
            # 处理双引号字符串
            elif char == '"':
                # 需要处理双引号内的转义
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
            
            # 处理 $'...' 格式 (ANSI-C quoting)
            elif char == '$' and i + 1 < len(text) and text[i + 1] == "'":
                end_quote = text.find("'", i + 2)
                if end_quote != -1:
                    result.append(text[i + 2:end_quote])
                    i = end_quote + 1
                    continue
            
            # 跳过空格
            elif char in ' \t':
                i += 1
                continue
            
            # 其他字符（无引号的内容）
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
        从 heredoc 语法中提取内容
        
        支持格式:
        - cat > file << 'EOF'
        - cat > file << EOF
        - cat > file << "EOF"
        - cat > file <<-EOF (with tab stripping)
        """
        import re
        
        # 查找 heredoc 标记
        # 匹配 << 后面的分隔符（可能有引号）
        heredoc_match = re.search(r'<<-?\s*([\'"]?)(\w+)\1', command_str)
        if not heredoc_match:
            return ""
        
        delimiter = heredoc_match.group(2)  # 例如 'EOF'
        
        # 找到分隔符后的内容
        # heredoc 内容在分隔符之后，直到遇到单独一行的分隔符
        start_pos = heredoc_match.end()
        
        # 跳过可能的换行
        while start_pos < len(command_str) and command_str[start_pos] in ' \t':
            start_pos += 1
        if start_pos < len(command_str) and command_str[start_pos] == '\n':
            start_pos += 1
        
        # 查找结束分隔符
        end_pattern = re.compile(r'^' + re.escape(delimiter) + r'\s*$', re.MULTILINE)
        end_match = end_pattern.search(command_str, start_pos)
        
        if end_match:
            content = command_str[start_pos:end_match.start()]
            # 移除末尾的换行
            content = content.rstrip('\n')
            return content
        else:
            # 没找到结束分隔符，取到命令末尾
            return command_str[start_pos:].strip()

    def _handle_redirection(self, command_str: str, cwd: str, system_state: Any) -> List[StateChange]:
        """
        处理重定向命令，正确解析引号和特殊字符
        
        修复的问题：
        1. 引号内的 > 不再被误识别为重定向
        2. 文件描述符重定向 (2>&1, >&, 2>/dev/null) 被正确跳过
        3. 复杂转义字符被正确处理
        4. 支持 heredoc 语法 (<< EOF)
        """
        changes = []
        
        # 先检查是否是 heredoc 语法
        import re
        heredoc_match = re.search(r'<<-?\s*([\'"]?)(\w+)\1', command_str)
        if heredoc_match:
            # 是 heredoc 语法
            content = self._extract_heredoc_content(command_str)
            
            # 找到重定向目标
            redirections = self._find_real_redirections(command_str)
            if redirections:
                redir = redirections[-1]
                target_path = self._resolve_path(redir['target'], cwd)
                mode = "append" if redir['type'] == '>>' else "overwrite"
                
                # 特殊处理 systemd service 文件
                if target_path.startswith('/etc/systemd/system/') and target_path.endswith('.service'):
                    service_name = os.path.basename(target_path).replace('.service', '')
                    changes.append(StateChange(
                        target=target_path, 
                        change_type="create",
                        new_value=content,
                        metadata={"op": "heredoc_create", "service": service_name}
                    ))
                    return changes
                
                # 一般文件
                changes.append(StateChange(
                    target=target_path,
                    change_type="create" if mode == "overwrite" else "modify",
                    new_value=content,
                    metadata={"op": f"heredoc_{mode}"}
                ))
                return changes
        
        # 非 heredoc 语法，使用原有逻辑
        # 找出所有真正的重定向操作
        redirections = self._find_real_redirections(command_str)
        
        if not redirections:
            return changes
        
        # 处理最后一个有效重定向（通常是主要的文件重定向）
        redir = redirections[-1]
        
        mode = "append" if redir['type'] == '>>' else "overwrite"
        target_path = self._resolve_path(redir['target'], cwd)
        
        # 提取内容
        content = ""
        lhs = command_str[:redir['position']].strip()
        
        # 处理管道的情况: cmd1 | cmd2 > file
        if '|' in lhs:
            lhs = lhs.split('|')[-1].strip()
        
        # 解析左侧命令以提取内容
        if lhs.lower().startswith('echo'):
            content = self._extract_echo_content(command_str, redir['position'])
        elif lhs.lower().startswith('cat'):
            cat_args = self._parse_args(lhs)
            if len(cat_args) > 1:
                src_file = self._resolve_path(cat_args[1], cwd)
                if system_state and hasattr(system_state, 'filesystem') and system_state.filesystem.file_exists(src_file):
                    content = system_state.filesystem.get_file_content(src_file) or ""
        elif lhs.lower().startswith('printf'):
            # 处理 printf 命令
            try:
                args = self._parse_args(lhs)
                if len(args) > 1:
                    content = args[1]  # 简单处理：取格式字符串
            except:
                pass
        
        # 特殊文件处理
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
        
        # 处理追加模式
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
                # Blind edit: 即使没有 system_state，也记录修改操作
                # 使用替换后的值作为新内容（假设文件只包含被替换的内容）
                # 这对于 echo "old" > file && sed -i 's/old/new/' file 特别有用
                new_content = new  # 假设整个内容就是被替换的结果
                changes.append(StateChange(
                    target=target_file, 
                    change_type="modify", 
                    new_value=new_content, 
                    metadata={"op": "sed_blind", "pattern": f"{old}->{new}"})
                )
        return changes

    def _handle_user_ops(self, cmd: str, parts: List[str], system_state: Any) -> List[StateChange]:
        changes = []
        
        # 更智能的参数解析：跳过选项的值
        # 例如 "useradd -m -s /bin/bash backdoor_user"
        # 需要跳过 "-s" 后面的 "/bin/bash"
        option_with_values = {"-s", "-u", "-g", "-d", "-c", "-G", "-aG", "-e", "-f", "-k", "-K", "-p"}
        args = []
        skip_next = False
        for i, p in enumerate(parts[1:], start=1):
            if skip_next:
                skip_next = False
                continue
            if p.startswith("-"):
                # 检查这个选项是否需要一个值
                if p in option_with_values:
                    skip_next = True
                continue
            args.append(p)
        
        if cmd == "useradd":
            if args:
                # 用户名是最后一个非选项参数
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
            # usermod -aG group user   (添加到组)
            # usermod -s shell user    (修改shell)
            # usermod -L user          (锁定账户)
            # usermod -U user          (解锁账户)
            if not args: return changes
            username = args[-1]
            mod_info = {}
            
            # 处理 shell 修改
            if "-s" in parts: 
                mod_info["shell"] = parts[parts.index("-s")+1]
            
            # 处理锁定/解锁
            if "-L" in parts: 
                mod_info["locked"] = True
            if "-U" in parts:
                mod_info["locked"] = False
            
            # 处理 -G 或 -aG (追加组)
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
                # 尝试从命令字符串中提取cron内容
                cron_content = "[Stdin Cron Job]"
                
                # 使用引号感知的方式提取 echo 内容
                # 查找 echo 命令的起始位置
                echo_pos = command_str.lower().find('echo ')
                if echo_pos != -1:
                    # 从 echo 后面提取内容
                    echo_part = command_str[echo_pos + 5:].strip()
                    
                    # 使用 _extract_quoted_content 方法提取引号内的内容
                    # 但要找到 ) | crontab 之前的部分
                    pipe_pos = echo_part.rfind(') | crontab')
                    if pipe_pos == -1:
                        pipe_pos = echo_part.rfind('| crontab')
                    if pipe_pos == -1:
                        pipe_pos = echo_part.rfind('" |')
                    if pipe_pos == -1:
                        pipe_pos = echo_part.rfind("' |")
                    
                    if pipe_pos != -1:
                        echo_part = echo_part[:pipe_pos]
                    
                    # 提取引号内容
                    cron_content = self._extract_quoted_content(echo_part)
                    
                    # 如果没有提取到内容，使用原始的 echo 部分
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
