"""
状态上下文构建器 (State Context Builder)

用于将系统状态信息转换为AI可理解的prompt上下文，
实现真正的跨会话一致性。
"""

from typing import Any, Dict, List, Optional
import re
from .memory_system import SystemState


class StateContextBuilder:
    """状态上下文构建器"""
    
    def __init__(self):
        self.max_files_to_show = 20  # 最多显示的文件数量
        self.max_users_to_show = 10   # 最多显示的用户数量
    
    def build_context_for_command(self, command: str, system_state: SystemState, 
                                  current_cwd: str = "/root") -> str:
        """
        根据命令类型构建相关的状态上下文信息
        
        Args:
            command: 用户输入的命令
            system_state: 当前系统状态
            current_cwd: 当前工作目录
            
        Returns:
            格式化的状态上下文字符串
        """
        if not command or not system_state:
            return ""
        
        command = command.strip()
        parts = command.split()
        if not parts:
            return ""
        
        cmd = parts[0]
        context_parts = []
        
        # 根据命令类型构建不同的上下文
        if cmd in ['ls', 'dir', 'll']:
            context_parts.append(self._build_ls_context(command, system_state, current_cwd))
        
        elif cmd in ['cat', 'more', 'less', 'head', 'tail']:
            context_parts.append(self._build_file_read_context(command, system_state, current_cwd))
        
        elif cmd in ['cd', 'pwd']:
            context_parts.append(self._build_directory_context(command, system_state, current_cwd))
        
        elif cmd in ['touch', 'mkdir', 'rm', 'rmdir']:
            context_parts.append(self._build_file_operation_context(command, system_state, current_cwd))
        
        elif cmd in ['cp', 'mv']:
            context_parts.append(self._build_copy_move_context(command, system_state, current_cwd))
        
        elif cmd in ['id', 'whoami', 'w', 'who']:
            context_parts.append(self._build_user_query_context(system_state))
        
        elif cmd in ['useradd', 'userdel', 'usermod', 'passwd']:
            context_parts.append(self._build_user_management_context(command, system_state))
        
        elif cmd in ['systemctl', 'service']:
            context_parts.append(self._build_service_context(command, system_state))
        
        elif cmd in ['ps', 'top', 'htop']:
            context_parts.append(self._build_process_context(system_state))
        
        elif cmd in ['dpkg', 'apt', 'apt-get', 'yum', 'rpm']:
            context_parts.append(self._build_package_context(command, system_state))
        
        # 添加当前工作目录信息（始终包含）
        context_parts.insert(0, f"Current working directory: {current_cwd}")
        
        # 过滤空内容
        context_parts = [part for part in context_parts if part]
        
        if not context_parts:
            return ""
        
        # 构建最终上下文
        context = "\n".join(context_parts)
        return f"""
[SYSTEM STATE CONTEXT - Use this information to ensure consistency with previous sessions]
{context}
[Execute the command based on this actual system state. Ensure your output reflects these facts.]
"""
    
    def _build_ls_context(self, command: str, system_state: SystemState, cwd: str) -> str:
        """构建ls命令的上下文"""
        # 解析目标路径
        target_path = self._extract_target_path(command, cwd, default=cwd)
        
        # 获取该目录下的文件和子目录
        files_in_dir = []
        dirs_in_dir = []
        
        for file_path, file_info in system_state.filesystem.files.items():
            parent_dir = self._get_parent_directory(file_path)
            if parent_dir == target_path:
                files_in_dir.append(self._get_basename(file_path))
        
        for dir_path in system_state.filesystem.directories.keys():
            parent_dir = self._get_parent_directory(dir_path)
            if parent_dir == target_path:
                dirs_in_dir.append(self._get_basename(dir_path))
        
        if not files_in_dir and not dirs_in_dir:
            return f"Directory '{target_path}' exists but is empty (no files or subdirectories created yet)."
        
        context = f"Contents of directory '{target_path}':\n"
        if dirs_in_dir:
            context += f"  Subdirectories: {', '.join(sorted(dirs_in_dir)[:self.max_files_to_show])}\n"
        if files_in_dir:
            context += f"  Files: {', '.join(sorted(files_in_dir)[:self.max_files_to_show])}\n"
        
        return context
    
    def _build_file_read_context(self, command: str, system_state: SystemState, cwd: str) -> str:
        """构建文件读取命令的上下文"""
        target_path = self._extract_target_path(command, cwd)
        if not target_path:
            return ""
        
        # 检查文件是否存在
        if target_path not in system_state.filesystem.files:
            return f"File '{target_path}' does NOT exist in the system."
        
        file_info = system_state.filesystem.files[target_path]
        content = file_info.get("content", "")
        
        # 限制内容长度
        if len(content) > 500:
            content_preview = content[:500] + "... (content truncated)"
        else:
            content_preview = content
        
        return f"""File '{target_path}' exists with the following content:
---
{content_preview}
---"""
    
    def _build_directory_context(self, command: str, system_state: SystemState, cwd: str) -> str:
        """构建目录操作的上下文"""
        if command.startswith('pwd'):
            return f"User is currently in: {cwd}"
        
        # cd 命令
        parts = command.split()
        if len(parts) < 2:
            return f"Target directory for 'cd': /root (user's home)"
        
        target = parts[1]
        target_path = self._resolve_path(target, cwd)
        
        # 检查目录是否存在
        if target_path in system_state.filesystem.directories:
            return f"Directory '{target_path}' EXISTS in the system. Allow navigation."
        else:
            return f"Directory '{target_path}' does NOT exist. Should show error."
    
    def _build_file_operation_context(self, command: str, system_state: SystemState, cwd: str) -> str:
        """构建文件操作的上下文"""
        target_path = self._extract_target_path(command, cwd)
        if not target_path:
            return ""
        
        cmd = command.split()[0]
        
        if cmd in ['touch', 'mkdir']:
            # 检查是否已存在
            if cmd == 'touch' and target_path in system_state.filesystem.files:
                return f"File '{target_path}' ALREADY exists. 'touch' should update timestamp only."
            elif cmd == 'mkdir' and target_path in system_state.filesystem.directories:
                return f"Directory '{target_path}' ALREADY exists. Should show error."
            else:
                return f"Target '{target_path}' does not exist yet. Operation will create it."
        
        elif cmd in ['rm', 'rmdir']:
            if target_path in system_state.filesystem.files or target_path in system_state.filesystem.directories:
                return f"Target '{target_path}' EXISTS and can be deleted."
            else:
                return f"Target '{target_path}' does NOT exist. Should show error."
        
        return ""
    
    def _build_copy_move_context(self, command: str, system_state: SystemState, cwd: str) -> str:
        """构建复制/移动命令的上下文"""
        parts = command.split()
        if len(parts) < 3:
            return ""
        
        src_path = self._resolve_path(parts[1], cwd)
        dst_path = self._resolve_path(parts[2], cwd)
        
        context = ""
        
        # 检查源文件
        if src_path in system_state.filesystem.files:
            content = system_state.filesystem.files[src_path].get("content", "")
            if len(content) > 200:
                content = content[:200] + "..."
            context += f"Source file '{src_path}' EXISTS with content: {content}\n"
        else:
            context += f"Source file '{src_path}' does NOT exist. Should show error.\n"
        
        # 检查目标
        if dst_path in system_state.filesystem.files:
            context += f"Destination '{dst_path}' ALREADY exists. Will be overwritten.\n"
        else:
            context += f"Destination '{dst_path}' does not exist yet.\n"
        
        return context
    
    def _build_user_query_context(self, system_state: SystemState) -> str:
        """构建用户查询命令的上下文"""
        current_user = system_state.users.current_user
        
        if current_user not in system_state.users.users:
            return f"Current user: {current_user} (default user)"
        
        user_info = system_state.users.users[current_user]
        context = f"Current user: {current_user}\n"
        context += f"  UID: {user_info.get('uid', 0)}\n"
        context += f"  GID: {user_info.get('gid', 0)}\n"
        context += f"  Home: {user_info.get('home', '/root')}\n"
        context += f"  Shell: {user_info.get('shell', '/bin/bash')}\n"
        
        return context
    
    def _build_user_management_context(self, command: str, system_state: SystemState) -> str:
        """构建用户管理命令的上下文"""
        parts = command.split()
        if len(parts) < 2:
            return ""
        
        username = parts[-1]  # 通常用户名是最后一个参数
        
        if username in system_state.users.users:
            user_info = system_state.users.users[username]
            return f"User '{username}' ALREADY exists with UID={user_info.get('uid', 'unknown')}."
        else:
            return f"User '{username}' does NOT exist yet."
    
    def _build_service_context(self, command: str, system_state: SystemState) -> str:
        """构建服务管理命令的上下文"""
        # 提取服务名称
        service_name = None
        parts = command.split()
        
        for i, part in enumerate(parts):
            if part in ['status', 'start', 'stop', 'enable', 'disable', 'restart']:
                if i + 1 < len(parts):
                    service_name = parts[i + 1].replace('.service', '')
                    break
        
        if not service_name:
            return ""
        
        if service_name in system_state.services.services:
            service_info = system_state.services.services[service_name]
            status = service_info.get('status', 'unknown')
            enabled = service_info.get('enabled', False)
            return f"Service '{service_name}' EXISTS. Status: {status}, Enabled: {enabled}"
        else:
            return f"Service '{service_name}' does NOT exist in the system."
    
    def _build_process_context(self, system_state: SystemState) -> str:
        """构建进程查询的上下文"""
        if not system_state.services.processes:
            return "No specific processes recorded. Show default system processes."
        
        process_count = len(system_state.services.processes)
        return f"System has {process_count} recorded processes."
    
    def _build_package_context(self, command: str, system_state: SystemState) -> str:
        """构建包管理命令的上下文"""
        # 提取包名
        package_name = None
        parts = command.split()
        
        for i, part in enumerate(parts):
            if part in ['install', 'remove', 'purge', 'search', 'show']:
                if i + 1 < len(parts):
                    package_name = parts[i + 1]
                    break
        
        if not package_name:
            return ""
        
        if package_name in system_state.packages.installed_packages:
            pkg_info = system_state.packages.installed_packages[package_name]
            version = pkg_info.get('version', 'unknown')
            return f"Package '{package_name}' is ALREADY installed (version {version})."
        else:
            return f"Package '{package_name}' is NOT installed yet."
    
    # 辅助方法
    
    def _extract_target_path(self, command: str, cwd: str, default: str = None) -> str:
        """从命令中提取目标路径"""
        parts = command.split()
        
        # 过滤掉选项参数
        paths = [p for p in parts[1:] if not p.startswith('-')]
        
        if not paths:
            return default or ""
        
        target = paths[0]
        return self._resolve_path(target, cwd)
    
    def _resolve_path(self, path: str, cwd: str) -> str:
        """解析路径为绝对路径"""
        if not path:
            return cwd
        
        if path.startswith("~"):
            path = path.replace("~", "/root", 1)
        
        if path.startswith("/"):
            return path
        
        # 相对路径
        import os
        full_path = os.path.join(cwd, path)
        return os.path.normpath(full_path).replace("\\", "/")
    
    def _get_parent_directory(self, path: str) -> str:
        """获取路径的父目录"""
        if '/' not in path:
            return "/"
        return '/'.join(path.split('/')[:-1]) or "/"
    
    def _get_basename(self, path: str) -> str:
        """获取路径的基础名称"""
        return path.split('/')[-1]

