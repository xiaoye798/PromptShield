"""
系统模板管理器 (System Template Manager)
没用上
定义基础系统模板，避免每次都加载完整状态信息，减少上下文长度。
攻击者的所有操作都基于这个模板进行增量修改。
"""

from typing import Dict, Any, List
from .memory_system import SystemState


class SystemTemplate:
    """系统模板类"""
    
    # 基础系统模板配置
    BASE_TEMPLATE = {
        "os_info": {
            "hostname": "honeypot",
            "kernel_version": "5.4.0-42-generic",
            "os_version": "Ubuntu 20.04.1 LTS",
            "architecture": "x86_64"
        },
        
        "default_directories": [
            "/", "/root", "/home", "/tmp", "/var", "/etc", "/usr", "/bin", "/sbin",
            "/opt", "/srv", "/mnt", "/media", "/dev", "/proc", "/sys"
        ],
        
        "default_users": {
            "root": {"uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
        },
        
        "default_packages": [
            "bash", "coreutils", "grep", "sed", "awk", "vim", "nano",
            "systemd", "openssh-server", "curl", "wget"
        ],
        
        "default_services": {
            "ssh": {"status": "active", "enabled": True},
            "cron": {"status": "active", "enabled": True},
        },
        
        "environment_variables": {
            "HOME": "/root",
            "SHELL": "/bin/bash",
            "USER": "root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        }
    }
    
    @classmethod
    def get_base_system_info(cls) -> str:
        """
        获取基础系统信息的简洁描述
        这个信息会被添加到AI的system prompt中
        """
        return f"""
You are simulating a Linux terminal with the following base configuration:
- OS: {cls.BASE_TEMPLATE['os_info']['os_version']}
- Kernel: {cls.BASE_TEMPLATE['os_info']['kernel_version']}
- Architecture: {cls.BASE_TEMPLATE['os_info']['architecture']}
- Current user: root (uid=0)
- Default directories exist: /, /root, /home, /tmp, /var, /etc, /usr, /bin, /sbin, /opt
- Common packages are installed: bash, coreutils, vim, nano, curl, wget, ssh, etc.
- Services: ssh (active), cron (active)

IMPORTANT: Beyond these defaults, you must ONLY acknowledge files, directories, users, and services 
that are explicitly mentioned in the [SYSTEM STATE CONTEXT] section below. 
If something is not mentioned in the state context, treat it as if it doesn't exist.
"""
    
    @classmethod
    def initialize_system_state(cls, ip_address: str) -> SystemState:
        """
        基于模板初始化一个新的系统状态
        
        Args:
            ip_address: IP地址
            
        Returns:
            初始化的SystemState对象
        """
        state = SystemState(ip_address=ip_address)
        
        # 设置系统信息
        state.hostname = cls.BASE_TEMPLATE['os_info']['hostname']
        state.kernel_version = cls.BASE_TEMPLATE['os_info']['kernel_version']
        state.os_version = cls.BASE_TEMPLATE['os_info']['os_version']
        
        # 创建默认目录
        for directory in cls.BASE_TEMPLATE['default_directories']:
            state.filesystem.add_directory(directory, permissions="755", owner="root")
        
        # 创建默认用户
        for username, user_info in cls.BASE_TEMPLATE['default_users'].items():
            state.users.add_user(
                username=username,
                uid=user_info['uid'],
                gid=user_info['gid'],
                home=user_info['home'],
                shell=user_info['shell']
            )
        
        # 安装默认包
        for package in cls.BASE_TEMPLATE['default_packages']:
            state.packages.install_package(package, version="latest", manager="apt")
        
        # 设置默认服务
        for service_name, service_info in cls.BASE_TEMPLATE['default_services'].items():
            state.services.add_service(
                name=service_name,
                status=service_info['status'],
                enabled=service_info['enabled']
            )
        
        # 设置环境变量
        state.environment = cls.BASE_TEMPLATE['environment_variables'].copy()
        
        return state
    
    @classmethod
    def get_diff_summary(cls, system_state: SystemState) -> Dict[str, Any]:
        """
        获取与基础模板的差异摘要
        只返回用户操作产生的增量变化
        
        Args:
            system_state: 当前系统状态
            
        Returns:
            差异摘要字典
        """
        diff = {
            "added_files": [],
            "added_directories": [],
            "added_users": [],
            "added_services": [],
            "installed_packages": [],
            "modified_files": [],
            "deleted_items": []
        }
        
        # 检查新增的目录（排除默认目录）
        default_dirs = set(cls.BASE_TEMPLATE['default_directories'])
        for directory in system_state.filesystem.directories.keys():
            if directory not in default_dirs:
                diff["added_directories"].append(directory)
        
        # 检查新增的文件（所有文件都是新增的，因为模板中没有预设文件）
        for file_path in system_state.filesystem.files.keys():
            diff["added_files"].append(file_path)
        
        # 检查新增的用户（排除默认用户）
        default_users = set(cls.BASE_TEMPLATE['default_users'].keys())
        for username in system_state.users.users.keys():
            if username not in default_users:
                diff["added_users"].append(username)
        
        # 检查新增的服务（排除默认服务）
        default_services = set(cls.BASE_TEMPLATE['default_services'].keys())
        for service_name in system_state.services.services.keys():
            if service_name not in default_services:
                diff["added_services"].append(service_name)
        
        # 检查新安装的包（排除默认包）
        default_packages = set(cls.BASE_TEMPLATE['default_packages'])
        for package_name in system_state.packages.installed_packages.keys():
            if package_name not in default_packages:
                diff["installed_packages"].append(package_name)
        
        return diff
    
    @classmethod
    def format_diff_for_context(cls, diff: Dict[str, Any], max_items: int = 50) -> str:
        """
        将差异格式化为上下文字符串
        
        Args:
            diff: 差异字典
            max_items: 最多显示的项目数量
            
        Returns:
            格式化的差异描述
        """
        lines = []
        
        if diff["added_directories"]:
            dirs = diff["added_directories"][:max_items]
            lines.append(f"User-created directories: {', '.join(dirs)}")
        
        if diff["added_files"]:
            files = diff["added_files"][:max_items]
            lines.append(f"User-created files: {', '.join(files)}")
        
        if diff["added_users"]:
            users = diff["added_users"][:max_items]
            lines.append(f"User-created accounts: {', '.join(users)}")
        
        if diff["added_services"]:
            services = diff["added_services"][:max_items]
            lines.append(f"User-created services: {', '.join(services)}")
        
        if diff["installed_packages"]:
            packages = diff["installed_packages"][:max_items]
            lines.append(f"User-installed packages: {', '.join(packages)}")
        
        if not lines:
            return "No modifications from base system yet."
        
        return "\n".join(lines)


class ContextOptimizer:
    """上下文优化器 - 确保上下文不超过限制"""
    
    def __init__(self, max_context_tokens: int = 2000):
        """
        Args:
            max_context_tokens: 最大上下文token数（粗略估算：4字符=1token）
        """
        self.max_context_tokens = max_context_tokens
        self.max_context_chars = max_context_tokens * 4
    
    def optimize_context(self, base_info: str, state_context: str, diff_summary: str) -> str:
        """
        优化上下文，确保不超过长度限制
        
        优先级：
        1. 基础信息（必须包含）
        2. 命令相关的状态上下文（最重要）
        3. 差异摘要（如果空间允许）
        
        Args:
            base_info: 基础系统信息
            state_context: 状态上下文（与当前命令相关）
            diff_summary: 差异摘要
            
        Returns:
            优化后的上下文字符串
        """
        # 优先级1: 基础信息（必须包含）
        total_context = base_info
        remaining_space = self.max_context_chars - len(total_context)
        
        # 优先级2: 命令相关的状态上下文
        if state_context and remaining_space > 0:
            if len(state_context) <= remaining_space:
                total_context += "\n" + state_context
                remaining_space -= len(state_context)
            else:
                # 截断状态上下文
                truncated = state_context[:remaining_space - 100] + "\n[...context truncated...]"
                total_context += "\n" + truncated
                remaining_space = 0
        
        # 优先级3: 差异摘要（如果还有空间）
        if diff_summary and remaining_space > 200:
            header = "\n[System modifications since start]:\n"
            if len(header) + len(diff_summary) <= remaining_space:
                total_context += header + diff_summary
            else:
                # 只包含摘要的一部分
                available = remaining_space - len(header) - 50
                truncated_diff = diff_summary[:available] + "..."
                total_context += header + truncated_diff
        
        return total_context
    
    def estimate_token_count(self, text: str) -> int:
        """
        粗略估算token数量
        
        Args:
            text: 文本内容
            
        Returns:
            估算的token数量
        """
        return len(text) // 4

