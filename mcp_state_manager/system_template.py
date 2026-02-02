"""
System Template Manager
Not currently in use
Defines the base system template to avoid loading full state information every time, reducing context length.
All attacker operations are based on incremental modifications to this template.
"""

from typing import Dict, Any, List
from .memory_system import SystemState


class SystemTemplate:
    """System Template Class"""
    
    # Base system template configuration
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
        Get a concise description of the base system information
        This information will be added to the AI's system prompt
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
        Initialize a new system state based on the template
        
        Args:
            ip_address: IP Address
            
        Returns:
            Initialized SystemState object
        """
        state = SystemState(ip_address=ip_address)
        
        # Set system information
        state.hostname = cls.BASE_TEMPLATE['os_info']['hostname']
        state.kernel_version = cls.BASE_TEMPLATE['os_info']['kernel_version']
        state.os_version = cls.BASE_TEMPLATE['os_info']['os_version']
        
        # Create default directories
        for directory in cls.BASE_TEMPLATE['default_directories']:
            state.filesystem.add_directory(directory, permissions="755", owner="root")
        
        # Create default users
        for username, user_info in cls.BASE_TEMPLATE['default_users'].items():
            state.users.add_user(
                username=username,
                uid=user_info['uid'],
                gid=user_info['gid'],
                home=user_info['home'],
                shell=user_info['shell']
            )
        
        # Install default packages
        for package in cls.BASE_TEMPLATE['default_packages']:
            state.packages.install_package(package, version="latest", manager="apt")
        
        # Set default services
        for service_name, service_info in cls.BASE_TEMPLATE['default_services'].items():
            state.services.add_service(
                name=service_name,
                status=service_info['status'],
                enabled=service_info['enabled']
            )
        
        # Set environment variables
        state.environment = cls.BASE_TEMPLATE['environment_variables'].copy()
        
        return state
    
    @classmethod
    def get_diff_summary(cls, system_state: SystemState) -> Dict[str, Any]:
        """
        Get the difference summary from the base template
        Only return incremental changes produced by user operations
        
        Args:
            system_state: Current system state
            
        Returns:
            Difference summary dictionary
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
        
        # Check for added directories (exclude default directories)
        default_dirs = set(cls.BASE_TEMPLATE['default_directories'])
        for directory in system_state.filesystem.directories.keys():
            if directory not in default_dirs:
                diff["added_directories"].append(directory)
        
        # Check for added files (all files are new, as there are no preset files in the template)
        for file_path in system_state.filesystem.files.keys():
            diff["added_files"].append(file_path)
        
        # Check for added users (exclude default users)
        default_users = set(cls.BASE_TEMPLATE['default_users'].keys())
        for username in system_state.users.users.keys():
            if username not in default_users:
                diff["added_users"].append(username)
        
        # Check for added services (exclude default services)
        default_services = set(cls.BASE_TEMPLATE['default_services'].keys())
        for service_name in system_state.services.services.keys():
            if service_name not in default_services:
                diff["added_services"].append(service_name)
        
        # Check for new installed packages (exclude default packages)
        default_packages = set(cls.BASE_TEMPLATE['default_packages'])
        for package_name in system_state.packages.installed_packages.keys():
            if package_name not in default_packages:
                diff["installed_packages"].append(package_name)
        
        return diff
    
    @classmethod
    def format_diff_for_context(cls, diff: Dict[str, Any], max_items: int = 50) -> str:
        """
        Format difference into context string
        
        Args:
            diff: Difference dictionary
            max_items: Maximum number of items to display
            
        Returns:
            Formatted difference description
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
    """Context Optimizer - Ensure context does not exceed limits"""
    
    def __init__(self, max_context_tokens: int = 2000):
        """
        Args:
            max_context_tokens: Maximum context tokens (rough estimate: 4 chars = 1 token)
        """
        self.max_context_tokens = max_context_tokens
        self.max_context_chars = max_context_tokens * 4
    
    def optimize_context(self, base_info: str, state_context: str, diff_summary: str) -> str:
        """
        Optimize context to ensure it does not exceed length limit
        
        Priority:
        1. Base Info (Must be included)
        2. Command-related state context (Most important)
        3. Difference Summary (If space permits)
        
        Args:
            base_info: Base system info
            state_context: State context (related to current command)
            diff_summary: Difference summary
            
        Returns:
            Optimized context string
        """
        # Priority 1: Base Info (Must be included)
        total_context = base_info
        remaining_space = self.max_context_chars - len(total_context)
        
        # Priority 2: Command-related state context
        if state_context and remaining_space > 0:
            if len(state_context) <= remaining_space:
                total_context += "\n" + state_context
                remaining_space -= len(state_context)
            else:
                # Truncate state context
                truncated = state_context[:remaining_space - 100] + "\n[...context truncated...]"
                total_context += "\n" + truncated
                remaining_space = 0
        
        # Priority 3: Difference Summary (If there is space)
        if diff_summary and remaining_space > 200:
            header = "\n[System modifications since start]:\n"
            if len(header) + len(diff_summary) <= remaining_space:
                total_context += header + diff_summary
            else:
                # Only include a part of the summary
                available = remaining_space - len(header) - 50
                truncated_diff = diff_summary[:available] + "..."
                total_context += header + truncated_diff
        
        return total_context
    
    def estimate_token_count(self, text: str) -> int:
        """
        Roughly estimate token count
        
        Args:
            text: Text content
            
        Returns:
            Estimated token count
        """
        return len(text) // 4
