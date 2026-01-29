"""
结构化长期记忆系统 (Structured Long-Term Memory System)

用于持久化存储和管理LLM蜜罐的系统状态、事件图和跨会话信息。
支持IP隔离、状态快照、增量更新和状态恢复。
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field

from .event_graph import EventGraph, EventNode


class FileSystemState(BaseModel):
    """文件系统状态"""
    files: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="文件信息")
    directories: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="目录信息")
    permissions: Dict[str, str] = Field(default_factory=dict, description="权限信息")
    links: Dict[str, str] = Field(default_factory=dict, description="链接信息")
    
    def add_file(self, path: str, content: str = "", permissions: str = "644", 
                 owner: str = "root", size: int = 0) -> None:
        """添加文件"""
        self.files[path] = {
            "content": content,
            "permissions": permissions,
            "owner": owner,
            "size": size,
            "created_at": datetime.now().isoformat(),
            "modified_at": datetime.now().isoformat()
        }
    
    def add_directory(self, path: str, permissions: str = "755", owner: str = "root") -> None:
        """添加目录"""
        self.directories[path] = {
            "permissions": permissions,
            "owner": owner,
            "created_at": datetime.now().isoformat()
        }
    
    def remove_file(self, path: str) -> bool:
        """删除文件"""
        return self.files.pop(path, None) is not None
    
    def remove_directory(self, path: str) -> bool:
        """删除目录"""
        return self.directories.pop(path, None) is not None
    
    def file_exists(self, path: str) -> bool:
        """检查文件是否存在"""
        return path in self.files
    
    def directory_exists(self, path: str) -> bool:
        """检查目录是否存在"""
        return path in self.directories
    
    def update_file_attributes(self, path: str, permissions: Optional[str] = None, owner: Optional[str] = None) -> bool:
        """更新文件属性"""
        if path in self.files:
            if permissions:
                self.files[path]["permissions"] = permissions
            if owner:
                self.files[path]["owner"] = owner
            self.files[path]["modified_at"] = datetime.now().isoformat()
            return True
        return False

    def get_file_content(self, path: str) -> Optional[str]:
        """获取文件内容"""
        file_info = self.files.get(path)
        return file_info["content"] if file_info else None


class UserState(BaseModel):
    """用户状态"""
    users: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="用户信息 /etc/passwd")
    groups: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="组信息 /etc/group")
    shadow: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="密码信息 /etc/shadow")
    sudoers: List[str] = Field(default_factory=list, description="sudo权限")
    current_user: str = Field(default="root", description="当前用户")
    login_history: List[Dict[str, Any]] = Field(default_factory=list, description="登录历史")
    
    def add_user(self, username: str, uid: int = 1000, gid: int = 1000, home: str = "", 
                 shell: str = "/bin/bash", password_hash: str = "!", shadow_info: Dict = None) -> None:
        """添加用户"""
        self.users[username] = {
            "uid": uid,
            "gid": gid,
            "home": home or f"/home/{username}",
            "shell": shell,
            "created_at": datetime.now().isoformat()
        }
        # Shadow entry default
        self.shadow[username] = shadow_info or {
            "password": password_hash,
            "last_change": 19000,
            "min": 0,
            "max": 99999,
            "warn": 7,
            "inactive": "",
            "expire": ""
        }
    
    def add_group(self, groupname: str, gid: int = 1000, members: List[str] = None) -> None:
        """添加用户组"""
        self.groups[groupname] = {
            "gid": gid,
            "members": members or [],
            "created_at": datetime.now().isoformat()
        }

    def modify_user(self, username: str, changes: Dict[str, Any]) -> bool:
        """修改用户信息 (usermod)"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        for k, v in changes.items():
            if k in user:
                user[k] = v
            # Handle group additions
            if k == "groups_add":
                for grp in v:
                    if grp in self.groups:
                        if username not in self.groups[grp]["members"]:
                            self.groups[grp]["members"].append(username)
        return True

    def set_password(self, username: str, password_hash: str) -> bool:
        """设置密码 (passwd)"""
        if username in self.shadow:
            self.shadow[username]["password"] = password_hash
            return True
        return False

    def remove_user(self, username: str) -> bool:
        """删除用户"""
        self.shadow.pop(username, None)
        return self.users.pop(username, None) is not None
    
    def user_exists(self, username: str) -> bool:
        """检查用户是否存在"""
        return username in self.users
    
    def set_current_user(self, username: str) -> bool:
        """设置当前用户"""
        if self.user_exists(username):
            self.current_user = username
            return True
        return False


class CronState(BaseModel):
    """计划任务状态"""
    user_crontabs: Dict[str, List[str]] = Field(default_factory=dict, description="用户crontab")
    system_cron_files: Dict[str, str] = Field(default_factory=dict, description="/etc/cron.d/等文件")
    etc_crontab: List[str] = Field(default_factory=list, description="/etc/crontab内容")
    anacrontab: List[str] = Field(default_factory=list, description="/etc/anacrontab内容")
    at_jobs: List[str] = Field(default_factory=list, description="at任务")

    def add_user_cron_line(self, username: str, line: str) -> None:
        if username not in self.user_crontabs:
            self.user_crontabs[username] = []
        self.user_crontabs[username].append(line)

    def add_system_cron_file(self, filename: str, content: str) -> None:
        self.system_cron_files[filename] = content

    def add_at_job(self, job_content: str) -> None:
        self.at_jobs.append(job_content)


class ServiceState(BaseModel):
    """服务状态"""
    services: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="服务信息")
    processes: Dict[int, Dict[str, Any]] = Field(default_factory=dict, description="进程信息")
    
    def add_service(self, name: str, status: str = "inactive", enabled: bool = False, 
                    unit_file_content: str = "") -> None:
        """添加服务"""
        self.services[name] = {
            "status": status,
            "enabled": enabled,
            "unit_content": unit_file_content,
            "created_at": datetime.now().isoformat()
        }
    
    def update_service_status(self, name: str, status: str) -> bool:
        """更新服务状态"""
        if name in self.services:
            self.services[name]["status"] = status
            self.services[name]["updated_at"] = datetime.now().isoformat()
            return True
        return False

    def update_service_enabled(self, name: str, enabled: bool) -> bool:
        """更新服务启用状态"""
        if name in self.services:
            self.services[name]["enabled"] = enabled
            self.services[name]["updated_at"] = datetime.now().isoformat()
            return True
        return False
    
    def service_exists(self, name: str) -> bool:
        """检查服务是否存在"""
        return name in self.services
    
    def get_service_status(self, name: str) -> Optional[str]:
        """获取服务状态"""
        service = self.services.get(name)
        return service["status"] if service else None


class NetworkState(BaseModel):
    """网络状态"""
    interfaces: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="网络接口")
    routes: List[str] = Field(default_factory=list, description="路由表")
    connections: List[Dict[str, Any]] = Field(default_factory=list, description="网络连接")
    hosts: Dict[str, str] = Field(default_factory=dict, description="/etc/hosts映射")
    iptables_rules: List[str] = Field(default_factory=list, description="iptables规则")
    nftables_rules: List[str] = Field(default_factory=list, description="nftables规则")
    dns_servers: List[str] = Field(default_factory=list, description="DNS服务器")
    
    def add_interface(self, name: str, ip: str, netmask: str = "255.255.255.0", 
                     status: str = "up") -> None:
        """添加网络接口"""
        self.interfaces[name] = {
            "ip": ip,
            "netmask": netmask,
            "status": status,
            "created_at": datetime.now().isoformat()
        }
    
    def add_host_entry(self, ip: str, hostname: str) -> None:
        self.hosts[hostname] = ip

    def add_route(self, route_spec: str) -> None:
        self.routes.append(route_spec)
        
    def add_iptables_rule(self, rule: str) -> None:
        self.iptables_rules.append(rule)


class PackageState(BaseModel):
    """软件包状态"""
    installed_packages: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="已安装软件包")
    available_packages: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="可用软件包")
    
    def install_package(self, name: str, version: str = "latest", manager: str = "apt") -> None:
        """安装软件包"""
        self.installed_packages[name] = {
            "version": version,
            "manager": manager,
            "installed_at": datetime.now().isoformat()
        }
    
    def remove_package(self, name: str) -> bool:
        """卸载软件包"""
        return self.installed_packages.pop(name, None) is not None
    
    def is_installed(self, name: str) -> bool:
        """检查软件包是否已安装"""
        return name in self.installed_packages


class SystemState(BaseModel):
    """系统状态快照"""
    ip_address: str = Field(description="IP地址")
    timestamp: datetime = Field(default_factory=datetime.now, description="快照时间")
    
    # 各子系统状态
    filesystem: FileSystemState = Field(default_factory=FileSystemState)
    users: UserState = Field(default_factory=UserState)
    services: ServiceState = Field(default_factory=ServiceState)
    network: NetworkState = Field(default_factory=NetworkState)
    packages: PackageState = Field(default_factory=PackageState)
    cron: CronState = Field(default_factory=CronState)
    
    # 系统信息
    hostname: str = Field(default="honeypot", description="主机名")
    kernel_version: str = Field(default="5.4.0", description="内核版本")
    os_version: str = Field(default="Ubuntu 20.04", description="操作系统版本")
    uptime: int = Field(default=0, description="系统运行时间（秒）")
    
    # 环境变量
    environment: Dict[str, str] = Field(default_factory=dict, description="环境变量")
    kernel_modules: List[str] = Field(default_factory=list, description="内核模块")
    sysctl_params: Dict[str, str] = Field(default_factory=dict, description="sysctl参数")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def apply_event(self, event: EventNode) -> List[str]:
        """应用事件到系统状态，返回应用的变化列表"""
        changes = []
        
        for state_change in event.state_changes:
            target = state_change.target
            change_type = state_change.change_type
            new_value = state_change.new_value
            
            if change_type == "create":
                if target.startswith("/"):  # 文件系统路径
                    # 检查metadata中的is_dir标志
                    is_dir = state_change.metadata.get("is_dir", False) if state_change.metadata else False
                    if target.endswith("/") or is_dir:  # 目录
                        self.filesystem.add_directory(target.rstrip("/"))
                        changes.append(f"Created directory: {target}")
                    else:  # 文件
                        content = new_value if isinstance(new_value, str) else ""
                        self.filesystem.add_file(target, content)
                        changes.append(f"Created file: {target}")
                        
                        # 特殊文件处理
                        if target == "/etc/hostname" and content:
                            self.hostname = content.strip()
                            changes.append(f"Updated hostname to: {self.hostname}")
                
                elif target.startswith("user:"):  # 用户操作
                    username = target.split(":", 1)[1]
                    # Support dict or simple uid/gid if provided
                    user_info = new_value if isinstance(new_value, dict) else {}
                    self.users.add_user(username, 
                                      uid=user_info.get("uid", 1000), 
                                      gid=user_info.get("gid", 1000),
                                      home=user_info.get("home", ""),
                                      shell=user_info.get("shell", "/bin/bash"))
                    changes.append(f"Created user: {username}")

                elif target.startswith("group:"):
                    groupname = target.split(":", 1)[1]
                    self.users.add_group(groupname)
                    changes.append(f"Created group: {groupname}")
                
                elif target.startswith("service:"):  # 服务操作
                    service_name = target.split(":", 1)[1]
                    status = "inactive"
                    enabled = False
                    unit_content = ""
                    if isinstance(new_value, dict):
                        status = new_value.get("status", "inactive")
                        enabled = new_value.get("enabled", False)
                        unit_content = new_value.get("unit_content", "")
                    self.services.add_service(service_name, status=status, enabled=enabled, unit_file_content=unit_content)
                    changes.append(f"Created service: {service_name}")
                
                elif target == "network:route":
                    self.network.add_route(str(new_value))
                    changes.append(f"Added route: {new_value}")
                
                elif target == "network:iptables":
                    self.network.add_iptables_rule(str(new_value))
                    changes.append(f"Added iptables rule: {new_value}")
                
                elif target == "cron:at":
                    self.cron.add_at_job(str(new_value))
                    changes.append(f"Added at job: {new_value}")
            
            elif change_type == "append":
                # 文件追加操作
                if target.startswith("/"):
                    content = new_value if isinstance(new_value, str) else str(new_value)
                    if self.filesystem.file_exists(target):
                        # 文件已存在，追加内容
                        current_content = self.filesystem.files[target].get("content", "")
                        self.filesystem.files[target]["content"] = current_content + "\n" + content if current_content else content
                        self.filesystem.files[target]["modified_at"] = datetime.now().isoformat()
                        changes.append(f"Appended to file: {target}")
                    else:
                        # 文件不存在，创建新文件
                        self.filesystem.add_file(target, content)
                        changes.append(f"Created file with append: {target}")
            
            elif change_type == "create_user":
                # 创建用户操作
                if target.startswith("user:"):
                    username = target.split(":", 1)[1]
                else:
                    username = target
                user_info = new_value if isinstance(new_value, dict) else {}
                if isinstance(new_value, str):
                    try:
                        user_info = json.loads(new_value)
                    except:
                        user_info = {}
                self.users.add_user(
                    username,
                    uid=user_info.get("uid", 1001),
                    gid=user_info.get("gid", 1001),
                    home=user_info.get("home", f"/home/{username}"),
                    shell=user_info.get("shell", "/bin/bash")
                )
                changes.append(f"Created user: {username}")
            
            elif change_type == "add_group":
                # 将用户添加到组
                if target.startswith("user:"):
                    username = target.split(":", 1)[1]
                else:
                    username = target
                group_name = new_value if isinstance(new_value, str) else str(new_value)
                # 确保用户存在
                if not self.users.user_exists(username):
                    self.users.add_user(username, uid=1001, gid=1001)
                    changes.append(f"Auto-created user: {username}")
                # 确保组存在
                if group_name not in self.users.groups:
                    self.users.add_group(group_name)
                    changes.append(f"Auto-created group: {group_name}")
                # 添加用户到组
                if username not in self.users.groups[group_name]["members"]:
                    self.users.groups[group_name]["members"].append(username)
                # 同时在用户信息中记录组
                if "groups" not in self.users.users[username]:
                    self.users.users[username]["groups"] = []
                if group_name not in self.users.users[username]["groups"]:
                    self.users.users[username]["groups"].append(group_name)
                changes.append(f"Added user {username} to group {group_name}")
            
            elif change_type == "add_cron":
                # 添加 cron 任务
                if target.startswith("crontab:"):
                    username = target.split(":", 1)[1]
                else:
                    username = "root"
                cron_line = new_value if isinstance(new_value, str) else str(new_value)
                self.cron.add_user_cron_line(username, cron_line)
                changes.append(f"Added cron job for {username}: {cron_line}")
            
            elif change_type == "create_at_job":
                # 添加 at 任务
                if isinstance(new_value, dict):
                    job_info = json.dumps(new_value)
                elif isinstance(new_value, str):
                    job_info = new_value
                else:
                    job_info = str(new_value)
                self.cron.add_at_job(job_info)
                changes.append(f"Added at job: {job_info}")
            
            elif change_type == "enable":
                # 启用服务
                if target.startswith("service:"):
                    service_name = target.split(":", 1)[1]
                    if not self.services.service_exists(service_name):
                        self.services.add_service(service_name, status="inactive", enabled=True)
                    else:
                        self.services.update_service_enabled(service_name, True)
                    changes.append(f"Enabled service: {service_name}")
            
            elif change_type == "modify":
                if target.startswith("/"):
                    # 检查操作类型
                    op = state_change.metadata.get("op", "") if state_change.metadata else ""
                    
                    if self.filesystem.file_exists(target):
                        # 文件已存在，修改内容
                        if isinstance(new_value, str):
                            if op == "redirect_append":
                                # 追加内容
                                current_content = self.filesystem.files[target].get("content", "")
                                self.filesystem.files[target]["content"] = current_content + "\n" + new_value if current_content else new_value
                            else:
                                # 覆盖内容
                                self.filesystem.files[target]["content"] = new_value
                            self.filesystem.files[target]["modified_at"] = datetime.now().isoformat()
                            changes.append(f"Modified file content: {target}")
                    elif op in ["redirect_append", "redirect_overwrite"]:
                        # 文件不存在但是重定向操作，创建新文件
                        content = new_value if isinstance(new_value, str) else ""
                        self.filesystem.add_file(target, content)
                        changes.append(f"Created file via redirection: {target}")
                
                elif target.startswith("user:"):
                    username = target.split(":", 1)[1]
                    if isinstance(new_value, dict):
                        # 如果用户不存在，先创建用户（对于蜜罐宽松处理）
                        if not self.users.user_exists(username):
                            self.users.add_user(username, uid=1001, gid=1001, 
                                              home=f"/home/{username}", shell="/bin/bash")
                            changes.append(f"Auto-created user {username} for modification")
                        
                        # 如果是添加组操作，确保组存在
                        if "groups_add" in new_value:
                            for group in new_value["groups_add"]:
                                if group not in self.users.groups:
                                    self.users.add_group(group)
                                    changes.append(f"Auto-created group {group}")
                        
                        self.users.modify_user(username, new_value)
                        changes.append(f"Modified user {username}: {new_value.keys()}")
                
                elif target.startswith("service:"):
                    service_name = target.split(":", 1)[1]
                    if isinstance(new_value, dict):
                        if "status" in new_value:
                            self.services.update_service_status(service_name, new_value["status"])
                            changes.append(f"Modified service {service_name} status: {new_value['status']}")
                        if "enabled" in new_value:
                            self.services.update_service_enabled(service_name, new_value["enabled"])
                            changes.append(f"Modified service {service_name} enabled: {new_value['enabled']}")
                
                elif target.startswith("cron:user:"):
                    username = target.split(":", 2)[2]
                    self.cron.add_user_cron_line(username, str(new_value))
                    changes.append(f"Added cron line for user {username}")

                elif target.startswith("cron:file:"):
                    filename = target.split(":", 2)[2]
                    self.cron.add_system_cron_file(filename, str(new_value))
                    changes.append(f"Added system cron file: {filename}")

                elif target == "system:hostname":
                    self.hostname = str(new_value)
                    changes.append(f"Changed hostname to {new_value}")

                elif target.startswith("sysctl:"):
                    param = target.split(":", 1)[1]
                    self.sysctl_params[param] = str(new_value)
                    changes.append(f"Set sysctl {param} = {new_value}")
                
                elif target == "network:hosts":
                    if isinstance(new_value, dict):
                        for host, ip in new_value.items():
                            self.network.add_host_entry(ip, host)
                            changes.append(f"Added host entry: {host} -> {ip}")

            elif change_type == "modify_attr":
                if target.startswith("/") and self.filesystem.file_exists(target):
                    # 修改文件属性
                    perms = new_value.get("permissions") if isinstance(new_value, dict) else None
                    owner = new_value.get("owner") if isinstance(new_value, dict) else None
                    self.filesystem.update_file_attributes(target, permissions=perms, owner=owner)
                    changes.append(f"Modified file attributes: {target} (perms={perms}, owner={owner})")

            elif change_type == "install":
                if target.startswith("package:"):
                    pkg_name = target.split(":", 1)[1]
                    version = "latest"
                    manager = "apt"
                    if isinstance(new_value, dict):
                        version = new_value.get("version", "latest")
                        manager = new_value.get("manager", "apt")
                    elif isinstance(new_value, str):
                        version = new_value
                    
                    self.packages.install_package(pkg_name, version, manager)
                    changes.append(f"Installed package: {pkg_name} ({manager})")
                
                elif target.startswith("module:"): # kernel module
                    mod_name = target.split(":", 1)[1]
                    if mod_name not in self.kernel_modules:
                        self.kernel_modules.append(mod_name)
                        changes.append(f"Loaded kernel module: {mod_name}")

            elif change_type == "uninstall":
                if target.startswith("package:"):
                    pkg_name = target.split(":", 1)[1]
                    self.packages.remove_package(pkg_name)
                    changes.append(f"Uninstalled package: {pkg_name}")
                elif target.startswith("module:"):
                    mod_name = target.split(":", 1)[1]
                    if mod_name in self.kernel_modules:
                        self.kernel_modules.remove(mod_name)
                        changes.append(f"Unloaded kernel module: {mod_name}")
            
            elif change_type == "delete":
                if target.startswith("/"):
                    if self.filesystem.file_exists(target):
                        self.filesystem.remove_file(target)
                        changes.append(f"Deleted file: {target}")
                    elif self.filesystem.directory_exists(target):
                        self.filesystem.remove_directory(target)
                        changes.append(f"Deleted directory: {target}")
                
                elif target.startswith("user:"):
                    username = target.split(":", 1)[1]
                    if self.users.remove_user(username):
                        changes.append(f"Deleted user: {username}")
                
                elif target.startswith("group:"):
                    # Basic group removal
                    groupname = target.split(":", 1)[1]
                    if groupname in self.users.groups:
                        del self.users.groups[groupname]
                        changes.append(f"Deleted group: {groupname}")
        
        self.timestamp = datetime.now()
        return changes
    
    def get_state_summary(self) -> Dict[str, Any]:
        """获取状态摘要"""
        return {
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "file_count": len(self.filesystem.files),
            "directory_count": len(self.filesystem.directories),
            "user_count": len(self.users.users),
            "service_count": len(self.services.services),
            "current_user": self.users.current_user
        }


class MemorySystem(BaseModel):
    """结构化长期记忆系统"""
    storage_path: str = Field(description="存储路径")
    instance_states: Dict[str, SystemState] = Field(default_factory=dict, description="实例状态映射")
    instance_graphs: Dict[str, EventGraph] = Field(default_factory=dict, description="实例事件图映射")
    ip_instance_map: Dict[str, str] = Field(default_factory=dict, description="IP到实例ID的映射")
    global_singleton_mode: bool = Field(default=False, description="是否启用全局单例模式")
    
    def __init__(self, storage_path: str = "./data/memory", global_singleton_mode: bool = False, **data):
        super().__init__(storage_path=storage_path, global_singleton_mode=global_singleton_mode, **data)
        self.storage_path = storage_path
        Path(storage_path).mkdir(parents=True, exist_ok=True)
        self._load_existing_data()
    
    def get_system_state(self, ip_address: str) -> SystemState:
        """获取指定IP的系统状态"""
        return self.get_or_create_state(ip_address)

    def _load_existing_data(self) -> None:
        """加载现有数据"""
        storage_dir = Path(self.storage_path)
        
        # 加载IP映射
        map_file = storage_dir / "ip_map.json"
        if map_file.exists():
            try:
                with open(map_file, 'r', encoding='utf-8') as f:
                    self.ip_instance_map = json.load(f)
            except Exception as e:
                print(f"Failed to load IP map: {e}")

        # 加载系统状态
        states_dir = storage_dir / "states"
        if states_dir.exists():
            for state_file in states_dir.glob("*.json"):
                instance_id = state_file.stem
                try:
                    with open(state_file, 'r', encoding='utf-8') as f:
                        state_data = json.load(f)
                    state_data["timestamp"] = datetime.fromisoformat(state_data["timestamp"])
                    self.instance_states[instance_id] = SystemState(**state_data)
                except Exception as e:
                    print(f"Failed to load state for instance {instance_id}: {e}")
        
        # 加载事件图
        graphs_dir = storage_dir / "graphs"
        if graphs_dir.exists():
            for graph_file in graphs_dir.glob("*.json"):
                instance_id = graph_file.stem
                try:
                    self.instance_graphs[instance_id] = EventGraph.import_from_json(str(graph_file))
                except Exception as e:
                    print(f"Failed to load graph for instance {instance_id}: {e}")
    
    def get_instance_id(self, ip_address: str) -> str:
        """根据IP地址获取实例ID"""
        if self.global_singleton_mode:
            return "global_default"
        
        if ip_address not in self.ip_instance_map:
            # 默认每个IP一个实例，但支持后续手动link
            self.ip_instance_map[ip_address] = ip_address
            self._save_ip_map()
            
        return self.ip_instance_map[ip_address]

    def link_ip_to_instance(self, ip_address: str, instance_id: str) -> None:
        """将IP关联到指定实例"""
        self.ip_instance_map[ip_address] = instance_id
        self._save_ip_map()

    def get_or_create_state(self, ip_address: str) -> SystemState:
        """获取或创建IP对应的系统状态"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_states:
            # 创建空的系统状态，让AI自由发挥
            self.instance_states[instance_id] = SystemState(ip_address=ip_address)
            self._save_state(instance_id)
        return self.instance_states[instance_id]
    
    def get_or_create_graph(self, ip_address: str) -> EventGraph:
        """获取或创建IP对应的事件图"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_graphs:
            self.instance_graphs[instance_id] = EventGraph(ip_address=ip_address)
            self._save_graph(instance_id)
        return self.instance_graphs[instance_id]
    
    def record_event(self, event: EventNode) -> str:
        """记录事件并更新状态"""
        ip_address = event.ip_address
        instance_id = self.get_instance_id(ip_address)
        
        # 获取或创建事件图和系统状态
        graph = self.get_or_create_graph(ip_address)
        state = self.get_or_create_state(ip_address)
        
        # 添加事件到图中
        event_id = graph.add_event(event)
        
        # 应用事件到系统状态
        changes = state.apply_event(event)
        
        # 保存更新
        self._save_graph(instance_id)
        self._save_state(instance_id)
        
        return event_id
    
    def query_state(self, ip_address: str, query_type: str, target: str) -> Any:
        """查询系统状态"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_states:
            return None
        
        state = self.instance_states[instance_id]
        
        if query_type == "file_exists":
            return state.filesystem.file_exists(target)
        elif query_type == "directory_exists":
            return state.filesystem.directory_exists(target)
        elif query_type == "file_content":
            return state.filesystem.get_file_content(target)
        elif query_type == "user_exists":
            return state.users.user_exists(target)
        elif query_type == "service_status":
            return state.services.get_service_status(target)
        elif query_type == "package_installed":
            return state.packages.is_installed(target)
        else:
            return None
    
    def validate_consistency(self, ip_address: str, target: str) -> Dict[str, Any]:
        """验证特定目标的一致性"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_graphs:
            return {"error": "No event graph found for IP"}
        
        graph = self.instance_graphs[instance_id]
        return graph.validate_state_consistency(target)
    
    def get_cross_session_state(self, ip_address: str) -> Dict[str, Any]:
        """获取跨会话状态信息"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_states:
            return {}
        
        state = self.instance_states[instance_id]
        graph = self.instance_graphs.get(instance_id)
        
        result = {
            "state_summary": state.get_state_summary(),
            "event_count": len(graph.nodes) if graph else 0,
            "session_count": len(set(node.session_id for node in graph.nodes.values())) if graph else 0
        }
        
        return result
    
    def get_event_graph(self, ip_address: str) -> Optional['EventGraph']:
        """获取指定IP的事件图"""
        instance_id = self.get_instance_id(ip_address)
        return self.instance_graphs.get(instance_id)
    
    def get_state_summary(self, ip_address: str) -> Dict[str, Any]:
        """
        获取系统状态的摘要信息，便于快速了解当前状态
        
        Returns:
            包含文件数、用户数、服务数等摘要信息的字典
        """
        state = self.get_system_state(ip_address)
        return {
            "hostname": state.hostname,
            "os_version": state.os_version,
            "current_user": state.users.current_user,
            "file_count": len(state.filesystem.files),
            "directory_count": len(state.filesystem.directories),
            "user_count": len(state.users.users),
            "service_count": len(state.services.services),
            "package_count": len(state.packages.installed_packages),
            "uptime": state.uptime
        }
    
    def check_file_exists(self, ip_address: str, file_path: str) -> bool:
        """检查文件是否存在"""
        state = self.get_system_state(ip_address)
        return state.filesystem.file_exists(file_path)
    
    def check_directory_exists(self, ip_address: str, dir_path: str) -> bool:
        """检查目录是否存在"""
        state = self.get_system_state(ip_address)
        return state.filesystem.directory_exists(dir_path)
    
    def get_file_content(self, ip_address: str, file_path: str) -> Optional[str]:
        """获取文件内容"""
        state = self.get_system_state(ip_address)
        return state.filesystem.get_file_content(file_path)
    
    def check_user_exists(self, ip_address: str, username: str) -> bool:
        """检查用户是否存在"""
        state = self.get_system_state(ip_address)
        return state.users.user_exists(username)
    
    def get_directory_contents(self, ip_address: str, dir_path: str) -> Dict[str, List[str]]:
        """
        获取目录内容（文件和子目录列表）
        
        Returns:
            {"files": [...], "directories": [...]}
        """
        state = self.get_system_state(ip_address)
        files = []
        directories = []
        
        for file_path in state.filesystem.files.keys():
            parent = '/'.join(file_path.split('/')[:-1]) or '/'
            if parent == dir_path:
                files.append(file_path.split('/')[-1])
        
        for directory in state.filesystem.directories.keys():
            parent = '/'.join(directory.split('/')[:-1]) or '/'
            if parent == dir_path:
                directories.append(directory.split('/')[-1])
        
        return {"files": files, "directories": directories}

    
    def _save_ip_map(self) -> None:
        """保存IP映射"""
        storage_dir = Path(self.storage_path)
        storage_dir.mkdir(parents=True, exist_ok=True)
        
        map_file = storage_dir / "ip_map.json"
        with open(map_file, 'w', encoding='utf-8') as f:
            json.dump(self.ip_instance_map, f, ensure_ascii=False, indent=2)

    def _save_state(self, instance_id: str) -> None:
        """保存系统状态"""
        if instance_id not in self.instance_states:
            return
        
        states_dir = Path(self.storage_path) / "states"
        states_dir.mkdir(parents=True, exist_ok=True)
        
        state_file = states_dir / f"{instance_id}.json"
        state_data = self.instance_states[instance_id].dict()
        
        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(state_data, f, ensure_ascii=False, indent=2, default=str)
    
    def _save_graph(self, instance_id: str) -> None:
        """保存事件图"""
        if instance_id not in self.instance_graphs:
            return
        
        graphs_dir = Path(self.storage_path) / "graphs"
        graphs_dir.mkdir(parents=True, exist_ok=True)
        
        graph_file = graphs_dir / f"{instance_id}.json"
        self.instance_graphs[instance_id].export_to_json(str(graph_file))
    
    def cleanup_old_data(self, days: int = 30) -> None:
        """清理旧数据"""
        cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
        
        # 清理旧的实例状态
        to_remove = []
        for instance_id, state in self.instance_states.items():
            if state.timestamp.timestamp() < cutoff_time:
                to_remove.append(instance_id)
        
        for instance_id in to_remove:
            del self.instance_states[instance_id]
            if instance_id in self.instance_graphs:
                del self.instance_graphs[instance_id]
            
            # 删除文件
            state_file = Path(self.storage_path) / "states" / f"{instance_id}.json"
            graph_file = Path(self.storage_path) / "graphs" / f"{instance_id}.json"
            
            if state_file.exists():
                state_file.unlink()
            if graph_file.exists():
                graph_file.unlink()
    
    def export_ip_data(self, ip_address: str, output_dir: str) -> None:
        """导出特定IP的所有数据"""
        instance_id = self.get_instance_id(ip_address)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 导出状态
        if instance_id in self.instance_states:
            state_file = output_path / f"{ip_address}_state.json"
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(self.instance_states[instance_id].dict(), f, 
                         ensure_ascii=False, indent=2, default=str)
        
        # 导出事件图
        if instance_id in self.instance_graphs:
            graph_file = output_path / f"{ip_address}_graph.json"
            self.instance_graphs[instance_id].export_to_json(str(graph_file))