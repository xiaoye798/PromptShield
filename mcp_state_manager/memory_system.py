"""
Structured Long-Term Memory System

Used for persistent storage and management of LLM honeypot system state, event graphs, and cross-session information.
Supports IP isolation, state snapshots, incremental updates, and state recovery.
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
    """File System State"""
    files: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="File information")
    directories: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Directory information")
    permissions: Dict[str, str] = Field(default_factory=dict, description="Permission information")
    links: Dict[str, str] = Field(default_factory=dict, description="Link information")
    
    def add_file(self, path: str, content: str = "", permissions: str = "644", 
                 owner: str = "root", size: int = 0) -> None:
        """Add file"""
        self.files[path] = {
            "content": content,
            "permissions": permissions,
            "owner": owner,
            "size": size,
            "created_at": datetime.now().isoformat(),
            "modified_at": datetime.now().isoformat()
        }
    
    def add_directory(self, path: str, permissions: str = "755", owner: str = "root") -> None:
        """Add directory"""
        self.directories[path] = {
            "permissions": permissions,
            "owner": owner,
            "created_at": datetime.now().isoformat()
        }
    
    def remove_file(self, path: str) -> bool:
        """Remove file"""
        return self.files.pop(path, None) is not None
    
    def remove_directory(self, path: str) -> bool:
        """Remove directory"""
        return self.directories.pop(path, None) is not None
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        return path in self.files
    
    def directory_exists(self, path: str) -> bool:
        """Check if directory exists"""
        return path in self.directories
    
    def update_file_attributes(self, path: str, permissions: Optional[str] = None, owner: Optional[str] = None) -> bool:
        """Update file attributes"""
        if path in self.files:
            if permissions:
                self.files[path]["permissions"] = permissions
            if owner:
                self.files[path]["owner"] = owner
            self.files[path]["modified_at"] = datetime.now().isoformat()
            return True
        return False

    def get_file_content(self, path: str) -> Optional[str]:
        """Get file content"""
        file_info = self.files.get(path)
        return file_info["content"] if file_info else None


class UserState(BaseModel):
    """User State"""
    users: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="User info /etc/passwd")
    groups: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Group info /etc/group")
    shadow: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Password info /etc/shadow")
    sudoers: List[str] = Field(default_factory=list, description="sudo permissions")
    current_user: str = Field(default="root", description="Current user")
    login_history: List[Dict[str, Any]] = Field(default_factory=list, description="Login history")
    
    def add_user(self, username: str, uid: int = 1000, gid: int = 1000, home: str = "", 
                 shell: str = "/bin/bash", password_hash: str = "!", shadow_info: Dict = None) -> None:
        """Add user"""
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
        """Add user group"""
        self.groups[groupname] = {
            "gid": gid,
            "members": members or [],
            "created_at": datetime.now().isoformat()
        }

    def modify_user(self, username: str, changes: Dict[str, Any]) -> bool:
        """Modify user info (usermod)"""
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
        """Set password (passwd)"""
        if username in self.shadow:
            self.shadow[username]["password"] = password_hash
            return True
        return False

    def remove_user(self, username: str) -> bool:
        """Remove user"""
        self.shadow.pop(username, None)
        return self.users.pop(username, None) is not None
    
    def user_exists(self, username: str) -> bool:
        """Check if user exists"""
        return username in self.users
    
    def set_current_user(self, username: str) -> bool:
        """Set current user"""
        if self.user_exists(username):
            self.current_user = username
            return True
        return False


class CronState(BaseModel):
    """Cron Job State"""
    user_crontabs: Dict[str, List[str]] = Field(default_factory=dict, description="User crontabs")
    system_cron_files: Dict[str, str] = Field(default_factory=dict, description="System cron files /etc/cron.d/ etc.")
    etc_crontab: List[str] = Field(default_factory=list, description="/etc/crontab content")
    anacrontab: List[str] = Field(default_factory=list, description="/etc/anacrontab content")
    at_jobs: List[str] = Field(default_factory=list, description="at jobs")

    def add_user_cron_line(self, username: str, line: str) -> None:
        if username not in self.user_crontabs:
            self.user_crontabs[username] = []
        self.user_crontabs[username].append(line)

    def add_system_cron_file(self, filename: str, content: str) -> None:
        self.system_cron_files[filename] = content

    def add_at_job(self, job_content: str) -> None:
        self.at_jobs.append(job_content)


class ServiceState(BaseModel):
    """Service State"""
    services: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Service info")
    processes: Dict[int, Dict[str, Any]] = Field(default_factory=dict, description="Process info")
    
    def add_service(self, name: str, status: str = "inactive", enabled: bool = False, 
                    unit_file_content: str = "") -> None:
        """Add service"""
        self.services[name] = {
            "status": status,
            "enabled": enabled,
            "unit_content": unit_file_content,
            "created_at": datetime.now().isoformat()
        }
    
    def update_service_status(self, name: str, status: str) -> bool:
        """Update service status"""
        if name in self.services:
            self.services[name]["status"] = status
            self.services[name]["updated_at"] = datetime.now().isoformat()
            return True
        return False

    def update_service_enabled(self, name: str, enabled: bool) -> bool:
        """Update service enabled status"""
        if name in self.services:
            self.services[name]["enabled"] = enabled
            self.services[name]["updated_at"] = datetime.now().isoformat()
            return True
        return False
    
    def service_exists(self, name: str) -> bool:
        """Check if service exists"""
        return name in self.services
    
    def get_service_status(self, name: str) -> Optional[str]:
        """Get service status"""
        service = self.services.get(name)
        return service["status"] if service else None


class NetworkState(BaseModel):
    """Network State"""
    interfaces: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Network interfaces")
    routes: List[str] = Field(default_factory=list, description="Routing table")
    connections: List[Dict[str, Any]] = Field(default_factory=list, description="Network connections")
    hosts: Dict[str, str] = Field(default_factory=dict, description="/etc/hosts mapping")
    iptables_rules: List[str] = Field(default_factory=list, description="iptables rules")
    nftables_rules: List[str] = Field(default_factory=list, description="nftables rules")
    dns_servers: List[str] = Field(default_factory=list, description="DNS servers")
    
    def add_interface(self, name: str, ip: str, netmask: str = "255.255.255.0", 
                     status: str = "up") -> None:
        """Add network interface"""
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
    """Package State"""
    installed_packages: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Installed packages")
    available_packages: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Available packages")
    
    def install_package(self, name: str, version: str = "latest", manager: str = "apt") -> None:
        """Install package"""
        self.installed_packages[name] = {
            "version": version,
            "manager": manager,
            "installed_at": datetime.now().isoformat()
        }
    
    def remove_package(self, name: str) -> bool:
        """Uninstall package"""
        return self.installed_packages.pop(name, None) is not None
    
    def is_installed(self, name: str) -> bool:
        """Check if package is installed"""
        return name in self.installed_packages


class SystemState(BaseModel):
    """System State Snapshot"""
    ip_address: str = Field(description="IP Address")
    timestamp: datetime = Field(default_factory=datetime.now, description="Snapshot time")
    
    # Subsystem states
    filesystem: FileSystemState = Field(default_factory=FileSystemState)
    users: UserState = Field(default_factory=UserState)
    services: ServiceState = Field(default_factory=ServiceState)
    network: NetworkState = Field(default_factory=NetworkState)
    packages: PackageState = Field(default_factory=PackageState)
    cron: CronState = Field(default_factory=CronState)
    
    # System info
    hostname: str = Field(default="honeypot", description="Hostname")
    kernel_version: str = Field(default="5.4.0", description="Kernel version")
    os_version: str = Field(default="Ubuntu 20.04", description="OS version")
    uptime: int = Field(default=0, description="System uptime (seconds)")
    
    # Environment variables
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    kernel_modules: List[str] = Field(default_factory=list, description="Kernel modules")
    sysctl_params: Dict[str, str] = Field(default_factory=dict, description="sysctl parameters")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def apply_event(self, event: EventNode) -> List[str]:
        """Apply event to system state, return list of changes"""
        changes = []
        
        for state_change in event.state_changes:
            target = state_change.target
            change_type = state_change.change_type
            new_value = state_change.new_value
            
            if change_type == "create":
                if target.startswith("/"):  # File system path
                    # Check is_dir flag in metadata
                    is_dir = state_change.metadata.get("is_dir", False) if state_change.metadata else False
                    if target.endswith("/") or is_dir:  # Directory
                        self.filesystem.add_directory(target.rstrip("/"))
                        changes.append(f"Created directory: {target}")
                    else:  # File
                        content = new_value if isinstance(new_value, str) else ""
                        self.filesystem.add_file(target, content)
                        changes.append(f"Created file: {target}")
                        
                        # Special file handling
                        if target == "/etc/hostname" and content:
                            self.hostname = content.strip()
                            changes.append(f"Updated hostname to: {self.hostname}")
                
                elif target.startswith("user:"):  # User operations
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
                
                elif target.startswith("service:"):  # Service operations
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
                # File append operation
                if target.startswith("/"):
                    content = new_value if isinstance(new_value, str) else str(new_value)
                    if self.filesystem.file_exists(target):
                        # File exists, append content
                        current_content = self.filesystem.files[target].get("content", "")
                        self.filesystem.files[target]["content"] = current_content + "\n" + content if current_content else content
                        self.filesystem.files[target]["modified_at"] = datetime.now().isoformat()
                        changes.append(f"Appended to file: {target}")
                    else:
                        # File does not exist, create new file
                        self.filesystem.add_file(target, content)
                        changes.append(f"Created file with append: {target}")
            
            elif change_type == "create_user":
                # Create user operation
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
                # Add user to group
                if target.startswith("user:"):
                    username = target.split(":", 1)[1]
                else:
                    username = target
                group_name = new_value if isinstance(new_value, str) else str(new_value)
                # Ensure user exists
                if not self.users.user_exists(username):
                    self.users.add_user(username, uid=1001, gid=1001)
                    changes.append(f"Auto-created user: {username}")
                # Ensure group exists
                if group_name not in self.users.groups:
                    self.users.add_group(group_name)
                    changes.append(f"Auto-created group: {group_name}")
                # Add user to group list
                if username not in self.users.groups[group_name]["members"]:
                    self.users.groups[group_name]["members"].append(username)
                # Also record group in user info
                if "groups" not in self.users.users[username]:
                    self.users.users[username]["groups"] = []
                if group_name not in self.users.users[username]["groups"]:
                    self.users.users[username]["groups"].append(group_name)
                changes.append(f"Added user {username} to group {group_name}")
            
            elif change_type == "add_cron":
                # Add cron job
                if target.startswith("crontab:"):
                    username = target.split(":", 1)[1]
                else:
                    username = "root"
                cron_line = new_value if isinstance(new_value, str) else str(new_value)
                self.cron.add_user_cron_line(username, cron_line)
                changes.append(f"Added cron job for {username}: {cron_line}")
            
            elif change_type == "create_at_job":
                # Add at job
                if isinstance(new_value, dict):
                    job_info = json.dumps(new_value)
                elif isinstance(new_value, str):
                    job_info = new_value
                else:
                    job_info = str(new_value)
                self.cron.add_at_job(job_info)
                changes.append(f"Added at job: {job_info}")
            
            elif change_type == "enable":
                # Enable service
                if target.startswith("service:"):
                    service_name = target.split(":", 1)[1]
                    if not self.services.service_exists(service_name):
                        self.services.add_service(service_name, status="inactive", enabled=True)
                    else:
                        self.services.update_service_enabled(service_name, True)
                    changes.append(f"Enabled service: {service_name}")
            
            elif change_type == "modify":
                if target.startswith("/"):
                    # Check operation type
                    op = state_change.metadata.get("op", "") if state_change.metadata else ""
                    
                    if self.filesystem.file_exists(target):
                        # File exists, modify content
                        if isinstance(new_value, str):
                            if op == "redirect_append":
                                # Redirect append
                                current_content = self.filesystem.files[target].get("content", "")
                                self.filesystem.files[target]["content"] = current_content + "\n" + new_value if current_content else new_value
                            else:
                                # Redirect overwrite
                                self.filesystem.files[target]["content"] = new_value
                            self.filesystem.files[target]["modified_at"] = datetime.now().isoformat()
                            changes.append(f"Modified file content: {target}")
                    elif op in ["redirect_append", "redirect_overwrite"]:
                        # File does not exist but redirect op, create new file
                        content = new_value if isinstance(new_value, str) else ""
                        self.filesystem.add_file(target, content)
                        changes.append(f"Created file via redirection: {target}")
                
                elif target.startswith("user:"):
                    username = target.split(":", 1)[1]
                    if isinstance(new_value, dict):
                        # If user does not exist, create it first (lenient for honeypot)
                        if not self.users.user_exists(username):
                            self.users.add_user(username, uid=1001, gid=1001, 
                                              home=f"/home/{username}", shell="/bin/bash")
                            changes.append(f"Auto-created user {username} for modification")
                        
                        # If adding group, ensure group exists
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
                    # Modify file attributes
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
        """Get state summary"""
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
    """Structured Long-Term Memory System"""
    storage_path: str = Field(description="Storage path")
    instance_states: Dict[str, SystemState] = Field(default_factory=dict, description="Instance state mapping")
    instance_graphs: Dict[str, EventGraph] = Field(default_factory=dict, description="Instance event graph mapping")
    ip_instance_map: Dict[str, str] = Field(default_factory=dict, description="IP to Instance ID mapping")
    global_singleton_mode: bool = Field(default=False, description="Enable global singleton mode")
    
    def __init__(self, storage_path: str = "./data/memory", global_singleton_mode: bool = False, **data):
        super().__init__(storage_path=storage_path, global_singleton_mode=global_singleton_mode, **data)
        self.storage_path = storage_path
        Path(storage_path).mkdir(parents=True, exist_ok=True)
        self._load_existing_data()
    
    def get_system_state(self, ip_address: str) -> SystemState:
        """Get system state for specific IP"""
        return self.get_or_create_state(ip_address)

    def _load_existing_data(self) -> None:
        """Load existing data"""
        storage_dir = Path(self.storage_path)
        
        # Load IP map
        map_file = storage_dir / "ip_map.json"
        if map_file.exists():
            try:
                with open(map_file, 'r', encoding='utf-8') as f:
                    self.ip_instance_map = json.load(f)
            except Exception as e:
                print(f"Failed to load IP map: {e}")

        # Load system states
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
        
        # Load event graphs
        graphs_dir = storage_dir / "graphs"
        if graphs_dir.exists():
            for graph_file in graphs_dir.glob("*.json"):
                instance_id = graph_file.stem
                try:
                    self.instance_graphs[instance_id] = EventGraph.import_from_json(str(graph_file))
                except Exception as e:
                    print(f"Failed to load graph for instance {instance_id}: {e}")
    
    def get_instance_id(self, ip_address: str) -> str:
        """Get instance ID by IP address"""
        if self.global_singleton_mode:
            return "global_default"
        
        if ip_address not in self.ip_instance_map:
            # Default one instance per IP, but supports manual linking
            self.ip_instance_map[ip_address] = ip_address
            self._save_ip_map()
            
        return self.ip_instance_map[ip_address]

    def link_ip_to_instance(self, ip_address: str, instance_id: str) -> None:
        """Link IP to specific instance"""
        self.ip_instance_map[ip_address] = instance_id
        self._save_ip_map()

    def get_or_create_state(self, ip_address: str) -> SystemState:
        """Get or create system state for IP"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_states:
            # Create empty system state, let AI improvise
            self.instance_states[instance_id] = SystemState(ip_address=ip_address)
            self._save_state(instance_id)
        return self.instance_states[instance_id]
    
    def get_or_create_graph(self, ip_address: str) -> EventGraph:
        """Get or create event graph for IP"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_graphs:
            self.instance_graphs[instance_id] = EventGraph(ip_address=ip_address)
            self._save_graph(instance_id)
        return self.instance_graphs[instance_id]
    
    def record_event(self, event: EventNode) -> str:
        """Record event and update state"""
        ip_address = event.ip_address
        instance_id = self.get_instance_id(ip_address)
        
        # Get or create event graph and system state
        graph = self.get_or_create_graph(ip_address)
        state = self.get_or_create_state(ip_address)
        
        # Add event to graph
        event_id = graph.add_event(event)
        
        # Apply event to system state
        changes = state.apply_event(event)
        
        # Save updates
        self._save_graph(instance_id)
        self._save_state(instance_id)
        
        return event_id
    
    def query_state(self, ip_address: str, query_type: str, target: str) -> Any:
        """Query system state"""
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
        """Validate consistency for specific target"""
        instance_id = self.get_instance_id(ip_address)
        
        if instance_id not in self.instance_graphs:
            return {"error": "No event graph found for IP"}
        
        graph = self.instance_graphs[instance_id]
        return graph.validate_state_consistency(target)
    
    def get_cross_session_state(self, ip_address: str) -> Dict[str, Any]:
        """Get cross-session state information"""
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
        """Get event graph for specific IP"""
        instance_id = self.get_instance_id(ip_address)
        return self.instance_graphs.get(instance_id)
    
    def get_state_summary(self, ip_address: str) -> Dict[str, Any]:
        """
        Get system state summary for quick overview
        
        Returns:
            Dictionary containing file count, user count, service count etc.
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
        """Check if file exists"""
        state = self.get_system_state(ip_address)
        return state.filesystem.file_exists(file_path)
    
    def check_directory_exists(self, ip_address: str, dir_path: str) -> bool:
        """Check if directory exists"""
        state = self.get_system_state(ip_address)
        return state.filesystem.directory_exists(dir_path)
    
    def get_file_content(self, ip_address: str, file_path: str) -> Optional[str]:
        """Get file content"""
        state = self.get_system_state(ip_address)
        return state.filesystem.get_file_content(file_path)
    
    def check_user_exists(self, ip_address: str, username: str) -> bool:
        """Check if user exists"""
        state = self.get_system_state(ip_address)
        return state.users.user_exists(username)
    
    def get_directory_contents(self, ip_address: str, dir_path: str) -> Dict[str, List[str]]:
        """
        Get directory contents (files and subdirectories)
        
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
        """Save IP map"""
        storage_dir = Path(self.storage_path)
        storage_dir.mkdir(parents=True, exist_ok=True)
        
        map_file = storage_dir / "ip_map.json"
        with open(map_file, 'w', encoding='utf-8') as f:
            json.dump(self.ip_instance_map, f, ensure_ascii=False, indent=2)

    def _save_state(self, instance_id: str) -> None:
        """Save system state"""
        if instance_id not in self.instance_states:
            return
        
        states_dir = Path(self.storage_path) / "states"
        states_dir.mkdir(parents=True, exist_ok=True)
        
        state_file = states_dir / f"{instance_id}.json"
        state_data = self.instance_states[instance_id].dict()
        
        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(state_data, f, ensure_ascii=False, indent=2, default=str)
    
    def _save_graph(self, instance_id: str) -> None:
        """Save event graph"""
        if instance_id not in self.instance_graphs:
            return
        
        graphs_dir = Path(self.storage_path) / "graphs"
        graphs_dir.mkdir(parents=True, exist_ok=True)
        
        graph_file = graphs_dir / f"{instance_id}.json"
        self.instance_graphs[instance_id].export_to_json(str(graph_file))
    
    def cleanup_old_data(self, days: int = 30) -> None:
        """Clean up old data"""
        cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
        
        # Clean up old instance states
        to_remove = []
        for instance_id, state in self.instance_states.items():
            if state.timestamp.timestamp() < cutoff_time:
                to_remove.append(instance_id)
        
        for instance_id in to_remove:
            del self.instance_states[instance_id]
            if instance_id in self.instance_graphs:
                del self.instance_graphs[instance_id]
            
            # Delete files
            state_file = Path(self.storage_path) / "states" / f"{instance_id}.json"
            graph_file = Path(self.storage_path) / "graphs" / f"{instance_id}.json"
            
            if state_file.exists():
                state_file.unlink()
            if graph_file.exists():
                graph_file.unlink()
    
    def export_ip_data(self, ip_address: str, output_dir: str) -> None:
        """Export all data for specific IP"""
        instance_id = self.get_instance_id(ip_address)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export state
        if instance_id in self.instance_states:
            state_file = output_path / f"{ip_address}_state.json"
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(self.instance_states[instance_id].dict(), f, 
                         ensure_ascii=False, indent=2, default=str)
        
        # Export event graph
        if instance_id in self.instance_graphs:
            graph_file = output_path / f"{ip_address}_graph.json"
            self.instance_graphs[instance_id].export_to_json(str(graph_file))
