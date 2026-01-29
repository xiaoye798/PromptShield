"""
事件图 (Event Graph) 实现

用于记录和管理LLM蜜罐中的命令执行事件、状态变化和因果关系。
支持事件链追踪、状态查询和一致性验证。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """事件类型枚举"""
    COMMAND_EXECUTION = "command_execution"
    FILE_OPERATION = "file_operation"
    USER_OPERATION = "user_operation"
    SERVICE_OPERATION = "service_operation"
    NETWORK_OPERATION = "network_operation"
    PACKAGE_OPERATION = "package_operation"
    CRON_OPERATION = "cron_operation"
    CONFIG_CHANGE = "config_change"
    KERNEL_OPERATION = "kernel_operation"
    DB_OPERATION = "db_operation"


class EventStatus(str, Enum):
    """事件状态枚举"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"


class StateChange(BaseModel):
    """状态变化记录"""
    target: str = Field(description="变化目标（文件路径、用户名等）")
    change_type: str = Field(description="变化类型（create、modify、delete等）")
    old_value: Optional[Any] = Field(default=None, description="变化前的值")
    new_value: Optional[Any] = Field(default=None, description="变化后的值")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class EventNode(BaseModel):
    """事件节点"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="事件唯一ID")
    timestamp: datetime = Field(default_factory=datetime.now, description="事件时间戳")
    event_type: EventType = Field(description="事件类型")
    command: str = Field(description="执行的命令")
    session_id: str = Field(description="会话ID")
    ip_address: str = Field(description="客户端IP地址")
    user_context: str = Field(description="用户上下文（用户名@主机名）")
    
    # 执行结果
    status: EventStatus = Field(description="事件执行状态")
    stdout: str = Field(default="", description="标准输出")
    stderr: str = Field(default="", description="标准错误")
    return_code: int = Field(default=0, description="返回码")
    
    # 状态变化
    state_changes: List[StateChange] = Field(default_factory=list, description="状态变化列表")
    
    # 元数据
    metadata: Dict[str, Any] = Field(default_factory=dict, description="事件元数据")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class EventEdge(BaseModel):
    """事件边 - 表示事件间的因果关系"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="边唯一ID")
    source_event_id: str = Field(description="源事件ID")
    target_event_id: str = Field(description="目标事件ID")
    relationship_type: str = Field(description="关系类型（depends_on、enables、conflicts等）")
    strength: float = Field(default=1.0, ge=0.0, le=1.0, description="关系强度")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="关系元数据")


class EventGraph(BaseModel):
    """事件图主类"""
    ip_address: str = Field(description="关联的IP地址")
    nodes: Dict[str, EventNode] = Field(default_factory=dict, description="事件节点字典")
    edges: Dict[str, EventEdge] = Field(default_factory=dict, description="事件边字典")
    created_at: datetime = Field(default_factory=datetime.now, description="图创建时间")
    updated_at: datetime = Field(default_factory=datetime.now, description="图更新时间")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_event(self, event: EventNode) -> str:
        """添加事件节点"""
        if event.ip_address != self.ip_address:
            raise ValueError(f"Event IP {event.ip_address} doesn't match graph IP {self.ip_address}")
        
        self.nodes[event.id] = event
        self.updated_at = datetime.now()
        
        # 自动检测和创建因果关系
        self._detect_causal_relationships(event)
        
        return event.id
    
    def add_relationship(self, edge: EventEdge) -> str:
        """添加事件关系"""
        if edge.source_event_id not in self.nodes:
            raise ValueError(f"Source event {edge.source_event_id} not found")
        if edge.target_event_id not in self.nodes:
            raise ValueError(f"Target event {edge.target_event_id} not found")
        
        self.edges[edge.id] = edge
        self.updated_at = datetime.now()
        return edge.id
    
    def get_event(self, event_id: str) -> Optional[EventNode]:
        """获取事件节点"""
        return self.nodes.get(event_id)
    
    def get_events_by_type(self, event_type: EventType) -> List[EventNode]:
        """按类型获取事件"""
        return [node for node in self.nodes.values() if node.event_type == event_type]
    
    def get_events_by_session(self, session_id: str) -> List[EventNode]:
        """按会话获取事件"""
        return [node for node in self.nodes.values() if node.session_id == session_id]
    
    def get_events(self, session_id: str = None, event_type: EventType = None) -> List[EventNode]:
        """获取事件列表，支持按会话ID和事件类型过滤"""
        events = list(self.nodes.values())
        
        if session_id:
            events = [event for event in events if event.session_id == session_id]
        
        if event_type:
            events = [event for event in events if event.event_type == event_type]
        
        return events
    
    def get_events_affecting_target(self, target: str) -> List[EventNode]:
        """获取影响特定目标的所有事件"""
        events = []
        for node in self.nodes.values():
            for change in node.state_changes:
                if change.target == target:
                    events.append(node)
                    break
        return events
    
    def get_dependency_chain(self, event_id: str) -> List[EventNode]:
        """获取事件的依赖链"""
        if event_id not in self.nodes:
            return []
        
        visited = set()
        chain = []
        
        def dfs(current_id: str):
            if current_id in visited:
                return
            visited.add(current_id)
            
            # 找到所有依赖的事件
            dependencies = []
            for edge in self.edges.values():
                if (edge.target_event_id == current_id and 
                    edge.relationship_type in ["depends_on", "caused_by"]):
                    dependencies.append(edge.source_event_id)
            
            # 递归处理依赖
            for dep_id in dependencies:
                dfs(dep_id)
            
            # 添加当前事件到链中
            if current_id in self.nodes:
                chain.append(self.nodes[current_id])
        
        dfs(event_id)
        return chain
    
    def validate_state_consistency(self, target: str) -> Dict[str, Any]:
        """验证特定目标的状态一致性"""
        events = self.get_events_affecting_target(target)
        events.sort(key=lambda x: x.timestamp)
        
        consistency_report = {
            "target": target,
            "is_consistent": True,
            "issues": [],
            "final_state": None,
            "event_count": len(events),
            "consistency_score": 1.0
        }
        
        if not events:
            consistency_report["issues"].append("No events found for target")
            consistency_report["consistency_score"] = 0.0
            return consistency_report
        
        # 模拟状态变化
        current_state = None
        issue_count = 0
        for event in events:
            for change in event.state_changes:
                if change.target == target:
                    if change.change_type == "create":
                        if current_state is not None:
                            consistency_report["issues"].append(
                                f"Attempt to create existing target at {event.timestamp}"
                            )
                            consistency_report["is_consistent"] = False
                            issue_count += 1
                        current_state = change.new_value
                    elif change.change_type == "modify":
                        if current_state is None:
                            consistency_report["issues"].append(
                                f"Attempt to modify non-existent target at {event.timestamp}"
                            )
                            consistency_report["is_consistent"] = False
                            issue_count += 1
                        else:
                            current_state = change.new_value
                    elif change.change_type == "delete":
                        if current_state is None:
                            consistency_report["issues"].append(
                                f"Attempt to delete non-existent target at {event.timestamp}"
                            )
                            consistency_report["is_consistent"] = False
                            issue_count += 1
                        else:
                            current_state = None
        
        # 计算一致性分数：基于问题数量和事件总数
        if len(events) > 0:
            consistency_report["consistency_score"] = max(0.0, 1.0 - (issue_count / len(events)))
        
        consistency_report["final_state"] = current_state
        return consistency_report
    
    def _detect_causal_relationships(self, new_event: EventNode) -> None:
        """自动检测和创建因果关系"""
        # 检测文件系统依赖
        if new_event.event_type == EventType.FILE_OPERATION:
            self._detect_filesystem_dependencies(new_event)
        
        # 检测用户操作依赖
        elif new_event.event_type == EventType.USER_OPERATION:
            self._detect_user_dependencies(new_event)
        
        # 检测服务依赖
        elif new_event.event_type == EventType.SERVICE_OPERATION:
            self._detect_service_dependencies(new_event)
    
    def _detect_filesystem_dependencies(self, event: EventNode) -> None:
        """检测文件系统依赖关系"""
        for change in event.state_changes:
            if change.change_type in ["create", "modify"]:
                # 查找可能的父目录创建事件
                target_path = change.target
                for existing_event in self.nodes.values():
                    if existing_event.id == event.id:
                        continue
                    
                    for existing_change in existing_event.state_changes:
                        if (existing_change.change_type == "create" and 
                            target_path.startswith(existing_change.target + "/")):
                            # 创建依赖关系
                            edge = EventEdge(
                                source_event_id=existing_event.id,
                                target_event_id=event.id,
                                relationship_type="enables",
                                strength=0.8,
                                metadata={"reason": "parent_directory_dependency"}
                            )
                            self.edges[edge.id] = edge
    
    def _detect_user_dependencies(self, event: EventNode) -> None:
        """检测用户操作依赖关系"""
        # 实现用户操作的依赖检测逻辑
        pass
    
    def _detect_service_dependencies(self, event: EventNode) -> None:
        """检测服务依赖关系"""
        # 实现服务操作的依赖检测逻辑
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        # 手动处理datetime序列化
        nodes_dict = {}
        for k, v in self.nodes.items():
            node_dict = v.dict()
            # 确保timestamp被正确序列化
            if isinstance(node_dict.get('timestamp'), datetime):
                node_dict['timestamp'] = node_dict['timestamp'].isoformat()
            nodes_dict[k] = node_dict
        
        edges_dict = {}
        for k, v in self.edges.items():
            edges_dict[k] = v.dict()
        
        return {
            "ip_address": self.ip_address,
            "nodes": nodes_dict,
            "edges": edges_dict,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventGraph:
        """从字典创建事件图"""
        graph = cls(ip_address=data["ip_address"])
        
        # 恢复节点
        for node_id, node_data in data["nodes"].items():
            node_data["timestamp"] = datetime.fromisoformat(node_data["timestamp"])
            graph.nodes[node_id] = EventNode(**node_data)
        
        # 恢复边
        for edge_id, edge_data in data["edges"].items():
            graph.edges[edge_id] = EventEdge(**edge_data)
        
        graph.created_at = datetime.fromisoformat(data["created_at"])
        graph.updated_at = datetime.fromisoformat(data["updated_at"])
        
        return graph
    
    def export_to_json(self, file_path: str) -> None:
        """导出到JSON文件"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
    
    @classmethod
    def import_from_json(cls, file_path: str) -> EventGraph:
        """从JSON文件导入"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)