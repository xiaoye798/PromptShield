"""
Event Graph Implementation

Used to record and manage command execution events, state changes, and causal relationships in LLM honeypots.
Supports event chain tracking, state queries, and consistency validation.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Event type enum"""
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
    """Event status enum"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"


class StateChange(BaseModel):
    """State change record"""
    target: str = Field(description="Target of change (file path, username, etc.)")
    change_type: str = Field(description="Type of change (create, modify, delete, etc.)")
    old_value: Optional[Any] = Field(default=None, description="Value before change")
    new_value: Optional[Any] = Field(default=None, description="Value after change")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class EventNode(BaseModel):
    """Event node"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique event ID")
    timestamp: datetime = Field(default_factory=datetime.now, description="Event timestamp")
    event_type: EventType = Field(description="Event type")
    command: str = Field(description="Executed command")
    session_id: str = Field(description="Session ID")
    ip_address: str = Field(description="Client IP address")
    user_context: str = Field(description="User context (username@hostname)")
    
    # Execution results
    status: EventStatus = Field(description="Event execution status")
    stdout: str = Field(default="", description="Standard output")
    stderr: str = Field(default="", description="Standard error")
    return_code: int = Field(default=0, description="Return code")
    
    # State changes
    state_changes: List[StateChange] = Field(default_factory=list, description="List of state changes")
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Event metadata")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class EventEdge(BaseModel):
    """Event edge - represents causal relationships between events"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Edge unique ID")
    source_event_id: str = Field(description="Source event ID")
    target_event_id: str = Field(description="Target event ID")
    relationship_type: str = Field(description="Relationship type (depends_on, enables, conflicts, etc.)")
    strength: float = Field(default=1.0, ge=0.0, le=1.0, description="Relationship strength")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Relationship metadata")


class EventGraph(BaseModel):
    """Event Graph main class"""
    ip_address: str = Field(description="Associated IP address")
    nodes: Dict[str, EventNode] = Field(default_factory=dict, description="Event nodes dictionary")
    edges: Dict[str, EventEdge] = Field(default_factory=dict, description="Event edges dictionary")
    created_at: datetime = Field(default_factory=datetime.now, description="Graph creation time")
    updated_at: datetime = Field(default_factory=datetime.now, description="Graph update time")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_event(self, event: EventNode) -> str:
        """Add event node"""
        if event.ip_address != self.ip_address:
            raise ValueError(f"Event IP {event.ip_address} doesn't match graph IP {self.ip_address}")
        
        self.nodes[event.id] = event
        self.updated_at = datetime.now()
        
        # Automatically detect and create causal relationships
        self._detect_causal_relationships(event)
        
        return event.id
    
    def add_relationship(self, edge: EventEdge) -> str:
        """Add event relationship"""
        if edge.source_event_id not in self.nodes:
            raise ValueError(f"Source event {edge.source_event_id} not found")
        if edge.target_event_id not in self.nodes:
            raise ValueError(f"Target event {edge.target_event_id} not found")
        
        self.edges[edge.id] = edge
        self.updated_at = datetime.now()
        return edge.id
    
    def get_event(self, event_id: str) -> Optional[EventNode]:
        """Get event node"""
        return self.nodes.get(event_id)
    
    def get_events_by_type(self, event_type: EventType) -> List[EventNode]:
        """Get events by type"""
        return [node for node in self.nodes.values() if node.event_type == event_type]
    
    def get_events_by_session(self, session_id: str) -> List[EventNode]:
        """Get events by session"""
        return [node for node in self.nodes.values() if node.session_id == session_id]
    
    def get_events(self, session_id: str = None, event_type: EventType = None) -> List[EventNode]:
        """Get event list, supports filtering by session ID and event type"""
        events = list(self.nodes.values())
        
        if session_id:
            events = [event for event in events if event.session_id == session_id]
        
        if event_type:
            events = [event for event in events if event.event_type == event_type]
        
        return events
    
    def get_events_affecting_target(self, target: str) -> List[EventNode]:
        """Get all events affecting a specific target"""
        events = []
        for node in self.nodes.values():
            for change in node.state_changes:
                if change.target == target:
                    events.append(node)
                    break
        return events
    
    def get_dependency_chain(self, event_id: str) -> List[EventNode]:
        """Get the dependency chain of an event"""
        if event_id not in self.nodes:
            return []
        
        visited = set()
        chain = []
        
        def dfs(current_id: str):
            if current_id in visited:
                return
            visited.add(current_id)
            
            # Find all dependent events
            dependencies = []
            for edge in self.edges.values():
                if (edge.target_event_id == current_id and 
                    edge.relationship_type in ["depends_on", "caused_by"]):
                    dependencies.append(edge.source_event_id)
            
            # Recursively process dependencies
            for dep_id in dependencies:
                dfs(dep_id)
            
            # Add current event to the chain
            if current_id in self.nodes:
                chain.append(self.nodes[current_id])
        
        dfs(event_id)
        return chain
    
    def validate_state_consistency(self, target: str) -> Dict[str, Any]:
        """Validate state consistency of a specific target"""
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
        
        # Simulate state changes
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
        """Automatically detect and create causal relationships"""
        # Detect filesystem dependencies
        if new_event.event_type == EventType.FILE_OPERATION:
            self._detect_filesystem_dependencies(new_event)
        
        # Detect user operation dependencies
        elif new_event.event_type == EventType.USER_OPERATION:
            self._detect_user_dependencies(new_event)
        
        # Detect service dependencies
        elif new_event.event_type == EventType.SERVICE_OPERATION:
            self._detect_service_dependencies(new_event)
    
    def _detect_filesystem_dependencies(self, event: EventNode) -> None:
        """Detect filesystem dependency relationships"""
        for change in event.state_changes:
            if change.change_type in ["create", "modify"]:
                # Look for possible parent directory creation events
                target_path = change.target
                for existing_event in self.nodes.values():
                    if existing_event.id == event.id:
                        continue
                    
                    for existing_change in existing_event.state_changes:
                        if (existing_change.change_type == "create" and 
                            target_path.startswith(existing_change.target + "/")):
                            # Create dependency relationship
                            edge = EventEdge(
                                source_event_id=existing_event.id,
                                target_event_id=event.id,
                                relationship_type="enables",
                                strength=0.8,
                                metadata={"reason": "parent_directory_dependency"}
                            )
                            self.edges[edge.id] = edge
    
    def _detect_user_dependencies(self, event: EventNode) -> None:
        """Detect user operation dependency relationships"""
        # Implement dependency detection logic for user operations
        pass
    
    def _detect_service_dependencies(self, event: EventNode) -> None:
        """Detect service dependency relationships"""
        # Implement dependency detection logic for service operations
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        # Manually handle datetime serialization
        nodes_dict = {}
        for k, v in self.nodes.items():
            node_dict = v.dict()
            # Ensure timestamp is correctly serialized
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
        """Create event graph from dictionary"""
        graph = cls(ip_address=data["ip_address"])
        
        # Restore nodes
        for node_id, node_data in data["nodes"].items():
            node_data["timestamp"] = datetime.fromisoformat(node_data["timestamp"])
            graph.nodes[node_id] = EventNode(**node_data)
        
        # Restore edges
        for edge_id, edge_data in data["edges"].items():
            graph.edges[edge_id] = EventEdge(**edge_data)
        
        graph.created_at = datetime.fromisoformat(data["created_at"])
        graph.updated_at = datetime.fromisoformat(data["updated_at"])
        
        return graph
    
    def export_to_json(self, file_path: str) -> None:
        """Export to JSON file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
    
    @classmethod
    def import_from_json(cls, file_path: str) -> EventGraph:
        """Import from JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)
