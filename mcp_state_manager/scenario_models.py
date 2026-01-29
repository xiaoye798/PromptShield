"""
测试场景状态模型 (Scenario State Models)

实现针对shelLM项目中11个测试场景的状态模型和验证逻辑。
每个场景都有特定的状态变化模式和一致性验证规则。
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from .event_graph import EventNode, EventType, StateChange
from .memory_system import SystemState


class ScenarioResult(BaseModel):
    """场景验证结果"""
    scenario_id: str
    scenario_name: str
    is_consistent: bool
    success_rate: float
    issues: List[str]
    expected_state: Dict[str, Any]
    actual_state: Dict[str, Any]
    session_results: Dict[str, Dict[str, Any]]


class BaseScenario(ABC):
    """基础场景类"""
    
    def __init__(self, scenario_id: str, name: str, description: str):
        self.scenario_id = scenario_id
        self.name = name
        self.description = description
    
    @abstractmethod
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """验证会话1的执行结果"""
        pass
    
    @abstractmethod
    def validate_session_2(self, events: List[EventNode], final_state: SystemState, 
                          session_1_state: SystemState) -> Dict[str, Any]:
        """验证会话2的执行结果和跨会话一致性"""
        pass
    
    @abstractmethod
    def get_expected_final_state(self) -> Dict[str, Any]:
        """获取期望的最终状态"""
        pass
    
    def validate_scenario(self, session_1_events: List[EventNode], session_1_state: SystemState,
                         session_2_events: List[EventNode], session_2_state: SystemState) -> ScenarioResult:
        """验证整个场景"""
        
        # 验证会话1
        session_1_result = self.validate_session_1(session_1_events, session_1_state)
        
        # 验证会话2
        session_2_result = self.validate_session_2(session_2_events, session_2_state, session_1_state)
        
        # 计算总体一致性
        issues = []
        issues.extend(session_1_result.get("issues", []))
        issues.extend(session_2_result.get("issues", []))
        
        is_consistent = session_1_result.get("success", False) and session_2_result.get("success", False)
        success_rate = (session_1_result.get("success_rate", 0) + session_2_result.get("success_rate", 0)) / 2
        
        return ScenarioResult(
            scenario_id=self.scenario_id,
            scenario_name=self.name,
            is_consistent=is_consistent,
            success_rate=success_rate,
            issues=issues,
            expected_state=self.get_expected_final_state(),
            actual_state=session_2_state.dict(),
            session_results={
                "session_1": session_1_result,
                "session_2": session_2_result
            }
        )


class PFSMScenario(BaseScenario):
    """P-FSM场景：文件系统管理"""
    
    def __init__(self, scenario_id: str, target_path: str, operation: str):
        super().__init__(scenario_id, f"文件系统管理-{operation}", f"测试{operation}操作的跨会话一致性")
        self.target_path = target_path
        self.operation = operation


class PFSM01Scenario(PFSMScenario):
    """P-FSM-01: 创建文件并验证存在性"""
    
    def __init__(self):
        super().__init__("P-FSM-01", "/tmp/test_file.txt", "创建文件")
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """验证会话1：touch /tmp/test_file.txt"""
        issues = []
        success = False
        
        # 检查是否有touch命令事件
        touch_events = [e for e in events if "touch" in e.command and self.target_path in e.command]
        
        if not touch_events:
            issues.append("No touch command found in session 1")
        else:
            touch_event = touch_events[0]
            if touch_event.status.value != "success":
                issues.append(f"Touch command failed: {touch_event.stderr}")
            else:
                # 检查状态变化
                file_created = any(
                    change.target == self.target_path and change.change_type == "create"
                    for change in touch_event.state_changes
                )
                if file_created:
                    success = True
                else:
                    issues.append("File creation not recorded in state changes")
        
        # 检查最终状态
        if not final_state.filesystem.file_exists(self.target_path):
            issues.append("File not found in final state")
            success = False
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "file_created": success
        }
    
    def validate_session_2(self, events: List[EventNode], final_state: SystemState, 
                          session_1_state: SystemState) -> Dict[str, Any]:
        """验证会话2：ls /tmp/test_file.txt"""
        issues = []
        success = False
        
        # 检查是否有ls命令事件
        ls_events = [e for e in events if "ls" in e.command and self.target_path in e.command]
        
        if not ls_events:
            issues.append("No ls command found in session 2")
        else:
            ls_event = ls_events[0]
            if ls_event.status.value != "success":
                issues.append(f"ls command failed: {ls_event.stderr}")
            else:
                # 检查输出是否包含文件名
                if self.target_path in ls_event.stdout or "test_file.txt" in ls_event.stdout:
                    success = True
                else:
                    issues.append("File not found in ls output")
        
        # 检查跨会话一致性
        if session_1_state.filesystem.file_exists(self.target_path):
            if not final_state.filesystem.file_exists(self.target_path):
                issues.append("File lost between sessions")
                success = False
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "cross_session_consistent": success
        }
    
    def get_expected_final_state(self) -> Dict[str, Any]:
        return {
            "file_exists": True,
            "file_path": self.target_path,
            "file_content": ""
        }


class PFSM02Scenario(PFSMScenario):
    """P-FSM-02: 写入文件内容并验证"""
    
    def __init__(self):
        super().__init__("P-FSM-02", "/tmp/hello.txt", "写入文件")
        self.content = "Hello, World!"
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """验证会话1：echo "Hello, World!" > /tmp/hello.txt"""
        issues = []
        success = False
        
        # 检查echo命令
        echo_events = [e for e in events if "echo" in e.command and self.target_path in e.command]
        
        if not echo_events:
            issues.append("No echo command found in session 1")
        else:
            echo_event = echo_events[0]
            if echo_event.status.value != "success":
                issues.append(f"Echo command failed: {echo_event.stderr}")
            else:
                # 检查文件内容
                file_content = final_state.filesystem.get_file_content(self.target_path)
                if file_content and self.content in file_content:
                    success = True
                else:
                    issues.append("File content not correctly written")
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "content_written": success
        }
    
    def validate_session_2(self, events: List[EventNode], final_state: SystemState, 
                          session_1_state: SystemState) -> Dict[str, Any]:
        """验证会话2：cat /tmp/hello.txt"""
        issues = []
        success = False
        
        # 检查cat命令
        cat_events = [e for e in events if "cat" in e.command and self.target_path in e.command]
        
        if not cat_events:
            issues.append("No cat command found in session 2")
        else:
            cat_event = cat_events[0]
            if cat_event.status.value != "success":
                issues.append(f"Cat command failed: {cat_event.stderr}")
            else:
                # 检查输出内容
                if self.content in cat_event.stdout:
                    success = True
                else:
                    issues.append("File content not correctly displayed")
        
        # 检查跨会话一致性
        session_1_content = session_1_state.filesystem.get_file_content(self.target_path)
        session_2_content = final_state.filesystem.get_file_content(self.target_path)
        
        if session_1_content != session_2_content:
            issues.append("File content changed between sessions")
            success = False
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "cross_session_consistent": success
        }
    
    def get_expected_final_state(self) -> Dict[str, Any]:
        return {
            "file_exists": True,
            "file_path": self.target_path,
            "file_content": self.content
        }


class PFSM03Scenario(PFSMScenario):
    """P-FSM-03: 创建深层嵌套目录"""
    
    def __init__(self):
        super().__init__("P-FSM-03", "/tmp/deep/nested/directory", "创建嵌套目录")
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """验证会话1：mkdir -p /tmp/deep/nested/directory"""
        issues = []
        success = False
        
        # 检查mkdir命令
        mkdir_events = [e for e in events if "mkdir" in e.command and "-p" in e.command]
        
        if not mkdir_events:
            issues.append("No mkdir -p command found in session 1")
        else:
            mkdir_event = mkdir_events[0]
            if mkdir_event.status.value != "success":
                issues.append(f"mkdir command failed: {mkdir_event.stderr}")
            else:
                # 检查目录是否创建
                if final_state.filesystem.directory_exists(self.target_path):
                    success = True
                else:
                    issues.append("Directory not created in final state")
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "directory_created": success
        }
    
    def validate_session_2(self, events: List[EventNode], final_state: SystemState, 
                          session_1_state: SystemState) -> Dict[str, Any]:
        """验证会话2：ls -d /tmp/deep/nested/directory"""
        issues = []
        success = False
        
        # 检查ls命令
        ls_events = [e for e in events if "ls" in e.command and "-d" in e.command]
        
        if not ls_events:
            issues.append("No ls -d command found in session 2")
        else:
            ls_event = ls_events[0]
            if ls_event.status.value != "success":
                issues.append(f"ls command failed: {ls_event.stderr}")
            else:
                # 检查输出
                if self.target_path in ls_event.stdout:
                    success = True
                else:
                    issues.append("Directory not found in ls output")
        
        # 检查跨会话一致性
        if session_1_state.filesystem.directory_exists(self.target_path):
            if not final_state.filesystem.directory_exists(self.target_path):
                issues.append("Directory lost between sessions")
                success = False
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "cross_session_consistent": success
        }
    
    def get_expected_final_state(self) -> Dict[str, Any]:
        return {
            "directory_exists": True,
            "directory_path": self.target_path
        }


class PUMScenario(BaseScenario):
    """P-UM场景：用户管理"""
    
    def __init__(self, scenario_id: str, username: str, operation: str):
        super().__init__(scenario_id, f"用户管理-{operation}", f"测试{operation}操作的跨会话一致性")
        self.username = username
        self.operation = operation


class PUM04Scenario(PUMScenario):
    """P-UM-04: 创建用户并验证"""
    
    def __init__(self):
        super().__init__("P-UM-04", "testuser", "创建用户")
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """验证会话1：useradd testuser"""
        issues = []
        success = False
        
        # 检查useradd命令
        useradd_events = [e for e in events if "useradd" in e.command and self.username in e.command]
        
        if not useradd_events:
            issues.append("No useradd command found in session 1")
        else:
            useradd_event = useradd_events[0]
            if useradd_event.status.value != "success":
                issues.append(f"useradd command failed: {useradd_event.stderr}")
            else:
                # 检查用户是否创建
                if final_state.users.user_exists(self.username):
                    success = True
                else:
                    issues.append("User not created in final state")
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "user_created": success
        }
    
    def validate_session_2(self, events: List[EventNode], final_state: SystemState, 
                          session_1_state: SystemState) -> Dict[str, Any]:
        """验证会话2：id testuser"""
        issues = []
        success = False
        
        # 检查id命令
        id_events = [e for e in events if "id" in e.command and self.username in e.command]
        
        if not id_events:
            issues.append("No id command found in session 2")
        else:
            id_event = id_events[0]
            if id_event.status.value != "success":
                issues.append(f"id command failed: {id_event.stderr}")
            else:
                # 检查输出包含用户信息
                if self.username in id_event.stdout and "uid=" in id_event.stdout:
                    success = True
                else:
                    issues.append("User information not found in id output")
        
        # 检查跨会话一致性
        if session_1_state.users.user_exists(self.username):
            if not final_state.users.user_exists(self.username):
                issues.append("User lost between sessions")
                success = False
        
        return {
            "success": success,
            "success_rate": 1.0 if success else 0.0,
            "issues": issues,
            "cross_session_consistent": success
        }
    
    def get_expected_final_state(self) -> Dict[str, Any]:
        return {
            "user_exists": True,
            "username": self.username
        }


class ScenarioManager:
    """场景管理器"""
    
    def __init__(self):
        self.scenarios = {
            "P-FSM-01": PFSM01Scenario(),
            "P-FSM-02": PFSM02Scenario(),
            "P-FSM-03": PFSM03Scenario(),
            "P-UM-04": PUM04Scenario(),
            # 可以继续添加其他场景
        }
    
    def get_scenario(self, scenario_id: str) -> Optional[BaseScenario]:
        """获取场景实例"""
        return self.scenarios.get(scenario_id)
    
    def validate_all_scenarios(self, test_data: Dict[str, Any]) -> Dict[str, ScenarioResult]:
        """验证所有场景"""
        results = {}
        
        for scenario_id, scenario in self.scenarios.items():
            if scenario_id in test_data:
                scenario_data = test_data[scenario_id]
                
                # 提取会话数据
                session_1_events = scenario_data.get("session_1_events", [])
                session_1_state = scenario_data.get("session_1_state")
                session_2_events = scenario_data.get("session_2_events", [])
                session_2_state = scenario_data.get("session_2_state")
                
                # 验证场景
                result = scenario.validate_scenario(
                    session_1_events, session_1_state,
                    session_2_events, session_2_state
                )
                
                results[scenario_id] = result
        
        return results
    
    def calculate_overall_ccsr(self, results: Dict[str, ScenarioResult]) -> float:
        """计算总体CCSR"""
        if not results:
            return 0.0
        
        consistent_count = sum(1 for result in results.values() if result.is_consistent)
        return consistent_count / len(results)
    
    def generate_report(self, results: Dict[str, ScenarioResult]) -> Dict[str, Any]:
        """生成验证报告"""
        overall_ccsr = self.calculate_overall_ccsr(results)
        
        report = {
            "overall_ccsr": overall_ccsr,
            "total_scenarios": len(results),
            "consistent_scenarios": sum(1 for r in results.values() if r.is_consistent),
            "scenario_details": {},
            "common_issues": self._analyze_common_issues(results)
        }
        
        for scenario_id, result in results.items():
            report["scenario_details"][scenario_id] = {
                "name": result.scenario_name,
                "is_consistent": result.is_consistent,
                "success_rate": result.success_rate,
                "issues": result.issues
            }
        
        return report
    
    def _analyze_common_issues(self, results: Dict[str, ScenarioResult]) -> List[str]:
        """分析常见问题"""
        issue_counts = {}
        
        for result in results.values():
            for issue in result.issues:
                issue_counts[issue] = issue_counts.get(issue, 0) + 1
        
        # 返回出现频率最高的问题
        common_issues = sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)
        return [issue for issue, count in common_issues if count > 1]