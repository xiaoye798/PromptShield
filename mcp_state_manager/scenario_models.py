"""
Scenario State Models

Implement state models and validation logic for 11 test scenarios in the shelLM project.
Each scenario has specific state change patterns and consistency validation rules.
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
    """Scenario validation result"""
    scenario_id: str
    scenario_name: str
    is_consistent: bool
    success_rate: float
    issues: List[str]
    expected_state: Dict[str, Any]
    actual_state: Dict[str, Any]
    session_results: Dict[str, Dict[str, Any]]


class BaseScenario(ABC):
    """Base scenario class"""
    
    def __init__(self, scenario_id: str, name: str, description: str):
        self.scenario_id = scenario_id
        self.name = name
        self.description = description
    
    @abstractmethod
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """Validate execution result of session 1"""
        pass
    
    @abstractmethod
    def validate_session_2(self, events: List[EventNode], final_state: SystemState, 
                          session_1_state: SystemState) -> Dict[str, Any]:
        """Validate execution result of session 2 and cross-session consistency"""
        pass
    
    @abstractmethod
    def get_expected_final_state(self) -> Dict[str, Any]:
        """Get expected final state"""
        pass
    
    def validate_scenario(self, session_1_events: List[EventNode], session_1_state: SystemState,
                         session_2_events: List[EventNode], session_2_state: SystemState) -> ScenarioResult:
        """Validate entire scenario"""
        
        # Validate session 1
        session_1_result = self.validate_session_1(session_1_events, session_1_state)
        
        # Validate session 2
        session_2_result = self.validate_session_2(session_2_events, session_2_state, session_1_state)
        
        # Calculate overall consistency
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
    """P-FSM Scenario: File System Management"""
    
    def __init__(self, scenario_id: str, target_path: str, operation: str):
        super().__init__(scenario_id, f"File System Management - {operation}", f"Test cross-session consistency of {operation} operation")
        self.target_path = target_path
        self.operation = operation


class PFSM01Scenario(PFSMScenario):
    """P-FSM-01: Create file and verify existence"""
    
    def __init__(self):
        super().__init__("P-FSM-01", "/tmp/test_file.txt", "Create File")
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """Validate Session 1: touch /tmp/test_file.txt"""
        issues = []
        success = False
        
        # Check for touch command event
        touch_events = [e for e in events if "touch" in e.command and self.target_path in e.command]
        
        if not touch_events:
            issues.append("No touch command found in session 1")
        else:
            touch_event = touch_events[0]
            if touch_event.status.value != "success":
                issues.append(f"Touch command failed: {touch_event.stderr}")
            else:
                # Check state changes
                file_created = any(
                    change.target == self.target_path and change.change_type == "create"
                    for change in touch_event.state_changes
                )
                if file_created:
                    success = True
                else:
                    issues.append("File creation not recorded in state changes")
        
        # Check final state
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
        """Validate Session 2: ls /tmp/test_file.txt"""
        issues = []
        success = False
        
        # Check for ls command event
        ls_events = [e for e in events if "ls" in e.command and self.target_path in e.command]
        
        if not ls_events:
            issues.append("No ls command found in session 2")
        else:
            ls_event = ls_events[0]
            if ls_event.status.value != "success":
                issues.append(f"ls command failed: {ls_event.stderr}")
            else:
                # Check if output contains filename
                if self.target_path in ls_event.stdout or "test_file.txt" in ls_event.stdout:
                    success = True
                else:
                    issues.append("File not found in ls output")
        
        # Check cross-session consistency
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
    """P-FSM-02: Write file content and verify"""
    
    def __init__(self):
        super().__init__("P-FSM-02", "/tmp/hello.txt", "Write to File")
        self.content = "Hello, World!"
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """Validate Session 1: echo "Hello, World!" > /tmp/hello.txt"""
        issues = []
        success = False
        
        # Check echo command
        echo_events = [e for e in events if "echo" in e.command and self.target_path in e.command]
        
        if not echo_events:
            issues.append("No echo command found in session 1")
        else:
            echo_event = echo_events[0]
            if echo_event.status.value != "success":
                issues.append(f"Echo command failed: {echo_event.stderr}")
            else:
                # Check file content
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
        """Validate Session 2: cat /tmp/hello.txt"""
        issues = []
        success = False
        
        # Check cat command
        cat_events = [e for e in events if "cat" in e.command and self.target_path in e.command]
        
        if not cat_events:
            issues.append("No cat command found in session 2")
        else:
            cat_event = cat_events[0]
            if cat_event.status.value != "success":
                issues.append(f"Cat command failed: {cat_event.stderr}")
            else:
                # Check output content
                if self.content in cat_event.stdout:
                    success = True
                else:
                    issues.append("File content not correctly displayed")
        
        # Check cross-session consistency
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
    """P-FSM-03: Create deep nested directory"""
    
    def __init__(self):
        super().__init__("P-FSM-03", "/tmp/deep/nested/directory", "Create Nested Directory")
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """Validate Session 1: mkdir -p /tmp/deep/nested/directory"""
        issues = []
        success = False
        
        # Check mkdir command
        mkdir_events = [e for e in events if "mkdir" in e.command and "-p" in e.command]
        
        if not mkdir_events:
            issues.append("No mkdir -p command found in session 1")
        else:
            mkdir_event = mkdir_events[0]
            if mkdir_event.status.value != "success":
                issues.append(f"mkdir command failed: {mkdir_event.stderr}")
            else:
                # Check if directory created
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
        """Validate Session 2: ls -d /tmp/deep/nested/directory"""
        issues = []
        success = False
        
        # Check ls command
        ls_events = [e for e in events if "ls" in e.command and "-d" in e.command]
        
        if not ls_events:
            issues.append("No ls -d command found in session 2")
        else:
            ls_event = ls_events[0]
            if ls_event.status.value != "success":
                issues.append(f"ls command failed: {ls_event.stderr}")
            else:
                # Check output
                if self.target_path in ls_event.stdout:
                    success = True
                else:
                    issues.append("Directory not found in ls output")
        
        # Check cross-session consistency
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
    """P-UM Scenario: User Management"""
    
    def __init__(self, scenario_id: str, username: str, operation: str):
        super().__init__(scenario_id, f"User Management - {operation}", f"Test cross-session consistency of {operation} operation")
        self.username = username
        self.operation = operation


class PUM04Scenario(PUMScenario):
    """P-UM-04: Create user and verify"""
    
    def __init__(self):
        super().__init__("P-UM-04", "testuser", "Create User")
    
    def validate_session_1(self, events: List[EventNode], final_state: SystemState) -> Dict[str, Any]:
        """Validate Session 1: useradd testuser"""
        issues = []
        success = False
        
        # Check useradd command
        useradd_events = [e for e in events if "useradd" in e.command and self.username in e.command]
        
        if not useradd_events:
            issues.append("No useradd command found in session 1")
        else:
            useradd_event = useradd_events[0]
            if useradd_event.status.value != "success":
                issues.append(f"useradd command failed: {useradd_event.stderr}")
            else:
                # Check if user created
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
        """Validate Session 2: id testuser"""
        issues = []
        success = False
        
        # Check id command
        id_events = [e for e in events if "id" in e.command and self.username in e.command]
        
        if not id_events:
            issues.append("No id command found in session 2")
        else:
            id_event = id_events[0]
            if id_event.status.value != "success":
                issues.append(f"id command failed: {id_event.stderr}")
            else:
                # Check output containing user info
                if self.username in id_event.stdout and "uid=" in id_event.stdout:
                    success = True
                else:
                    issues.append("User information not found in id output")
        
        # Check cross-session consistency
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
    """Scenario Manager"""
    
    def __init__(self):
        self.scenarios = {
            "P-FSM-01": PFSM01Scenario(),
            "P-FSM-02": PFSM02Scenario(),
            "P-FSM-03": PFSM03Scenario(),
            "P-UM-04": PUM04Scenario(),
            # More scenarios can be added here
        }
    
    def get_scenario(self, scenario_id: str) -> Optional[BaseScenario]:
        """Get scenario instance"""
        return self.scenarios.get(scenario_id)
    
    def validate_all_scenarios(self, test_data: Dict[str, Any]) -> Dict[str, ScenarioResult]:
        """Validate all scenarios"""
        results = {}
        
        for scenario_id, scenario in self.scenarios.items():
            if scenario_id in test_data:
                scenario_data = test_data[scenario_id]
                
                # Extract session data
                session_1_events = scenario_data.get("session_1_events", [])
                session_1_state = scenario_data.get("session_1_state")
                session_2_events = scenario_data.get("session_2_events", [])
                session_2_state = scenario_data.get("session_2_state")
                
                # Validate scenario
                result = scenario.validate_scenario(
                    session_1_events, session_1_state,
                    session_2_events, session_2_state
                )
                
                results[scenario_id] = result
        
        return results
    
    def calculate_overall_ccsr(self, results: Dict[str, ScenarioResult]) -> float:
        """Calculate overall CCSR"""
        if not results:
            return 0.0
        
        consistent_count = sum(1 for result in results.values() if result.is_consistent)
        return consistent_count / len(results)
    
    def generate_report(self, results: Dict[str, ScenarioResult]) -> Dict[str, Any]:
        """Generate validation report"""
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
        """Analyze common issues"""
        issue_counts = {}
        
        for result in results.values():
            for issue in result.issues:
                issue_counts[issue] = issue_counts.get(issue, 0) + 1
        
        # Return most frequent issues
        common_issues = sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)
        return [issue for issue, count in common_issues if count > 1]
