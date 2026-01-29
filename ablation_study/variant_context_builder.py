from typing import Any, Dict, List, Optional
import json
from mcp_state_manager.state_context_builder import StateContextBuilder
from mcp_state_manager.memory_system import SystemState
from .injection_variants import InjectionMode
from .raw_history_store import RawHistoryStore

class VariantContextBuilder(StateContextBuilder):
    """
    Extended ContextBuilder that supports different injection modes for ablation study.
    """
    
    def __init__(self, mode: InjectionMode, ip_address: str):
        super().__init__()
        self.mode = mode
        self.ip_address = ip_address
        self.raw_history_store = RawHistoryStore.get_instance()
        
    def build_context_for_command(self, command: str, system_state: SystemState, 
                                  current_cwd: str = "/root") -> str:
        """
        Build context based on the selected injection mode.
        """
        if self.mode == InjectionMode.ORIGINAL:
            # Use the original selective injection logic
            return super().build_context_for_command(command, system_state, current_cwd)
            
        elif self.mode == InjectionMode.RAW_HISTORY:
            # Build context from raw command history
            return self._build_raw_history_context()
            
        elif self.mode == InjectionMode.FULL_CONTEXT:
            # Dump the entire system state
            return self._build_full_context(system_state)
            
        return ""

    def _build_raw_history_context(self) -> str:
        history = self.raw_history_store.get_history(self.ip_address)
        if not history:
            return ""
            
        context_lines = ["Previous command history (RAW):"]
        for entry in history:
            cmd = entry.get("command", "")
            resp = entry.get("response", "")
            # Truncate long responses to avoid context window overflow
            if len(resp) > 500:
                resp = resp[:500] + "... (truncated)"
            context_lines.append(f"User: {cmd}\nSystem: {resp}")
            
        return "\n".join(context_lines)

    def _build_full_context(self, system_state: SystemState) -> str:
        # Serialize the entire state to JSON
        # Note: This simulates the 'dump everything' approach
        
        # Helper to serializable dict
        def state_to_dict(obj):
            if hasattr(obj, "__dict__"):
                return {k: state_to_dict(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
            elif isinstance(obj, dict):
                return {k: state_to_dict(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [state_to_dict(v) for v in obj]
            else:
                return obj

        try:
            # Using the to_dict method if available, or manual serialization
            # Assuming SystemState structure based on reading code or general knowledge
            # Since SystemState isn't fully visible here, we use a robust approach
            
            # Simple manual construction based on expected components
            full_state = {
                "users": getattr(system_state, "users", {}).__dict__ if hasattr(getattr(system_state, "users", None), "__dict__") else str(getattr(system_state, "users", "N/A")),
                "filesystem": getattr(system_state, "filesystem", {}).__dict__ if hasattr(getattr(system_state, "filesystem", None), "__dict__") else str(getattr(system_state, "filesystem", "N/A")),
                "services": getattr(system_state, "services", {}).__dict__ if hasattr(getattr(system_state, "services", None), "__dict__") else str(getattr(system_state, "services", "N/A")),
                "packages": getattr(system_state, "packages", {}).__dict__ if hasattr(getattr(system_state, "packages", None), "__dict__") else str(getattr(system_state, "packages", "N/A")),
                "cron": getattr(system_state, "cron", {}).__dict__ if hasattr(getattr(system_state, "cron", None), "__dict__") else str(getattr(system_state, "cron", "N/A")),
            }
            
            # Use json.dumps with sort_keys to be deterministic
            state_json = json.dumps(full_state, default=str, indent=2)
            
            return f"""
[FULL SYSTEM STATE DUMP]
The following is the COMPLETE current state of the system.
{state_json}
[End of State Dump]
"""
        except Exception as e:
            return f"[Error building full context: {str(e)}]"
