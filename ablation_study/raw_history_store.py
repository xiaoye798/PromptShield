from typing import List, Dict, Any

class RawHistoryStore:
    """
    Simple in-memory store for raw command history.
    Used for the RAW_HISTORY ablation variant.
    """
    _instance = None
    
    def __init__(self):
        # Map IP address -> List of {"command": str, "response": str}
        self.history: Dict[str, List[Dict[str, str]]] = {}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = RawHistoryStore()
        return cls._instance
    
    def add_interaction(self, ip_address: str, command: str, response: str):
        if ip_address not in self.history:
            self.history[ip_address] = []
        
        self.history[ip_address].append({
            "command": command,
            "response": response
        })
        
    def get_history(self, ip_address: str) -> List[Dict[str, str]]:
        return self.history.get(ip_address, [])
        
    def clear(self, ip_address: str = None):
        if ip_address:
            if ip_address in self.history:
                del self.history[ip_address]
        else:
            self.history = {}
