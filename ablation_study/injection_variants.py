from enum import Enum

class InjectionMode(Enum):
    ORIGINAL = "original"           # Selective injection (PromptShield full)
    RAW_HISTORY = "raw_history"     # No structure, just raw history
    FULL_CONTEXT = "full_context"   # No selection, dump everything
    STATELESS = "stateless"         # No state layer at all (baseline equivalent)

