# PromptShield

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Persistence-red.svg)](https://attack.mitre.org/)

> 🛡️ A Novel MCP-based Architecture for Overcoming Statelessness in LLM-powered Honeypots

## 🎯 Project Overview

PromptShield is a stateful defense framework designed to address the critical architectural weakness of LLM-powered honeypots: **the inherent statelessness that causes implanted persistence mechanisms to vanish upon session termination**.

Built upon the **Model Context Protocol (MCP)**, PromptShield introduces an external state management layer that enables LLM honeypots to exhibit coherent state awareness across independent attacker sessions while maintaining **O(1)** operational complexity.

### ✨ Key Features

- 🔄 **Cross-Session State Persistence**: Maintains state fidelity across arbitrary session boundaries
- 🧠 **Semantic Command Analysis**: Distinguishes state-altering commands from read-only queries  
- 💉 **Selective Context Injection**: Injects only query-relevant state to minimize prompt overhead
- 🛡️ **Robust Noise Resilience**: Withstands high-entropy noise attacks and sandwich injection
- ⚡ **Constant Complexity**: Achieves O(1) token consumption vs O(N) for history-stacking approaches
- 🔌 **MCP Protocol Support**: Compatible with all MCP-enabled LLM clients

## 🚀 Quick Start

### Requirements

- Python 3.8+
- DeepSeek API key or OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/anonymous/PromptShield.git
cd PromptShield

# Install dependencies
pip install -r requirements.txt

# Configure API credentials
cp .env.example .env
# Edit .env with your API keys
```

### Basic Usage

```bash
# Start the PromptShield honeypot
python LinuxSSHbot_mcp.py

# Or with custom configuration
python LinuxSSHbot_mcp.py --config personalitySSH.yml
```

## 📖 Architecture

```
┌─────────────────────────────────────┐
│         Attacker Session            │
│      (SSH Terminal / Web Shell)     │
└─────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│        Command Analyzer             │
│  (Semantic Classification Layer)    │
└─────────────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
┌───────────────┐   ┌───────────────┐
│ record_event  │   │ query_state   │
│  (MCP Tool)   │   │  (MCP Tool)   │
└───────────────┘   └───────────────┘
        │                   │
        └─────────┬─────────┘
                  ▼
┌─────────────────────────────────────┐
│      Persistent State Storage       │
│   ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐   │
│   │ 𝓕   │ │ 𝓤  │ │ 𝓒   │ │ 𝓥   │   │
│   │File │ │User │ │Cron │ │Svc  │   │
│   └─────┘ └─────┘ └─────┘ └─────┘   │
└─────────────────────────────────────┘
```

## 📁 Project Structure

```
PromptShield/
├── mcp_state_manager/         # Core PromptShield Framework
│   ├── command_analyzer.py    # Semantic command classification
│   ├── memory_system.py       # State persistence layer
│   ├── fastmcp_server.py      # MCP server implementation
│   └── state_context_builder.py  # Context injection logic
│
├── baselines/                 # Baseline Systems for Comparison
│   ├── shelLM/               # shelLM reference implementation
│   └── beelzebub/            # Beelzebub reference implementation
│
├── ablation_study/           # Ablation Study Scripts
│   ├── run_ablation.py       # Main ablation runner
│   ├── test_ambiguity.py     # Boundary condition tests
│   └── variant_context_builder.py  # Architectural variants
│
├── HoneyComb_v2_*.csv        # HoneyComb Benchmark Suite
├── test_honeycomb_e2e_real.py # End-to-end evaluation
└── *_results*.json           # Experimental results
```

## 🍯 HoneyComb Benchmark

HoneyComb is a domain-specific benchmark suite comprising **10 real-world persistence scenarios** derived from MITRE ATT&CK tactics:

| Category | MITRE ID | Scenario |
|----------|----------|----------|
| Account & Privilege | T1098.004 | SSH Keys |
| Account & Privilege | T1136.001 | Local Account |
| Scheduled Tasks | T1053.003 | Cron |
| Scheduled Tasks | T1543.002 | Systemd |
| Boot/Logon Init | T1546.004 | Shell Config |
| Boot/Logon Init | T1037.004 | RC Scripts |
| Boot/Logon Init | T1078.003 | Valid Accounts |
| Hijacking/Backdoor | T1505.003 | Web Shell |
| Hijacking/Backdoor | T1574.006 | Linker Hijack |
| Hijacking/Backdoor | T1556.003 | PAM Backdoor |

## 📊 Evaluation Metrics

| Metric | Description |
|--------|-------------|
| **SFR** (State Fidelity Rate) | Semantic accuracy and operational viability |
| **SPR** (State Persistence Rate) | Logical existence of state artifacts |
| **Latency** | Average response time |
| **Tokens** | Total tokens processed per interaction |

## 📈 Experimental Results

| System | Ideal SFR | Noise-100 SFR | Sandwich SFR | Token Usage |
|--------|-----------|---------------|--------------|-------------|
| **PromptShield** | ✅ 10/10 | ✅ 10/10 | ✅ 10/10 | 25K |
| shelLM | ✅ 10/10 | ⚠️ 8/10 | ❌ 0/10 | 394K |
| Beelzebub | ❌ 0/10 | ❌ 0/10 | ❌ 0/10 | 4.5K |

> 💡 PromptShield achieves **100% SFR** across all conditions with **15.8× lower token consumption** compared to shelLM.

## 🛠️ MCP Tools Reference

### record_event - Record State Changes

```python
record_event(
    command="useradd -m sysupdate",
    event_type="USER_OPERATION",
    state_changes={"user_created": "sysupdate", "uid": 1001}
)
```

### query_state - Retrieve Persisted State

```python
query_state(
    query_type="user_list",
    target="sysupdate"
)
```


