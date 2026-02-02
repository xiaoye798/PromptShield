# PromptShield

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Persistence-red.svg)](https://attack.mitre.org/)

> 🛡️ **Beyond the Blank Slate: A Novel MCP-based Architecture for Overcoming Statelessness in LLM-powered Honeypots**

## 🎯 Project Overview

PromptShield is a stateful defense framework designed to address the critical architectural weakness of LLM-powered honeypots: **the inherent statelessness that causes implanted persistence mechanisms to vanish upon session termination**.

While LLM-powered honeypots offer high-fidelity interactions, they suffer from "Persistence Violation" — when an adversary attempts to utilize a previously implanted backdoor in a new session, the honeypot fails to recognize it. This logical discrepancy exposes the artificial nature of the environment.

Built upon the **Model Context Protocol (MCP)**, PromptShield introduces an external, structured state management layer that offloads the tracking of state changes to permanent external storage rather than relying on the temporary conversation history. This enables LLM-powered honeypots to exhibit coherent state awareness across independent attacker sessions while maintaining **O(1)** operational complexity.

### ✨ Key Features

- 🔄 **Cross-Session State Persistence**: Maintains state fidelity across arbitrary session boundaries by offloading state to structured external memory
- 🧠 **Semantic Command Analysis**: Distinguishes state-altering commands (e.g., `useradd`, `echo`) from read-only queries (e.g., `ls`, `cat`)
- 💉 **Selective Context Injection**: Injects only query-relevant state fragments to minimize prompt overhead
- 🛡️ **Robust Noise Resilience**: Withstands high-entropy noise attacks and sandwich injection with constant O(1) complexity
- ⚡ **Constant Complexity**: Achieves O(1) token consumption vs O(N) for history-stacking approaches (15.8× lower than shelLM)
- 🔌 **MCP Protocol Support**: Compatible with all MCP-enabled LLM clients

## 📊 Key Results

| System | Ideal SFR | Noise-100 SFR | Sandwich SFR | Token Usage |
|--------|-----------|---------------|--------------|-------------|
| **PromptShield** | ✅ 10/10 | ✅ 10/10 | ✅ 10/10 | 25K |
| shelLM | ✅ 10/10 | ⚠️ 8/10 | ❌ 0/10 | 394K |
| Beelzebub | ❌ 0/10 | ❌ 0/10 | ❌ 0/10 | 4.5K |

> 💡 PromptShield achieves **100% State Fidelity Rate (SFR)** across all conditions with **15.8× lower token consumption** compared to shelLM.

## 🚀 Quick Start

### Requirements

- Python 3.8+


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

PromptShield operates through two core MCP tools:
- **`Record_event`**: Captures and persists state-altering operations
- **`Query_state`**: Retrieves relevant context for query-driven injection

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
│ Record_event  │   │ Query_state   │
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

### Structured State Model

The system state `S` maintained by PromptShield is a four-component tuple targeting Linux persistence vectors:

- **𝓕 (FileSystemState)**: Files, directories, permissions and symbolic links
- **𝓤 (UserState)**: Users, groups, shadow entries and sudoers configuration
- **𝓒 (CronState)**: User crontabs, system cron files and scheduled jobs
- **𝓥 (ServiceState)**: Systemd unit files and their enabled/active states

## 📁 Project Structure

```
PromptShield/
├── mcp_state_manager/             # Core PromptShield Framework
│   ├── command_analyzer.py        # Semantic command classification
│   ├── memory_system.py           # State persistence layer
│   ├── fastmcp_server.py          # MCP server implementation
│   ├── state_context_builder.py   # Context injection logic
│   ├── event_graph.py             # Event graph management
│   ├── scenario_models.py         # Scenario data models
│   └── system_template.py         # System configuration templates
│
├── baselines/                     # Baseline Systems for Comparison
│   ├── README.md                  # Baseline documentation
│   ├── shelLM/                    # shelLM reference implementation
│   │   ├── LinuxSSHbot.py         # shelLM honeypot core
│   │   ├── shellm_direct_test.py  # HoneyComb evaluation script
│   │   ├── shelLM_*_results.json  # Evaluation results (Ideal, Noise-100, Sandwich)
│   │   ├── history_*.txt          # Cumulative conversation history logs
│   │   └── tokens_*.json          # Token consumption records
│   └── beelzebub/                 # Beelzebub reference implementation
│       ├── main.go                # Beelzebub honeypot core (Go)
│       ├── beelzebub_direct_test.py  # HoneyComb evaluation script
│       └── beelzebub_direct_results.json  # Evaluation results
│
├── ablation_study/                # Ablation Study Scripts
│   ├── run_ablation.py            # Main ablation runner
│   ├── run_full_ablation.py       # Full ablation experiments
│   ├── run_adversarial_test.py    # Adversarial robustness tests
│   ├── test_ambiguity.py          # Boundary condition tests
│   ├── variant_context_builder.py # Architectural variants (ORIGINAL, RAW_HISTORY, FULL_CONTEXT, STATELESS)
│   ├── full_ablation_results.json # Complete ablation experiment results
│   └── adversarial_results.json   # Adversarial robustness test results
│
├── test-record/                   # Experimental Results & Execution Logs
│   ├── promptshield_*.json        # PromptShield evaluation results (Ideal, Noise-100, Sandwich)
│   ├── beelzebub_*.json           # Beelzebub baseline results
│   └── honeycomb_e2e_*.json       # HoneyComb end-to-end test logs
│
├── honeypot_memory/               # Runtime State Storage (Persistent)
│   ├── states/                    # Serialized SystemState (JSON format)
│   │   └── global_default.json    # Default state file (𝓕, 𝓤, 𝓒, 𝓥)
│   └── graphs/                    # Event graph storage
│       └── global_default.json    # Event dependency graph
│
├── LinuxSSHbot_mcp.py             # Main honeypot entry point
├── mcp_client.py                  # MCP client implementation
├── deepseek_client.py             # DeepSeek API client
├── api_selector.py                # API provider selector
├── personalitySSH.yml             # SSH honeypot configuration
├── HoneyComb_Benchmark.csv        # HoneyComb Benchmark Suite (10 scenarios)
├── test_honeycomb_e2e_real.py     # End-to-end evaluation scripts
├── requirements.txt               # Python dependencies
└── .env.example                   # API configuration template
```

## 🍯 HoneyComb Benchmark

HoneyComb is a domain-specific benchmark suite comprising **10 real-world persistence scenarios** derived from MITRE ATT&CK tactics and the Atomic Red Team framework:

| Category | MITRE ID | Scenario | Persistence Mechanism |
|----------|----------|----------|----------------------|
| Account & Privilege | T1098.004 | SSH Keys | Backdoor `authorized_keys` |
| Account & Privilege | T1136.001 | Local Account | Create privileged user with sudo |
| Scheduled Tasks | T1053.003 | Cron | Malicious `crontab` entry |
| Scheduled Tasks | T1543.002 | Systemd | Backdoor `.service` unit |
| Boot/Logon Init | T1546.004 | Shell Config | Inject into `.bashrc` |
| Boot/Logon Init | T1037.004 | RC Scripts | Modify `/etc/rc.local` |
| Boot/Logon Init | T1078.003 | Valid Accounts | Weaponize existing accounts |
| Hijacking/Backdoor | T1505.003 | Web Shell | PHP webshell in webroot |
| Hijacking/Backdoor | T1574.006 | Linker Hijack | `ld.so.preload` injection |
| Hijacking/Backdoor | T1556.003 | PAM Backdoor | Modify PAM authentication |

## 📊 Evaluation Metrics

| Metric | Description |
|--------|-------------|
| **SFR** (State Fidelity Rate) | Semantic accuracy and operational viability of persisted state |
| **SPR** (State Persistence Rate) | Logical existence of state artifacts across sessions |
| **Latency** | Average response time (operational threshold: 30s) |
| **Token Consumption** | Total tokens processed per interaction |

## 🧪 Ablation Study Variants

The ablation study evaluates four architectural variants:

| Variant | Description |
|---------|-------------|
| **ORIGINAL** | Complete PromptShield with structured JSON state and selective injection |
| **RAW_HISTORY** | Disables structured storage; appends raw command-response pairs (simulates shelLM) |
| **FULL_CONTEXT** | Retains structured state but injects entire state graph regardless of relevance |
| **STATELESS** | No state persistence (equivalent to Beelzebub's architecture) |

## 🛠️ MCP Tools Reference

### Record_event - Capture State Changes

The `Record_event` tool captures state-altering operations and persists them to structured storage:

```python
# Example: Recording a user creation operation
record_event(
    command="useradd -m -s /bin/bash sysupdate",
    event_type="USER_OPERATION",
    state_changes={
        "user_created": "sysupdate",
        "uid": 1001,
        "shell": "/bin/bash"
    }
)
```

### Query_state - Retrieve Persisted State

The `Query_state` tool retrieves relevant context for LLM context injection:

```python
# Example: Querying user list state
query_state(
    query_type="user_list",
    target="sysupdate"
)

# Returns structured state for context injection
# {
#   "users": {
#     "sysupdate": {"uid": 1001, "shell": "/bin/bash"}
#   },
#   "groups": {"sudo": {"members": ["sysupdate"]}}
# }
```

## 📈 Command Event Mapping

| Event Type | Description | State Component | Commands | Query Patterns |
|------------|-------------|-----------------|----------|----------------|
| USER_OPERATION | User/Group Ops | 𝓤 (UserState) | `useradd`, `usermod` | `id`, `whoami`, `who` |
| FILE_OPERATION | File Creation/Mod | 𝓕 (FileSystemState) | `touch`, `echo` | `cat`, `head`, `grep` |
| SERVICE_OPERATION | Service Control | 𝓥 (ServiceState) | `systemctl` | `systemctl` |
| CRON_OPERATION | Scheduled Tasks | 𝓒 (CronState) | `crontab` | `crontab`, `cron` |


## 🔗 Related Resources

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io) - Open standard for LLM-external context interaction
- [MITRE ATT&CK](https://attack.mitre.org/) - Knowledge base of adversary tactics and techniques
- [Atomic Red Team](https://atomicredteam.io/) - Library of adversary emulation tests

