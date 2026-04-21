# PromptShield

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Persistence-red.svg)](https://attack.mitre.org/)

> 🛡️ **Beyond the Blank Slate: Typed Operating System State for Cross-Session Consistency in LLM-Powered Honeypots**

## 🎯 Project Overview

PromptShield is a stateful defense framework designed to address the critical architectural weakness of LLM-powered honeypots: **the inherent statelessness that causes implanted persistence mechanisms to vanish upon session termination**.

While LLM-powered honeypots offer high-fidelity interactions, they suffer from **"Persistence Violation"** — when an adversary attempts to utilize a previously implanted backdoor in a new session, the honeypot fails to recognize it. This logical discrepancy exposes the artificial nature of the environment and may cause attackers to withhold sophisticated malware to avoid exposure.

Built upon the **Model Context Protocol (MCP)**, PromptShield models attacker-visible OS state as **typed components** and retrieves only the state that the current command can legitimately observe. It records state-changing commands into a structured state model and injects only command-relevant state during inference, enabling cross-session consistency.

### ✨ Key Features

- 🔄 **Cross-Session State Persistence**: Models OS state as typed components (files, users, cron, services) and persists them across arbitrary session boundaries
- 🧠 **Semantic Command Analysis**: Classifies commands into state-altering vs. read-only, handles compound commands (`&&`, `||`, `;`), redirections, and heredocs
- 💉 **Selective Context Injection**: Injects only query-relevant state fragments via command-aware pattern matching, minimizing prompt overhead
- 🛡️ **Robust Noise Resilience**: Maintains KR=0.98 under Noise-100 and Sandwich-100 adversarial conditions with constant O(1) context overhead
- ⚡ **Constant Complexity**: O(1) token consumption vs O(N) for history-stacking approaches — context overhead stays at ~19 tokens regardless of noise
- 🔌 **MCP Protocol Support**: Compatible with all MCP-enabled LLM clients
- 🐳 **Production Deployment**: Includes Docker-based deployment setup with PAM auto-authentication, tested in a 14-day public deployment

## 📊 Key Results

### Comprehensive Evaluation: State Fidelity and Operational Costs

| Metric | shelLM (Ideal) | shelLM (N100) | Beelzebub (Ideal) | MemGPT (Ideal) | **PromptShield (Ideal)** | **PromptShield (N100)** |
|--------|---------------|---------------|-------------------|----------------|--------------------------|-------------------------|
| **Avg. SFS** | 0.87 | 0.85 | 0.26 | 0.54 | **0.98** | **0.98** |
| **Avg. KR** | 0.87 | 0.87 | 0.26 | 0.88 | **0.98** | **0.98** |
| **SPR** | 0.96 | 0.92 | 0.38 | 0.98 | 0.96 | 0.96 |
| **Latency** | 9.0s | 7.4s | 9.1s | 59.4s | 9.9s | 3.2s |

> 💡 PromptShield achieves **KR=0.98** across all 24 HoneyComb scenarios under both ideal and adversarial conditions. Under Sandwich-100, shelLM collapses to SFS=0.00 (latency 117.6s) while PromptShield maintains SFS=0.86 (latency 4.6s).

This public bundle is artifact-oriented. It retains the core runtime, deployment material, appendix sources, committed result logs, and state snapshots used to support the paper, while omitting several internal benchmark driver scripts from the original working repository.

### Ablation Analysis: Context Overhead

| Variant | Context Tokens (Ideal) | Context Tokens (N100) | Expansion | Avg. SFS (Ideal) |
|---------|----------------------|----------------------|-----------|------------------|
| **ORIGINAL** | 19 | 19 | 1.0× | **0.98** |
| RAW_HISTORY | 15 | 643 | **42.9×** | 0.97 |
| FULL_CONTEXT | 26 | 27 | 1.1× | 0.89 |
| STATELESS | 0 | 0 | N/A | 0.00 |

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
```

### Available Evaluation Workflows

```bash
# Run the retained ablation workflow
cd ablation_study
python run_full_ablation.py

# Run the retained cumulative-session experiment
cd ..
python accumulation_experiment.py
```

Committed outputs from additional historical experiments are included under `test-record/`, while curated appendix sources are preserved under `per_scenario_table_sources/`.

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
│   ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ │
│   │ 𝓕   │ │ 𝓤   │ │ 𝓒   │ │ 𝓥   │ │
│   │File │ │User │ │Cron │ │Svc  │ │
│   └─────┘ └─────┘ └─────┘ └─────┘ │
└─────────────────────────────────────┘
```

### Structured State Model

The system state `S` maintained by PromptShield is a four-component tuple targeting Linux persistence vectors:

$$\mathcal{S} = \langle \mathcal{F}, \mathcal{U}, \mathcal{C}, \mathcal{V} \rangle$$

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
├── ablation_study/                # Ablation Study Scripts
│   ├── run_ablation.py            # Main ablation runner
│   ├── run_full_ablation.py       # Full ablation experiments (Ideal/N100/Sandwich)
│   ├── run_adversarial_test.py    # Adversarial robustness tests
│   ├── variant_context_builder.py # Architectural variants (ORIGINAL, RAW_HISTORY, FULL_CONTEXT, STATELESS)
│   ├── injection_variants.py      # Injection strategy implementations
│   ├── raw_history_store.py       # Raw history accumulation (simulates shelLM)
│   └── test_ambiguity.py          # Boundary condition tests
│
├── test-record/                   # Committed historical result artifacts (JSON)
│   ├── *benchmark*.json                     # Archived benchmark runs
│   ├── accumulation_experiment_*.json       # Cumulative mode results
│   ├── attack_replay_*.json                 # Attack replay result artifacts
│   ├── interactive_scenarios_report_*.json  # Interactive scenario result artifacts
│   ├── mutated_replay_report_*.json         # Command mutation result artifacts
│   └── pre_deploy_test_report_*.json        # Pre-deployment validation outputs
│
├── deployment/                    # Production Deployment (RQ4)
│   ├── Dockerfile                 # Container image definition
│   ├── docker-compose.yml         # Service orchestration
│   ├── config/                    # SSH/PAM configuration
│   │   ├── sshd_config            # Custom SSH daemon config
│   │   ├── pam_sshd              # PAM module for auto-authentication
│   │   ├── pam_autocreate.sh     # Auto-create accounts on first login
│   │   ├── honeypot_command.sh   # Command handler wrapper
│   │   └── honeypot_users.txt    # Seed user list
│   ├── monitoring/                # Operational monitoring
│   │   ├── check_honeypot.sh     # Health check script
│   │   └── stats.py              # Traffic statistics
│   ├── scripts/                   # Container lifecycle
│   │   ├── entrypoint.sh         # Container entrypoint
│   │   └── setup.sh              # Environment setup
│   └── field_data/                # Anonymized Deployment Data (RQ4)
│       ├── README.md              # Data provenance & IP anonymization notes
│       ├── ssh_sessions.log       # Docker SSH log (IPs pseudonymized, health-checks removed)
│       ├── history.txt            # Attacker command transcript (1 interactive session)
│       └── honeypot_memory/       # MCP state captured during deployment
│           ├── states/global_default.json
│           └── graphs/global_default.json
│
├── per_scenario_table_sources/    # Data Sources for Paper Appendix Tables
│   ├── README.md                  # Data provenance documentation
│   ├── row_scenario_mapping.csv   # Scenario-to-table-row mapping
│   └── *.json                     # Raw benchmark data per condition
│
├── honeypot_memory/               # Runtime State Storage (Persistent)
│   ├── states/
│   │   └── global_default.json    # Default state file (𝓕, 𝓤, 𝓒, 𝓥)
│   └── graphs/
│       └── global_default.json    # Event dependency graph
│
├── accumulation_test_memory/      # Committed cumulative-experiment state snapshots
│   └── N_5/
│       ├── states/
│       └── graphs/
│
├── LinuxSSHbot_mcp.py             # Main honeypot entry point (PromptShield)
├── mcp_client.py                  # MCP client implementation
├── deepseek_client.py             # DeepSeek API client
├── api_selector.py                # API provider selector
├── HoneyComb_Benchmark.csv        # HoneyComb Benchmark Suite (24 scenarios)
│
├── accumulation_experiment.py     # Cumulative mode endurance test
├── telnet_honeypot.py             # Telnet protocol honeypot service
│
├── aggregate_results.py           # Result aggregation utilities
├── analyze_ideal.py               # Ideal-condition analysis
├── extract_memgpt_data.py         # MemGPT result extraction
├── extract_n100_table.py          # Noise-100 table generation
├── n100_stats.py                  # Noise-100 statistics
├── parse_results.py               # Result parsing utilities
├── show_n100.py                   # Noise-100 result display
├── update_appendix_table.py       # Appendix table updater
├── validate_tables.py             # Table validation checks
│
├── requirements.txt               # Python dependencies
└── .env.example                   # API configuration template
```


## 🍯 HoneyComb Benchmark

HoneyComb is a domain-specific benchmark suite comprising **24 cross-session-verifiable persistence scenarios** derived from MITRE ATT&CK tactics and the Atomic Red Team framework. Each scenario follows a strict two-session protocol: **Session A** implants a persistence artifact, and **Session B** verifies its cross-session survival.

| Category | MITRE ID | Persistence Mechanism |
|----------|----------|-----------------------|
| Access Footholds | T1098.004 | Backdoor `authorized_keys` |
| Access Footholds | T1136.001 | Create privileged user with sudo |
| Access Footholds | T1078.003 | Repurpose an existing local account |
| Access Footholds | T1548.001 | Set SUID bit on a backdoor binary |
| Auto-Start Hooks | T1053.003 | Malicious crontab entry |
| Auto-Start Hooks | T1543.002 | Backdoor systemd `.service` unit |
| Auto-Start Hooks | T1546.004 | Inject into `.bashrc` via `PROMPT_COMMAND` |
| Auto-Start Hooks | T1037.004 | Overwrite `/etc/rc.local` with launcher |
| Auto-Start Hooks | T1037.004 | Variant: `/etc/rc.local` Python stager |
| Execution Hijacks | T1574.006 | Add shared object to `ld.so.preload` |
| Execution Hijacks | T1574.006 | Variant: alternate preload library path |
| Backdoor Implants | T1556.003 | Modify PAM authentication |
| Backdoor Implants | T1505.003 | Drop hidden PHP shell in web root |
| Backdoor Implants | T1505.003 | Variant: hidden shell `.error_handler.php` |
| Payload Stagers | T1105 | `curl\|sh` download loop with `nohup` |
| Payload Stagers | T1499 | Install UDP flood launcher script |
| C2 Implants | T1071 | IRC botnet client installation |
| C2 Implants | T1071.004 | Encode exfiltration into DNS lookups |
| C2 Implants | T1059 | Install Python/Perl reverse shell launchers |
| Lateral Spread | T1021.004 | Drop `sshpass`-based propagation script |
| Credential/Data Theft | T1003 | Dump `/etc/shadow` and SSH keys |
| Credential/Data Theft | T1552.001 | Capture secrets from `env`/`.env` data |
| Credential/Data Theft | T1560 | Archive and stage files for exfiltration |
| Stealth | T1036.004 | Hide payloads as `[kworker/0:1]` |

> A scenario is included only if: (1) Session A creates or modifies an attacker-visible artifact, (2) Session B has an explicit verification command, and (3) the full set covers all four state components (𝓕, 𝓤, 𝓒, 𝓥).

## 📊 Evaluation Metrics

| Metric | Description |
|--------|-------------|
| **KR** (Keyword Recall) | Fraction of expected keywords present in the verification response |
| **SFS** (State Fidelity Score) | Combined metric incorporating keyword recall and latency penalty (30s threshold) |
| **SPR** (State Persistence Rate) | Binary: whether the state artifact logically exists across sessions |
| **Latency** | Average end-to-end time from command submission to complete response |

## 🧪 Evaluation Settings

Four experimental conditions are used to evaluate robustness:

| Setting | Description |
|---------|-------------|
| **Ideal** | Baseline: implant in Session A, verify in Session B with no noise |
| **Noise-100** | 100 irrelevant commands inserted between implant and verification |
| **Sandwich-100** | Critical command buried inside 100 irrelevant inputs (50 before, 50 after) |
| **Cumulative** | All scenarios run in one session without clearing history |

## 🧪 Ablation Study Variants

| Variant | Description |
|---------|-------------|
| **ORIGINAL** | Complete PromptShield with structured JSON state and selective injection |
| **RAW_HISTORY** | Disables structured storage; appends raw command-response pairs (simulates shelLM) |
| **FULL_CONTEXT** | Retains structured state but injects entire state graph regardless of relevance |
| **STATELESS** | No state persistence (equivalent to Beelzebub's architecture) |

## 🛠️ MCP Tools Reference

### Record_event — Capture State Changes

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

### Query_state — Retrieve Persisted State

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

| Event Type | State Component | Mod. Commands | Query Patterns | Query Type |
|------------|-----------------|---------------|----------------|------------|
| USER_OP | 𝓤 (UserState) | `useradd`, `usermod` | `id`, `whoami`, `who` | `user_list` |
| FILE_OP | 𝓕 (FileSysState) | `touch`, `echo` | `cat`, `head`, `grep` | `file_content` |
| SERVICE_OP | 𝓥 (SvcState) | `systemctl` | `systemctl` | `service_list` |
| CRON_OP | 𝓒 (CronState) | `crontab` | `crontab`, `cron` | `cron_list` |

## 🐳 Deployment (RQ4)

The `deployment/` directory contains everything needed to replicate the public deployment described in the paper:

```bash
cd deployment
docker-compose up -d
```

The deployment exposes SSH (port 22) and Telnet (port 23) with PAM configured to accept arbitrary credentials and auto-create local accounts. All sessions share a single global MCP state instance.

During the deployment window:
- ~151,000 inbound connections were recorded
- A coordinated SSH proxy-abuse campaign from 3 Vietnamese IPs produced 43 successful authentications using 20+ distinct usernames
- Zero inference failures across all attacker interactions

## 🔗 Related Resources

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io) — Open standard for LLM-external context interaction
- [MITRE ATT&CK](https://attack.mitre.org/) — Knowledge base of adversary tactics and techniques
- [Atomic Red Team](https://atomicredteam.io/) — Library of adversary emulation tests
