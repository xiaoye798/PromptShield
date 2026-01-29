# PromptShield

> A Novel MCP-based Architecture for Overcoming Statelessness in LLM-powered Honeypots

## Overview

PromptShield is a stateful defense framework designed to address the critical architectural weakness of LLM-powered honeypots: the inherent statelessness that causes implanted persistence mechanisms to vanish upon session termination.

Built upon the **Model Context Protocol (MCP)**, PromptShield introduces an external state management layer that:
- Captures state-altering operations through a semantic **Command Analyzer**
- Persists state changes to structured external storage
- Dynamically injects query-relevant context during inference

This enables LLM honeypots to exhibit coherent state awareness across independent attacker sessions while maintaining **O(1)** operational complexity.

## Key Features

- **Cross-Session State Persistence**: Maintains state fidelity across arbitrary session boundaries
- **Semantic Command Analysis**: Distinguishes state-altering commands from read-only queries
- **Selective Context Injection**: Injects only query-relevant state to minimize prompt overhead
- **Robust Noise Resilience**: Withstands high-entropy noise attacks and sandwich injection
- **Constant Complexity**: Achieves O(1) token consumption vs O(N) for history-stacking approaches

## Installation

### Prerequisites

- Python 3.8+
- DeepSeek API key or OpenAI API key

### Setup

1. Clone the repository:
```bash
git clone https://github.com/anonymous/PromptShield.git
cd PromptShield
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API credentials:
```bash
cp .env.example .env
# Edit .env with your API keys
```

## Quick Start

### Running PromptShield Honeypot

```bash
python LinuxSSHbot_mcp.py
```

### Running with Custom Configuration

```bash
python LinuxSSHbot_mcp.py --config personalitySSH.yml
```

## Project Structure

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

## HoneyComb Benchmark

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

## Evaluation Metrics

- **State Fidelity Rate (SFR)**: Measures semantic accuracy and operational viability
- **State Persistence Rate (SPR)**: Measures logical existence of state artifacts
- **Response Latency**: Average time between command and response
- **Token Consumption**: Total tokens processed per interaction

## Experimental Results

| System | Ideal SFR | Noise-100 SFR | Token Usage |
|--------|-----------|---------------|-------------|
| PromptShield | 10/10 | 10/10 | 25K |
| shelLM | 10/10 | 8/10 | 394K |
| Beelzebub | 0/10 | 0/10 | 4.5K |

## Citation

```bibtex
@inproceedings{promptshield2026,
  title={Beyond the Blank Slate: A Novel MCP-based Architecture for Overcoming Statelessness in LLM-powered Honeypots},
  author={Anonymous},
  booktitle={Proceedings of [Conference]},
  year={2026}
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This research was supported by [Anonymous for Review].
