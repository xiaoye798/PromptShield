# Deployment Field Data

## Provenance

Data collected from a 14-day public honeypot deployment (2026-04-02 to 2026-04-16) on a cloud VPS in Manchester, UK, with SSH (port 22) and Telnet (port 23) exposed to the public Internet. The SSH service ran inside a Docker container with PromptShield integrated, using DeepSeek Chat (temperature=0) for response generation.

Corresponds to **Section 6 (RQ4)** of the paper.

## IP Anonymization

All external IP addresses have been replaced with [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) documentation-range addresses. The mapping preserves the /16 subnet relationships described in the paper:

| Paper Label | Anonymized IP | RFC 5737 Block | Subnet Note |
|-------------|--------------|----------------|-------------|
| VN-1 | `198.51.100.1` | TEST-NET-2 | Own /16 prefix |
| VN-2 | `203.0.113.1` | TEST-NET-3 | Shares /16 with VN-3 |
| VN-3 | `203.0.113.2` | TEST-NET-3 | Shares /16 with VN-2 |
| SCAN-1 | `192.0.2.1` | TEST-NET-1 | Scanner (no auth attempt) |
| SCAN-2 | `192.0.2.2` | TEST-NET-1 | Scanner (no auth attempt) |

Docker-internal addresses (`172.18.0.x`) are retained as-is (RFC 1918 private, not attributable).

## Files

| File | Description |
|------|-------------|
| `ssh_sessions.log` | Anonymized Docker container SSH log. Health-check lines from `127.0.0.1` (~2,500 lines) have been filtered out. Contains all `Accepted password`, `Failed password`, port-forward, and session lifecycle events referenced in Tables 4 and 5. |
| `history.txt` | Attacker command transcript from the single interactive SSH session (4 commands: `whoami`, `uname -a`, `id`, `exit`). |
| `honeypot_memory/states/global_default.json` | PromptShield MCP state file — the four-component state tuple S = ⟨F, U, C, V⟩ as persisted during deployment. |
| `honeypot_memory/graphs/global_default.json` | Event dependency graph — filtered to real deployment entries only (2026-04-16). Development/testing entries from prior dates have been removed. |

## Mapping to Paper Tables

- **Table 4** (Coordinated SSH Campaign from Three Vietnamese IPs): Derived from `Accepted password` and `Failed password` lines in `ssh_sessions.log` for IPs `198.51.100.1` (VN-1), `203.0.113.1` (VN-2), `203.0.113.2` (VN-3).
- **Table 5** (Interleaved Login Sequence): A representative chronological excerpt from the same log showing alternating VN-1/VN-2 authentications with different usernames.

## Notes

- The Telnet service log (`connections.log`) containing ~150,000+ Mirai-like scanning connections is not included in this export due to size. The SSH log captures all authenticated sessions relevant to the paper's analysis.
- The port-forwarding target `ip-who.com` appearing in `refused local port forward` messages is a public IP geolocation service used by the attacker for proxy exit verification (MITRE ATT&CK T1090).
