# Baseline Systems

This directory contains reference implementations of two baseline LLM-powered honeypot systems used for comparative evaluation in the PromptShield research.

## Systems

### shelLM

A shell-focused honeypot leveraging LLMs for dynamic terminal responses.

- **Source**: [GitHub - urdfrn/shelLM](https://github.com/urdfrn/shelLM)
- **Architecture**: Cumulative history accumulation
- **Characteristics**: 
  - Maintains state through conversation history
  - O(N) token complexity growth
  - Vulnerable to context window exhaustion under noise

### Beelzebub

A multi-protocol honeypot deployed on Deutsche Telekom's T-Pot platform.

- **Source**: [GitHub - mariocandela/beelzebub](https://github.com/mariocandela/beelzebub)
- **Architecture**: Single-session stateless
- **Characteristics**:
  - O(1) constant complexity
  - No cross-session state persistence
  - 0% State Fidelity Rate on HoneyComb benchmark

## Usage

These baselines are included for reproducibility of the comparative evaluation. See the main README for evaluation instructions.

## Note

The code in this directory is sourced from the original projects with minimal modifications necessary for benchmark integration.
