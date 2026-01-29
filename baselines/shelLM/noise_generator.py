#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
高熵噪声命令生成器 (Noise Generator)

模拟真实蜜罐流量中的自动化扫描命令，用于测试 Lost-in-the-Middle 效应。
噪声特征：随机 IP、端口、时间戳、路径等高熵数据。

Author: PromptShield Research Team
"""

import random
import string
import hashlib
from datetime import datetime, timedelta
from typing import List


class NoiseGenerator:
    """高熵噪声命令生成器"""
    
    # 噪声模板 - 模拟真实蜜罐流量
    NOISE_TEMPLATES = [
        # Nmap 扫描
        "nmap -sV -p {port_range} {ip}",
        "nmap -sS -O {ip}",
        "nmap -sU -p 53,161,123 {ip}",
        # SSH 爆破
        "ssh {user}@{ip} -o ConnectTimeout=3",
        "ssh -p {port} {user}@{ip}",
        # Web 扫描 (DirBuster/Gobuster)
        "curl -I http://{ip}:{port}/{path}",
        "wget -q --spider http://{ip}/{path}",
        "curl -s -o /dev/null -w '%{{http_code}}' http://{ip}:{port}/{path}",
        # 系统探测
        "cat /etc/passwd | head -1",
        "uname -a",
        "cat /proc/version",
        "id",
        "whoami",
        # 日志枚举
        "ls -la /var/log/{logfile}",
        "cat /var/log/auth.log.{timestamp}",
        "tail -n 10 /var/log/syslog",
        # 网络探测
        "ping -c 1 {ip}",
        "netstat -an | grep {port}",
        "ss -tunlp | grep {port}",
        # 文件探测
        "ls -la /tmp/{hash}",
        "cat /etc/shadow 2>/dev/null",
        "find / -name '*.conf' 2>/dev/null | head -5",
    ]
    
    # 常见爆破用户名
    USERNAMES = ["admin", "root", "user", "test", "guest", "ubuntu", "ec2-user", "deploy", "ftpuser", "www-data"]
    
    # 常见扫描路径
    WEB_PATHS = [
        "admin.php", ".git/config", "wp-admin/", "phpmyadmin/", 
        "robots.txt", ".env", "config.php", "backup.sql",
        "shell.php", "cmd.php", "test.php", "upload.php"
    ]
    
    # 日志文件名
    LOG_FILES = ["auth.log", "syslog", "messages", "secure", "apache2/access.log", "nginx/error.log"]
    
    def __init__(self, seed: int = None):
        """Initialize with optional seed for reproducibility."""
        if seed is not None:
            random.seed(seed)
    
    def _random_ip(self) -> str:
        """生成随机 IP 地址"""
        return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _random_port(self) -> int:
        """生成随机端口"""
        common_ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 21, 23, 25, 3389]
        return random.choice(common_ports) if random.random() < 0.7 else random.randint(1024, 65535)
    
    def _random_port_range(self) -> str:
        """生成随机端口范围"""
        start = random.randint(1, 1000)
        end = start + random.randint(10, 100)
        return f"{start}-{end}"
    
    def _random_hash(self, length: int = 8) -> str:
        """生成随机哈希片段"""
        return hashlib.md5(str(random.random()).encode()).hexdigest()[:length]
    
    def _random_timestamp(self) -> str:
        """生成随机时间戳"""
        delta = timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))
        ts = datetime.now() - delta
        return ts.strftime("%Y%m%d%H%M%S")
    
    def generate_single_noise(self) -> str:
        """生成单条噪声命令"""
        template = random.choice(self.NOISE_TEMPLATES)
        
        # 替换占位符
        command = template.format(
            ip=self._random_ip(),
            port=self._random_port(),
            port_range=self._random_port_range(),
            user=random.choice(self.USERNAMES),
            path=random.choice(self.WEB_PATHS),
            logfile=random.choice(self.LOG_FILES),
            timestamp=self._random_timestamp(),
            hash=self._random_hash()
        )
        
        return command
    
    def generate_noise_batch(self, count: int) -> List[str]:
        """
        生成指定数量的噪声命令
        
        Args:
            count: 噪声命令数量
            
        Returns:
            噪声命令列表
        """
        return [self.generate_single_noise() for _ in range(count)]
    
    def generate_noise_sequence(self, key_commands: List[str], 
                                  noise_per_command: int) -> List[str]:
        """
        在关键命令之间插入噪声，制造 Lost-in-Middle 效应
        
        Args:
            key_commands: 关键命令列表（如 HoneyComb 测试命令）
            noise_per_command: 每个关键命令前插入的噪声数量
            
        Returns:
            混合后的命令序列（噪声 + 关键命令交替）
        """
        result = []
        
        for cmd in key_commands:
            # 先插入噪声
            result.extend(self.generate_noise_batch(noise_per_command))
            # 再插入关键命令
            result.append(cmd)
        
        return result
    
    def generate_noise_for_history(self, count: int) -> str:
        """
        生成适合写入 history.txt 的噪声内容
        
        模拟用户输入和系统响应的对话格式
        
        Args:
            count: 噪声交互轮次数
            
        Returns:
            格式化的历史记录文本
        """
        lines = []
        
        for _ in range(count):
            command = self.generate_single_noise()
            # 模拟用户输入
            lines.append(f"root@honeypot-{random.randint(1,50)}:~# {command}")
            # 模拟系统响应（简化）
            response = self._generate_fake_response(command)
            lines.append(response)
            lines.append("")  # 空行分隔
        
        return "\n".join(lines)
    
    def _generate_fake_response(self, command: str) -> str:
        """为噪声命令生成模拟响应"""
        if "nmap" in command:
            return f"Starting Nmap scan... Host is up (0.{random.randint(1,99):02d}s latency)."
        elif "ssh" in command:
            return f"ssh: connect to host {self._random_ip()} port 22: Connection timed out"
        elif "curl" in command or "wget" in command:
            codes = ["200", "404", "403", "500", "301"]
            return f"HTTP/1.1 {random.choice(codes)} OK"
        elif "cat" in command or "ls" in command:
            return f"Permission denied" if random.random() < 0.3 else f"-rw-r--r-- 1 root root {random.randint(100, 10000)} Jan 21 {random.randint(0,23):02d}:{random.randint(0,59):02d}"
        elif "ping" in command:
            return f"PING: 64 bytes from {self._random_ip()}: icmp_seq=1 ttl=64 time={random.uniform(0.1, 50):.1f} ms"
        else:
            return f"Command executed."


# CLI for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="High-entropy noise command generator")
    parser.add_argument("--count", type=int, default=10, help="Number of noise commands")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--format", choices=["list", "history"], default="list",
                        help="Output format: list (one per line) or history (simulated session)")
    
    args = parser.parse_args()
    
    gen = NoiseGenerator(seed=args.seed)
    
    if args.format == "list":
        for cmd in gen.generate_noise_batch(args.count):
            print(cmd)
    else:
        print(gen.generate_noise_for_history(args.count))
