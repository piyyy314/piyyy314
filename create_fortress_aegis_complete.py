#!/usr/bin/env python3
"""
Fortress Aegis — Complete Cybersecurity Toolkit
================================================
A comprehensive, educational cybersecurity framework covering:
  • System security auditing
  • Network security analysis
  • Password strength evaluation
  • File integrity monitoring
  • Threat-pattern detection
  • Security hardening recommendations
  • HTML report generation

Author  : @shiatoali
License : MIT
"""

import os
import sys
import re
import json
import socket
import hashlib
import platform
import datetime
import ipaddress
import subprocess
import secrets
import string
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"

def c(color: str, text: str) -> str:
    """Wrap *text* with *color* and reset."""
    return f"{color}{text}{RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
  █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
  ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
  ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

   █████╗ ███████╗ ██████╗ ██╗███████╗
  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
  ███████║█████╗  ██║  ███╗██║███████╗
  ██╔══██║██╔══╝  ██║   ██║██║╚════██║
  ██║  ██║███████╗╚██████╔╝██║███████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝  — Complete Edition
"""


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding produced by any module."""
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    title: str
    description: str
    recommendation: str = ""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def severity_color(self) -> str:
        return {
            "CRITICAL": RED,
            "HIGH":     RED,
            "MEDIUM":   YELLOW,
            "LOW":      CYAN,
            "INFO":     WHITE,
        }.get(self.severity, WHITE)


@dataclass
class AegisReport:
    """Aggregated report produced by FortressAegis."""
    hostname: str = ""
    os_info: str = ""
    timestamp: str = ""
    findings: List[Finding] = field(default_factory=list)
    score: int = 100          # starts at 100 and is deducted per finding

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        deduction = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        self.score = max(0, self.score - deduction.get(finding.severity, 0))

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s: 0 for s in Finding.SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def grade(self) -> str:
        s = self.score
        if s >= 90: return "A+"
        if s >= 80: return "A"
        if s >= 70: return "B"
        if s >= 60: return "C"
        if s >= 50: return "D"
        return "F"


# ─────────────────────────────────────────────────────────────────────────────
# Module 1 — System information collector
# ─────────────────────────────────────────────────────────────────────────────

class SystemCollector:
    """Collect basic OS / environment facts."""

    @staticmethod
    def collect(report: AegisReport) -> None:
        report.hostname = socket.gethostname()
        report.os_info  = f"{platform.system()} {platform.release()} ({platform.machine()})"
        report.timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Python version check
        py_ver = sys.version_info
        if py_ver < (3, 8):
            report.add(Finding(
                severity="HIGH",
                category="System",
                title="Outdated Python runtime",
                description=f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} is end-of-life.",
                recommendation="Upgrade to Python 3.10 or later.",
            ))
        else:
            report.add(Finding(
                severity="INFO",
                category="System",
                title="Python runtime",
                description=f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} detected.",
            ))

        # Environment variable leakage checks
        sensitive_vars = ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY",
                          "DB_PASS", "AWS_SECRET", "GITHUB_TOKEN"]
        leaked = [v for v in sensitive_vars if os.environ.get(v)]
        if leaked:
            report.add(Finding(
                severity="CRITICAL",
                category="System",
                title="Sensitive environment variables exposed",
                description=f"Variables found in environment: {', '.join(leaked)}",
                recommendation="Remove secrets from environment; use a secrets manager.",
            ))

        # Temp-directory world-writable check (Unix)
        tmp = Path("/tmp")
        if tmp.exists():
            mode = oct(tmp.stat().st_mode)[-3:]
            if mode == "777":
                report.add(Finding(
                    severity="LOW",
                    category="System",
                    title="/tmp is world-writable",
                    description="World-writable /tmp can allow symlink attacks.",
                    recommendation="Consider using a sticky-bit (/tmp perms 1777).",
                ))


# ─────────────────────────────────────────────────────────────────────────────
# Module 2 — Password strength analyser
# ─────────────────────────────────────────────────────────────────────────────

class PasswordAnalyser:
    """Evaluate password strength and entropy."""

    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "master", "hello", "sunshine", "shadow", "princess",
        "football", "iloveyou", "admin", "welcome", "login",
        "passw0rd", "password1", "1q2w3e4r", "qwerty123",
    }

    @classmethod
    def evaluate(cls, password: str) -> Dict:
        length       = len(password)
        has_upper    = bool(re.search(r"[A-Z]", password))
        has_lower    = bool(re.search(r"[a-z]", password))
        has_digit    = bool(re.search(r"\d", password))
        has_special  = bool(re.search(r"[^A-Za-z0-9]", password))
        is_common    = password.lower() in cls.COMMON_PASSWORDS
        has_repeat   = bool(re.search(r"(.)\1{2,}", password))

        charset = 0
        if has_lower:   charset += 26
        if has_upper:   charset += 26
        if has_digit:   charset += 10
        if has_special: charset += 32

        import math
        entropy = length * math.log2(charset) if charset else 0

        score = 0
        if length >= 8:  score += 1
        if length >= 12: score += 1
        if length >= 16: score += 1
        if has_upper:    score += 1
        if has_lower:    score += 1
        if has_digit:    score += 1
        if has_special:  score += 1
        if not is_common:  score += 1
        if not has_repeat: score += 1

        strength = ("Very Weak" if score <= 2 else
                    "Weak"      if score <= 4 else
                    "Fair"      if score <= 6 else
                    "Strong"    if score <= 7 else
                    "Very Strong")

        return {
            "length": length, "entropy": round(entropy, 1),
            "has_upper": has_upper, "has_lower": has_lower,
            "has_digit": has_digit, "has_special": has_special,
            "is_common": is_common, "has_repeat": has_repeat,
            "score": score, "strength": strength,
        }

    @staticmethod
    def generate_secure(length: int = 20) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        while True:
            pwd = "".join(secrets.choice(alphabet) for _ in range(length))
            if (any(c.isupper() for c in pwd) and
                    any(c.islower() for c in pwd) and
                    any(c.isdigit() for c in pwd) and
                    any(c in "!@#$%^&*()-_=+" for c in pwd)):
                return pwd


# ─────────────────────────────────────────────────────────────────────────────
# Module 3 — Network security analyser
# ─────────────────────────────────────────────────────────────────────────────

class NetworkAnalyser:
    """Analyse network-layer security posture."""

    WELL_KNOWN_RISKY_PORTS = {
        21: "FTP (plaintext)",
        23: "Telnet (plaintext)",
        25: "SMTP (may relay)",
        53: "DNS",
        69: "TFTP",
        110: "POP3 (plaintext)",
        111: "RPCbind",
        135: "MS-RPC",
        137: "NetBIOS",
        139: "NetBIOS Session",
        143: "IMAP (plaintext)",
        161: "SNMP (v1/v2 cleartext)",
        389: "LDAP (plaintext)",
        445: "SMB",
        512: "rexec",
        513: "rlogin",
        514: "rsh",
        1433: "MS SQL Server",
        1521: "Oracle DB",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        27017: "MongoDB",
    }

    @classmethod
    def scan_localhost_ports(cls, report: AegisReport,
                             timeout: float = 0.3) -> List[int]:
        """Probe localhost for listening ports from the risky list."""
        open_ports: List[int] = []
        for port, service in cls.WELL_KNOWN_RISKY_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        open_ports.append(port)
                        severity = ("HIGH" if port in
                                    {21, 23, 111, 135, 137, 139, 445, 512, 513, 514, 5900}
                                    else "MEDIUM")
                        report.add(Finding(
                            severity=severity,
                            category="Network",
                            title=f"Risky port {port} open ({service})",
                            description=f"Port {port} ({service}) is listening on localhost.",
                            recommendation=f"Disable {service} if not required, or restrict access with a firewall.",
                        ))
            except OSError:
                pass
        if not open_ports:
            report.add(Finding(
                severity="INFO",
                category="Network",
                title="No high-risk ports detected on localhost",
                description="None of the commonly-abused ports are listening.",
            ))
        return open_ports

    @staticmethod
    def validate_cidr(cidr: str) -> Tuple[bool, str]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen < 16:
                return False, f"/{net.prefixlen} is very broad; consider narrowing the range."
            return True, f"Valid network: {net} ({net.num_addresses} addresses)"
        except ValueError as exc:
            return False, str(exc)

    @staticmethod
    def dns_lookup(hostname: str) -> Optional[str]:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Module 4 — File integrity monitor
# ─────────────────────────────────────────────────────────────────────────────

class FileIntegrityMonitor:
    """Compute and compare SHA-256 hashes for a set of files."""

    @staticmethod
    def hash_file(path: Path, block: int = 65536) -> Optional[str]:
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                while chunk := fh.read(block):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    @classmethod
    def snapshot(cls, paths: List[Path]) -> Dict[str, str]:
        return {str(p): (cls.hash_file(p) or "ERROR") for p in paths}

    @classmethod
    def verify(cls, baseline: Dict[str, str]) -> List[str]:
        """Return list of files whose hash has changed or that are missing."""
        changed = []
        for path_str, expected in baseline.items():
            current = cls.hash_file(Path(path_str))
            if current is None:
                changed.append(f"MISSING  {path_str}")
            elif current != expected:
                changed.append(f"MODIFIED {path_str}")
        return changed

    @classmethod
    def audit_directory(cls, directory: Path, report: AegisReport,
                        extensions: Tuple[str, ...] = (".py", ".sh", ".conf", ".env")) -> None:
        files = [p for p in directory.rglob("*")
                 if p.is_file() and p.suffix in extensions]
        if not files:
            report.add(Finding(
                severity="INFO",
                category="FileIntegrity",
                title="No monitored files found",
                description=f"No {extensions} files found under {directory}.",
            ))
            return

        snapshot = cls.snapshot(files)
        report.add(Finding(
            severity="INFO",
            category="FileIntegrity",
            title=f"File integrity baseline captured ({len(snapshot)} files)",
            description="SHA-256 hashes recorded for monitored files.",
            recommendation="Store this baseline securely and re-run to detect tampering.",
        ))

        # Check for world-writable scripts (Unix)
        for f in files:
            try:
                mode = f.stat().st_mode
                if mode & 0o002:
                    report.add(Finding(
                        severity="HIGH",
                        category="FileIntegrity",
                        title=f"World-writable file: {f.name}",
                        description=f"{f} is writable by anyone.",
                        recommendation="Run `chmod o-w` to remove world-write permission.",
                    ))
            except OSError:
                pass

        # Look for .env files containing secrets
        for f in files:
            if f.suffix == ".env":
                try:
                    content = f.read_text(errors="replace")
                    secret_lines = [l.strip() for l in content.splitlines()
                                    if re.search(r"(?i)(password|secret|token|key)\s*=\s*.+", l)]
                    if secret_lines:
                        report.add(Finding(
                            severity="HIGH",
                            category="FileIntegrity",
                            title=f"Secrets detected in {f.name}",
                            description=f"{len(secret_lines)} secret-like variable(s) found.",
                            recommendation="Move secrets to a vault or secrets manager; never commit .env files.",
                        ))
                except OSError:
                    pass


# ─────────────────────────────────────────────────────────────────────────────
# Module 5 — Threat pattern detector
# ─────────────────────────────────────────────────────────────────────────────

class ThreatDetector:
    """Scan source files for common insecure coding patterns."""

    PATTERNS: List[Tuple[str, str, str, str]] = [
        # (regex, severity, title, recommendation)
        (r"eval\s*\(",          "HIGH",   "Use of eval()",
         "Avoid eval(); use ast.literal_eval() or safer alternatives."),
        (r"exec\s*\(",          "HIGH",   "Use of exec()",
         "exec() can execute arbitrary code; use subprocess for external commands."),
        (r"pickle\.loads?\s*\(","HIGH",   "Insecure pickle deserialisation",
         "Never unpickle data from untrusted sources; use JSON instead."),
        (r"shell\s*=\s*True",   "HIGH",   "subprocess shell=True",
         "shell=True is vulnerable to injection; pass a list of args instead."),
        (r"md5\s*\(",           "MEDIUM", "Weak hash: MD5",
         "Replace MD5 with SHA-256 or bcrypt for password hashing."),
        (r"sha1\s*\(",          "MEDIUM", "Weak hash: SHA-1",
         "Replace SHA-1 with SHA-256 or stronger."),
        (r"random\.random\s*\(","MEDIUM", "Insecure random (random.random)",
         "Use secrets module for security-sensitive randomness."),
        (r"random\.randint\s*\(","MEDIUM","Insecure random (random.randint)",
         "Use secrets.randbelow() for security-sensitive integers."),
        (r"http://",            "LOW",    "Plaintext HTTP URL",
         "Use HTTPS for all remote connections."),
        (r"0\.0\.0\.0",         "LOW",    "Binding to all interfaces (0.0.0.0)",
         "Bind only to the required interface unless a public service is intended."),
        (r"DEBUG\s*=\s*True",   "MEDIUM", "Debug mode enabled",
         "Disable DEBUG in production environments."),
        (r"verify\s*=\s*False", "HIGH",   "TLS certificate verification disabled",
         "Never set verify=False; this defeats TLS protection."),
        (r"password\s*=\s*['\"][^'\"]+['\"]", "CRITICAL", "Hardcoded password",
         "Remove hardcoded credentials; use environment variables or a vault."),
        (r"secret\s*=\s*['\"][^'\"]+['\"]",   "CRITICAL", "Hardcoded secret",
         "Remove hardcoded secrets; use a secrets manager."),
        (r"token\s*=\s*['\"][^'\"]+['\"]",    "HIGH",     "Hardcoded token",
         "Remove hardcoded tokens; load from environment or vault."),
    ]

    @classmethod
    def scan_file(cls, path: Path, report: AegisReport) -> None:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            return
        for lineno, line in enumerate(lines, 1):
            for pattern, severity, title, rec in cls.PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    report.add(Finding(
                        severity=severity,
                        category="ThreatDetection",
                        title=f"{title} — {path.name}:{lineno}",
                        description=f"Pattern `{pattern}` matched: {line.strip()[:120]}",
                        recommendation=rec,
                    ))

    @classmethod
    def scan_directory(cls, directory: Path, report: AegisReport,
                       extensions: Tuple[str, ...] = (".py", ".js", ".ts", ".sh", ".php")) -> None:
        # Exclude this script itself to avoid false positives from the pattern table
        this_file = Path(__file__).resolve()
        files = [p for p in directory.rglob("*")
                 if p.is_file() and p.suffix in extensions and p.resolve() != this_file]
        for f in files:
            cls.scan_file(f, report)
        if not files:
            report.add(Finding(
                severity="INFO",
                category="ThreatDetection",
                title="No source files found to scan",
                description=f"No {extensions} files found under {directory}.",
            ))


# ─────────────────────────────────────────────────────────────────────────────
# Module 6 — Hardening adviser
# ─────────────────────────────────────────────────────────────────────────────

class HardeningAdviser:
    """Emit platform-specific hardening recommendations."""

    LINUX_RECOMMENDATIONS = [
        ("INFO", "Enable automatic security updates",
         "Configure unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/Fedora)."),
        ("INFO", "Configure firewall",
         "Use ufw (Ubuntu) or firewalld (RHEL): deny all inbound by default, allow only required ports."),
        ("INFO", "Disable root SSH login",
         "Set `PermitRootLogin no` in /etc/ssh/sshd_config."),
        ("INFO", "Use SSH key authentication",
         "Set `PasswordAuthentication no` in sshd_config after placing your public key."),
        ("INFO", "Enable audit logging",
         "Install and start auditd; configure rules for privilege escalation and file access."),
        ("INFO", "Restrict SUID/SGID binaries",
         "Run `find / -perm /6000 -type f` and remove SUID from binaries that don't need it."),
        ("INFO", "Enable SELinux or AppArmor",
         "Mandatory access control limits damage from compromised processes."),
        ("INFO", "Disable unused services",
         "Run `systemctl list-units --type=service` and disable anything not required."),
        ("INFO", "Use Fail2Ban",
         "Install Fail2Ban to auto-block IPs with repeated failed authentication attempts."),
        ("INFO", "Keep kernel up-to-date",
         "Kernel exploits are a common privilege escalation path; patch regularly."),
    ]

    WINDOWS_RECOMMENDATIONS = [
        ("INFO", "Enable Windows Defender & ATP",       "Keep real-time protection on."),
        ("INFO", "Configure Windows Firewall",          "Deny all inbound by default."),
        ("INFO", "Disable SMBv1",                       "SMBv1 is exploitable (EternalBlue); disable via PowerShell."),
        ("INFO", "Enable BitLocker",                    "Encrypt drives to protect data at rest."),
        ("INFO", "Enable audit policy",                 "Use Group Policy to log logon events, privilege use, and policy changes."),
        ("INFO", "Restrict PowerShell execution policy","Set ExecutionPolicy to RemoteSigned or AllSigned."),
        ("INFO", "Apply CIS Benchmark",                 "Follow CIS Windows benchmarks for comprehensive hardening."),
    ]

    @classmethod
    def advise(cls, report: AegisReport) -> None:
        system = platform.system()
        recs = cls.LINUX_RECOMMENDATIONS if system == "Linux" else cls.WINDOWS_RECOMMENDATIONS
        for severity, title, rec in recs:
            report.add(Finding(
                severity=severity,
                category="Hardening",
                title=title,
                description="",
                recommendation=rec,
            ))


# ─────────────────────────────────────────────────────────────────────────────
# Module 7 — HTML report generator
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate a self-contained HTML security report."""

    SEVERITY_COLORS = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e74c3c",
        "MEDIUM":   "#e67e22",
        "LOW":      "#f1c40f",
        "INFO":     "#2ecc71",
    }

    @classmethod
    def to_html(cls, report: AegisReport) -> str:
        summary = report.summary()
        rows = ""
        for f in sorted(report.findings,
                        key=lambda x: Finding.SEVERITY_ORDER.get(x.severity, 99)):
            color = cls.SEVERITY_COLORS.get(f.severity, "#999")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{f.severity}</span></td>
              <td>{f.category}</td>
              <td><strong>{f.title}</strong></td>
              <td>{f.description}</td>
              <td>{f.recommendation}</td>
            </tr>"""

        summary_html = "".join(
            f'<div class="stat"><span class="sev" style="color:{cls.SEVERITY_COLORS[s]}">'
            f'{s}</span><br><strong>{summary.get(s,0)}</strong></div>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fortress Aegis — Security Report</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:20px; }}
  h1   {{ color:#58a6ff; }} h2 {{ color:#79c0ff; border-bottom:1px solid #30363d; padding-bottom:6px; }}
  .meta {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; margin-bottom:20px; }}
  .score-box {{ display:inline-block; background:#238636; border-radius:50%; width:80px; height:80px;
                line-height:80px; text-align:center; font-size:28px; font-weight:bold; margin-right:20px; color:#fff; }}
  .stats {{ display:flex; gap:20px; flex-wrap:wrap; margin:20px 0; }}
  .stat  {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px 20px; text-align:center; min-width:80px; }}
  .sev   {{ font-weight:bold; font-size:13px; }}
  table  {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th,td  {{ padding:10px 12px; border:1px solid #30363d; text-align:left; vertical-align:top; }}
  th     {{ background:#161b22; color:#79c0ff; }}
  tr:hover {{ background:#161b22; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-size:12px; font-weight:bold; }}
  footer {{ margin-top:40px; color:#484f58; font-size:12px; }}
</style>
</head>
<body>
<h1>🛡️ Fortress Aegis — Security Report</h1>
<div class="meta">
  <span class="score-box">{report.grade()}</span>
  <strong>Host:</strong> {report.hostname}<br>
  <strong>OS:</strong> {report.os_info}<br>
  <strong>Scanned:</strong> {report.timestamp}<br>
  <strong>Security Score:</strong> {report.score} / 100
</div>
<h2>Summary</h2>
<div class="stats">{summary_html}</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<footer>Generated by Fortress Aegis Complete — @shiatoali — {report.timestamp}</footer>
</body>
</html>"""

    @classmethod
    def to_json(cls, report: AegisReport) -> str:
        return json.dumps({
            "hostname":  report.hostname,
            "os":        report.os_info,
            "timestamp": report.timestamp,
            "score":     report.score,
            "grade":     report.grade(),
            "summary":   report.summary(),
            "findings":  [
                {"severity": f.severity, "category": f.category,
                 "title": f.title, "description": f.description,
                 "recommendation": f.recommendation}
                for f in report.findings
            ],
        }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestrator — FortressAegis
# ─────────────────────────────────────────────────────────────────────────────

class FortressAegis:
    """
    Orchestrates all security modules and drives the interactive CLI.
    """

    def __init__(self, target_dir: Optional[Path] = None) -> None:
        self.target_dir = target_dir or Path.cwd()
        self.report = AegisReport()

    # ── pretty printers ────────────────────────────────────────────────────

    @staticmethod
    def _section(title: str) -> None:
        print(f"\n{c(CYAN, BOLD + '━' * 60)}")
        print(c(BOLD + CYAN, f"  {title}"))
        print(c(CYAN, '━' * 60))

    @staticmethod
    def _finding(f: Finding) -> None:
        color = f.severity_color()
        print(f"  {c(color, f'[{f.severity:<8}]')} {c(BOLD, f.title)}")
        if f.description:
            print(f"             {f.description}")
        if f.recommendation:
            print(f"             {c(YELLOW, '→ ' + f.recommendation)}")

    # ── run all modules ────────────────────────────────────────────────────

    def run(self) -> None:
        print(c(CYAN, BANNER))
        print(c(WHITE, "  Initialising full security assessment …\n"))

        # 1. System
        self._section("1 · System Security Audit")
        SystemCollector.collect(self.report)
        for f in [x for x in self.report.findings if x.category == "System"]:
            self._finding(f)

        # 2. Network
        self._section("2 · Network Security Analysis  (localhost port probe)")
        print(c(YELLOW, "  Scanning localhost for high-risk listening ports …"))
        before = len(self.report.findings)
        NetworkAnalyser.scan_localhost_ports(self.report)
        net_findings = self.report.findings[before:]
        if not net_findings:
            print(c(GREEN, "  ✔ No risky ports found."))
        for f in net_findings:
            self._finding(f)

        # 3. File integrity
        self._section("3 · File Integrity Monitor")
        FileIntegrityMonitor.audit_directory(self.target_dir, self.report)
        fim_findings = [x for x in self.report.findings if x.category == "FileIntegrity"]
        for f in fim_findings:
            self._finding(f)

        # 4. Threat detection
        self._section("4 · Threat Pattern Detection")
        before = len(self.report.findings)
        ThreatDetector.scan_directory(self.target_dir, self.report)
        threat_findings = self.report.findings[before:]
        if not threat_findings:
            print(c(GREEN, "  ✔ No insecure patterns detected."))
        for f in threat_findings:
            self._finding(f)

        # 5. Password demo
        self._section("5 · Password Security Demo")
        demo_passwords = [
            "password", "P@ssw0rd!", "Tr0ub4dor&3", "correcthorsebatterystaple",
            FortressAegis._demo_generated(),
        ]
        for pwd in demo_passwords:
            result = PasswordAnalyser.evaluate(pwd)
            strength_color = (GREEN if result["strength"] in ("Strong", "Very Strong")
                              else YELLOW if result["strength"] == "Fair"
                              else RED)
            masked = pwd[:3] + "*" * max(0, len(pwd) - 3)
            print(f"  {c(WHITE, masked):<28}  "
                  f"Strength: {c(strength_color, result['strength']):<18}  "
                  f"Entropy: {result['entropy']:6.1f} bits  "
                  f"{'⚠ COMMON' if result['is_common'] else ''}")
        suggest = PasswordAnalyser.generate_secure(20)
        print(f"\n  {c(GREEN, '✔ Suggested secure password:')} {suggest}")

        # 6. Hardening
        self._section("6 · Hardening Recommendations")
        HardeningAdviser.advise(self.report)
        for f in [x for x in self.report.findings if x.category == "Hardening"]:
            print(f"  {c(CYAN, '•')} {c(BOLD, f.title)}")
            print(f"    {c(YELLOW, '→')} {f.recommendation}")

        # 7. Summary & reports
        self._section("7 · Assessment Complete")
        summary = self.report.summary()
        grade_color = GREEN if self.report.grade() in ("A+", "A") else YELLOW if self.report.grade() in ("B", "C") else RED
        print(f"\n  Security Score : {c(grade_color + BOLD, str(self.report.score) + ' / 100')}  "
              f"Grade: {c(grade_color + BOLD, self.report.grade())}")
        print(f"  Findings       : "
              f"{c(RED,    str(summary['CRITICAL']) + ' Critical')}  "
              f"{c(RED,    str(summary['HIGH'])     + ' High')}  "
              f"{c(YELLOW, str(summary['MEDIUM'])   + ' Medium')}  "
              f"{c(CYAN,   str(summary['LOW'])      + ' Low')}  "
              f"{c(WHITE,  str(summary['INFO'])     + ' Info')}")

        # Write reports
        html_path = self.target_dir / "fortress_aegis_report.html"
        json_path = self.target_dir / "fortress_aegis_report.json"
        html_path.write_text(ReportGenerator.to_html(self.report), encoding="utf-8")
        json_path.write_text(ReportGenerator.to_json(self.report), encoding="utf-8")
        print(f"\n  {c(GREEN, '✔')} HTML report : {html_path}")
        print(f"  {c(GREEN, '✔')} JSON report : {json_path}")
        print(f"\n{c(CYAN, '  Fortress Aegis assessment complete.  Stay secure! 🛡️')}\n")

    @staticmethod
    def _demo_generated() -> str:
        return PasswordAnalyser.generate_secure(18)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    if not target.is_dir():
        print(c(RED, f"[ERROR] '{target}' is not a directory."), file=sys.stderr)
        sys.exit(1)
    aegis = FortressAegis(target_dir=target)
    aegis.run()


if __name__ == "__main__":
    main()
