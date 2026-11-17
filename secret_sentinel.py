"""
Trishula Secret Sentinel v1.1 - Air-Gapped Secret Scanner

Scans files, directories, staged git changes and git history for leaked
credentials. Runs fully offline: no cloud API, no registry, no telemetry.
Pure Python standard library.

Features:
    - 34 regex patterns (cloud, VCS, payment, database, private keys and
      LLM-provider keys such as Anthropic, OpenAI, Google/Gemini, HuggingFace)
    - Optional Shannon-entropy detection for secrets no pattern knows about
    - Staged-change scanning (pre-commit use) and git history scanning
    - Content-bound, tamper-evident attestation: SHA-256 over the engine
      version, ruleset, per-file digests and findings, plus a SHA3-512 Merkle
      root. The attestation is a digest, not a signature (it is unsigned).
    - JSON, SARIF 2.1.0, Markdown and one-line text output
    - Matches are always redacted; raw secret values are never printed

Library usage:
    from secret_sentinel import SecretSentinel
    sentinel = SecretSentinel()
    sentinel.scan_directory("./src")
    print(sentinel.generate_attestation()["verdict"])

CLI usage:
    python secret_sentinel.py scan ./src --format text
    python secret_sentinel.py staged
    python secret_sentinel.py history --max-commits 200
    python secret_sentinel.py scan . --attest-out attestation.json
    python secret_sentinel.py verify attestation.json .
"""

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ENGINE_VERSION = "1.1.0"

# PEM header fragments are assembled at import time so this file never
# contains a literal private-key marker (keeps naive scanners from tripping).
_PEM = "-----" + "BEGIN "


# -- Secret Patterns ---------------------------------------------------

SECRET_PATTERNS = [
    # AWS
    {"id": "AWS_ACCESS_KEY", "pattern": r"(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}", "severity": "CRITICAL",
     "description": "AWS Access Key ID"},
    {"id": "AWS_SECRET_KEY", "pattern": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", "severity": "CRITICAL",
     "description": "AWS Secret Access Key"},
    # GitHub
    {"id": "GITHUB_PAT", "pattern": r"ghp_[A-Za-z0-9]{36}", "severity": "CRITICAL",
     "description": "GitHub Personal Access Token"},
    {"id": "GITHUB_OAUTH", "pattern": r"gho_[A-Za-z0-9]{36}", "severity": "HIGH",
     "description": "GitHub OAuth Token"},
    {"id": "GITHUB_APP", "pattern": r"ghu_[A-Za-z0-9]{36}", "severity": "HIGH",
     "description": "GitHub App Token"},
    {"id": "GITHUB_REFRESH", "pattern": r"ghr_[A-Za-z0-9]{36}", "severity": "HIGH",
     "description": "GitHub Refresh Token"},
    # Generic API
    {"id": "GENERIC_API_KEY", "pattern": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})", "severity": "HIGH",
     "description": "Generic API Key assignment"},
    {"id": "GENERIC_SECRET", "pattern": r"(?:secret|SECRET|Secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", "severity": "HIGH",
     "description": "Generic secret assignment"},
    {"id": "GENERIC_TOKEN", "pattern": r"(?:token|TOKEN|Token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})", "severity": "HIGH",
     "description": "Generic token assignment"},
    # Passwords
    {"id": "PASSWORD_ASSIGN", "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "severity": "CRITICAL",
     "description": "Hardcoded password"},
    {"id": "PASSWORD_URL", "pattern": r"://[^:]+:([^@]{8,})@", "severity": "CRITICAL",
     "description": "Password in URL"},
    # Private Keys
    {"id": "RSA_PRIVATE_KEY", "pattern": _PEM + r"(?:RSA )?PRIVATE KEY-----", "severity": "CRITICAL",
     "description": "RSA Private Key"},
    {"id": "EC_PRIVATE_KEY", "pattern": _PEM + r"EC PRIVATE KEY-----", "severity": "CRITICAL",
     "description": "EC Private Key"},
    {"id": "PGP_PRIVATE_KEY", "pattern": _PEM + r"PGP PRIVATE KEY BLOCK-----", "severity": "CRITICAL",
     "description": "PGP Private Key"},
    {"id": "SSH_PRIVATE_KEY", "pattern": _PEM + r"OPENSSH PRIVATE KEY-----", "severity": "CRITICAL",
     "description": "OpenSSH Private Key"},
    # JWT
    {"id": "JWT_TOKEN", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "severity": "HIGH",
     "description": "JSON Web Token"},
    # Cloud Providers
    {"id": "AZURE_CLIENT_SECRET", "pattern": r"(?:AZURE_CLIENT_SECRET|azure_client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-.~]{30,})", "severity": "CRITICAL",
     "description": "Azure Client Secret"},
    {"id": "GCP_SERVICE_KEY", "pattern": r'"type"\s*:\s*"service_account"', "severity": "CRITICAL",
     "description": "GCP Service Account Key"},
    {"id": "SLACK_TOKEN", "pattern": r"xox[bprs]-[A-Za-z0-9\-]{10,}", "severity": "HIGH",
     "description": "Slack API Token"},
    {"id": "SLACK_WEBHOOK", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "severity": "HIGH",
     "description": "Slack Webhook URL"},
    # Database
    {"id": "POSTGRES_URI", "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+", "severity": "CRITICAL",
     "description": "PostgreSQL Connection URI"},
    {"id": "MYSQL_URI", "pattern": "mysql" + r"://[^:]+:[^@]+@[^/]+", "severity": "CRITICAL",
     "description": "MySQL Connection URI"},
    {"id": "MONGO_URI", "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+", "severity": "CRITICAL",
     "description": "MongoDB Connection URI"},
    # Stripe
    {"id": "STRIPE_KEY", "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}", "severity": "CRITICAL",
     "description": "Stripe API Key"},
    # SendGrid
    {"id": "SENDGRID_KEY", "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "severity": "HIGH",
     "description": "SendGrid API Key"},
    # LLM providers and developer platforms (added in v1.1)
    {"id": "ANTHROPIC_KEY", "pattern": r"sk-ant-[A-Za-z0-9]{3,12}-[A-Za-z0-9_\-]{40,}", "severity": "CRITICAL",
     "description": "Anthropic API Key"},
    {"id": "OPENAI_KEY", "pattern": r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}", "severity": "CRITICAL",
     "description": "OpenAI API Key"},
    {"id": "GOOGLE_API_KEY", "pattern": r"AIza[0-9A-Za-z_\-]{35}", "severity": "HIGH",
     "description": "Google / Gemini API Key"},
    {"id": "HUGGINGFACE_TOKEN", "pattern": r"hf_[A-Za-z0-9]{34,}", "severity": "HIGH",
     "description": "HuggingFace Access Token"},
    {"id": "GITHUB_FINE_GRAINED_PAT", "pattern": r"github_pat_[A-Za-z0-9_]{22,}", "severity": "CRITICAL",
     "description": "GitHub Fine-Grained Personal Access Token"},
    {"id": "NPM_TOKEN", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "CRITICAL",
     "description": "npm Access Token"},
    {"id": "PYPI_TOKEN", "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "severity": "CRITICAL",
     "description": "PyPI API Token"},
    {"id": "DISCORD_BOT_TOKEN", "pattern": r"\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}", "severity": "HIGH",
     "description": "Discord Bot Token"},
    {"id": "TELEGRAM_BOT_TOKEN", "pattern": r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b", "severity": "HIGH",
     "description": "Telegram Bot Token"},
]

# File extensions to skip (binary, media, etc.)
SKIP_EXTENSIONS = {
    '.pyc', '.pyo', '.class', '.jar', '.war', '.ear',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.exe', '.dll', '.so', '.dylib', '.bin',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.woff', '.woff2', '.ttf', '.eot',
    '.db', '.sqlite', '.sqlite3',
}

# Directory names pruned during directory walks (matched on the name, never
# on the absolute path, so a repo that lives under a folder called "build"
# is still scanned).
SKIP_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv',
    '.tox', '.mypy_cache', '.pytest_cache', 'dist', 'build',
    '.eggs',
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


# -- Helpers -----------------------------------------------------------

def merkle_root(leaves: list) -> str:
    """Deterministic SHA3-512 Merkle root over a list of string leaves."""
    if not leaves:
        return hashlib.sha3_512(b"SECRET_SENTINEL_EMPTY_SET").hexdigest()
    layer = [hashlib.sha3_512(item.encode("utf-8")).hexdigest() for item in leaves]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [
            hashlib.sha3_512((layer[i] + layer[i + 1]).encode("utf-8")).hexdigest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0]


# -- Data Models -------------------------------------------------------

@dataclass
class Finding:
    """A single detected secret."""
    rule_id: str
    description: str
    severity: str
    file: str
    line: int
    match: str  # Redacted match
    entropy: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report with attestation."""
    scan_id: str
    timestamp: str
    files_scanned: int
    findings: list
    clean: bool
    attestation_hash: str = ""
    duration_ms: float = 0.0
    merkle_root: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# -- Core Scanner ------------------------------------------------------

class SecretSentinel:
    """Air-gapped secret scanner. Zero external dependencies."""

    def __init__(self, patterns: Optional[list] = None, entropy_threshold: float = 4.5,
                 entropy_scan: bool = False, skip_comments: bool = True,
                 max_file_bytes: int = 1_000_000):
        self.patterns = patterns or SECRET_PATTERNS
        self._compiled = [(p, re.compile(p["pattern"])) for p in self.patterns]
        self.entropy_threshold = entropy_threshold
        self.entropy_scan = entropy_scan
        self.skip_comments = skip_comments
        self.max_file_bytes = max_file_bytes
        self._findings: list[Finding] = []
        self._files_scanned = 0
        self._files_skipped = 0
        self._file_digests: dict[str, str] = {}

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length)
                    for count in freq.values())

    @staticmethod
    def redact(match: str, show: int = 4) -> str:
        """Redact a secret, showing only first `show` characters."""
        if len(match) <= show:
            return "****"
        return match[:show] + "*" * (len(match) - show)

    def _should_skip_file(self, filepath: str) -> bool:
        """Extension-based skip. Directory pruning happens during the walk."""
        return Path(filepath).suffix.lower() in SKIP_EXTENSIONS

    @staticmethod
    def _is_skipped_dir(name: str) -> bool:
        return name in SKIP_DIRS or name.endswith(".egg-info")

    def _is_comment(self, stripped: str) -> bool:
        return self.skip_comments and (
            stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('--'))

    def scan_content(self, content: str, filepath: str = "<stdin>",
                     track_digest: bool = True, digest: Optional[str] = None) -> list[Finding]:
        """Scan a string for secrets. Findings are recorded for the report."""
        if track_digest:
            self._file_digests[filepath] = digest or hashlib.sha256(
                content.encode("utf-8", errors="ignore")).hexdigest()

        findings = []
        for line_num, line in enumerate(content.split('\n'), 1):
            if self._is_comment(line.strip()):
                continue

            for pattern_def, compiled in self._compiled:
                for match in compiled.finditer(line):
                    matched_text = match.group(0)
                    # Skip documentation / placeholder values
                    if any(test_val in matched_text.lower() for test_val in
                           ['example', 'placeholder', 'your_', 'xxx', 'changeme', 'fixme']):
                        continue

                    findings.append(Finding(
                        rule_id=pattern_def["id"],
                        description=pattern_def["description"],
                        severity=pattern_def["severity"],
                        file=filepath,
                        line=line_num,
                        match=self.redact(matched_text),
                        entropy=self.shannon_entropy(matched_text)
                    ))

        self._findings.extend(findings)

        if self.entropy_scan:
            flagged_lines = {f.line for f in findings}
            extra = [f for f in self.scan_entropy(content, filepath, record=False)
                     if f.line not in flagged_lines]
            self._findings.extend(extra)
            findings.extend(extra)

        return findings

    def scan_file(self, filepath: str, display_name: Optional[str] = None) -> list[Finding]:
        """Scan a single file for secrets."""
        if self._should_skip_file(filepath):
            return []

        path = Path(filepath)
        try:
            if path.stat().st_size > self.max_file_bytes:
                self._files_skipped += 1
                return []
            raw = path.read_bytes()
        except (OSError, PermissionError):
            return []

        if b"\x00" in raw[:8192]:  # binary content
            self._files_skipped += 1
            return []

        self._files_scanned += 1
        return self.scan_content(
            raw.decode("utf-8", errors="ignore"),
            display_name or str(filepath),
            digest=hashlib.sha256(raw).hexdigest(),
        )

    def scan_directory(self, directory: str, recursive: bool = True) -> list[Finding]:
        """Scan a directory for secrets, pruning skipped directories early."""
        findings = []
        root = Path(directory)

        for current, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not self._is_skipped_dir(d))
            for name in sorted(files):
                full = Path(current) / name
                rel = full.relative_to(root).as_posix()
                findings.extend(self.scan_file(str(full), display_name=rel))
            if not recursive:
                break

        return findings

    def scan_entropy(self, content: str, filepath: str = "<stdin>",
                     min_length: int = 20, record: bool = True) -> list[Finding]:
        """Scan for high-entropy strings (potential secrets not caught by patterns)."""
        findings = []

        for line_num, line in enumerate(content.split('\n'), 1):
            stripped = line.strip()
            if self.skip_comments and (stripped.startswith('#') or stripped.startswith('//')):
                continue

            for match in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', line):
                value = match.group(1)
                entropy = self.shannon_entropy(value)
                if entropy >= self.entropy_threshold and len(value) >= min_length:
                    findings.append(Finding(
                        rule_id="HIGH_ENTROPY",
                        description=f"High-entropy string (entropy={entropy:.2f})",
                        severity="MEDIUM",
                        file=filepath,
                        line=line_num,
                        match=self.redact(value),
                        entropy=entropy
                    ))

        if record:
            self._findings.extend(findings)
        return findings

    # -- Git integration (list-argument subprocess, no shell) ----------

    @staticmethod
    def _run_git(args: list, cwd: str, timeout: int = 120) -> str:
        try:
            result = subprocess.run(
                ["git", "-c", "core.quotepath=off", *args], cwd=cwd,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"git unavailable or timed out: {exc}")
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "git command failed")
        return result.stdout

    def _scan_diff(self, diff_text: str, suffix_for_commit: bool = False) -> list[Finding]:
        """Scan only the ADDED lines of a unified diff, with real line numbers."""
        findings = []
        added: dict[str, list[str]] = {}
        commit = ""
        current_file = None
        old_left = new_left = 0
        new_line = 0

        for raw in diff_text.splitlines():
            if old_left > 0 or new_left > 0:
                if raw.startswith("+"):
                    new_left -= 1
                    text = raw[1:]
                    label = (f"{current_file}@{commit}" if suffix_for_commit else current_file)
                    if label:
                        added.setdefault(label, []).append(text)
                        for f in self.scan_content(text, label, track_digest=False):
                            f.line = new_line
                            findings.append(f)
                    new_line += 1
                elif raw.startswith("-"):
                    old_left -= 1
                elif raw.startswith("\\"):
                    pass
                else:
                    old_left -= 1
                    new_left -= 1
                    new_line += 1
                continue

            if raw.startswith("commit:"):
                commit = raw[7:].strip()[:8]
            elif raw.startswith("+++ "):
                path = raw[4:].strip("\t ")
                if path == "/dev/null":
                    current_file = None
                else:
                    current_file = path[2:] if path.startswith("b/") else path
            else:
                m = _HUNK_RE.match(raw)
                if m:
                    old_left = int(m.group(2)) if m.group(2) is not None else 1
                    new_line = int(m.group(3))
                    new_left = int(m.group(4)) if m.group(4) is not None else 1

        for label, lines in added.items():
            self._file_digests[label] = hashlib.sha256("\n".join(lines).encode("utf-8", errors="ignore")).hexdigest()
            self._files_scanned += 1
        return findings

    def scan_staged(self, repo_path: str = ".") -> list[Finding]:
        """Scan lines staged for commit (use before `git commit`)."""
        diff = self._run_git(["diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff"], repo_path)
        return self._scan_diff(diff)

    def scan_history(self, repo_path: str = ".", max_commits: int = 200) -> list[Finding]:
        """Scan lines added in past commits, including secrets deleted later."""
        out = self._run_git(
            ["log", "-p", "--unified=0", "--no-color", "--no-ext-diff",
             "--format=commit:%H", "-n", str(int(max_commits))], repo_path)
        return self._scan_diff(out, suffix_for_commit=True)

    # -- Reporting -----------------------------------------------------

    def _ruleset_digest(self) -> str:
        blob = "|".join(sorted(f"{p['id']}:{p['pattern']}" for p in self.patterns))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def settings(self) -> dict:
        return {
            "entropy_scan": self.entropy_scan,
            "skip_comments": self.skip_comments,
            "max_file_bytes": self.max_file_bytes,
        }

    def generate_report(self) -> ScanReport:
        """Generate a report whose attestation is bound to the scanned content."""
        findings = [f.to_dict() for f in self._findings]
        files = dict(sorted(self._file_digests.items()))
        payload = json.dumps({
            "engine": ENGINE_VERSION,
            "ruleset": self._ruleset_digest(),
            "settings": self.settings(),
            "files": files,
            "findings": findings,
        }, sort_keys=True, default=str)
        leaves = [f"file:{p}:{d}" for p, d in files.items()]
        leaves += [f"finding:{json.dumps(f, sort_keys=True, default=str)}" for f in findings]

        return ScanReport(
            scan_id=f"scan_{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            files_scanned=self._files_scanned,
            findings=findings,
            clean=len(findings) == 0,
            attestation_hash=hashlib.sha256(payload.encode()).hexdigest(),
            merkle_root=merkle_root(leaves),
        )

    def generate_attestation(self) -> dict:
        """Tamper-evident attestation bound to engine, ruleset, files and findings."""
        report = self.generate_report()
        return {
            "verdict": "CLEAN" if report.clean else "FINDINGS_DETECTED",
            "engine_version": ENGINE_VERSION,
            "ruleset_sha256": self._ruleset_digest(),
            "files_scanned": report.files_scanned,
            "files_skipped": self._files_skipped,
            "finding_count": len(report.findings),
            "attestation_hash": report.attestation_hash,
            "merkle_root_sha3_512": report.merkle_root,
            "settings": self.settings(),
            "signed": False,
            "timestamp": report.timestamp,
            "severity_breakdown": self._severity_breakdown()
        }

    def _severity_breakdown(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_sarif(self) -> dict:
        """SARIF 2.1.0 document for GitHub Code Scanning and CI dashboards."""
        level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        rules = {}
        results = []
        for f in self._findings:
            rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.description}})
            results.append({
                "ruleId": f.rule_id,
                "level": level.get(f.severity, "warning"),
                "message": {"text": f"{f.description} (redacted match: {f.match})"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": max(1, f.line)}}}],
            })
        att = self.generate_attestation()
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Trishula Secret Sentinel",
                    "version": ENGINE_VERSION,
                    "informationUri": "https://github.com/TrishulaSoftware/trishula-secret-sentinel",
                    "rules": list(rules.values())}},
                "properties": {"attestation_hash": att["attestation_hash"],
                               "merkle_root_sha3_512": att["merkle_root_sha3_512"]},
                "results": results,
            }],
        }

    @property
    def pattern_count(self) -> int:
        return len(self.patterns)

    def reset(self):
        """Reset scanner state for a new scan."""
        self._findings = []
        self._files_scanned = 0
        self._files_skipped = 0
        self._file_digests = {}


# -- Formatting and CLI ------------------------------------------------

def format_text(s: SecretSentinel) -> str:
    att = s.generate_attestation()
    lines = [f"SECRET SENTINEL v{ENGINE_VERSION} | verdict: {att['verdict']}"]
    for f in s._findings:
        lines.append(f"{f.file}:{f.line}: [{f.severity}] {f.rule_id} - {f.description}  {f.match}")
    sb = att["severity_breakdown"]
    lines.append(
        f"files: {att['files_scanned']} | findings: {att['finding_count']} "
        f"(CRITICAL {sb['CRITICAL']}, HIGH {sb['HIGH']}, MEDIUM {sb['MEDIUM']}, LOW {sb['LOW']})")
    lines.append(f"attestation sha256: {att['attestation_hash']}")
    return "\n".join(lines)


def format_markdown(s: SecretSentinel) -> str:
    att = s.generate_attestation()
    sb = att["severity_breakdown"]
    lines = [
        "# Secret Sentinel Scan Report", "",
        f"- **Verdict:** `{att['verdict']}`",
        f"- **Files scanned:** {att['files_scanned']} (skipped: {att['files_skipped']})",
        f"- **Findings:** {att['finding_count']} (CRITICAL {sb['CRITICAL']}, HIGH {sb['HIGH']}, "
        f"MEDIUM {sb['MEDIUM']}, LOW {sb['LOW']})",
        f"- **Attestation (SHA-256):** `{att['attestation_hash']}`",
        f"- **Merkle root (SHA3-512):** `{att['merkle_root_sha3_512'][:32]}...`",
        f"- **Engine:** v{ENGINE_VERSION} (attestation is unsigned)", "",
    ]
    if s._findings:
        lines += ["| Severity | Rule | Location | Redacted match |", "| :--- | :--- | :--- | :--- |"]
        for f in s._findings:
            safe = f.match.replace("|", "\\|")
            lines.append(f"| `{f.severity}` | `{f.rule_id}` | `{f.file}:{f.line}` | `{safe}` |")
        lines.append("")
    lines.append("Matches are redacted. Raw secret values are never printed.")
    return "\n".join(lines)


def scan_target(s: SecretSentinel, target: str) -> None:
    path = Path(target)
    if path.is_file():
        s.scan_file(str(path), display_name=path.name)
    else:
        s.scan_directory(str(path))


def verify_attestation(attestation: dict, target: str) -> dict:
    """Re-scan `target` with the recorded settings and compare attestation hashes."""
    st = attestation.get("settings", {})
    s = SecretSentinel(entropy_scan=st.get("entropy_scan", False),
                       skip_comments=st.get("skip_comments", True),
                       max_file_bytes=st.get("max_file_bytes", 1_000_000))
    scan_target(s, target)
    fresh = s.generate_attestation()
    return {
        "match": fresh["attestation_hash"] == attestation.get("attestation_hash"),
        "merkle_match": fresh["merkle_root_sha3_512"] == attestation.get("merkle_root_sha3_512"),
        "expected": attestation.get("attestation_hash"),
        "actual": fresh["attestation_hash"],
    }


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "markdown", "json", "sarif"], default="markdown")
    common.add_argument("--entropy", action="store_true", help="also flag high-entropy strings")
    common.add_argument("--include-comments", action="store_true", help="scan comment lines too")
    common.add_argument("--attest-out", help="write the attestation JSON to this file")
    common.add_argument("--fail-on", choices=["any", "medium", "high", "critical", "never"], default="any",
                        help="lowest severity that produces exit code 1 (default: any)")

    parser = argparse.ArgumentParser(prog="secret_sentinel", description="Air-gapped secret scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    p_scan = sub.add_parser("scan", parents=[common], help="scan a file or directory")
    p_scan.add_argument("path", nargs="?", default=".")
    p_staged = sub.add_parser("staged", parents=[common], help="scan lines staged for commit")
    p_staged.add_argument("--repo", default=".")
    p_hist = sub.add_parser("history", parents=[common], help="scan lines added in past commits")
    p_hist.add_argument("--repo", default=".")
    p_hist.add_argument("--max-commits", type=int, default=200)
    p_verify = sub.add_parser("verify", help="re-scan a path and compare against an attestation file")
    p_verify.add_argument("attestation")
    p_verify.add_argument("path", nargs="?", default=".")
    args = parser.parse_args(argv)

    if args.command == "verify":
        try:
            attestation = json.loads(Path(args.attestation).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"error: cannot read attestation: {exc}", file=sys.stderr)
            return 2
        result = verify_attestation(attestation, args.path)
        print(json.dumps(result, indent=2))
        return 0 if result["match"] else 1

    s = SecretSentinel(entropy_scan=args.entropy, skip_comments=not args.include_comments)
    try:
        if args.command == "scan":
            if not Path(args.path).exists():
                print(f"error: path not found: {args.path}", file=sys.stderr)
                return 2
            scan_target(s, args.path)
        elif args.command == "staged":
            s.scan_staged(args.repo)
        else:
            s.scan_history(args.repo, args.max_commits)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    att = s.generate_attestation()
    if args.attest_out:
        Path(args.attest_out).write_text(json.dumps(att, indent=2), encoding="utf-8")

    if args.format == "json":
        print(json.dumps({"attestation": att, "findings": [f.to_dict() for f in s._findings]}, indent=2))
    elif args.format == "sarif":
        print(json.dumps(s.to_sarif(), indent=2))
    elif args.format == "text":
        print(format_text(s))
    else:
        print(format_markdown(s))

    if args.fail_on == "never" or not s._findings:
        return 0
    threshold = 1 if args.fail_on == "any" else SEVERITY_RANK[args.fail_on.upper()]
    return 1 if any(SEVERITY_RANK.get(f.severity, 1) >= threshold for f in s._findings) else 0


if __name__ == "__main__":
    sys.exit(main())
