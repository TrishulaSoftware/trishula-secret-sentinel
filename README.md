# Trishula Secret Sentinel

**Air-gapped secret scanner for codebases and AI coding agents. Zero dependencies. Content-bound, tamper-evident scan attestation.**

[![CI](https://github.com/TrishulaSoftware/trishula-secret-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/TrishulaSoftware/trishula-secret-sentinel/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 102/102](https://img.shields.io/badge/tests-102%2F102-brightgreen.svg)]()
[![SQA v5 ASCENDED](https://img.shields.io/badge/SQA-v5_ASCENDED-gold.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/deps-zero-blue.svg)]()

---

## The Problem

**Credential leaks are the #1 attack vector, and the tools you trust to find them are the ones getting compromised.**

| Incident | What Happened | Date |
|:--|:--|:--|
| **Checkmarx KICS trojanized** | Docker Hub images of a security scanner exfiltrated credentials | Apr 22, 2026 |
| **Vercel/Context.ai breach** | Lumma Stealer harvested OAuth tokens → full lateral movement | Apr 2026 |
| **LiteLLM supply chain** | Credential-stealing malware injected into LLM gateway package | Apr 2026 |
| **Bitwarden CLI npm** | 90-minute window where install hook harvested GitHub tokens + SSH keys | Apr 22, 2026 |
| **MCP protocol RCE** | 7,000+ servers vulnerable to agent communication hijacking | Apr 2026 |

Existing secret scanners (Gitleaks, TruffleHog, detect-secrets) are excellent, and their rule sets are far larger than ours. They typically ship as Go binaries or Python packages with dependencies. In an air-gapped or high-security environment, a scanner with **zero third-party code** has a very small attack surface of its own. Use Sentinel on its own, or alongside a larger rule set.

### Where Sentinel Fits

| Feature | Trishula Sentinel | Gitleaks | TruffleHog | detect-secrets |
|:--|:--|:--|:--|:--|
| Zero dependencies | ✅ Python stdlib | ❌ Go binary | ❌ Go binary | ⚠️ Python + deps |
| Air-gapped operation | ✅ Native | ✅ Native | ⚠️ `--no-verification` | ✅ Native |
| Content-bound scan attestation | ✅ SHA-256 + SHA3-512 Merkle (unsigned) | ❌ | ❌ | ❌ |
| Entropy analysis | ✅ Shannon (opt-in) | ✅ Shannon | ✅ | ✅ |
| Pattern count | 34 | ~150 (TOML) | ~800 | ~30 |
| LLM-provider keys (Anthropic, OpenAI, Gemini, HuggingFace) | ✅ | varies | varies | varies |
| Staged + history scanning | ✅ | ✅ | ✅ | ⚠️ |
| SARIF output | ✅ | ✅ | ✅ | ❌ |

---

## What It Does

Scans files, directories, staged git changes, and git history for **34 secret patterns**:

| Category | Patterns | Examples |
|:--|:--|:--|
| AWS | 2 | Access Key ID, Secret Access Key |
| GitHub | 5 | PAT, fine-grained PAT, OAuth, App, Refresh tokens |
| Private Keys | 4 | RSA, EC, SSH, PGP |
| Passwords | 2 | Hardcoded assignments, URL-embedded |
| Cloud Providers | 4 | Azure, GCP Service Account, Slack token, Slack webhook |
| Databases | 3 | PostgreSQL, MySQL, MongoDB URIs |
| Payment / Email | 2 | Stripe, SendGrid |
| JWT | 1 | JSON Web Tokens |
| Generic | 3 | API key / secret / token assignments |
| **LLM & dev platforms (v1.1)** | 8 | Anthropic, OpenAI, Google/Gemini, HuggingFace, npm, PyPI, Discord bot, Telegram bot |
| **Entropy (opt-in)** | 1 | High-randomness string detection |

Matches are **always redacted**; raw secret values are never printed or written to reports.

---

## Quick Start

### CLI

```bash
python secret_sentinel.py scan ./src --format text      # files / directories
python secret_sentinel.py staged                         # lines staged for commit
python secret_sentinel.py history --max-commits 200      # secrets added in past commits
python secret_sentinel.py scan . --format sarif          # SARIF 2.1.0 for CI dashboards
python secret_sentinel.py scan . --attest-out att.json   # write a scan attestation
python secret_sentinel.py verify att.json .              # re-scan and compare
```

Exit code is `0` when clean, `1` when findings meet `--fail-on` (default `any`), `2` on usage or git errors.
Other flags: `--entropy` (also flag high-entropy strings), `--include-comments`, `--format text|markdown|json|sarif`.

### Pre-commit hook

Save as `.git/hooks/pre-commit` and make it executable:

```sh
#!/bin/sh
python path/to/secret_sentinel.py staged --format text --fail-on high
```

### Library

```python
from secret_sentinel import SecretSentinel

sentinel = SecretSentinel()
sentinel.scan_directory("./src")
sentinel.scan_content(text_you_want_checked)

attestation = sentinel.generate_attestation()
print(attestation["verdict"])  # "CLEAN" or "FINDINGS_DETECTED"
```

---

## About the Attestation

The attestation hash covers the engine version, the ruleset, a SHA-256 digest of **every file scanned**, and every finding. A clean result therefore attests to *those exact file contents*: change a byte and `verify` fails. A SHA3-512 Merkle root is included for per-leaf auditing.

It is a **digest, not a signature**. Anyone can recompute it, so it is tamper-evident but does not authenticate who ran the scan. Sign the attestation file with your own key if you need that.

---

## Known Limitations

- **Smaller rule set** than Gitleaks or TruffleHog (34 patterns). Pair it with them for breadth.
- **Comment lines are skipped by default** to cut false positives. A secret pasted into a comment is still a leak: run with `--include-comments` for a strict pass.
- **Entropy detection is opt-in** (`--entropy`) and only flags quoted strings of roughly 23+ characters.
- **No live verification** of whether a detected credential is still valid (that would need network access).
- **No allowlist / ignore file yet.** Intentional test fixtures will be reported.
- `build/`, `dist/`, and `node_modules/` directories are pruned during directory scans.
- Files over 1 MB and files containing NUL bytes are skipped and counted in `files_skipped`.

---

## Proof It Works: 102 Tests

```
CATEGORY 1-6:  v1.0 suite (init, 18 detection vectors, false-positive suppression,
               files and directories, entropy, reporting) ........ 45/45 PASS
CATEGORY 7:    LLM and dev-platform keys + a gate that every one of the
               34 patterns has a detecting vector (34/34) ......... PASS
CATEGORY 8:    Regression fixes (see below) ....................... PASS
CATEGORY 9:    Content-bound attestation, Merkle root, verify ..... PASS
CATEGORY 10:   SARIF 2.1.0 and raw-secret-never-printed checks .... PASS
CATEGORY 11:   Staged and history scanning in a real temp git repo,
               CLI exit codes and --fail-on thresholds ............ PASS
CATEGORY 12:   MCP JSON-RPC 2.0 STDIO server (5 tools) ............ PASS

TOTAL: 102/102 PASSED
```

```bash
python test_sentinel.py
```

### v1.1 fixes worth knowing about

- `scan_content()` findings were not recorded, so scanning a string and then attesting could report `CLEAN` even when a secret was found.
- Directory skipping matched *absolute* path parts, so a repository checked out under a folder named `build` or `dist` was silently skipped and reported clean.
- The attestation of a clean scan was identical for every clean scan (a hash of an empty list). It is now bound to the scanned file contents.
- Several patterns had no test vector in v1.0. All 34 now do, and a test enforces it.
- Previously documented-but-missing features (git history scanning, SARIF output, pre-commit use) are now implemented.

---

## Installation

```bash
# No external dependencies - stdlib only
git clone https://github.com/TrishulaSoftware/trishula-secret-sentinel.git
cd trishula-secret-sentinel
python test_sentinel.py   # Verify 102/102
```

## License

MIT
