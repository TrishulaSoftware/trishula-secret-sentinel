---
name: trishula-secret-sentinel
description: Scan code, staged git changes, git history, and text for leaked credentials (cloud keys, LLM provider keys, access tokens, private keys, database URLs) before an AI agent commits, pushes, or shares anything. Offline, standard-library Python, redacted output, tamper-evident attestation.
---

# Trishula Secret Sentinel

An offline secret scanner for AI coding agents. One Python file, no third-party packages, no network access. It finds leaked credentials in the working tree, in the lines you are about to commit, and in git history, and it never prints the secret itself.

## When to use this skill

Run it whenever:
1. You are about to run `git commit` or `git push` in a repository that was edited in this session.
2. You are about to paste file contents, logs, or configuration into a prompt, issue, pull request, or chat message.
3. The user asks you to audit a repository, or its history, for leaked keys or passwords.
4. You created or edited a `.env`, config, deployment, or CI file.

## Rules for the agent

- Never print, quote, or retype a detected secret. Report only the rule name, file, line, and the redacted match the tool gives you.
- Do not rewrite git history, delete files, or rotate credentials on your own. Tell the user what you found and recommend rotation; wait for approval before changing history.
- Treat every finding as a real leak until the user says it is a test fixture. A secret that was deleted in a later commit is still exposed if it appears in history.
- If the scan exits with code 1, stop and report before continuing with the commit or push.

## Step 1: Scan the working tree

```bash
python scripts/secret_sentinel.py scan . --format text
```

## Step 2: Scan only what is staged for commit (run before every commit)

```bash
python scripts/secret_sentinel.py staged --format text
```

This checks just the added lines in `git diff --cached` and reports the real file and line number.

## Step 3: Scan git history

```bash
python scripts/secret_sentinel.py history --max-commits 200 --format text
```

This checks lines added in past commits, including secrets that were later deleted. Findings are labelled `file@commit`.

## Options

| Flag | Effect |
| :--- | :--- |
| `--format text` or `markdown` or `json` or `sarif` | Output style. `text` is one line per finding; `sarif` is SARIF 2.1.0 for CI dashboards. |
| `--entropy` | Also flag high-entropy quoted strings that match no known pattern. |
| `--include-comments` | Scan comment lines too. Comments are skipped by default. |
| `--fail-on any` or `medium` or `high` or `critical` or `never` | Lowest severity that makes the command exit 1. Default is `any`. |
| `--attest-out FILE` | Write the scan attestation as JSON. |

Exit codes: `0` clean, `1` findings at or above the `--fail-on` level, `2` usage or git error.

## What it detects (34 patterns)

Cloud and VCS credentials (AWS, GitHub including fine-grained tokens, Slack, Azure, GCP service accounts), LLM provider keys (Anthropic, OpenAI, Google/Gemini, HuggingFace), package registry tokens (npm, PyPI), bot tokens (Discord, Telegram), payment and email keys (Stripe, SendGrid), private key blocks (RSA, EC, OpenSSH, PGP), JSON Web Tokens, database connection URLs with passwords, hardcoded passwords, and generic API key, secret, and token assignments.

## Reading the results

| Severity | Typical meaning | What to tell the user |
| :--- | :--- | :--- |
| CRITICAL | Live-credential shapes: cloud keys, private keys, database URLs, provider API keys | Rotate the credential now, then remove it from the code and history. |
| HIGH | Tokens and generic secret assignments | Confirm whether it is real; rotate if so. |
| MEDIUM | High-entropy string (only with `--entropy`) | Review manually; may be a hash or an ID. |

Example text output (matches are redacted):

```
SECRET SENTINEL v1.1.0 | verdict: FINDINGS_DETECTED
config.py:3: [CRITICAL] AWS_ACCESS_KEY - AWS Access Key ID  AKIA****************
deploy.yaml:7: [CRITICAL] GITHUB_PAT - GitHub Personal Access Token  ghp_************************************
files: 4 | findings: 2 (CRITICAL 2, HIGH 0, MEDIUM 0, LOW 0)
attestation sha256: <64 hex characters>
```

## Attestation

Each scan produces a SHA-256 digest bound to the engine version, the ruleset, the digest of every file scanned, and every finding, plus a SHA3-512 Merkle root. Save it with `--attest-out att.json`, then later run:

```bash
python scripts/secret_sentinel.py verify att.json .
```

If any scanned file changed, `match` is `false`. The attestation is a digest, not a signature: it detects changes but does not prove who ran the scan.

## Limitations

- 34 patterns. Larger tools such as Gitleaks and TruffleHog cover many more services; use them alongside this one for breadth.
- It does not check whether a detected credential is still valid, because that needs network access.
- There is no ignore file yet, so intentional test fixtures will be reported.
- Files over 1 MB and files containing NUL bytes are skipped and counted.
- `build`, `dist`, `node_modules`, `.git`, and virtual-environment directories are skipped in directory scans.

## Requirements

Python 3.10 or newer. Git is needed only for the `staged` and `history` commands.
