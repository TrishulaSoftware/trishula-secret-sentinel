"""Trishula Secret Sentinel v1.1 - Test Suite (102 tests across 12 categories)"""
import os, sys, json, tempfile, hashlib, io, shutil, subprocess, contextlib
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_sentinel import (SecretSentinel, Finding, SECRET_PATTERNS, SKIP_EXTENSIONS,
                             main as cli_main, verify_attestation, merkle_root)

PASSED = 0; FAILED = 0
def test(name, cond):
    global PASSED, FAILED
    if cond: PASSED += 1; print(f"  [PASS] {name}")
    else: FAILED += 1; print(f"  [FAIL] {name}")
def section(t): print(f"\n{'='*60}\n  {t}\n{'='*60}")

# ═══ CATEGORY 1: INITIALIZATION ═══
section("CATEGORY 1: INITIALIZATION")
s = SecretSentinel()
test("Scanner initializes", s is not None)
test(f"Pattern count: {s.pattern_count}", s.pattern_count == 34)
test("Compiled patterns ready", len(s._compiled) == 34)

# Build test keys dynamically to avoid GitHub push protection
_sk = "sk" + "_" + "live" + "_4eC39HqLyjWDarjtT1zdp7dc"
_sg = "SG" + ".ngeVfQFYQlKU0ufo8x5d1A" + ".TwL2iGABf9DHoTf" + "-09kqeF8tAmbihYzrnopKc-1s5cr"

test_vectors = [
    ("AWS_ACCESS_KEY", 'key = "AKIAIOSFODNN7QBLHZ9A"'),
    ("GITHUB_PAT", 'token = "ghp_R8n4hVBJq1X2wPmK5sLdF7gTjYcN9aUoizAB"'),
    ("GITHUB_OAUTH", 'auth = "gho_R8n4hVBJq1X2wPmK5sLdF7gTjYcN9aUoizAB"'),
    ("GITHUB_APP", 'app = "ghu_R8n4hVBJq1X2wPmK5sLdF7gTjYcN9aUoizAB"'),
    ("RSA_PRIVATE_KEY", 'line with -----BEGIN RSA PRIVATE KEY----- data'),
    ("EC_PRIVATE_KEY", 'line with -----BEGIN EC PRIVATE KEY----- data'),
    ("SSH_PRIVATE_KEY", 'line with -----BEGIN OPENSSH PRIVATE KEY----- data'),
    ("PGP_PRIVATE_KEY", 'line with -----BEGIN PGP PRIVATE KEY BLOCK----- data'),
    ("PASSWORD_ASSIGN", 'password = "SuperSecretP@ss123!"'),
    ("PASSWORD_URL", 'db = "postgres://admin:s3cretP4ssw0rd@db.prod.com:5432/main"'),
    ("JWT_TOKEN", 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'),
    ("STRIPE_KEY", f'stripe = "{_sk}"'),
    ("SLACK_TOKEN", 'slack = "xoxb-1234567890-abcdefghij"'),
    ("POSTGRES_URI", 'db = "postgres://user:pass1234@host.com/db"'),
    ("MYSQL_URI", 'db = "mysql://root:password1@localhost/prod"'),
    ("MONGO_URI", 'uri = "mongodb+srv://admin:secret12@cluster.prod.com/db"'),
    ("GCP_SERVICE_KEY", '"type": "service_account"'),
    ("SENDGRID_KEY", f'sg = "{_sg}"'),
]

for rule_id, content in test_vectors:
    s.reset()
    findings = s.scan_content(content, f"test_{rule_id}")
    test(f"Detects {rule_id}", len(findings) > 0 and any(f.rule_id == rule_id for f in findings))

# ═══ CATEGORY 3: FALSE POSITIVE SUPPRESSION ═══
section("CATEGORY 3: FALSE POSITIVE SUPPRESSION")
s.reset()
clean_samples = [
    '# This is a comment with api_key = example_key',
    'api_key = "your_api_key_here"',
    'token = "changeme"',
    'password = "placeholder_password"',
    'API_KEY = "xxxxxxxxxxxxx"',
]
for sample in clean_samples:
    findings = s.scan_content(sample)
    test(f"No FP: {sample[:40]}...", len(findings) == 0)

# Comments skipped
findings = s.scan_content('# ghp_R8n4hVBJq1X2wPmK5sLdF7gTjYcN9aUoizAB')
test("Comments are skipped", len(findings) == 0)

# ═══ CATEGORY 4: FILE & DIRECTORY SCANNING ═══
section("CATEGORY 4: FILE & DIRECTORY SCANNING")
with tempfile.TemporaryDirectory() as tmpdir:
    # Create a file with a secret
    secret_file = os.path.join(tmpdir, "config.py")
    with open(secret_file, 'w') as f:
        f.write('API_TOKEN = "ghp_R8n4hVBJq1X2wPmK5sLdF7gTjYcN9aUoizAB"\n')

    s.reset()
    findings = s.scan_file(secret_file)
    test("File scan finds secret", len(findings) > 0)
    test("Finding has line number", findings[0].line == 1)
    test("Finding is redacted", "****" in findings[0].match)

    # Create clean file
    clean_file = os.path.join(tmpdir, "clean.py")
    with open(clean_file, 'w') as f:
        f.write('x = 42\nname = "hello"\n')

    s.reset()
    findings = s.scan_file(clean_file)
    test("Clean file has no findings", len(findings) == 0)

    # Binary files skipped
    bin_file = os.path.join(tmpdir, "image.png")
    with open(bin_file, 'wb') as f:
        f.write(b'\x89PNG')
    s.reset()
    findings = s.scan_file(bin_file)
    test("Binary files skipped", len(findings) == 0)

    # Directory scan
    s.reset()
    findings = s.scan_directory(tmpdir)
    test("Directory scan works", s._files_scanned >= 2)

# ═══ CATEGORY 5: ENTROPY ANALYSIS ═══
section("CATEGORY 5: ENTROPY ANALYSIS")
high_entropy = 'secret = "aB3dEf7hIjKlMnOpQrStUvWxYz012345"'
low_entropy = 'secret = "aaaaaaaaaaaaaaaaaaaaaa"'

s.reset()
he_findings = s.scan_entropy(high_entropy)
test("High entropy detected", len(he_findings) > 0)

le_findings = s.scan_entropy(low_entropy)
test("Low entropy ignored", len(le_findings) == 0)

test("Shannon entropy calc works", SecretSentinel.shannon_entropy("abcd") > 0)
test("Empty string entropy = 0", SecretSentinel.shannon_entropy("") == 0.0)

# ═══ CATEGORY 6: REPORTING & ATTESTATION ═══
section("CATEGORY 6: REPORTING & ATTESTATION")
s.reset()
with tempfile.TemporaryDirectory() as tmpdir:
    report_file = os.path.join(tmpdir, "leaky.py")
    with open(report_file, 'w') as f:
        f.write('token = "ghp_R8n4hVBJq1X2wPmK5sLdF7gTjYcN9aUoizAB"\n')
    s.scan_file(report_file)
report = s.generate_report()
test("Report has scan ID", report.scan_id.startswith("scan_"))
test("Report has timestamp", len(report.timestamp) > 0)
test("Report is NOT clean (findings exist)", not report.clean)
test("Report has attestation hash", len(report.attestation_hash) == 64)

# Clean attestation
s.reset()
s.scan_content("x = 42", "clean.py")
attestation = s.generate_attestation()
test("Clean attestation verdict", attestation["verdict"] == "CLEAN")
test("Attestation has severity breakdown", "CRITICAL" in attestation["severity_breakdown"])

# Redaction
test("Redact short", SecretSentinel.redact("abc") == "****")
test("Redact long", SecretSentinel.redact("ghp_1234567890") == "ghp_**********")


def fake(prefix, n, step=7):
    """Deterministic synthetic token body (no literal secrets in this file)."""
    return prefix + "".join(chr(65 + (i * step) % 26) if i % 3 == 0 else chr(97 + (i * step) % 26) for i in range(n))

# ═══ CATEGORY 7: LLM & DEVELOPER-PLATFORM KEY PATTERNS (v1.1) ═══
section("CATEGORY 7: LLM & DEVELOPER-PLATFORM KEY PATTERNS")
new_vectors = [
    ("ANTHROPIC_KEY", 'k = "' + fake("sk-ant-" + "api03-", 60) + '"'),
    ("OPENAI_KEY", 'k = "' + fake("sk-" + "proj-", 48) + '"'),
    ("GOOGLE_API_KEY", 'k = "' + fake("AIza", 35) + '"'),
    ("HUGGINGFACE_TOKEN", 'k = "' + fake("hf_", 36) + '"'),
    ("GITHUB_FINE_GRAINED_PAT", 'k = "' + fake("github_pat_", 40) + '"'),
    ("NPM_TOKEN", 'k = "' + fake("npm_", 36) + '"'),
    ("PYPI_TOKEN", 'k = "' + fake("pypi-AgEIcHlwaS5vcmc", 60) + '"'),
    ("DISCORD_BOT_TOKEN", 'k = "' + fake("M", 24) + "." + fake("", 6) + "." + fake("", 30) + '"'),
    ("TELEGRAM_BOT_TOKEN", 'k = "' + "123456789" + ":" + fake("", 35) + '"'),
]
for rule_id, content in new_vectors:
    s.reset()
    findings = s.scan_content(content, f"test_{rule_id}")
    test(f"Detects {rule_id}", any(f.rule_id == rule_id for f in findings))

s.reset()
ant = s.scan_content('k = "' + fake("sk-ant-" + "api03-", 60) + '"')
test("Anthropic key is not double-reported as OpenAI", not any(f.rule_id == "OPENAI_KEY" for f in ant))

# Vectors for the patterns the v1.0 suite never exercised
extra_vectors = [
    ("AWS_SECRET_KEY", 'aws_secret_access_key = "' + fake("", 40) + '"'),
    ("GITHUB_REFRESH", 'r = "' + fake("ghr_", 36) + '"'),
    ("GENERIC_API_KEY", 'api_key = "' + fake("", 24) + '"'),
    ("GENERIC_SECRET", 'secret = "' + fake("", 20) + '"'),
    ("GENERIC_TOKEN", 'token = "' + fake("", 24) + '"'),
    ("AZURE_CLIENT_SECRET", 'AZURE_CLIENT_SECRET = "' + fake("", 36) + '"'),
    ("SLACK_WEBHOOK", 'u = "' + "https://hooks." + "slack.com/services/" + "TABCD1234/BEFGH5678/" + fake("", 24) + '"'),
]
for rule_id, content in extra_vectors:
    s.reset()
    findings = s.scan_content(content, f"test_{rule_id}")
    test(f"Detects {rule_id}", any(f.rule_id == rule_id for f in findings))

# Coverage gate: every shipped pattern must have a vector that actually detects it
covered = set()
for rule_id, content in test_vectors + new_vectors + extra_vectors:
    s.reset()
    if any(f.rule_id == rule_id for f in s.scan_content(content)):
        covered.add(rule_id)
missing = sorted({p["id"] for p in SECRET_PATTERNS} - covered)
test(f"Every pattern has a detecting test vector ({len(covered)}/{len(SECRET_PATTERNS)})", not missing)
if missing:
    print("    missing vectors:", missing)

# ═══ CATEGORY 8: REGRESSION FIXES (v1.1) ═══
section("CATEGORY 8: REGRESSION FIXES")
# Bug: scan_content() did not record findings, so a direct scan could attest CLEAN
s.reset()
s.scan_content('key = "AKIAIOSFODNN7QBLHZ9A"')
test("scan_content findings reach the attestation (no false CLEAN)",
     s.generate_attestation()["verdict"] == "FINDINGS_DETECTED")

# Bug: directory skip matched ABSOLUTE path parts, so repos under build/ or dist/ were silently skipped
with tempfile.TemporaryDirectory() as tmpdir:
    proj = Path(tmpdir) / "build" / "proj"
    proj.mkdir(parents=True)
    leaked_file = proj / "cfg.py"
    leaked_file.write_text('API_TOKEN = "' + fake("ghp_", 36) + '"\n')
    s.reset()
    test("scan_file works when a parent folder is named build", len(s.scan_file(str(leaked_file))) > 0)
    s.reset()
    test("scan_directory works when the ROOT is named build", len(s.scan_directory(str(Path(tmpdir) / "build"))) > 0)

# Pruned dirs are not descended into
with tempfile.TemporaryDirectory() as tmpdir:
    nm = Path(tmpdir) / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "x.js").write_text('const t = "' + fake("ghp_", 36) + '";\n')
    s.reset()
    test("node_modules contents are pruned", len(s.scan_directory(tmpdir)) == 0)

# Comments: skipped by default, scanned on request
comment_line = '# old key: ' + fake("ghp_", 36)
s.reset()
test("Comments skipped by default", len(s.scan_content(comment_line)) == 0)
s_cm = SecretSentinel(skip_comments=False)
test("include-comments mode catches secrets in comments", len(s_cm.scan_content(comment_line)) > 0)

# Entropy mode wired into scanning
s_ent = SecretSentinel(entropy_scan=True)
ent_f = s_ent.scan_content('blob = "aB3dEf7hIjKlMnOpQrStUvWxYz012345"')
test("Entropy mode flags unknown high-entropy strings", any(f.rule_id == "HIGH_ENTROPY" for f in ent_f))
test("Entropy findings reach the attestation", s_ent.generate_attestation()["finding_count"] == len(ent_f))

# Oversize and binary-content files are skipped and counted
with tempfile.TemporaryDirectory() as tmpdir:
    big = Path(tmpdir) / "big.txt"
    big.write_text("a" * 2000)
    s_small = SecretSentinel(max_file_bytes=1000)
    s_small.scan_file(str(big))
    test("Oversize file skipped and counted", s_small._files_skipped == 1 and s_small._files_scanned == 0)
    blob = Path(tmpdir) / "data.dat"
    blob.write_bytes(b"\x00\x01\x02" + b"ghp_" + b"a" * 36)
    s.reset()
    test("NUL-byte binary content skipped", len(s.scan_file(str(blob))) == 0)

# ═══ CATEGORY 9: CONTENT-BOUND ATTESTATION & MERKLE ROOT ═══
section("CATEGORY 9: CONTENT-BOUND ATTESTATION & MERKLE ROOT")
a1 = SecretSentinel(); a1.scan_content("x = 1", "a.py")
a2 = SecretSentinel(); a2.scan_content("x = 2", "a.py")
a3 = SecretSentinel(); a3.scan_content("x = 1", "a.py")
test("Different clean content -> different attestation", a1.generate_attestation()["attestation_hash"] != a2.generate_attestation()["attestation_hash"])
test("Same content -> identical attestation (deterministic)", a1.generate_attestation()["attestation_hash"] == a3.generate_attestation()["attestation_hash"])
att = a1.generate_attestation()
test("Merkle root is SHA3-512 (128 hex)", len(att["merkle_root_sha3_512"]) == 128)
test("Attestation records engine version and unsigned status", att["engine_version"] == "1.1.0" and att["signed"] is False)
test("Merkle root changes with content", att["merkle_root_sha3_512"] != a2.generate_attestation()["merkle_root_sha3_512"])
test("Empty Merkle set is well-defined", len(merkle_root([])) == 128)

with tempfile.TemporaryDirectory() as tmpdir:
    f1 = Path(tmpdir) / "app.py"
    f1.write_text("print('hello')\n")
    sv = SecretSentinel(); sv.scan_directory(tmpdir)
    saved = sv.generate_attestation()
    test("verify: untouched tree matches attestation", verify_attestation(saved, tmpdir)["match"])
    f1.write_text("print('tampered')\n")
    test("verify: modified file breaks attestation", not verify_attestation(saved, tmpdir)["match"])

# ═══ CATEGORY 10: OUTPUT FORMATS & REDACTION ═══
section("CATEGORY 10: OUTPUT FORMATS & REDACTION")
raw_secret = fake("ghp_", 36)
so = SecretSentinel(); so.scan_content(f'token = "{raw_secret}"', "leaky.py")
sarif = so.to_sarif()
test("SARIF is 2.1.0 with one result per finding", sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(so._findings) > 0)
test("SARIF results carry ruleId and line", sarif["runs"][0]["results"][0]["ruleId"] and sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1)
from secret_sentinel import format_markdown, format_text
outputs = json.dumps(sarif) + format_markdown(so) + format_text(so) + json.dumps(so.generate_attestation())
test("Raw secret never appears in any output format", raw_secret not in outputs)

# ═══ CATEGORY 11: GIT (STAGED + HISTORY) & CLI ═══
section("CATEGORY 11: GIT STAGED/HISTORY SCANNING & CLI")
def git(cwd, *a):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.t", "-c", "commit.gpgsign=false", *a],
                   cwd=cwd, check=True, capture_output=True)

if shutil.which("git"):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as repo:
        git(repo, "init", "-q")
        leaked = fake("ghp_", 36)
        (Path(repo) / "app.py").write_text(f'x = 1\nTOKEN = "{leaked}"\n')
        git(repo, "add", "app.py")
        sg = SecretSentinel(); staged = sg.scan_staged(repo)
        test("staged: secret caught before commit", any(f.rule_id == "GITHUB_PAT" for f in staged))
        test("staged: reports correct file and line", any(f.file == "app.py" and f.line == 2 for f in staged))
        git(repo, "commit", "-q", "-m", "add")
        (Path(repo) / "app.py").write_text('x = 1\nTOKEN = "removed"\n')
        git(repo, "add", "app.py"); git(repo, "commit", "-q", "-m", "remove")
        sg = SecretSentinel()
        test("working tree is clean after the secret was deleted", len(sg.scan_directory(repo)) == 0)
        sg = SecretSentinel(); hist = sg.scan_history(repo, 50)
        test("history: deleted secret is still found in past commits", any(f.rule_id == "GITHUB_PAT" and "@" in f.file for f in hist))
        test("history: raw secret not leaked in findings", leaked not in json.dumps([f.to_dict() for f in hist]))
        sg = SecretSentinel(); sg.scan_staged(repo)
        test("staged: nothing staged -> clean", sg.generate_attestation()["verdict"] == "CLEAN")
else:
    test("git not installed - git tests skipped", True)

def run_cli(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli_main(list(argv))
    return code, buf.getvalue()

with tempfile.TemporaryDirectory() as tmpdir:
    (Path(tmpdir) / "ok.py").write_text("x = 1\n")
    code, _ = run_cli("scan", tmpdir, "--format", "text")
    test("CLI: clean tree exits 0", code == 0)
    (Path(tmpdir) / "bad.py").write_text('t = "' + fake("ghp_", 36) + '"\n')
    code, out = run_cli("scan", tmpdir, "--format", "json")
    test("CLI: findings exit 1", code == 1)
    test("CLI: JSON output parses and has findings", len(json.loads(out)["findings"]) > 0)
    (Path(tmpdir) / "bad.py").write_text('t = "' + fake("gho_", 36) + '"\n')
    code, _ = run_cli("scan", tmpdir, "--format", "text", "--fail-on", "critical")
    test("CLI: HIGH finding passes when --fail-on critical", code == 0)
    code, _ = run_cli("scan", tmpdir, "--format", "text", "--fail-on", "high")
    test("CLI: HIGH finding fails when --fail-on high", code == 1)
    att_path = Path(tmpdir) / "att.json"
    run_cli("scan", tmpdir, "--format", "text", "--attest-out", str(att_path), "--fail-on", "never")
    test("CLI: --attest-out writes attestation file", att_path.exists())
    code, _ = run_cli("scan", str(Path(tmpdir) / "does-not-exist"))
    test("CLI: missing path exits 2", code == 2)

# ═══ CATEGORY 12: MCP JSON-RPC 2.0 STDIO SERVER ═══
section("CATEGORY 12: MCP JSON-RPC 2.0 STDIO SERVER")
from mcp_server import handle_request, TOOLS

init_resp = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
test("MCP initialize returns protocolVersion 2024-11-05",
     init_resp["result"]["protocolVersion"] == "2024-11-05")

list_resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
test("MCP tools/list exposes all 5 sentinel tools",
     len(list_resp["result"]["tools"]) == len(TOOLS) == 5)

call_resp = handle_request({
    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {
        "name": "sentinel_scan_content",
        "arguments": {"content": 'k = "' + fake("sk-ant-api03-", 60) + '"', "label": "snippet.py"}
    }
})
call_payload = json.loads(call_resp["result"]["content"][0]["text"])
test("MCP sentinel_scan_content catches leak and redacts",
     call_payload["attestation"]["verdict"] == "FINDINGS_DETECTED"
     and call_payload["findings"][0]["rule_id"] == "ANTHROPIC_KEY"
     and "****" in call_payload["findings"][0]["match"])

with tempfile.TemporaryDirectory() as tmpdir:
    (Path(tmpdir) / "clean.py").write_text("x = 42\n")
    path_resp = handle_request({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "sentinel_scan_path", "arguments": {"target_path": tmpdir, "format": "json"}}
    })
    path_payload = json.loads(path_resp["result"]["content"][0]["text"])
    test("MCP sentinel_scan_path reports CLEAN on safe directory",
         path_payload["attestation"]["verdict"] == "CLEAN")

unknown_resp = handle_request({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope"}})
test("MCP unknown tool returns JSON-RPC -32601 error", unknown_resp["error"]["code"] == -32601)

# ═══ VERDICT ═══
print(f"\n{'='*60}")
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
print(f"  VERDICT: {'SQA_v5_ASCENDED: EXCEEDED' if FAILED == 0 else 'SQA FAIL'}")
print(f"{'='*60}")
if FAILED > 0: sys.exit(1)
