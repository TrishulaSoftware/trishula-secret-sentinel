#!/usr/bin/env python3
"""
Trishula Secret Sentinel v1.1 - Model Context Protocol (MCP) JSON-RPC 2.0 Server
Provides zero-dependency secret scanning, git staged/history auditing, and
content-bound cryptographic attestation over STDIO.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict

from secret_sentinel import (
    ENGINE_VERSION,
    SecretSentinel,
    format_markdown,
    scan_target,
    verify_attestation,
)

SERVER_NAME = "trishula-secret-sentinel"
SERVER_VERSION = ENGINE_VERSION

TOOLS = [
    {
        "name": "sentinel_scan_path",
        "description": "Recursively scan a file or directory for 34 secret patterns (AWS, GitHub, Anthropic, OpenAI, Google, private keys, DB URLs) with optional Shannon entropy analysis and redacted Markdown/JSON/SARIF output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Path to file or directory to scan."
                },
                "entropy": {
                    "type": "boolean",
                    "description": "Enable Shannon entropy flagging for unknown secrets.",
                    "default": False
                },
                "include_comments": {
                    "type": "boolean",
                    "description": "Scan comment lines in addition to code.",
                    "default": False
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json", "sarif"],
                    "default": "markdown"
                }
            },
            "required": ["target_path"]
        }
    },
    {
        "name": "sentinel_scan_content",
        "description": "Audit a raw text snippet, config block, or prompt payload for leaked credentials before committing, logging, or sharing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Text or code snippet to inspect."
                },
                "label": {
                    "type": "string",
                    "description": "Display label for findings.",
                    "default": "<stdin>"
                },
                "entropy": {
                    "type": "boolean",
                    "default": False
                }
            },
            "required": ["content"]
        }
    },
    {
        "name": "sentinel_scan_staged",
        "description": "Inspect staged git diff lines (git diff --cached) before committing to catch leaked keys before they enter repository history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "default": "."
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json", "sarif"],
                    "default": "markdown"
                }
            }
        }
    },
    {
        "name": "sentinel_scan_history",
        "description": "Audit recent git commit history for secrets added in past commits, including keys that were later deleted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "default": "."
                },
                "max_commits": {
                    "type": "integer",
                    "default": 200
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json", "sarif"],
                    "default": "markdown"
                }
            }
        }
    },
    {
        "name": "sentinel_verify_attestation",
        "description": "Re-scan a target path and verify its SHA-256 and SHA3-512 Merkle attestation digests against a previously saved attestation object.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "attestation": {
                    "type": "object",
                    "description": "Previously generated attestation dictionary."
                },
                "target_path": {
                    "type": "string",
                    "default": "."
                }
            },
            "required": ["attestation"]
        }
    }
]


def _render_output(s: SecretSentinel, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(
            {
                "attestation": s.generate_attestation(),
                "findings": [f.to_dict() for f in s._findings],
            },
            indent=2,
        )
    if fmt == "sarif":
        return json.dumps(s.to_sarif(), indent=2)
    return format_markdown(s)


def handle_request(req: Dict[str, Any]) -> Dict[str, Any] | None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method != "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not implemented"},
        }

    params = req.get("params", {}) or {}
    tool_name = params.get("name")
    args = params.get("arguments", {}) or {}

    try:
        if tool_name == "sentinel_scan_path":
            target = str(args.get("target_path", "."))
            if not Path(target).exists():
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Path not found: {target}"}],
                    },
                }
            s = SecretSentinel(
                entropy_scan=bool(args.get("entropy", False)),
                skip_comments=not bool(args.get("include_comments", False)),
            )
            scan_target(s, target)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": _render_output(s, str(args.get("format", "markdown")))}]},
            }

        if tool_name == "sentinel_scan_content":
            s = SecretSentinel(entropy_scan=bool(args.get("entropy", False)))
            s.scan_content(str(args.get("content", "")), str(args.get("label", "<stdin>")))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": _render_output(s, "json")}]},
            }

        if tool_name == "sentinel_scan_staged":
            s = SecretSentinel()
            s.scan_staged(str(args.get("repo_path", ".")))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": _render_output(s, str(args.get("format", "markdown")))}]},
            }

        if tool_name == "sentinel_scan_history":
            s = SecretSentinel()
            s.scan_history(str(args.get("repo_path", ".")), int(args.get("max_commits", 200)))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": _render_output(s, str(args.get("format", "markdown")))}]},
            }

        if tool_name == "sentinel_verify_attestation":
            res = verify_attestation(args.get("attestation", {}), str(args.get("target_path", ".")))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]},
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"},
        }
    except Exception as exc:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "isError": True,
                "content": [{"type": "text", "text": f"Error: {exc}"}],
            },
        }


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
