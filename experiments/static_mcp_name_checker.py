#!/usr/bin/env python3
"""Static checker for Mcp-Name sentinel-handling evidence.

The checker verifies the local source evidence used by Section VIII. It is not
a general vulnerability scanner; it records whether the expected files exist
and whether the inspected decode/compare patterns are present in the cloned
repositories.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / "public_gateway_sources"
OUT = ROOT / "results"


REPOS = [
    {
        "name": "hoophq/mcpproxy",
        "path": "hoophq_mcpproxy",
        "role": "gateway with body/header comparison gate",
        "revision": "9b667828530dc0a4ce6c5c070660c75cf8053ac3",
        "commit_date": "2026-08-06T11:21:29-03:00",
        "checks": [
            ("mcp/revision.go", r"func DecodeHeaderName"),
            ("gateway/revision.go", r"got, ok := mcp\.DecodeHeaderName\(raw\)"),
            ("gateway/revision.go", r"if got != want"),
        ],
    },
    {
        "name": "kerlenton/mcpsnoop",
        "path": "kerlenton_mcpsnoop",
        "role": "observability shim with mismatch classification",
        "revision": "b9e90e7732eed233f20b99738d17ea8c053830a3",
        "commit_date": "2026-08-26T23:17:27+03:00",
        "checks": [
            ("internal/proxy/header.go", r"func DecodeHeaderValue"),
            ("internal/store/store.go", r"decodeHeaderValue\(ev\.mcpName\)"),
            ("internal/store/store.go", r"routing header Mcp-Name"),
        ],
    },
    {
        "name": "tfohlmeister/convex-mcp-gateway",
        "path": "tfohlmeister_convex_mcp_gateway",
        "role": "gateway with body/header comparison gate",
        "revision": "13abade1125700b9d451bb1dec79e38c93b0b72c",
        "commit_date": "2026-09-07T13:35:06+02:00",
        "checks": [
            ("src/client/mcp-handler.ts", r"function decodeMcpHeaderValue"),
            ("src/client/mcp-handler.ts", r"const headerName = decodeMcpHeaderValue"),
            ("src/client/mcp-handler.ts", r"if \(!statelessNameMatches\(message, request\)\)"),
        ],
    },
    {
        "name": "PrefectHQ/fastmcp",
        "path": "PrefectHQ_fastmcp",
        "role": "framework extension with task-route validation",
        "revision": "e3fb4af36892e6477399df2597f0dd5abd469799",
        "commit_date": "2026-09-04T21:59:50-05:00",
        "checks": [
            ("fastmcp_tasks/fastmcp_tasks/extension.py", r"from mcp\.shared\.inbound import MCP_NAME_HEADER, decode_header_value"),
            ("fastmcp_tasks/fastmcp_tasks/extension.py", r"decode_header_value\(header\) != task_id"),
        ],
    },
    {
        "name": "punkpeye/mcp-proxy",
        "path": "punkpeye_mcp_proxy",
        "role": "proxy; no independent comparison gate found",
        "revision": "606b82854861719253f4f2712776948b19ddf0f0",
        "commit_date": "2026-09-06T12:51:36-06:00",
        "checks": [
            ("src/startHTTPServer.ts", r'"Mcp-Name"'),
            ("README.md", r"Mcp-Method.*Mcp-Name"),
        ],
        "negative_patterns": [
            r"headers\.(get|has)\([\"']mcp-name[\"']\).*==",
            r"req\.headers\[[\"']mcp-name[\"']\].*==",
            r"HeaderMismatch",
        ],
    },
]


def read_revision(repo_path: Path) -> str | None:
    head = repo_path / ".git" / "HEAD"
    if not head.exists():
        return None
    value = head.read_text(encoding="utf-8").strip()
    if value.startswith("ref: "):
        ref = repo_path / ".git" / value[5:]
        if ref.exists():
            return ref.read_text(encoding="utf-8").strip()
    return value


def grep_tree(repo_path: Path, pattern: str) -> list[str]:
    compiled = re.compile(pattern, re.I | re.M)
    hits: list[str] = []
    for path in repo_path.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if compiled.search(text):
            hits.append(str(path.relative_to(repo_path)).replace("\\", "/"))
    return sorted(hits)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for repo in REPOS:
        repo_path = SOURCES / repo["path"]
        checks = []
        for rel, pattern in repo["checks"]:
            target = repo_path / rel
            text = target.read_text(encoding="utf-8") if target.exists() else ""
            checks.append(
                {
                    "file": rel,
                    "pattern": pattern,
                    "matched": bool(re.search(pattern, text, re.M)),
                }
            )
        negative_hits = {
            pattern: grep_tree(repo_path, pattern)
            for pattern in repo.get("negative_patterns", [])
        }
        rows.append(
            {
                "repository": repo["name"],
                "role": repo["role"],
                "expected_revision": repo["revision"],
                "observed_revision": read_revision(repo_path),
                "commit_date": repo["commit_date"],
                "checks": checks,
                "negative_pattern_hits": negative_hits,
                "all_expected_patterns_matched": all(check["matched"] for check in checks),
            }
        )

    report = {
        "scope": "static local-source evidence check; not active testing",
        "search_patterns": ["Mcp-Name", "mcp-name", "HeaderMismatch", "base64", "decode"],
        "rows": rows,
        "summary": {
            "repositories": len(rows),
            "expected_pattern_checks": sum(len(row["checks"]) for row in rows),
            "matched_expected_pattern_checks": sum(
                sum(check["matched"] for check in row["checks"]) for row in rows
            ),
            "revision_matches": sum(
                row["expected_revision"] == row["observed_revision"] for row in rows
            ),
        },
    }
    (OUT / "static_checker_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
