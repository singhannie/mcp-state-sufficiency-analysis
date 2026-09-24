"""Which implementations actually support the 2026-07-28 revision?

The evaluation runs against servers we wrote, on one SDK. The obvious question
is why not a third-party server, or a second SDK. This records the answer as a
check rather than an assertion: at the time of writing, the official Python
SDK on its 2.x line is the only implementation surveyed that reaches
2026-07-28. The reference servers pin `mcp<2`, and the TypeScript SDK's latest
release declares protocol versions no later than 2025-11-25.

Offline by default: the recorded evidence is replayed from
results/ecosystem_survey.json. Pass --refresh to re-query the package indexes
and rebuild it, which needs network access.

Run:  python ecosystem_revision_survey.py [--refresh]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"
TARGET = "2026-07-28"

VERSION_RE = re.compile(rb"20\d\d-\d\d-\d\d")


def python_sdk_facts() -> dict:
    """What the installed Python SDK declares."""
    import importlib.metadata as md

    from mcp.types import LATEST_PROTOCOL_VERSION

    return {
        "implementation": "Python SDK (modelcontextprotocol/python-sdk)",
        "version": md.version("mcp"),
        "latest_protocol_version": LATEST_PROTOCOL_VERSION,
        "supports_target": LATEST_PROTOCOL_VERSION == TARGET,
        "evidence": "mcp.types.LATEST_PROTOCOL_VERSION in the installed package",
    }


def reference_server_facts(tmp: Path) -> list[dict]:
    """The official reference servers' SDK pin."""
    facts = []
    for package in ("mcp-server-fetch", "mcp-server-git", "mcp-server-time"):
        dest = tmp / package
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [sys.executable, "-m", "pip", "download", package,
             "-d", str(dest), "--no-deps", "-q"],
            check=False, capture_output=True,
        )
        pin, version = None, None
        for wheel in dest.glob("*.whl"):
            with zipfile.ZipFile(wheel) as archive:
                for name in archive.namelist():
                    if name.endswith("METADATA"):
                        meta = archive.read(name).decode("utf-8", "replace")
                        for line in meta.splitlines():
                            if line.startswith("Version:"):
                                version = line.split(":", 1)[1].strip()
                            if line.startswith("Requires-Dist: mcp"):
                                pin = line.split(":", 1)[1].strip()
        facts.append(
            {
                "implementation": package,
                "version": version,
                "sdk_requirement": pin,
                "supports_target": False if pin and "<2" in pin else None,
                "evidence": "Requires-Dist in the published wheel METADATA",
            }
        )
    return facts


def typescript_sdk_facts(tmp: Path) -> dict:
    """The TypeScript SDK's declared protocol versions."""
    dest = tmp / "ts"
    dest.mkdir(parents=True, exist_ok=True)
    version = subprocess.run(
        ["npm", "view", "@modelcontextprotocol/sdk", "version"],
        capture_output=True, text=True, shell=True, cwd=dest,
    ).stdout.strip()
    subprocess.run(
        ["npm", "pack", f"@modelcontextprotocol/sdk@{version}"],
        capture_output=True, shell=True, cwd=dest,
    )
    declared: set[str] = set()
    for tarball in dest.glob("*.tgz"):
        subprocess.run(["tar", "xzf", tarball.name], cwd=dest,
                       capture_output=True, shell=True)
    for source in (dest / "package" / "dist").rglob("*.js"):
        declared.update(m.decode() for m in VERSION_RE.findall(source.read_bytes()))
    return {
        "implementation": "TypeScript SDK (@modelcontextprotocol/sdk)",
        "version": version,
        "declared_protocol_versions": sorted(declared),
        "latest_protocol_version": max(declared) if declared else None,
        "supports_target": TARGET in declared,
        "evidence": "protocol version strings in the published dist bundle",
    }


def summarize(rows: list[dict]) -> dict:
    supporting = [r for r in rows if r.get("supports_target") is True]
    return {
        "target_revision": TARGET,
        "implementations_surveyed": len(rows),
        "implementations_supporting_target": len(supporting),
        "supporting": [r["implementation"] for r in supporting],
        "scope": (
            "a survey of published packages, not of every MCP implementation "
            "in existence; it records why the live evaluation runs on one SDK "
            "rather than claiming none other could exist"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true",
                        help="re-query package indexes (needs network)")
    args = parser.parse_args()
    path = OUT / "ecosystem_survey.json"

    if not args.refresh:
        if not path.exists():
            raise SystemExit("no recorded survey; re-run with --refresh")
        print(json.dumps(json.load(path.open())["summary"], indent=2))
        return

    tmp = OUT / "_survey_tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    rows = [python_sdk_facts()]
    rows.extend(reference_server_facts(tmp))
    rows.append(typescript_sdk_facts(tmp))

    results = {"rows": rows, "summary": summarize(rows)}
    OUT.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()
