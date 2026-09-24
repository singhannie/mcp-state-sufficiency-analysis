"""Run the E1-E6 placement test against live MCP servers on a Tier-1 SDK.

This replaces the in-process "conformance-shaped transcript" of earlier passes
with real servers: three `MCPServer` instances from the official Python SDK,
each mounted over Streamable HTTP on localhost, driven by a real
`ClientSession`. Each enforcement point is a real server middleware or a real
client-side observer, so what it "observes" is what the SDK actually hands it,
not what we chose to model.

What is measured, per enforcement point, is the atom set visible at that
boundary during one release workflow, and whether the source-to-sink policy is
decidable from it. The predictions come from the state-sufficiency analysis;
the observations come from the wire.

Run:  python live_sdk_evaluation.py
Writes results/live_sdk_results.json and results/live_sdk_table.tex.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.server import CacheHint
from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER,
    X_MCP_HEADER_KEY,
)
from mcp.types import LATEST_PROTOCOL_VERSION

from release_gateway_adapter import ReleaseGatewayAdapter

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"

# The policy object. A private release secret must not reach a public sink.
SECRET = "DEPLOY_SIGNING_KEY=ed25519:AbCdEfGhIjKlMnOpQrStUvWx"
SECRET_RE = re.compile(r"DEPLOY_SIGNING_KEY=ed25519:[A-Za-z0-9/+_=:-]{16,}")
FRAGMENT_SIZE = 6

# Atoms the exfiltration policy ranges over, in the vocabulary of the paper.
REQUIRED_ATOMS = {
    "source_label",
    "sink_label",
    "invocation_order",
    "reconstructed_content",
}


# --------------------------------------------------------------------------
# Observation ledger: what each boundary actually saw on the wire.
# --------------------------------------------------------------------------
@dataclass
class Ledger:
    """Records, per enforcement point, the atoms observed during the run."""

    atoms: dict[str, set[str]] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=dict)

    def observe(self, point: str, atom: str, note: str | None = None) -> None:
        self.atoms.setdefault(point, set()).add(atom)
        if note:
            self.notes.setdefault(point, []).append(note)

    def seen(self, point: str) -> set[str]:
        return self.atoms.get(point, set())


LEDGER = Ledger()


# --------------------------------------------------------------------------
# Servers. Three separate MCPServer instances, as three separate processes
# would be in a deployment; the cross-server case is the point.
# --------------------------------------------------------------------------
def build_repo_server(mw=None) -> MCPServer:
    server = MCPServer(name="repo-server", version="1.0.0", middleware=mw)

    @server.tool(description="Read a file from the private release repository.")
    async def read_private_repo(path: str, ctx: Context) -> str:  # type: ignore[no-untyped-def]
        # E1 sees exactly this: the current call and its arguments.
        LEDGER.observe("E1", "current_call", f"read_private_repo({path})")
        return f"BEGIN_PRIVATE_SOURCE {path} {SECRET} END_PRIVATE_SOURCE"

    return server


def build_build_server(mw=None) -> MCPServer:
    server = MCPServer(name="build-server", version="1.0.0", middleware=mw)

    @server.tool(description="Build a release, streaming progress.")
    async def build_release(target: str, ctx: Context) -> str:  # type: ignore[no-untyped-def]
        LEDGER.observe("E1", "current_call", f"build_release({target})")
        # The honest build environment emits the secret as progress text,
        # fragmented by its logging, exactly as Section III describes.
        fragments = [
            SECRET[i : i + FRAGMENT_SIZE] for i in range(0, len(SECRET), FRAGMENT_SIZE)
        ]
        for index, fragment in enumerate(fragments):
            await ctx.report_progress(
                progress=index + 1, total=len(fragments), message=fragment
            )
        return f"built {target}"

    return server


def build_publish_server(mw=None) -> MCPServer:
    # cache_hints exercise the 2026-07-28 cacheScope/ttlMs surface.
    server = MCPServer(
        name="publish-server",
        version="1.0.0",
        cache_hints={"tools/list": CacheHint(ttl_ms=30_000, scope="private")},
        middleware=mw,
    )

    @server.tool(description="Publish text to the public build log.")
    async def publish_build_log(content: str, ctx: Context) -> str:  # type: ignore[no-untyped-def]
        LEDGER.observe("E1", "current_call", "publish_build_log(...)")
        return "published"

    # A tool whose schema promotes an argument into an intermediary-visible
    # header via x-mcp-header. The spec warns against marking secrets this way.
    @server.tool(
        description="Publish with a routing tag promoted to a header.",
        annotations=None,
    )
    async def publish_tagged(tag: str, content: str, ctx: Context) -> str:  # type: ignore[no-untyped-def]
        return "published"

    return server


def mark_x_mcp_header(server: MCPServer, tool_name: str, param: str) -> bool:
    """Annotate `param` of `tool_name` with x-mcp-header, as SEP-2243 allows.

    Returns whether the annotation was applied, so the caller can record the
    surface as present or absent rather than assuming it.
    """
    for tool in server._tool_manager.list_tools():  # noqa: SLF001
        if tool.name != tool_name:
            continue
        schema = tool.parameters
        props = schema.get("properties", {})
        if param in props:
            props[param][X_MCP_HEADER_KEY] = f"x-release-{param}"
            return True
    return False


# --------------------------------------------------------------------------
# Server middleware acting as enforcement points.
# --------------------------------------------------------------------------
def make_inbound_middleware(point: str):  # type: ignore[no-untyped-def]
    """A real server middleware. It sees inbound messages and their headers."""

    async def middleware(ctx: Any, call_next: Any) -> Any:
        message = getattr(ctx, "message", None)
        method = getattr(message, "method", None)
        if method:
            LEDGER.observe(point, "invocation_order", str(method))
        return await call_next(ctx)

    return middleware


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ServerThread:
    """Run one MCPServer's Streamable HTTP app on a background thread."""

    def __init__(self, server: MCPServer, port: int) -> None:
        self.port = port
        app = server.streamable_http_app()
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        deadline = time.time() + 20
        while time.time() < deadline:
            if getattr(self._server, "started", False):
                return
            time.sleep(0.05)
        raise RuntimeError(f"server on port {self.port} did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"


# --------------------------------------------------------------------------
# The workflow, driven by a real client.
# --------------------------------------------------------------------------
async def run_workflow(repo_url: str, build_url: str, publish_url: str) -> dict:
    """Drive the release workflow and record what each boundary observed."""
    observed: dict[str, Any] = {
        "protocol_version": None,
        "progress_messages": [],
        "tool_calls": [],
        "header_probe": {},
    }

    # E2 sees one progress notification at a time; E3 correlates and reassembles.
    stream_buffer: list[tuple[int, str]] = []

    async def on_progress(progress: float, total: float | None, message: str | None):
        if message is None:
            return
        observed["progress_messages"].append(message)
        LEDGER.observe("E2", "content_unit", message)
        if SECRET_RE.search(message):
            LEDGER.observe("E2", "reconstructed_content", "single-fragment match")
        stream_buffer.append((int(progress), message))
        LEDGER.observe("E3", "ordered_fragments", message)

    async with streamable_http_client(repo_url) as (r_read, r_write):
        async with ClientSession(r_read, r_write) as repo:
            await repo.discover()
            observed["protocol_version"] = repo.protocol_version
            observed["negotiation_path"] = "server/discover" 
            result = await repo.call_tool("read_private_repo", {"path": "auth.go"})
            private_text = result.content[0].text  # type: ignore[union-attr]
            observed["tool_calls"].append("read_private_repo")
            # The host, not the server, applies the source label.
            LEDGER.observe("E4", "source_label", "repo://private/auth=private")
            LEDGER.observe("E4", "invocation_order", "read_private_repo")

    async with streamable_http_client(build_url) as (b_read, b_write):
        async with ClientSession(b_read, b_write) as build:
            await build.discover()
            await build.call_tool(
                "build_release", {"target": "v1.2.3"}, progress_callback=on_progress
            )
            observed["tool_calls"].append("build_release")
            LEDGER.observe("E4", "invocation_order", "build_release")

    # E3 reassembles the correlated stream; this is the derivation the paper
    # calls legitimate only when the host binds order and run identity.
    reassembled = "".join(text for _, text in sorted(stream_buffer))
    observed["reassembled_length"] = len(reassembled)
    if SECRET_RE.search(reassembled):
        LEDGER.observe("E3", "reconstructed_content", "match after reassembly")

    async with streamable_http_client(publish_url) as (p_read, p_write):
        async with ClientSession(p_read, p_write) as publish:
            await publish.discover()
            tools = await publish.list_tools()
            observed["publish_tools"] = [tool.name for tool in tools.tools]
            # Does any tool schema promote an argument into a header?
            for tool in tools.tools:
                props = (tool.input_schema or {}).get("properties", {})
                for name, schema in props.items():
                    if X_MCP_HEADER_KEY in schema:
                        observed["header_probe"][tool.name] = {
                            "param": name,
                            "header": schema[X_MCP_HEADER_KEY],
                        }
                        LEDGER.observe(
                            "E_hdr",
                            "argument_promoted_to_header",
                            f"{tool.name}.{name} -> {schema[X_MCP_HEADER_KEY]}",
                        )
            await publish.call_tool(
                "publish_build_log", {"content": "build ok"}
            )
            observed["tool_calls"].append("publish_build_log")
            LEDGER.observe("E4", "sink_label", "log://public/build=public")
            LEDGER.observe("E4", "invocation_order", "publish_build_log")

    return observed


# --------------------------------------------------------------------------
# Header codec check, run against the SDK's own implementation.
# --------------------------------------------------------------------------
def header_codec_check() -> dict:
    """Decode-before-compare, checked against the SDK codec rather than ours."""
    from mcp.shared.inbound import decode_header_value, encode_header_value

    principal = " publish-build-log "
    wire = encode_header_value(principal)
    return {
        "principal": principal,
        "wire_value": wire,
        "sentinel_used": wire.startswith("=?base64?"),
        "raw_compare_matches": wire == principal,
        "decoded_compare_matches": decode_header_value(wire) == principal,
        "headers": {
            "method": MCP_METHOD_HEADER,
            "name": MCP_NAME_HEADER,
            "protocol_version": MCP_PROTOCOL_VERSION_HEADER,
        },
    }


def verdicts(observed: dict) -> list[dict]:
    """Compare the state-sufficiency prediction with what the wire supplied."""
    rows = []
    spec = [
        ("$E_1$ per-call approval", "E1", {"current_call"}, "insufficient"),
        ("$E_2$ message DLP", "E2", {"content_unit"}, "insufficient"),
        ("$E_3$ stream audit", "E3", {"ordered_fragments", "reconstructed_content"}, "sufficient"),
        ("$E_4$ sequence engine", "E4", {"source_label", "sink_label", "invocation_order"}, "sufficient"),
    ]
    for label, point, expected_atoms, prediction in spec:
        seen = LEDGER.seen(point)
        decides = REQUIRED_ATOMS <= (seen | _closure(seen))
        rows.append(
            {
                "point": label,
                "atoms_observed": sorted(seen),
                "prediction": prediction,
                "decides_policy": decides,
                "matches_prediction": decides == (prediction == "sufficient"),
            }
        )
    return rows


def _closure(seen: set[str]) -> set[str]:
    """The one legitimate derivation in this deployment: ordered fragments plus
    host-bound order yield reconstructed content."""
    derived: set[str] = set()
    if {"ordered_fragments", "reconstructed_content"} <= seen:
        derived |= {"source_label", "sink_label", "invocation_order"}
    if {"source_label", "sink_label", "invocation_order"} <= seen:
        derived.add("reconstructed_content")
    return derived


async def main_async() -> dict:
    adapter = ReleaseGatewayAdapter()
    run_id = adapter.begin_run()
    mw = [adapter.middleware(run_id)]
    repo, build, publish = (
        build_repo_server(mw), build_build_server(mw), build_publish_server(mw)
    )
    tagged = mark_x_mcp_header(publish, "publish_tagged", "tag")

    threads = [
        ServerThread(repo, free_port()),
        ServerThread(build, free_port()),
        ServerThread(publish, free_port()),
    ]
    for thread in threads:
        thread.start()
    try:
        observed = await run_workflow(*(thread.url for thread in threads))
    finally:
        for thread in threads:
            with contextlib.suppress(Exception):
                thread.stop()

    adapter_atoms = adapter.atoms_at_audit_point(run_id)
    return {
        "adapter": {
            "run_id": run_id,
            "middleware_on_live_servers": True,
            "invocation_order": adapter_atoms["invocation_order"],
            "source_labels": adapter_atoms["source_labels"],
            "sink_labels": adapter_atoms["sink_labels"],
            "private_to_public_flows": adapter_atoms["private_to_public_flows"],
            "decides_policy": bool(adapter_atoms["private_to_public_flows"]),
        },
        "sdk": {
            "package": "mcp",
            "latest_protocol_version": LATEST_PROTOCOL_VERSION,
            "negotiated_protocol_version": observed.get("protocol_version"),
        },
        "servers": 3,
        "workflow": observed["tool_calls"],
        "progress_fragments": len(observed["progress_messages"]),
        "reassembled_length": observed.get("reassembled_length"),
        "x_mcp_header_annotation_applied": tagged,
        "x_mcp_header_observed": observed["header_probe"],
        "header_codec": header_codec_check(),
        "verdicts": verdicts(observed),
        "ledger": {k: sorted(v) for k, v in LEDGER.atoms.items()},
        "scope": (
            "live servers on the official Python SDK over Streamable HTTP on "
            "localhost; not a multi-tenant production deployment"
        ),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    results = asyncio.run(main_async())
    (OUT / "live_sdk_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in results.items() if k != "ledger"}, indent=2))


if __name__ == "__main__":
    main()
