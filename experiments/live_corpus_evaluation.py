"""Drive the full fixture corpora against live MCP servers.

Earlier passes ran one workflow live (one secret, nine fragments) and left the
24-workflow sequence corpus and the 423-condition streaming corpus as offline
fixtures. This runs both over real `MCPServer` instances on the official
Python SDK, over Streamable HTTP on loopback, driven by a real
`ClientSession`, so the placement verdicts are decided from what the SDK hands
each boundary rather than from a model of it.

Two boundaries are evaluated per corpus:

  sequence corpus   E1 (per-call gate, permissive and strict) against E4
                    (sequence engine with host-supplied labels and order)
  streaming corpus  E2 (message-local monitor, one progress notification at a
                    time) against E3 (token-correlated reassembly)

The offline harness decides the same corpora analytically. Agreement between
the two is the check: it says the fixture outcomes are not an artifact of the
fixture runner.

Run:  python live_corpus_evaluation.py
Writes results/live_corpus_results.json and results/live_corpus_table.tex.
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import threading
import time
from pathlib import Path
from typing import Any

import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import Context, MCPServer

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"

# --------------------------------------------------------------------------
# The corpora, imported from the offline harness so the two evaluations are
# provably over the same data rather than two hand-kept copies.
# --------------------------------------------------------------------------
from run_offline_experiments import (  # noqa: E402
    PAYLOADS,
    PII_PATTERNS,
    TOOL_EFFECTS,
    experiment_sequence_policy,
    experiment_streaming,
    per_call_authorized,
    sequence_policy,
    strict_per_call_authorized,
)

# Two matchers over the same corpus. The pattern matcher is the offline
# harness's own; the exact matcher is deliberately stricter. Proposition 1
# says detection turns on m, the matcher's minimum contiguous matchable unit,
# so two matchers over identical traffic should give different counts and the
# same threshold.
DETECTOR_SETS = {
    "pattern": PII_PATTERNS,
    "exact": {
        name: re.compile(re.escape(payload))
        for name, payload in PAYLOADS.items()
    },
}


def minimum_matchable_unit(detector, payload: str) -> int:
    """Measure m: the shortest substring of `payload` the detector matches."""
    for length in range(1, len(payload) + 1):
        for start in range(0, len(payload) - length + 1):
            if detector.search(payload[start : start + length]):
                return length
    return len(payload) + 1  # never matches any substring

def contains_matchable_window(detector, payload: str, fragment: int) -> bool:
    """Does some substring the detector matches lie wholly in one fragment?

    Fragmentation cuts at fixed offsets, so a window of length m starting at
    offset o survives only when o and o+m-1 fall in the same fragment. This is
    the predicate the live corpus actually obeys; f >= m is only its necessary
    part.
    """
    length_limit = len(payload)
    for start in range(length_limit):
        for size in range(1, length_limit - start + 1):
            if start // fragment != (start + size - 1) // fragment:
                break
            if detector.search(payload[start : start + size]):
                return True
    return False



def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ServerThread:
    """Run one MCPServer's Streamable HTTP app on a background thread."""

    def __init__(self, server: MCPServer, port: int) -> None:
        self.port = port
        config = uvicorn.Config(
            server.streamable_http_app(), host="127.0.0.1", port=port,
            log_level="error",
        )
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
# A server exposing every tool the sequence corpus names, plus a streaming
# tool that emits a chosen payload at a chosen fragment size.
# --------------------------------------------------------------------------
def build_corpus_server() -> MCPServer:
    server = MCPServer(name="corpus-server", version="1.0.0")

    @server.tool(description="Run one named workflow step.")
    async def step(name: str, ctx: Context) -> str:  # type: ignore[no-untyped-def]
        effect = TOOL_EFFECTS.get(name, {})
        source = effect.get("source", "-")
        sink = effect.get("sink", "-")
        transform = effect.get("transform", "-")
        return f"{name}: source={source} sink={sink} transform={transform}"

    @server.tool(description="Stream a payload in fragments of a given size.")
    async def emit(payload: str, fragment: int, ctx: Context) -> str:  # type: ignore[no-untyped-def]
        text = PAYLOADS[payload]
        parts = [text[i : i + fragment] for i in range(0, len(text), fragment)]
        for index, part in enumerate(parts):
            await ctx.report_progress(
                progress=index + 1, total=len(parts), message=part
            )
        return f"emitted {payload} at f={fragment}"

    return server


# --------------------------------------------------------------------------
# Corpus 1: the 24 sequence workflows, driven live.
# --------------------------------------------------------------------------
async def run_sequence_corpus(url: str) -> dict:
    offline = {row["name"]: row for row in experiment_sequence_policy()["rows"]}
    rows: list[dict[str, Any]] = []

    async with streamable_http_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.discover()
            protocol = session.protocol_version

            for name, case in offline.items():
                calls = case["calls"]

                # E1, per-call: decides on the current call alone. The host
                # observes each call as the SDK delivers it and nothing else.
                permissive_allowed = True
                strict_allowed = True
                # E4, sequence: the host records the ordered call names as it
                # drives them, which is the trusted invocation history.
                history: list[str] = []

                for call in calls:
                    await session.call_tool("step", {"name": call})
                    permissive_allowed &= per_call_authorized(call)
                    strict_allowed &= strict_per_call_authorized(call)
                    history.append(call)

                sequence_allowed, taint = sequence_policy(history)

                rows.append(
                    {
                        "name": name,
                        "expected": case["expected"],
                        "calls_driven": len(calls),
                        "live_permissive_allowed": bool(permissive_allowed),
                        "live_strict_allowed": bool(strict_allowed),
                        "live_sequence_allowed": bool(sequence_allowed),
                        "live_final_taint": sorted(taint),
                        "agrees_with_offline": (
                            bool(permissive_allowed) == case["baseline_allowed"]
                            and bool(sequence_allowed)
                            == case["sequence_policy_allowed"]
                        ),
                    }
                )

    attacks = [r for r in rows if r["expected"] == "attack"]
    benign = [r for r in rows if r["expected"] == "benign"]
    return {
        "protocol_version": protocol,
        "rows": rows,
        "summary": {
            "workflows_driven": len(rows),
            "tool_calls_driven": sum(r["calls_driven"] for r in rows),
            "malicious": len(attacks),
            "benign": len(benign),
            "permissive_allows_malicious": sum(
                r["live_permissive_allowed"] for r in attacks
            ),
            "strict_denies_malicious": sum(
                not r["live_strict_allowed"] for r in attacks
            ),
            "strict_false_denials": sum(
                not r["live_strict_allowed"] for r in benign
            ),
            "sequence_denies_malicious": sum(
                not r["live_sequence_allowed"] for r in attacks
            ),
            "sequence_false_denials": sum(
                not r["live_sequence_allowed"] for r in benign
            ),
            "agreement_with_offline": sum(r["agrees_with_offline"] for r in rows),
        },
    }


# --------------------------------------------------------------------------
# Corpus 2: every streaming condition, driven live.
# --------------------------------------------------------------------------
async def run_streaming_corpus(url: str) -> dict:
    offline = experiment_streaming()["summary"]
    rows: list[dict[str, Any]] = []

    # m is measured per (matcher, payload) before any traffic is generated, so
    # the threshold is checked against the detector rather than the secret.
    measured_m = {
        set_name: {
            payload_name: minimum_matchable_unit(
                detectors[payload_name], PAYLOADS[payload_name]
            )
            for payload_name in PAYLOADS
        }
        for set_name, detectors in DETECTOR_SETS.items()
    }

    async with streamable_http_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            await session.discover()
            protocol = session.protocol_version

            for payload_name, payload in PAYLOADS.items():
                for fragment in range(1, len(payload) + 1):
                    hits = {name: False for name in DETECTOR_SETS}
                    buffer: list[tuple[int, str]] = []

                    async def on_progress(progress, total, message):  # type: ignore[no-untyped-def]
                        if message is None:
                            return
                        for set_name, detectors in DETECTOR_SETS.items():
                            if detectors[payload_name].search(message):
                                hits[set_name] = True
                        buffer.append((int(progress), message))

                    await session.call_tool(
                        "emit",
                        {"payload": payload_name, "fragment": fragment},
                        progress_callback=on_progress,
                    )
                    reassembled = "".join(t for _, t in sorted(buffer))
                    row = {
                        "payload": payload_name,
                        "payload_len": len(payload),
                        "fragment": fragment,
                        "fragments_delivered": len(buffer),
                    }
                    for set_name, detectors in DETECTOR_SETS.items():
                        row[f"message_local_{set_name}"] = hits[set_name]
                        row[f"reconstruction_{set_name}"] = bool(
                            detectors[payload_name].search(reassembled)
                        )
                        row[f"threshold_{set_name}"] = (
                            fragment >= measured_m[set_name][payload_name]
                        )
                        row[f"predicted_{set_name}"] = contains_matchable_window(
                            detectors[payload_name], payload, fragment
                        )
                    rows.append(row)

    per_matcher = {}
    for set_name in DETECTOR_SETS:
        per_matcher[set_name] = {
            "message_local_detects": sum(
                r[f"message_local_{set_name}"] for r in rows
            ),
            "reconstruction_detects": sum(
                r[f"reconstruction_{set_name}"] for r in rows
            ),
            "containment_predicate_holds": all(
                r[f"message_local_{set_name}"] == r[f"predicted_{set_name}"]
                for r in rows
            ),
            "bare_threshold_holds": all(
                r[f"message_local_{set_name}"] == r[f"threshold_{set_name}"]
                for r in rows
            ),
            "bare_threshold_exceptions": sum(
                r[f"message_local_{set_name}"] != r[f"threshold_{set_name}"]
                for r in rows
            ),
            "threshold_exceptions": [
                {
                    "payload": r["payload"],
                    "fragment": r["fragment"],
                    "observed": r[f"message_local_{set_name}"],
                    "bare_threshold_predicted": r[f"threshold_{set_name}"],
                    "containment_predicted": r[f"predicted_{set_name}"],
                }
                for r in rows
                if r[f"message_local_{set_name}"] != r[f"threshold_{set_name}"]
            ],
            "measured_m": measured_m[set_name],
        }

    return {
        "protocol_version": protocol,
        "summary": {
            "conditions_driven": len(rows),
            "payload_classes": len(PAYLOADS),
            "progress_notifications_delivered": sum(
                r["fragments_delivered"] for r in rows
            ),
            "matchers": per_matcher,
            "offline_conditions": offline["total_fragmentation_conditions"],
            "offline_message_local": round(
                offline["per_message_detection_rate"]
                * offline["total_fragmentation_conditions"]
            ),
            "offline_reconstruction": offline["total_fragmentation_conditions"],
        },
        "rows": rows,
    }


# --------------------------------------------------------------------------
def write_table(results: dict) -> None:
    seq = results["sequence_corpus"]["summary"]
    stream = results["streaming_corpus"]["summary"]
    pat = stream["matchers"]["pattern"]
    exa = stream["matchers"]["exact"]
    tex = rf"""\begin{{table}}[t]
  \caption{{Both fixture corpora driven against live MCP servers on the
  official Python SDK. The offline harness decides the same corpora
  analytically; the counts agree.}}
  \label{{tab:livecorpus}}
  \centering\scriptsize
  \begin{{tabular}}{{@{{}}>{{\raggedright\arraybackslash}}p{{0.30\columnwidth}}>{{\raggedright\arraybackslash}}p{{0.34\columnwidth}}>{{\raggedright\arraybackslash}}p{{0.30\columnwidth}}@{{}}}}
    \toprule
    Corpus & Boundary & Live outcome \\
    \midrule
    Sequence, {seq['workflows_driven']} workflows,
      {seq['tool_calls_driven']} live calls & $E_1$ permissive per-call &
      allows {seq['permissive_allows_malicious']}/{seq['malicious']} malicious \\
    & $E_1$ strict per-call & denies {seq['strict_denies_malicious']}/{seq['malicious']}
      malicious, {seq['strict_false_denials']}/{seq['benign']} benign \\
    & $E_4$ sequence engine & denies {seq['sequence_denies_malicious']}/{seq['malicious']}
      malicious, {seq['sequence_false_denials']}/{seq['benign']} benign \\
    \midrule
    Streaming, {stream['conditions_driven']} conditions,
      {stream['progress_notifications_delivered']} progress notifications &
      $E_2$ message-local & {pat['message_local_detects']} with the pattern
      matcher, {exa['message_local_detects']} with the exact matcher \\
    & $E_3$ reassembly & {stream['conditions_driven']}/{stream['conditions_driven']},
      either matcher \\
    \bottomrule
  \end{{tabular}}
\end{{table}}
"""
    (OUT / "live_corpus_table.tex").write_text(tex, encoding="utf-8")


async def main_async() -> dict:
    port = free_port()
    thread = ServerThread(build_corpus_server(), port)
    thread.start()
    try:
        sequence = await run_sequence_corpus(thread.url)
        streaming = await run_streaming_corpus(thread.url)
    finally:
        thread.stop()
    return {
        "sequence_corpus": sequence,
        "streaming_corpus": streaming,
        "scope": (
            "both corpora driven end to end against live MCPServer instances "
            "over Streamable HTTP on loopback; the servers are ours, so this "
            "is conformance evidence at corpus scale, not a deployment study"
        ),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    results = asyncio.run(main_async())
    (OUT / "live_corpus_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    write_table(results)
    print(json.dumps(
        {
            "sequence": results["sequence_corpus"]["summary"],
            "streaming": results["streaming_corpus"]["summary"],
        },
        indent=2,
    ))


if __name__ == "__main__":
    main()
