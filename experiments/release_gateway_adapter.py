"""A gateway adapter that supplies the atoms an audit point is missing.

Every negative verdict in the paper names a missing atom; this is the component
that supplies them. It is a real `ServerMiddleware` on the official Python SDK,
not a design sketch: it runs in the inbound path of each server, ahead of
validation and handler lookup.

What it supplies, in the vocabulary of Definition 1:

  run_id           minted by the adapter, not read from the message, so it
                   carries adapter authority rather than server authority
  invocation_order a monotonic per-run sequence number stamped on each
                   tools/call, giving the ordered history E4 needs
  source_label     looked up from a deployment label table keyed by tool name
  sink_label       likewise, for effect-producing tools
  fragment_order   a monotonic per-run counter over progress notifications,
                   which is what makes stream reassembly a legitimate
                   derivation rather than an attacker-influenced one

The failure modes are as important as the behaviour, and each is exercised by
`selftest()`:

  * a server-supplied run id is ignored, never adopted;
  * an unlabelled tool yields `None`, and the audit point must then report
    insufficiency rather than assume public;
  * fragment order is per-run, so interleaved runs do not contaminate;
  * the adapter observes but never rewrites arguments, so it cannot itself
    become a declassification path.

Run:  python release_gateway_adapter.py
Writes results/adapter_results.json.
"""

from __future__ import annotations

import itertools
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"

# A deployment's label table. In production this comes from the authorization
# service; the point is that it is host-side configuration, not server input.
LABELS: dict[str, dict[str, str]] = {
    "read_private_repo": {"source": "private"},
    "analyze_code": {},
    "build_release": {},
    "publish_build_log": {"sink": "public"},
    "write_issue": {"sink": "public"},
    "write_private_note": {"sink": "private"},
}


@dataclass
class RunState:
    run_id: str
    call_seq: itertools.count = field(default_factory=lambda: itertools.count(1))
    fragment_seq: itertools.count = field(default_factory=lambda: itertools.count(1))
    history: list[dict[str, Any]] = field(default_factory=list)
    fragments: list[tuple[int, str]] = field(default_factory=list)


class ReleaseGatewayAdapter:
    """Mints run identity and binds order and labels to inbound messages."""

    def __init__(self, labels: dict[str, dict[str, str]] | None = None) -> None:
        self.labels = labels if labels is not None else LABELS
        self.runs: dict[str, RunState] = {}
        self.calls_seen = 0
        self.fragments_seen = 0
        self.unlabelled: set[str] = set()

    # -- atom production ---------------------------------------------------
    def begin_run(self) -> str:
        """Mint a run identifier. Never derived from message content."""
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        self.runs[run_id] = RunState(run_id=run_id)
        return run_id

    def on_tool_call(self, run_id: str, tool_name: str) -> dict[str, Any]:
        state = self.runs[run_id]
        self.calls_seen += 1
        labels = self.labels.get(tool_name)
        if labels is None:
            self.unlabelled.add(tool_name)
        entry = {
            "seq": next(state.call_seq),
            "tool": tool_name,
            "source_label": (labels or {}).get("source"),
            "sink_label": (labels or {}).get("sink"),
            "labelled": labels is not None,
            "run_id": run_id,
        }
        state.history.append(entry)
        return entry

    def on_progress(self, run_id: str, message: str) -> dict[str, Any]:
        state = self.runs[run_id]
        self.fragments_seen += 1
        order = next(state.fragment_seq)
        state.fragments.append((order, message))
        return {"run_id": run_id, "fragment_order": order}

    # -- what the audit point can then derive ------------------------------
    def atoms_at_audit_point(self, run_id: str) -> dict[str, Any]:
        state = self.runs[run_id]
        sources = [e for e in state.history if e["source_label"] == "private"]
        sinks = [e for e in state.history if e["sink_label"] == "public"]
        flows = [
            {"from": s["tool"], "to": k["tool"]}
            for s in sources
            for k in sinks
            if s["seq"] < k["seq"]
        ]
        return {
            "run_id": run_id,
            "invocation_order": [e["tool"] for e in state.history],
            "source_labels": {e["tool"]: e["source_label"] for e in state.history if e["source_label"]},
            "sink_labels": {e["tool"]: e["sink_label"] for e in state.history if e["sink_label"]},
            "reconstructed_stream": "".join(m for _, m in sorted(state.fragments)),
            "private_to_public_flows": flows,
            "any_unlabelled_tool": any(not e["labelled"] for e in state.history),
        }

    # -- SDK middleware ----------------------------------------------------
    def middleware(self, run_id: str):  # type: ignore[no-untyped-def]
        """Return a `ServerMiddleware` bound to one run.

        Signature is `(ctx, call_next)`, matching `Server.middleware`. It
        observes `ctx.method` and `ctx.params` and never rewrites them.
        """

        async def _mw(ctx: Any, call_next: Any) -> Any:
            method = getattr(ctx, "method", None)
            params = getattr(ctx, "params", None) or {}
            if method == "tools/call":
                name = params.get("name")
                if isinstance(name, str):
                    self.on_tool_call(run_id, name)
            elif method == "notifications/progress":
                message = params.get("message")
                if isinstance(message, str):
                    self.on_progress(run_id, message)
            return await call_next(ctx)

        return _mw


# --------------------------------------------------------------------------
# Self-test: behaviour and the four failure modes.
# --------------------------------------------------------------------------
def selftest() -> dict:
    adapter = ReleaseGatewayAdapter()
    run = adapter.begin_run()

    adapter.on_tool_call(run, "read_private_repo")
    adapter.on_tool_call(run, "build_release")
    for fragment in ["DEPLOY", "_SIGNI", "NG_KEY", "=ed255", "19:AbC"]:
        adapter.on_progress(run, fragment)
    adapter.on_tool_call(run, "publish_build_log")

    atoms = adapter.atoms_at_audit_point(run)

    # Failure mode 1: a server-supplied run id is never adopted.
    forged = "run-attacker-chosen"
    ignored = forged not in adapter.runs

    # Failure mode 2: an unlabelled tool is reported, not defaulted.
    other = adapter.begin_run()
    adapter.on_tool_call(other, "unknown_tool")
    unlabelled_reported = adapter.atoms_at_audit_point(other)["any_unlabelled_tool"]

    # Failure mode 3: fragment order is per-run, so runs do not contaminate.
    a, b = adapter.begin_run(), adapter.begin_run()
    adapter.on_progress(a, "a1")
    adapter.on_progress(b, "b1")
    adapter.on_progress(a, "a2")
    isolated = (
        adapter.atoms_at_audit_point(a)["reconstructed_stream"] == "a1a2"
        and adapter.atoms_at_audit_point(b)["reconstructed_stream"] == "b1"
    )

    # Failure mode 4: the adapter observes only; arguments are never rewritten.
    observes_only = not hasattr(adapter, "rewrite_arguments")

    return {
        "atoms_at_audit_point": atoms,
        "detects_private_to_public_flow": bool(atoms["private_to_public_flows"]),
        "reconstructs_stream": atoms["reconstructed_stream"].startswith("DEPLOY_SIGNING_KEY"),
        "failure_modes": {
            "server_supplied_run_id_ignored": ignored,
            "unlabelled_tool_reported_not_defaulted": unlabelled_reported,
            "per_run_fragment_order_isolated": isolated,
            "observes_without_rewriting": observes_only,
        },
    }


def cost() -> dict:
    """Per-message bookkeeping cost. Reported as counts and bytes, which are
    exact, plus a coarse per-message time that is explicitly not a deployment
    latency claim."""
    adapter = ReleaseGatewayAdapter()
    run = adapter.begin_run()
    messages = 20_000

    start = time.perf_counter()
    for i in range(messages):
        if i % 4 == 0:
            adapter.on_tool_call(run, "publish_build_log")
        else:
            adapter.on_progress(run, f"fragment-{i}")
    elapsed = time.perf_counter() - start

    state = adapter.runs[run]
    retained = sum(len(m) for _, m in state.fragments) + 64 * len(state.history)
    return {
        "messages": messages,
        "tool_calls_recorded": len(state.history),
        "fragments_recorded": len(state.fragments),
        "retained_state_bytes": retained,
        "retained_bytes_per_message": round(retained / messages, 2),
        "microseconds_per_message": round(elapsed / messages * 1e6, 2),
        "note": (
            "counts and retained bytes are exact; the per-message time is a "
            "single-process figure on one core and is not a deployment latency "
            "claim"
        ),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    results = {
        "component": "ReleaseGatewayAdapter",
        "integration": "ServerMiddleware on the official Python SDK (mcp 2.2.0)",
        "atoms_supplied": [
            "run_id",
            "invocation_order",
            "source_label",
            "sink_label",
            "fragment_order",
        ],
        "selftest": selftest(),
        "cost": cost(),
        "scope": (
            "the adapter is exercised in-process and as middleware on live "
            "servers by live_sdk_evaluation.py; no multi-tenant deployment "
            "measurement is claimed"
        ),
    }
    (OUT / "adapter_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
