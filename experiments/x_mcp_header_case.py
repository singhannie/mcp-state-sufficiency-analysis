"""The `x-mcp-header` surface: a server-controlled widening of observability.

MCP 2026-07-28 lets a tool's input schema mark parameters with `x-mcp-header`,
and the SDK mirrors those argument values into `Mcp-Param-*` request headers so
intermediaries can route on them. The specification warns against marking
secrets this way.

Measured behaviour (against the SDK's own codec and header builder, not a model
of them): the value is *mirrored*, not moved. It remains in the JSON-RPC body
and additionally appears in a header. So a body-reading inspector does not lose
the atom. Two things do change, and both matter for placement:

1.  A boundary that sees only headers -- a reverse proxy, an L7 gateway, an
    access log -- now observes a value it previously could not. Observability
    widens toward components that never parse bodies.
2.  Which values those boundaries observe is chosen by the *server*, through a
    schema annotation, not by the host or the policy author. A gateway routing
    on `Mcp-Param-*` is therefore consuming a server-controlled atom: by
    Definition 1 it carries server authority and untrusted provenance, whatever
    its surface value.

The state-sufficiency reading is about authority and provenance rather than
containment: the annotation does not remove an atom from any boundary, it adds
an untrusted one to boundaries that did not have it.

Run:  python x_mcp_header_case.py
Writes results/x_mcp_header_case.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.shared.inbound import (
    X_MCP_HEADER_KEY,
    decode_header_value,
    find_invalid_x_mcp_header,
    mcp_param_headers,
)

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"

SECRET = "DEPLOY_SIGNING_KEY=ed25519:AbCdEfGhIjKlMnOpQrStUvWx"


def base_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "release_tag": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["release_tag", "content"],
    }


def annotated_schema() -> dict[str, Any]:
    schema = base_schema()
    schema["properties"]["release_tag"][X_MCP_HEADER_KEY] = "release-tag"
    return schema


def header_map(schema: dict[str, Any]) -> dict[tuple[str, ...], str]:
    return {
        (name,): prop[X_MCP_HEADER_KEY]
        for name, prop in schema.get("properties", {}).items()
        if isinstance(prop.get(X_MCP_HEADER_KEY), str)
    }


def body_reader_sees(arguments: dict[str, Any], headers: dict[str, str]) -> bool:
    """A boundary that parses the JSON-RPC body: host runtime, server handler."""
    return SECRET in json.dumps(arguments)


def header_only_reader_sees(arguments: dict[str, Any], headers: dict[str, str]) -> bool:
    """A boundary that sees headers only: reverse proxy, L7 gateway, access log."""
    return any(
        (decode_header_value(value) or "").find(SECRET) >= 0
        for value in headers.values()
    )


def run_case(label: str, schema: dict[str, Any], arguments: dict[str, Any]) -> dict:
    mapping = header_map(schema)
    headers = mcp_param_headers(mapping, arguments) if mapping else {}
    return {
        "case": label,
        "annotated_params": [name for (name,) in mapping],
        "headers_emitted": headers,
        "body_reader_observes_secret": body_reader_sees(arguments, headers),
        "header_only_reader_observes_secret": header_only_reader_sees(
            arguments, headers
        ),
        "atom_authority": "server (schema annotation)" if mapping else "n/a",
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    arguments = {"release_tag": SECRET, "content": "build ok"}

    before = run_case("no x-mcp-header", base_schema(), arguments)
    after = run_case("release_tag annotated", annotated_schema(), arguments)

    bad = base_schema()
    bad["properties"]["size"] = {"type": "number", X_MCP_HEADER_KEY: "size"}

    results = {
        "sdk_package": "mcp 2.2.0",
        "cases": [before, after],
        "value_is_mirrored_not_moved": (
            before["body_reader_observes_secret"]
            and after["body_reader_observes_secret"]
        ),
        "observability_widened_to_header_only_boundaries": (
            not before["header_only_reader_observes_secret"]
            and after["header_only_reader_observes_secret"]
        ),
        "sdk_rejects_number_typed_annotation": find_invalid_x_mcp_header(bad),
        "finding": (
            "The annotation mirrors the argument into an Mcp-Param-* header "
            "rather than moving it, so no boundary loses the atom. What changes "
            "is that header-only boundaries gain it, and the server chooses "
            "which values they gain through a schema annotation. A gateway "
            "routing on Mcp-Param-* consumes an atom of server authority and "
            "untrusted provenance."
        ),
        "scope": (
            "exercises the SDK's own x-mcp-header codec, header builder and "
            "schema validator; no claim about how often deployments annotate "
            "secret-bearing parameters"
        ),
    }
    (OUT / "x_mcp_header_case.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
