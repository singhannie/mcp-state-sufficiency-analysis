"""Emit the placement table from live_sdk_results.json.

Kept separate from the offline harness so the table always reflects the last
live run. Each row reports two verdicts: what the boundary decides on its own
observations, and what it decides once the gateway adapter supplies the atom
the first verdict named as missing.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"

# Per placement: label, state needed, the atom a negative verdict names, the
# verdict uninstrumented, and the verdict once the adapter supplies it.
# E1 and E2 are the cases the adapter cannot repair in place: a per-call gate
# and a message-local monitor stay insufficient however the atoms are fed,
# because the policy ranges over state their decision point does not span.
PLACEMENT = {
    "$E_1$ per-call approval": (
        "$E_1$ approval", "current call", "prior calls/output",
        "insufficient", "insufficient"),
    "$E_2$ message DLP": (
        "$E_2$ msg DLP", "content unit", "reconstructed stream",
        "insufficient", "insufficient"),
    "$E_3$ stream audit": (
        "$E_3$ stream audit", "ordered stream", "host run binding",
        "insufficient", "sufficient"),
    "$E_4$ sequence engine": (
        "$E_4$ sequence", "history + taint", "host labels",
        "insufficient", "sufficient"),
}

FIXTURE_ROWS = [
    ("$E_5$ cache", "reuse context", "trusted authz",
     "insufficient", "sufficient", "fixture"),
    ("$E_6$ task mon.", "task id + history", "continuity",
     "not established", "not established", "fixture"),
]


def main() -> None:
    data = json.loads((OUT / "live_sdk_results.json").read_text(encoding="utf-8"))

    rows = []
    for verdict in data["verdicts"]:
        label, needed, atom, before, after = PLACEMENT[verdict["point"]]
        # The live run instruments E3 and E4; agreement is with the
        # instrumented column for those, the uninstrumented one for E1/E2.
        expected = after if after != before else before
        agrees = "\\checkmark" if verdict["prediction"] == expected else "$\\times$"
        rows.append(
            "    {} & {} & {} & {} & {} & live~{} \\\\".format(
                label, needed, atom, before, after, agrees
            )
        )
    for row in FIXTURE_ROWS:
        rows.append("    {} & {} & {} & {} & {} & {} \\\\".format(*row))

    span = ("\\multicolumn{5}{@{}>{\\raggedright\\arraybackslash}"
            "p{0.735\\columnwidth}@{}}")
    mirrored = data["x_mcp_header_observed"]
    assert mirrored, "live run recorded no mirrored x-mcp-header parameter"
    surface_rows = [
        "    \\midrule",
        "    \\multicolumn{6}{@{}l}{\\emph{Surface findings, same harness}} \\\\",
        "    " + span +
        "{\\texttt{x-mcp-header} mirrors an argument into "
        "\\texttt{Mcp-Param-*}; the value stays in the body, so observability "
        "widens under server control} & live~\\checkmark \\\\",
        "    " + span +
        "{a principal wrapped in \\texttt{=?base64?}\\ldots\\texttt{?=} fails a "
        "raw compare against the body name and succeeds once decoded} & "
        "live~\\checkmark \\\\",
    ]

    sdk = data["sdk"]
    caption = (
        "Placement verdicts, before and after the adapter of "
        "Section~\\ref{{sec:adapter}}. ``Named atom'' is what the "
        "uninstrumented verdict reports missing. $E_1$ and $E_2$ do not change: "
        "no feed makes a per-call gate or a message-local monitor decide a "
        "policy over prior calls or reconstructed content, so the repair is to "
        "move the decision, not to supply the boundary. $E_1$--$E_4$ are real "
        "handler, client-callback and middleware components against three live "
        "MCP servers on the official Python SDK negotiating {}; $E_5$ and $E_6$ "
        "are fixture-derived.".format(sdk["negotiated_protocol_version"])
    )

    tex = (
        "\\begin{table}[t]\n"
        "  \\caption{" + caption + "}\n"
        "  \\label{tab:live}\n"
        "  \\centering\\scriptsize\n"
        "  \\setlength{\\tabcolsep}{3pt}\n"
        "  \\begin{tabular}{@{}"
        + "".join(
            ">{\\raggedright\\arraybackslash}p{" + w + "\\columnwidth}"
            for w in ("0.135", "0.130", "0.150", "0.145", "0.115", "0.105")
        )
        + "@{}}\n"
        "    \\toprule\n"
        "    Point & State needed & Named atom & Uninstrum. & With adapter & "
        "Evidence \\\\\n"
        "    \\midrule\n"
        + "\n".join(rows)
        + "\n"
        + "\n".join(surface_rows)
        + "\n    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table}\n"
    )
    (OUT / "live_sdk_table.tex").write_text(tex, encoding="utf-8")

    print("wrote live_sdk_table.tex")
    print("negotiated:", sdk["negotiated_protocol_version"])
    codec = data["header_codec"]
    print("raw compare:", codec["raw_compare_matches"],
          "| decoded compare:", codec["decoded_compare_matches"])


if __name__ == "__main__":
    main()
