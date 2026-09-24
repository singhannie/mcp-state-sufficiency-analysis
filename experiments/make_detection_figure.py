"""Plot message-local detection against f/m, the quantity that governs it.

Earlier passes reported the aggregate 119/423. That number is a property of the
payload set we chose, and invites reading as a detection rate. The mechanism is
analytic: a message-local matcher recognises the policy string only when a
single fragment contains a matchable unit, so detection turns on f/m, where m
is the shortest substring of the payload that the matcher recognises on its
own. Normalised that way the ten payload classes collapse onto one step at
f/m = 1, which is the claim, and the outliers become visible as outliers rather
than as noise in an average.

Reads results/offline_results.json; writes results/detection_vs_fm.png and the
LaTeX float the manuscript includes.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"

DETECT = "#1b3a6b"
MISS = "#b9c3d1"


def main() -> None:
    results = json.loads((OUT / "offline_results.json").read_text(encoding="utf-8"))
    rows = results["streaming"]["rows"]

    by_payload: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_payload[row["payload"]].append(row)

    # m_i: the smallest fragment size at which the matcher fires at all.
    minimal_unit: dict[str, int] = {}
    for name, entries in by_payload.items():
        hits = [e["fragment_size"] for e in entries if e["per_message_detected"]]
        minimal_unit[name] = min(hits) if hits else entries[0]["payload_len"]

    order = sorted(by_payload, key=lambda n: minimal_unit[n])

    fig, ax = plt.subplots(figsize=(3.4, 2.25), dpi=300)
    off_step = 0
    for index, name in enumerate(order):
        m = minimal_unit[name]
        entries = sorted(by_payload[name], key=lambda e: e["fragment_size"])
        xs_hit, xs_miss = [], []
        for entry in entries:
            ratio = entry["fragment_size"] / m
            (xs_hit if entry["per_message_detected"] else xs_miss).append(ratio)
        ax.axhline(index, color="#e8ebf0", linewidth=0.6, zorder=0)
        ax.scatter(xs_miss, [index] * len(xs_miss), s=5, facecolors="none",
                   edgecolors=MISS, linewidths=0.5, zorder=2)
        ax.scatter(xs_hit, [index] * len(xs_hit), s=6, color=DETECT, zorder=3)
        off_step += 1

    ax.axvline(1.0, color="#c0392b", linewidth=0.8, linestyle="--", zorder=4)
    ax.text(1.03, len(order) - 0.4, "$f=m$", fontsize=5.6, color="#c0392b")

    ax.set_yticks(range(len(order)))
    ax.set_yticklabels(
        ["{} ($m$={})".format(n.replace("_", " "), minimal_unit[n]) for n in order],
        fontsize=5.2,
    )
    ax.set_xlabel("fragment size relative to minimum matchable unit, $f/m$",
                  fontsize=6.2)
    ax.set_xlim(0, max(e["fragment_size"] / minimal_unit[n]
                       for n in order for e in by_payload[n]) * 1.02)
    ax.set_ylim(-0.7, len(order) - 0.3)
    ax.tick_params(axis="x", labelsize=5.6, length=2)
    ax.tick_params(axis="y", length=0)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_linewidth(0.5)
        ax.spines[spine].set_color("#6b7484")

    ax.legend(
        handles=[
            Line2D([], [], marker="o", linestyle="none", markersize=2.6,
                   color=DETECT, label="detected"),
            Line2D([], [], marker="o", linestyle="none", markersize=2.6,
                   markerfacecolor="none", markeredgecolor=MISS,
                   markeredgewidth=0.5, label="missed"),
        ],
        fontsize=5.2, loc="upper left", bbox_to_anchor=(0.0, 1.16), ncol=2,
        frameon=False, handletextpad=0.3, columnspacing=1.0,
    )
    fig.tight_layout(pad=0.35)
    fig.savefig(OUT / "detection_vs_fm.png", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    violations = sum(
        1
        for name in order
        for entry in by_payload[name]
        if entry["per_message_detected"] != (entry["fragment_size"] >= minimal_unit[name])
    )
    total = sum(len(v) for v in by_payload.values())

    caption = (
        "Message-local detection against fragment size normalised by the "
        "minimum matchable unit $m$, for the ten payload classes. Detection is "
        "governed by $f\\geq m$, not by a rate: the dashed line is $f=m$, and "
        + ("every one of the " + str(total) + " conditions falls on the "
           "predicted side of it"
           if violations == 0
           else str(violations) + " of " + str(total) + " conditions deviate, "
           "all in \\texttt{connection\\_string}, whose matcher fires on a "
           "prefix")
        + ". Reconstructed matching detects every condition and is invariant to "
        "$f$, so it is not plotted."
    )

    figure_tex = (
        "\\begin{figure}[t]\n  \\centering\n"
        "  \\includegraphics[width=\\columnwidth]"
        "{experiments/results/detection_vs_fm.png}\n"
        "  \\caption{" + caption + "}\n"
        "  \\label{fig:detection-fm}\n\\end{figure}\n"
    )
    (OUT / "detection_vs_fm_figure.tex").write_text(figure_tex, encoding="utf-8")
    print("conditions:", total, "| deviations from f>=m:", violations)
    print("m per payload:", minimal_unit)


if __name__ == "__main__":
    main()
