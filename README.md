# mcp-state-sufficiency-analysis

# Below the Agent - Reproducibility Code

This repository snapshot contains the experiment and proof-of-concept code used
for the v42 paper artifact:

**State-Sufficiency Analysis: A Placement Test for Security Enforcement in
Model Context Protocol (MCP) Workflows**

The code is intentionally small and local. It does not call an LLM, does not
exercise commercial products, and does not actively test public services.

## Contents

- `experiments/run_offline_experiments.py` generates the deterministic fixture
  results, tables, state-sufficiency examples, adaptive-bypass matrix,
  construction checks, and artifact-only support tables.
- `experiments/state_sufficiency_checker.py` is the JSON-driven closure/subset
  checker used for the worked examples.
- `experiments/release_gateway_adapter.py` is the gateway-adapter proof of
  concept. It mints run IDs, stamps invocation order, attaches source/sink
  labels, and counts progress fragments per run. It does not supply the E5
  trusted authorization-context atom.
- `experiments/live_sdk_evaluation.py` runs E1-E4 against live local MCP
  servers using the official Python SDK.
- `experiments/live_corpus_evaluation.py` drives the sequence and streaming
  fixture corpora through local MCP servers.
- `experiments/x_mcp_header_case.py` measures the SDK behavior for the
  `x-mcp-header` / `Mcp-Param-*` surface.
- `experiments/static_mcp_name_checker.py` checks commit-pinned local clones
  for decoded `Mcp-Name` / body-name comparison behavior.
- `experiments/make_detection_figure.py` and `experiments/make_live_table.py`
  regenerate paper-facing derived outputs.
- `experiments/examples/` contains the two declarative checker inputs.
- `experiments/results/` contains generated JSON/TEX/figure outputs included
  for comparison with a fresh run.

## Setup

Use Python 3.10+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The static source checker optionally expects commit-pinned repositories under:

```text
experiments/public_gateway_sources/
```

Those third-party source trees are not included here. The checked report is
included as `experiments/results/static_checker_report.json`.

## Reproduction Order

From the repository root:

```powershell
python experiments/run_offline_experiments.py
python experiments/release_gateway_adapter.py
python experiments/live_sdk_evaluation.py
python experiments/live_corpus_evaluation.py
python experiments/x_mcp_header_case.py
python experiments/make_detection_figure.py
python experiments/make_live_table.py
```

Run the declarative checker examples:

```powershell
python experiments/state_sufficiency_checker.py experiments/examples/p_exfil_sequence_engine.json
python experiments/state_sufficiency_checker.py experiments/examples/p_cache_untrusted_tenant.json
```

Optional, if the commit-pinned public repositories have been cloned:

```powershell
python experiments/static_mcp_name_checker.py
```

On Windows, the live corpus run may print asyncio loopback shutdown messages
such as `ConnectionResetError: [WinError 10054]` after successful local HTTP
requests. The v42 copy was verified with that warning present and a zero process
exit code.

## Expected Outputs

The scripts write into `experiments/results/`. Important outputs include:

- `offline_results.json`
- `live_sdk_results.json`
- `live_corpus_results.json`
- `adapter_results.json`
- `x_mcp_header_case.json`
- `static_checker_report.json`
- `live_sdk_table.tex`
- `state_sufficiency_table.tex`
- `adaptive_table.tex`
- `detection_vs_fm.png`

The reconstruction benchmark's latency columns are hardware-sensitive and are
not claimed as deployment-latency results in the paper. The memory accounting
and the fixture counts are deterministic.

## Claim Boundary

The included experiments are mechanism and conformance evidence. They do not
claim deployment prevalence, detector precision/recall, commercial gateway
coverage, or production latency.
