"""Declarative state-sufficiency checker for the Review25 artifact.

Input is a JSON object with:
  - policy: free-text policy identifier
  - required_atoms: list of atom strings for the declared abstraction A(P)
  - observations: trusted atom strings directly observed at E
  - closure_rules: list of {"name", "requires", "derives"} records

Rules fire to a fixed point when all required atoms are present. The verdict is
"sufficient" iff every required atom is derivable; otherwise it is
"insufficient under declared abstraction".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_case(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def compute_closure(observations: set[str], rules: list[dict]) -> tuple[set[str], list[str]]:
    closure = set(observations)
    fired: list[str] = []
    changed = True
    while changed:
        changed = False
        for rule in rules:
            name = str(rule.get("name", "unnamed"))
            requires = set(rule.get("requires", []))
            derives = set(rule.get("derives", []))
            if requires <= closure and not derives <= closure:
                closure.update(derives)
                fired.append(name)
                changed = True
    return closure, fired


def check(case: dict) -> dict:
    required = set(case.get("required_atoms", []))
    observations = set(case.get("observations", []))
    closure, fired = compute_closure(observations, case.get("closure_rules", []))
    missing = sorted(required - closure)
    verdict = "sufficient" if not missing else "insufficient under declared abstraction"
    return {
        "policy": case.get("policy", ""),
        "enforcement_point": case.get("enforcement_point", ""),
        "verdict": verdict,
        "missing_atoms": missing,
        "closure": sorted(closure),
        "fired_rules": fired,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python experiments/state_sufficiency_checker.py CASE.json", file=sys.stderr)
        return 2
    result = check(load_case(Path(argv[1])))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
