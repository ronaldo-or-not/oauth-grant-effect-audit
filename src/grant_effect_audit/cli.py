"""Command line interface for local, redacted evidence files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import EvidenceError, evaluate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check recorded OAuth grant-to-effect evidence without making network requests"
    )
    parser.add_argument("evidence", type=Path, help="redacted JSON evidence file")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable verdict")
    args = parser.parse_args(argv)
    try:
        raw = json.loads(args.evidence.read_text(encoding="utf-8"))
        verdict = evaluate(raw)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        print(f"invalid evidence: {error}", file=sys.stderr)
        return 64
    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        print(f"{verdict.case_id}: {verdict.status}")
        for reason in verdict.reasons:
            print(f"  - {reason}")
        print(f"  observed effect delta: {verdict.effect_delta}")
    return 2 if verdict.status == "out_of_grant_effect_observed" else 3 if verdict.status == "inconclusive" else 0


if __name__ == "__main__":
    raise SystemExit(main())
