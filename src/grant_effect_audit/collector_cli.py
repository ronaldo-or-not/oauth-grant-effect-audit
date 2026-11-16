"""Load a trusted local adapter and write a redacted evidence file."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

from .collector import CollectionError, collect
from .core import EvidenceError


def _load_adapter(path: Path, factory_name: str):
    if not path.is_file():
        raise CollectionError("adapter file does not exist")
    spec = importlib.util.spec_from_file_location("grant_effect_local_adapter", path)
    if spec is None or spec.loader is None:
        raise CollectionError("adapter file cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(module)
    factory = getattr(module, factory_name, None)
    if not callable(factory):
        raise CollectionError("adapter factory is missing or not callable")
    return factory()


def _write_private_json(path: Path, payload: dict) -> None:
    data = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect evidence using a trusted local adapter; loopback target by default"
    )
    parser.add_argument(
        "--adapter",
        required=True,
        type=Path,
        help="trusted Python adapter file with create_adapter()",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new JSON evidence file; never overwritten",
    )
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--target", required=True, help="canonical protected resource URI"
    )
    parser.add_argument("--transition", required=True)
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="explicitly permit an authorized non-loopback target",
    )
    args = parser.parse_args(argv)
    if args.output.exists():
        print("collection failed: output already exists", file=sys.stderr)
        return 64
    try:
        adapter = _load_adapter(args.adapter.resolve(), "create_adapter")
        evidence, verdict = collect(
            adapter,
            case_id=args.case_id,
            target_resource=args.target,
            transition=args.transition,
            allow_non_loopback=args.allow_non_loopback,
        )
        _write_private_json(args.output, evidence)
    except (CollectionError, EvidenceError, OSError, ValueError) as error:
        # Adapter error strings can accidentally contain tokens. Keep the CLI
        # error generic; the operator can debug the adapter in private.
        print(f"collection failed: {type(error).__name__}", file=sys.stderr)
        return 64
    except Exception as error:
        print(f"collection failed: {type(error).__name__}", file=sys.stderr)
        return 64
    print(f"{verdict.case_id}: {verdict.status}; saved {args.output}")
    return (
        2
        if verdict.status == "out_of_grant_effect_observed"
        else 3 if verdict.status == "inconclusive" else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
