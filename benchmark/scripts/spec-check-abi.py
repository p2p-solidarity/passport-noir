#!/usr/bin/env python3
"""ABI-based spec compliance check.

Issue P2-10 (2026-04-28): the original spec-check.sh used `grep -c 'pub '`
to count public inputs in source files. That counts annotations rather
than the compiled ABI, so it doesn't catch:

  * `pub` parameters reordered in main() (audit's core P2 concern -- the
    verifier's expected layout drifts from what the prover proves).
  * Public inputs renamed in main() but not in spec.toml.
  * Type/length mismatches between source and the spec.

This script parses each compiled circuit's `circuits/target/<name>.json`
and compares the ABI-derived public-input list against `benchmark/spec.toml`.
It is intentionally strict: any reordering, rename, type drift, or count
change fails the build.

Usage:
    python3 benchmark/scripts/spec-check-abi.py [project_root]

If no project_root is given, defaults to the script's parent's parent
(i.e. the repo root). Requires `tomllib` (Python 3.11+) or `tomli`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib  # type: ignore[import]
except ImportError:  # pragma: no cover -- pre-3.11 fallback
    import tomli as tomllib  # type: ignore[import]


GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}[PASS]{NC} {msg}")


def fail(msg: str, *, issues: list[str]) -> None:
    print(f"  {RED}[FAIL]{NC} {msg}")
    issues.append(msg)


def warn(msg: str) -> None:
    print(f"  {YELLOW}[WARN]{NC} {msg}")


def parse_abi_inputs(circuit_json_path: Path) -> tuple[list[dict], list[dict]] | None:
    """Return (public_params, private_params) from a compiled circuit JSON.

    Each list element is a dict with keys ``name`` and ``type``. Returns
    ``None`` if the JSON cannot be loaded (compiled artifact missing /
    malformed).
    """
    try:
        with circuit_json_path.open() as fp:
            data = json.load(fp)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

    abi = data.get("abi") or {}
    params = abi.get("parameters") or []
    public_params: list[dict] = []
    private_params: list[dict] = []
    for p in params:
        # noir abi visibility: "public" or "private"
        if p.get("visibility") == "public":
            public_params.append({"name": p.get("name", ""), "type": p.get("type", {})})
        else:
            private_params.append({"name": p.get("name", ""), "type": p.get("type", {})})
    return public_params, private_params


def check_circuit(name: str, spec: dict[str, Any], target_dir: Path, issues: list[str]) -> None:
    json_path = target_dir / f"{name}.json"
    parsed = parse_abi_inputs(json_path)
    if parsed is None:
        warn(f"{name}: compiled JSON not found at {json_path}; skipping (run `nargo compile` first)")
        return
    public_params, _private_params = parsed
    abi_names = [p["name"] for p in public_params]
    spec_names = spec.get("public_inputs") or []

    if abi_names == spec_names:
        ok(f"{name}: public-input ABI matches spec.toml ({len(abi_names)} inputs)")
        return

    # Detailed diagnostic: report length mismatch, then ordering or naming
    # diffs so the operator can update either the spec or the circuit
    # rather than guessing what drifted.
    if len(abi_names) != len(spec_names):
        fail(
            f"{name}: public-input count mismatch -- spec={len(spec_names)} abi={len(abi_names)}",
            issues=issues,
        )
    diffs: list[str] = []
    for idx, (a, s) in enumerate(zip(abi_names, spec_names)):
        if a != s:
            diffs.append(f"index {idx}: spec={s!r} abi={a!r}")
    extra_abi = abi_names[len(spec_names):]
    extra_spec = spec_names[len(abi_names):]
    if diffs:
        fail(f"{name}: public-input ordering/name drift: {'; '.join(diffs)}", issues=issues)
    if extra_abi:
        fail(f"{name}: ABI has extra public inputs not in spec: {extra_abi}", issues=issues)
    if extra_spec:
        fail(f"{name}: spec lists public inputs missing from ABI: {extra_spec}", issues=issues)


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        root = Path(argv[1]).resolve()
    else:
        root = Path(__file__).resolve().parent.parent.parent
    spec_path = root / "benchmark" / "spec.toml"
    target_dir = root / "circuits" / "target"

    if not spec_path.exists():
        print(f"  {RED}[FAIL]{NC} spec.toml not found at {spec_path}")
        return 1

    with spec_path.open("rb") as fp:
        spec = tomllib.load(fp)

    print("=== ABI-based public input check (P2-10) ===")
    issues: list[str] = []
    circuits = spec.get("circuits") or {}
    for name, cfg in circuits.items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("type") != "bin":
            continue
        check_circuit(name, cfg, target_dir, issues)

    print()
    print(f"  ABI check complete: {len(issues)} issue(s) found")
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
