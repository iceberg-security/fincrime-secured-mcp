"""``python -m evals.validate`` — lint every dataset YAML under
``evals/datasets/``.

Wired up by ``make validate-evals``. Non-zero exit on the first
validation error, with a path-prefixed message. Quiet on success
(prints a one-line summary).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evals.datasets.schema import EvalSchemaError, validate_dataset_dir

DEFAULT_DATASET_DIR = Path(__file__).resolve().parent / "datasets"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        default=str(DEFAULT_DATASET_DIR),
        help=f"Directory to scan (default: {DEFAULT_DATASET_DIR})",
    )
    args = parser.parse_args(argv)

    try:
        datasets = validate_dataset_dir(args.dir)
    except EvalSchemaError as exc:
        print(f"validate-evals: FAILED\n  {exc}", file=sys.stderr)
        return 1

    print(f"validate-evals: OK ({len(datasets)} dataset(s) validated)")
    for ds in datasets:
        print(
            f"  - {ds.id:<24} scenario={ds.scenario:<13} "
            f"verdict={ds.expected_verdict}"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
