#!/usr/bin/env python3
"""Synchronize labeled CRC arrays in the repository's autotest.json files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


# Define shared framebuffer CRCs here. A label may accept multiple ROM-specific
# renderings; the script writes every value into the matching expected_CRCs.
CRC_VALUES: dict[str, tuple[str, ...]] = {
    "@success": ("D1F2869F",),
    "@lwip_installed": ("F7C03D8D",),
}

CRC_RE = re.compile(r"^[0-9A-F]{8}$")
LABELED_ARRAY_RE = re.compile(
    r'(?P<prefix>"label"\s*:\s*"(?P<label>@[A-Za-z0-9_.-]+)"\s*,\s*\n'
    r'(?P<indent>[ \t]*)"expected_CRCs"\s*:\s*)'
    r"\[(?P<values>[^\]]*)\]"
)


class UpdateError(ValueError):
    pass


def validate_definitions() -> None:
    for label, values in CRC_VALUES.items():
        if not label.startswith("@"):
            raise UpdateError(f"shared CRC label must start with @: {label!r}")
        if not values:
            raise UpdateError(f"shared CRC label has no values: {label}")
        for value in values:
            if not CRC_RE.fullmatch(value):
                raise UpdateError(f"invalid CRC {value!r} for {label}")


def labeled_hashes(config: object, path: Path) -> list[str]:
    if not isinstance(config, dict):
        raise UpdateError(f"{path}: top-level JSON value must be an object")
    hashes = config.get("hashes", {})
    if not isinstance(hashes, dict):
        raise UpdateError(f"{path}: 'hashes' must be an object")

    labels: list[str] = []
    for hash_id, hash_config in hashes.items():
        if not isinstance(hash_config, dict):
            continue
        label = hash_config.get("label")
        if label is None:
            continue
        if not isinstance(label, str):
            raise UpdateError(f"{path}: hash {hash_id} has a non-string label")
        if label not in CRC_VALUES:
            raise UpdateError(f"{path}: hash {hash_id} uses unknown label {label!r}")
        labels.append(label)
    return labels


def format_values(
    values: tuple[str, ...], indent: str, previous_values: str
) -> str:
    if "\n" not in previous_values:
        return "[" + ", ".join(f'"{value}"' for value in values) + "]"

    item_indent = indent + "  "
    body = ",\n".join(f'{item_indent}"{value}"' for value in values)
    return f"[\n{body}\n{indent}]"


def update_file(path: Path, check: bool) -> bool:
    original = path.read_text(encoding="utf-8")
    try:
        config = json.loads(original)
    except json.JSONDecodeError as exc:
        raise UpdateError(f"{path}: invalid JSON: {exc}") from exc

    expected_labels = labeled_hashes(config, path)
    replaced_labels: list[str] = []

    def replace(match: re.Match[str]) -> str:
        label = match.group("label")
        if label not in CRC_VALUES:
            raise UpdateError(f"{path}: unknown label {label!r}")
        replaced_labels.append(label)
        return match.group("prefix") + format_values(
            CRC_VALUES[label], match.group("indent"), match.group("values")
        )

    updated = LABELED_ARRAY_RE.sub(replace, original)
    if replaced_labels != expected_labels:
        raise UpdateError(
            f"{path}: each labeled hash must place 'label' immediately before "
            f"'expected_CRCs' (found {len(expected_labels)}, patched {len(replaced_labels)})"
        )

    # Validate the exact bytes that would be written.
    json.loads(updated)
    changed = updated != original
    if changed and not check:
        path.write_text(updated, encoding="utf-8")
    return changed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="autotest.json files or directories (default: every file under tests)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report stale files without modifying them",
    )
    return parser.parse_args(argv)


def find_configs(paths: list[Path]) -> list[Path]:
    if not paths:
        paths = [Path(__file__).resolve().parents[2]]

    configs: set[Path] = set()
    for path in paths:
        path = path.resolve()
        if path.is_dir():
            configs.update(path.rglob("autotest.json"))
        elif path.name == "autotest.json" and path.is_file():
            configs.add(path)
        else:
            raise UpdateError(f"not an autotest.json file or directory: {path}")
    return sorted(configs)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        validate_definitions()
        configs = find_configs(args.paths)
        changed = [path for path in configs if update_file(path, args.check)]
    except (OSError, UpdateError) as exc:
        print(f"update_autotest_crcs.py: {exc}", file=sys.stderr)
        return 2

    if args.check and changed:
        for path in changed:
            print(f"stale: {path}")
        return 1

    action = "would update" if args.check else "updated"
    print(f"{action} {len(changed)} of {len(configs)} autotest files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
