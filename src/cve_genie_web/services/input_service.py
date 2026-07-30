from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class InputFileError(RuntimeError):
    pass


def read_input_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise InputFileError("Input JSON file does not exist")

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputFileError(
            f"Input JSON is invalid: {exc}"
        ) from exc

    if not isinstance(value, dict):
        raise InputFileError(
            "The root of the input JSON must be an object"
        )

    return value


def write_input_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    temporary_path.replace(path)
