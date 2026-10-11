"""File handling utilities for the hackbot agent."""

import json
import os


def read_json(file_path: str) -> dict:
    """Read and parse a JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(file_path: str, data: dict) -> None:
    """Write data to a JSON file."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
