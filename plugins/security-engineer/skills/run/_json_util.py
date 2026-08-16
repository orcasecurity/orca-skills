#!/usr/bin/env python3
"""Shared JSON extraction utility for parsing claude CLI output."""
import json


def find_last_json_with_key(text: str, key: str) -> dict | None:
    """
    Find the last valid JSON object in text that contains the given key.
    Uses bracket-counting to handle multi-line objects.
    """
    depth = 0
    start = None
    candidates = []

    for i, c in enumerate(text):
        if c == '{':
            if depth == 0:
                start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start is not None:
                snippet = text[start:i + 1]
                try:
                    parsed = json.loads(snippet)
                    if key in parsed:
                        candidates.append(parsed)
                except json.JSONDecodeError:
                    pass
                start = None

    return candidates[-1] if candidates else None
