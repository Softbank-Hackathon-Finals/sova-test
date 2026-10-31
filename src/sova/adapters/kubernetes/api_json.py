"""Kubernetes wire JSON has deeper managedFields than Sova's public contracts."""

import json
import math
from sova.domain.contracts import ContractError


def decode_api_json(raw, *, limit=2 * 1024 * 1024):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ContractError("Kubernetes JSON size limit")

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ContractError("Duplicate Kubernetes JSON field")
            obj[key] = value
        return obj

    def constant(_):
        raise ContractError("Non-finite Kubernetes JSON")

    try:
        result = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant
        )
        stack = [(result, 0)]
        count = 0
        while stack:
            item, depth = stack.pop()
            count += 1
            if depth > 64 or count > 100000:
                raise ContractError("Kubernetes JSON structure limit")
            if isinstance(item, dict):
                stack.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                stack.extend((value, depth + 1) for value in item)
            elif isinstance(item, float) and not math.isfinite(item):
                raise ContractError("Non-finite Kubernetes JSON")
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError("Invalid Kubernetes API JSON") from exc
