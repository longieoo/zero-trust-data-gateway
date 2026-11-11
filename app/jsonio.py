"""Reject ambiguous keys and nonstandard numeric constants in trusted JSON files."""

import json


def strict_json_loads(content):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Nonstandard JSON constant: {value}")

    return json.loads(content, object_pairs_hook=unique_object, parse_constant=invalid_constant)
