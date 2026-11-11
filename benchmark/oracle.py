"""Independent Python interpreter for the benchmark's bounded condition language.

No import from the app's decision, OPA, or policy evaluator. This checks generated
policy semantics, not authentication, provenance, or correctness of the business rules.
"""


def lookup(attributes: dict, path: list):
    value = attributes
    for part in path:
        value = value[part]
    return value


def check(attributes: dict, condition: dict) -> bool:
    left = lookup(attributes, condition["path"])
    right = lookup(attributes, condition["other"]) if "other" in condition else condition["value"]
    operation = condition["op"]
    if operation == "eq":
        return left == right
    if operation == "neq":
        return left != right
    if operation == "in":
        return left in right
    if operation == "gte":
        return left >= right
    if operation == "lt":
        return left < right
    if operation == "rank_lt":
        order = ["public", "internal", "confidential", "restricted"]
        return order.index(left) < order.index(right)
    raise ValueError("Unsupported oracle condition")


def decide(attributes: dict, policies: list) -> str:
    effects = []
    for policy in policies:
        if all(check(attributes, c) for c in policy["target"] + policy["conditions"]):
            effects.append(policy["effect"])
    return "ALLOW" if "Permit" in effects and "Deny" not in effects else "DENY"
