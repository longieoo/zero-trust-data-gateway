"""One deterministic combiner; explanations use the selected outcome records."""


def combine(outcomes: list[dict], strategy: str) -> dict:
    errors = [p for p in outcomes if p["outcome"] == "Indeterminate"]
    effective = sorted(
        [p for p in outcomes if p["outcome"] in ("Permit", "Deny")],
        key=lambda p: (-p["priority"], p["id"]),
    )
    permits = [p for p in effective if p["outcome"] == "Permit"]
    denies = [p for p in effective if p["outcome"] == "Deny"]
    conflict = bool(permits and denies)
    if errors:
        winners = sorted(errors, key=lambda p: p["id"])
        decision, status = "DENY", "DENIED_DUE_TO_TECHNICAL_FAILURE"
    elif not effective:
        winners = []
        decision, status = "DENY", "DENIED_BY_POLICY"
    else:
        if strategy == "deny-overrides":
            winners = denies or permits
        elif strategy == "permit-overrides":
            winners = permits or denies
        elif strategy == "priority-based":
            top = [p for p in effective if p["priority"] == effective[0]["priority"]]
            winners = [p for p in top if p["outcome"] == "Deny"] or top
        else:
            raise ValueError("Unknown combining strategy")
        decision = "ALLOW" if winners[0]["outcome"] == "Permit" else "DENY"
        status = "PERMITTED" if decision == "ALLOW" else "DENIED_BY_POLICY"
    chosen = winners[0] if winners else None
    reason = chosen["reason_code"] if chosen else "NO_APPLICABLE_PERMIT"
    explanation = chosen["description"] if chosen else "No applicable Permit supports access."
    if errors:
        reason = "INDETERMINATE_POLICY"
        explanation = (
            f"Policy {chosen['id']} returned Indeterminate; a trustworthy decision is unavailable."
        )
    return {
        "decision": decision,
        "decision_status": status,
        "reason_code": reason,
        "explanation": explanation,
        "effective_policies": [p["id"] for p in effective],
        "winning_policies": [p["id"] for p in winners],
        "conflict": conflict,
        "combining_rule": "fail-closed-indeterminate" if errors else strategy,
    }
