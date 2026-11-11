"""Resolve server configuration and per-request observations with explicit provenance."""

from zoneinfo import ZoneInfo

from app.attribute_provider import AttributeProvider, DecisionError
from app.models import Context, Resource, Subject

RESOURCES = {
    "customers": {
        "id": "customers",
        "type": "dataset",
        "department": "marketing",
        "sensitivity": "confidential",
    },
    "financial": {
        "id": "financial",
        "type": "records",
        "department": "finance",
        "sensitivity": "restricted",
    },
    "production": {
        "id": "production",
        "type": "database",
        "department": "data",
        "sensitivity": "restricted",
    },
}


class GatewayProvider:
    def __init__(self, subject, context, observed_at, business_timezone):
        self.subject = subject
        self.context = context
        self.observed_at = observed_at
        self.business_timezone = business_timezone

    def resolve(self, request, now, simulation):
        if request.context is not None or request.failure_mode != "none":
            raise DecisionError("UNTRUSTED_OVERRIDE", "Gateway does not accept context overrides.")
        if request.subject_id != self.subject["id"] or request.resource_id not in RESOURCES:
            raise DecisionError("UNKNOWN_RESOURCE", "Unknown identity or resource.", False)
        values, provenance = {}, {}
        for name, attrs, model, source in (
            ("subject", self.subject, Subject, "server/account-registry"),
            ("resource", RESOURCES[request.resource_id], Resource, "server/resource-registry"),
            ("context", self.context, Context, "server/TLS-proxy-and-clock"),
        ):
            values[name], provenance[name] = AttributeProvider.validate(
                {"attributes": attrs, "timestamp": self.observed_at.isoformat(), "ttl_seconds": 30},
                model,
                now,
                source,
            )
        values["context"]["hour"] = self.observed_at.astimezone(
            ZoneInfo(self.business_timezone)
        ).hour
        values["action"] = "read"
        return {"attributes": values, "provenance": provenance}
