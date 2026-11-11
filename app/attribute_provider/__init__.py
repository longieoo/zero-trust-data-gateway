"""Trusted snapshot lookup with explicit provenance and freshness."""

from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from app.models import AccessRequest, Context, Resource, Subject
from app.jsonio import strict_json_loads


class DecisionError(Exception):
    def __init__(
        self, code: str, explanation: str, technical: bool = True, evidence: dict | None = None
    ):
        super().__init__(explanation)
        self.code = code
        self.explanation = explanation
        self.technical = technical
        self.evidence = evidence or {}


class AttributeProvider:
    def __init__(self, root: Path):
        self.root = root

    def read(self, name: str):
        try:
            data = strict_json_loads((self.root / f"{name}.json").read_text(encoding="utf-8"))
            if name in ("users", "resources", "scenarios"):
                if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                    raise ValueError("Expected record list")
                if name in ("users", "resources") and any(
                    not isinstance(row.get("attributes"), dict) for row in data
                ):
                    raise ValueError("Expected attribute objects")
                if name in ("users", "resources"):
                    identifiers = [row["attributes"].get("id") for row in data]
                    if any(not isinstance(value, str) or not value for value in identifiers):
                        raise ValueError("Invalid identifier")
                    if len(set(identifiers)) != len(identifiers):
                        raise ValueError("Ambiguous duplicate identifiers")
            elif not isinstance(data, dict):
                raise ValueError("Expected keyed context snapshots")
            return data
        except (OSError, ValueError) as exc:
            raise DecisionError(
                "PROVIDER_UNAVAILABLE", "Cannot read trusted attribute snapshot."
            ) from exc

    def resolve(self, request: AccessRequest, now: datetime, simulation: bool) -> dict:
        if request.failure_mode == "provider_unavailable":
            raise DecisionError("PROVIDER_UNAVAILABLE", "Injected provider outage.")
        resolved = {}
        provenance = {}
        for group, name, identifier, model in (
            ("subject", "users", request.subject_id, Subject),
            ("resource", "resources", request.resource_id, Resource),
        ):
            rows = self.read(name)
            entry = next(
                (row for row in rows if row.get("attributes", {}).get("id") == identifier), None
            )
            if entry is None:
                raise DecisionError(
                    f"UNKNOWN_{group.upper()}", f"Unknown {group} identifier.", False
                )
            values, metadata = self.validate(entry, model, now, name)
            resolved[group] = values
            provenance[group] = metadata
        # Context is required only by the context-aware baseline. No fabricated defaults.
        if request.baseline == "context_abac":
            if request.context is not None:
                if not simulation:
                    raise DecisionError(
                        "CLIENT_CONTEXT_FORBIDDEN", "Context overrides require simulation mode."
                    )
                entry = {
                    "attributes": request.context.model_dump(),
                    "timestamp": now.isoformat(),
                    "ttl_seconds": 300,
                }
                source = "SIMULATION_ONLY/client"
            else:
                entry = self.read("contexts").get(request.subject_id)
                source = "contexts.json/server"
                if entry is None:
                    raise DecisionError("MISSING_ATTRIBUTE", "No trusted context for subject.")
            if not isinstance(entry, dict) or not isinstance(entry.get("attributes"), dict):
                raise DecisionError("INVALID_ATTRIBUTE", "Invalid context snapshot envelope.")
            if request.failure_mode == "missing_attribute":
                entry["attributes"].pop("risk_score", None)
            if request.failure_mode == "stale_attribute":
                entry["timestamp"] = "2000-01-01T00:00:00+00:00"
            values, metadata = self.validate(entry, Context, now, source)
            values["hour"] = (
                datetime.fromisoformat(values["time"].replace("Z", "+00:00"))
                .astimezone(timezone.utc)
                .hour
            )
            resolved["context"] = values
            provenance["context"] = metadata
        resolved["action"] = request.action
        return {"attributes": resolved, "provenance": provenance}

    @staticmethod
    def validate(entry: dict, model, now: datetime, source: str):
        try:
            values = model.model_validate(entry["attributes"]).model_dump()
            timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
            ttl = entry["ttl_seconds"]
            if timestamp.utcoffset() is None or type(ttl) is not int or ttl <= 0:
                raise ValueError("Invalid timestamp/TTL")
            age = (now - timestamp).total_seconds()
            if age < 0:
                raise ValueError("Future timestamp")
            if age >= ttl:
                raise DecisionError(
                    "STALE_ATTRIBUTE",
                    f"Required attributes from {source} expired.",
                    evidence={
                        "source": source,
                        "timestamp": timestamp.isoformat(),
                        "ttl_seconds": ttl,
                        "age_seconds": age,
                        "fresh": False,
                    },
                )
            metadata = {
                key: {
                    "source": source,
                    "timestamp": timestamp.isoformat(),
                    "ttl_seconds": ttl,
                    "age_seconds": age,
                    "fresh": True,
                }
                for key in values
            }
            return values, metadata
        except ValidationError as exc:
            missing = any(item["type"] == "missing" for item in exc.errors())
            code = "MISSING_ATTRIBUTE" if missing else "INVALID_ATTRIBUTE"
            raise DecisionError(
                code,
                f"Required attributes from {source} are missing or invalid.",
                evidence={
                    "source": source,
                    "invalid_fields": [list(item["loc"]) for item in exc.errors()],
                },
            ) from exc
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
            raise DecisionError(
                "INVALID_ATTRIBUTE", f"Invalid attribute envelope from {source}."
            ) from exc
