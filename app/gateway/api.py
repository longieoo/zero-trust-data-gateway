"""Private Gateway application. Only the TLS proxy is an external entry point."""

import hmac
import ipaddress
import logging
import os
import re
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4
from zoneinfo import ZoneInfo

import jwt
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field

from app.gateway.database import Database, ViewPlan
from app.gateway.provider import GatewayProvider
from app.gateway.security import decode_token, issue_token, verify_password, hash_password
from app.gateway.sessions import Sessions, PostgresSessions
from app.gateway.pagination import issue_cursor, read_cursor
from app.gateway.access import AccessStore, attach_access_routes
from app.gateway.audit import AuditStore
from app.gateway.releases import (
    ReleaseRepository,
    local_release,
    engine_revision,
    validate_payload,
    digest,
)
from app.gateway.evaluator import evaluate_snapshot, compare, semantic
from app.attribute_provider import DecisionError
from app.jsonio import strict_json_loads
from app.models import AccessRequest, StrictModel, Subject
from app.services import DecisionService, ROOT

LOG = logging.getLogger("gateway.audit")
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    LOG.addHandler(logging.StreamHandler())
LOG.propagate = False


class ImpactRequest(StrictModel):
    revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    limit: int = Field(default=20, ge=1, le=50)


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


def load_registry(path):
    registry = strict_json_loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(registry, dict) or set(registry) != {"accounts", "devices"}:
        raise ValueError("Invalid registry structure")
    if not isinstance(registry["accounts"], dict) or not isinstance(registry["devices"], dict):
        raise ValueError("Invalid registry collections")
    for name, row in registry["accounts"].items():
        if not isinstance(row, dict) or set(row) != {
            "subject",
            "password_hash",
            "enabled",
            "auth_version",
        }:
            raise ValueError("Invalid account contract")
        if not isinstance(row["password_hash"], str) or not re.fullmatch(
            r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", row["password_hash"]
        ):
            raise ValueError("Invalid password hash contract")
        if "tenant_id" not in row["subject"]:
            raise ValueError("Account must explicitly declare its tenant")
        subject = Subject.model_validate(row["subject"])
        if subject.id != name or type(row["enabled"]) is not bool:
            raise ValueError("Invalid account registry")
        if type(row["auth_version"]) is not int or row["auth_version"] < 1:
            raise ValueError("Invalid authorization version")
    for serial, device in registry["devices"].items():
        if (
            not re.fullmatch(r"[0-9A-F]{1,64}", serial)
            or not isinstance(device, dict)
            or set(device) != {"id", "enabled"}
            or type(device["enabled"]) is not bool
            or not isinstance(device["id"], str)
            or not 1 <= len(device["id"]) <= 100
        ):
            raise ValueError("Invalid device registry")
    return registry


class LoginLimiter:
    def __init__(self):
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, address):
        with self.lock:
            now = time.monotonic()
            # Bound memory; evict only expired entries, never active restrictions.
            for key in list(self.attempts):
                while self.attempts[key] and self.attempts[key][0] < now - 60:
                    self.attempts[key].popleft()
                if not self.attempts[key]:
                    del self.attempts[key]
            if address not in self.attempts and len(self.attempts) >= 4096:
                raise HTTPException(429, "Login capacity exceeded")
            attempts = self.attempts[address]
            if len(attempts) >= 10:
                raise HTTPException(429, "Too many login attempts; retry after one minute")
            attempts.append(now)


def create_app(config=None, database=None, clock=None):
    config = config or {
        "secret": os.environ["GATEWAY_JWT_SECRET"],
        "release_dir": os.environ["GATEWAY_RELEASE_DIR"],
        "trust_file": os.environ["GATEWAY_TRUST_FILE"],
        "audit_file": os.environ["GATEWAY_AUDIT_FILE"],
        "audit_key": os.environ["GATEWAY_AUDIT_KEY"],
        "proxy_secret": os.environ["GATEWAY_PROXY_SECRET"],
        "registry": os.environ["GATEWAY_REGISTRY"],
        "database_url": os.environ["DATABASE_URL"],
        "office_networks": os.getenv("OFFICE_NETWORKS", "127.0.0.0/8,::1/128"),
        "timezone": os.getenv("BUSINESS_TIMEZONE", "Asia/Bangkok"),
        "policy_file": os.getenv("GATEWAY_POLICY_FILE", str(ROOT / "policies/policies.json")),
    }
    if len(config["secret"]) < 32 or len(config["proxy_secret"]) < 32:
        raise ValueError("Gateway secrets must be independently generated, at least 32 characters")
    networks = [
        ipaddress.ip_network(value.strip()) for value in config["office_networks"].split(",")
    ]
    ZoneInfo(config["timezone"])
    load_registry(config["registry"])
    session_url = config.get("session_database_url") or os.getenv("SESSION_DATABASE_URL")
    sessions = (
        PostgresSessions(session_url)
        if session_url
        else Sessions(
            config.get("session_file")
            or os.getenv("GATEWAY_SESSION_FILE")
            or str(Path(config["registry"]).parent / "sessions.sqlite")
        )
    )
    audit_store = AuditStore(config["audit_file"], config["audit_key"])
    releases = (
        ReleaseRepository(config["release_dir"], config["trust_file"])
        if config.get("release_dir")
        else None
    )
    if releases is None and not config.get("allow_unsigned_policies", False):
        raise ValueError("Signed policy releases required")
    db = database or Database(config["database_url"])

    def active_release():
        if releases:
            return releases.active()
        return local_release(list(core.repository.load(core.policy_path)))

    # Every request gets a provider; HTTP client/catalogue repository remain shared.
    core = DecisionService()
    core.simulation = False
    core.dev_failures = False
    core.policy_path = Path(config["policy_file"])
    get_now = clock or (lambda: datetime.now(timezone.utc))
    access_store = AccessStore(
        config.get("access_file") or str(Path(config["audit_file"]).parent / "access.sqlite"),
        clock=get_now,
    )
    grant_required = config.get("grant_required", os.getenv("GATEWAY_GRANT_REQUIRED", ""))
    if isinstance(grant_required, str):
        grant_required = [name.strip() for name in grant_required.split(",") if name.strip()]
    if not set(grant_required) <= {"customers", "financial", "production"}:
        raise ValueError("Unknown grant-required resource")
    limiter = LoginLimiter()
    dummy_hash = hash_password("nonexistent-account-dummy-password")

    @asynccontextmanager
    async def lifespan(app):
        yield
        core.opa.client.close()
        db.close()
        if isinstance(sessions, PostgresSessions):
            sessions.close()

    app = FastAPI(
        title="ABAC Data Gateway", version="5.1.0", lifespan=lifespan, docs_url=None, redoc_url=None
    )
    app.state.database = db
    app.state.core = core
    app.state.sessions = sessions
    app.state.audit = audit_store
    app.state.releases = releases
    app.state.access = access_store
    app.state.grant_required = frozenset(grant_required)

    @app.middleware("http")
    async def private_ingress(request, call_next):
        request_id = str(uuid4())
        request.state.request_id = request_id
        request.state.event = {"db_queried": False}
        audited = request.url.path not in {"/health", "/", "/gateway.js", "/gateway.css"}
        try:
            if audited:
                audit_store.append(request_id, "received", {"method": request.method})
            if request.url.path != "/health" and not hmac.compare_digest(
                request.headers.get("x-gateway-proxy-secret", "").encode(),
                config["proxy_secret"].encode(),
            ):
                request.state.event.update(reason_code="UNTRUSTED_PROXY")
                response = JSONResponse(
                    status_code=403,
                    content={
                        "request_id": request_id,
                        "decision": "DENY",
                        "reason_code": "UNTRUSTED_PROXY",
                        "db_queried": False,
                    },
                )
            else:
                response = await call_next(request)
        except Exception:
            response = JSONResponse(
                status_code=503,
                content={
                    "request_id": request_id,
                    "decision": "DENY",
                    "reason_code": "GATEWAY_FAILURE",
                    "db_queried": request.state.event["db_queried"],
                },
            )
        if audited or response.status_code >= 400:
            subject = getattr(request.state, "subject", {})
            event = {
                **request.state.event,
                "http_status": response.status_code,
                "decision": "DENY"
                if response.status_code >= 400
                else request.state.event.get("decision", "NONE"),
                "route": getattr(request.scope.get("route"), "path", "unmatched"),
            }
            try:
                audit_store.append(
                    request_id,
                    "response",
                    event,
                    tenant=subject.get("tenant_id"),
                    subject=subject.get("id"),
                )
            except Exception:
                # No successful protected response leaves the application without durable audit.
                LOG.error("audit_unavailable request_id=%s", request_id)
                response = JSONResponse(
                    status_code=503,
                    content={
                        "request_id": request_id,
                        "decision": "DENY",
                        "reason_code": "AUDIT_UNAVAILABLE",
                        "db_queried": request.state.event["db_queried"],
                    },
                )
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
        )
        return response

    @app.exception_handler(HTTPException)
    async def rejected(request, exc):
        code = {
            401: "AUTHENTICATION_FAILED",
            403: "UNTRUSTED_CONTEXT",
            404: "UNKNOWN_RESOURCE",
            422: "INVALID_REQUEST",
            429: "RATE_LIMITED",
        }.get(exc.status_code, "REQUEST_REJECTED")
        request.state.event.update(reason_code=code)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "request_id": request.state.request_id,
                "decision": "DENY",
                "reason_code": code,
                "detail": exc.detail,
                "db_queried": False,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        request.state.event.update(reason_code="INVALID_REQUEST")
        return JSONResponse(
            status_code=422,
            content={
                "request_id": request.state.request_id,
                "decision": "DENY",
                "reason_code": "INVALID_REQUEST",
                "db_queried": False,
            },
        )

    def peer(request):
        try:
            # Proxy overwrites this header with its actual TCP peer, not X-Forwarded-For.
            return ipaddress.ip_address(request.headers["x-gateway-client-ip"])
        except (KeyError, ValueError):
            raise HTTPException(403, "Invalid trusted client address") from None

    @app.get("/health")
    def health():
        ready = database_ready = policy_ready = audit_ready = False
        session_ready = access_ready = False
        revision = None
        try:
            release = active_release()
            revision = release["revision"]
            policy_ready = True
            engine = core.opa.client.get("/v1/data/deployment/engine_revision")
            contract = core.opa.client.get("/v1/data/gateway/contract")
            ready = (
                engine.json().get("result") == engine_revision()
                and contract.json().get("result") == "gateway-5.0.0"
            )
        except Exception:
            pass
        try:
            database_ready = db.ready()
            audit_ready = audit_store.ready()
        except Exception:
            pass
        try:
            session_ready = sessions.ready()
            access_ready = access_store.ready()
        except Exception:
            pass
        return JSONResponse(
            status_code=200
            if all((ready, database_ready, policy_ready, audit_ready, session_ready, access_ready))
            else 503,
            content={
                "version": "5.1.0",
                "opa_ready": ready,
                "database_ready": database_ready,
                "policy_ready": policy_ready,
                "audit_ready": audit_ready,
                "session_ready": session_ready,
                "access_ready": access_ready,
                "policy_revision": revision,
            },
        )

    @app.get("/")
    def home():
        return FileResponse(ROOT / "ui/gateway/index.html")

    @app.get("/gateway.js")
    def javascript():
        return FileResponse(ROOT / "ui/gateway/gateway.js", media_type="application/javascript")

    @app.get("/gateway.css")
    def stylesheet():
        return FileResponse(ROOT / "ui/gateway/gateway.css", media_type="text/css")

    @app.post("/auth/login")
    def login(body: Login, request: Request):
        limiter.check(str(peer(request)))
        row = load_registry(config["registry"])["accounts"].get(body.username)
        matched = verify_password(body.password, row["password_hash"] if row else dummy_hash)
        if not row or not matched or not row["enabled"]:
            raise HTTPException(401, "Invalid credentials")
        serial = (
            request.headers.get("x-gateway-device-serial", "").upper()
            if request.headers.get("x-gateway-device-verified") == "SUCCESS"
            else None
        )
        request.state.subject = row["subject"]
        token = issue_token(
            body.username,
            config["secret"],
            row["auth_version"],
            serial,
            row["subject"]["tenant_id"],
        )
        sessions.add(decode_token(token, config["secret"]))
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 600,
            "tenant_id": row["subject"]["tenant_id"],
            "role": row["subject"]["role"],
        }

    def authenticate(request, registry):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Authentication required")
        try:
            claims = decode_token(authorization[7:], config["secret"])
            row = registry["accounts"][claims["sub"]]
            if not row["enabled"] or claims["auth_version"] != row["auth_version"]:
                raise ValueError("Revoked identity")
            if claims["tenant_id"] != row["subject"]["tenant_id"]:
                raise ValueError("Tenant binding changed")
            if not sessions.active(claims):
                raise ValueError("Inactive session")
            actual_serial = (
                request.headers.get("x-gateway-device-serial", "").upper()
                if request.headers.get("x-gateway-device-verified") == "SUCCESS"
                else None
            )
            if claims["device_serial"] != actual_serial:
                raise ValueError("Token device mismatch")
            request.state.claims = claims
            request.state.subject = row["subject"]
            return row["subject"]
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            raise HTTPException(401, "Invalid or expired identity token") from None

    @app.post("/auth/logout")
    def logout(request: Request):
        authenticate(request, load_registry(config["registry"]))
        sessions.revoke(request.state.claims)
        return {"revoked": True}

    def audit_identity(request):
        registry = load_registry(config["registry"])
        subject = authenticate(request, registry)
        serial = request.headers.get("x-gateway-device-serial", "").upper()
        if request.headers.get("x-gateway-device-verified") != "SUCCESS" or not registry[
            "devices"
        ].get(serial, {}).get("enabled"):
            raise HTTPException(403, "Enrolled device required")
        if not any(peer(request) in network for network in networks):
            raise HTTPException(403, "Trusted location required")
        return subject

    attach_access_routes(app, audit_identity, access_store)

    @app.get("/api/v1/catalog")
    def catalog(request: Request):
        subject = audit_identity(request)
        from app.gateway.provider import RESOURCES

        return {
            "tenant_id": subject["tenant_id"],
            "resources": [
                {
                    **value,
                    "pii_columns": ["email", "salary", "national_id"]
                    if name == "customers"
                    else [],
                    "max_page_size": 100,
                    "grant_required": name in app.state.grant_required,
                }
                for name, value in RESOURCES.items()
            ],
        }

    @app.get("/api/v1/policy")
    def policy_status(request: Request):
        audit_identity(request)
        release = active_release()
        return {
            "revision": release["revision"],
            "engine_revision": release["payload"]["engine_revision"],
            "description": release["payload"]["description"],
            "signers": list(release["signatures"]),
            "policy_count": len(release["payload"]["policies"]),
            "signed": bool(releases),
        }

    @app.get("/api/v1/audit")
    def audit_list(request: Request, before: int = 2**63 - 1, limit: int = 20):
        subject = audit_identity(request)
        if not 1 <= limit <= 100 or not 1 <= before <= 2**63 - 1:
            raise HTTPException(422, "Invalid pagination")
        rows = audit_store.list(
            subject["tenant_id"],
            None if subject["role"] == "admin" else subject["id"],
            before,
            limit,
        )
        return {
            "events": rows,
            "next_cursor": rows[-1]["sequence"] if rows else None,
            "tenant_id": subject["tenant_id"],
        }

    def historical(request_id, subject):
        try:
            return audit_store.snapshot(
                request_id,
                subject["tenant_id"],
                None if subject["role"] == "admin" else subject["id"],
            )
        except (InvalidTag, ValueError, KeyError, UnicodeError):
            return None

    def replay_snapshot(snapshot):
        if not isinstance(snapshot, dict) or snapshot.get("schema") != 1:
            return {
                "status": "UNREPLAYABLE",
                "reason": "Historical snapshot unavailable or unauthorized",
                "db_queried": False,
            }
        try:
            release = snapshot["release"]
            validate_payload(release["payload"])
            if digest(release["payload"]) != release["revision"]:
                raise ValueError("Historical revision mismatch")
            current = evaluate_snapshot(core.opa.client, snapshot["attributes"], release)
            return {
                "status": "MATCH"
                if semantic(current) == semantic(snapshot["evaluation"])
                else "MISMATCH",
                "recorded": semantic(snapshot["evaluation"]),
                "replayed": semantic(current),
                "evaluated_at": snapshot["evaluated_at"],
                "policy_revision": release["revision"],
                "scope": "decision_only_no_historical_rows",
                "db_queried": False,
            }
        except (ValueError, KeyError, TypeError, AttributeError, DecisionError):
            return {
                "status": "UNREPLAYABLE",
                "reason": "Interpreter or PDP unavailable/incompatible",
                "db_queried": False,
            }

    @app.post("/api/v1/audit/{request_id}/replay")
    def replay(request_id: str, request: Request):
        subject = audit_identity(request)
        return replay_snapshot(historical(request_id, subject))

    @app.post("/api/v1/policies/impact")
    def impact(body: ImpactRequest, request: Request):
        subject = audit_identity(request)
        if subject["role"] != "admin" or releases is None:
            raise HTTPException(403, "Tenant admin and signed proposal required")
        try:
            candidate = releases.read(body.revision, required=1)
        except Exception:
            raise HTTPException(422, "Invalid signed candidate") from None
        events = audit_store.list(subject["tenant_id"], limit=100)
        records = []
        for event in events:
            if event.get("route") != "/api/v1/data/{resource}":
                continue
            snapshot = historical(event["request_id"], subject)
            original = replay_snapshot(snapshot)
            record = {"request_id": event["request_id"], "status": original["status"]}
            if original["status"] == "MATCH":
                try:
                    after = evaluate_snapshot(core.opa.client, snapshot["attributes"], candidate)
                    record.update(
                        status="COMPARED",
                        changes=compare(snapshot["evaluation"], after),
                        before=semantic(snapshot["evaluation"]),
                        after=semantic(after),
                    )
                except DecisionError:
                    record.update(status="UNREPLAYABLE")
            records.append(record)
            if len(records) >= body.limit:
                break
        return {
            "candidate_revision": body.revision,
            "tenant_id": subject["tenant_id"],
            "records": records,
            "compared": sum(row["status"] == "COMPARED" for row in records),
            "coverage_note": "Bounded historical sample; not a proof over all future inputs",
            "db_queried": False,
        }

    @app.get("/api/v1/data/{resource}")
    def protected_data(resource: str, request: Request):
        params = request.query_params
        if set(params) - {"page_size", "cursor"} or len(params.multi_items()) != len(params):
            raise HTTPException(422, "Unsupported or duplicate query parameter")
        try:
            page_size = int(params["page_size"]) if "page_size" in params else None
            if page_size is not None and not 1 <= page_size <= 100:
                raise ValueError("Page size outside bounds")
            if "cursor" in params and page_size is None:
                raise ValueError("Cursor requires page_size")
        except ValueError:
            raise HTTPException(422, "Invalid pagination") from None
        started = perf_counter()
        registry = load_registry(config["registry"])
        subject = authenticate(request, registry)
        if resource not in {"customers", "financial", "production"}:
            raise HTTPException(404, "Unknown protected resource")
        address = peer(request)
        device = registry["devices"].get(request.headers.get("x-gateway-device-serial", "").upper())
        trusted = request.headers.get("x-gateway-device-verified") == "SUCCESS" and bool(
            device and device["enabled"]
        )
        now = get_now()
        context = {
            "device_trusted": trusted,
            "location": "office" if any(address in network for network in networks) else "external",
            "time": now.isoformat(),
            "risk_score": 10 if trusted else 50,
        }
        provider = GatewayProvider(subject, context, now, config["timezone"])
        access = AccessRequest(subject_id=subject["id"], resource_id=resource, action="read")
        event = request.state.event
        event.update(resource=resource)
        try:
            try:
                release = active_release()
            except Exception as exc:
                raise DecisionError("INVALID_POLICY", "No valid signed active release") from exc
            after_id = 0
            if "cursor" in params:
                try:
                    after_id = read_cursor(
                        params["cursor"],
                        config["secret"],
                        subject,
                        request.state.claims["jti"],
                        resource,
                        release["revision"],
                        page_size,
                        now,
                    )
                except ValueError:
                    event.update(decision="DENY", reason_code="INVALID_CURSOR")
                    return JSONResponse(
                        status_code=422, content={"request_id": request.state.request_id, **event}
                    )
            resolved = provider.resolve(access, now, False)
            evaluation = evaluate_snapshot(core.opa.client, resolved["attributes"], release)
            event.update(
                decision=evaluation["decision"],
                reason_code=evaluation["reason_code"],
                policy_revision=release["revision"],
            )
            snapshot = {
                "schema": 1,
                "attributes": resolved["attributes"],
                "provenance": resolved["provenance"],
                "evaluated_at": now.isoformat(),
                "release": release,
                "evaluation": evaluation,
            }
            audit_store.append(
                request.state.request_id,
                "intent",
                dict(event),
                snapshot,
                subject["tenant_id"],
                subject["id"],
            )
            if evaluation["decision"] != "ALLOW":
                return JSONResponse(
                    status_code=403 if evaluation["decision_status"] == "DENIED_BY_POLICY" else 503,
                    content={"request_id": request.state.request_id, **event},
                )
            plan = ViewPlan.model_validate(evaluation["obligations"])
            if resource in app.state.grant_required:
                grant = access_store.active_grant(subject, resource)
                if grant is None:
                    event.update(decision="DENY", reason_code="ACCESS_APPROVAL_REQUIRED")
                    return JSONResponse(
                        status_code=403, content={"request_id": request.state.request_id, **event}
                    )
                event["access_request_id"] = grant["request_id"]
            tick = perf_counter()
            event["db_queried"] = True
            has_more = False
            if page_size is not None:
                plan = plan.model_copy(update={"limit": min(plan.limit, page_size)})
                rows, has_more = db.page(plan, after_id)
            else:
                rows = db.query(plan)
            database_ms = (perf_counter() - tick) * 1000
        except DecisionError as exc:
            event.update(decision="DENY", reason_code=exc.code)
            return JSONResponse(
                status_code=503, content={"request_id": request.state.request_id, **event}
            )
        except Exception:
            event.update(decision="DENY", reason_code="ENFORCEMENT_FAILURE")
            return JSONResponse(
                status_code=503, content={"request_id": request.state.request_id, **event}
            )
        event.update(row_count=len(rows), obligations=plan.model_dump())
        next_cursor = (
            issue_cursor(
                config["secret"],
                subject,
                request.state.claims["jti"],
                resource,
                release["revision"],
                page_size,
                rows[-1]["id"],
                now,
            )
            if has_more and rows
            else None
        )
        return {
            "request_id": request.state.request_id,
            **event,
            "data": rows,
            "pagination": {
                "page_size": page_size,
                "has_more": has_more,
                "next_cursor": next_cursor,
            },
            "context": {
                **context,
                "tenant_id": subject["tenant_id"],
                "business_timezone": config["timezone"],
                "device_id": device["id"] if trusted else None,
                "source": "verified TLS proxy + server clock",
                "risk_model": "demo-heuristic-v1",
            },
            "metrics": {
                **evaluation["metrics"],
                "database_ms": database_ms,
                "gateway_ms": (perf_counter() - started) * 1000,
            },
        }

    return app
