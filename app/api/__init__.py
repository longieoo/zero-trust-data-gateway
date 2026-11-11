"""FastAPI transport; minimal enforcement lives only in /protected."""

from uuid import uuid4
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.models import AccessRequest
from app.services import DecisionService

service = DecisionService()


@asynccontextmanager
async def lifespan(app):
    try:
        yield
    finally:
        service.opa.client.close()


app = FastAPI(title="Zero Trust Policy Decision Lab", version="2.0.0", lifespan=lifespan)


@app.exception_handler(Exception)
async def unexpected_failure(request: Request, exc: Exception):
    # No protected resource is returned on any unexpected transport/server failure.
    result = {
        "request_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": "DENY",
        "decision_status": "DENIED_DUE_TO_TECHNICAL_FAILURE",
        "reason_code": "INTERNAL_ERROR",
        "explanation": "Authorization could not be completed.",
    }
    return JSONResponse(
        status_code=503, content={**result, "trace": {**result, "stages": ["failed_closed"]}}
    )


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    result = {
        "request_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": "DENY",
        "decision_status": "DENIED_DUE_TO_TECHNICAL_FAILURE",
        "reason_code": "MALFORMED_REQUEST",
        "explanation": "Request schema validation failed.",
    }
    return JSONResponse(
        status_code=422,
        content={**result, "trace": {**result, "stages": ["request_validation_failed"]}},
    )


@app.get("/health")
def health():
    try:
        response = service.opa.client.get("/health")
        engine = service.opa.client.get("/v1/data/capstone/engine_version")
        opa_ready = response.status_code == 200 and engine.json().get("result") == "2.0.0"
    except Exception:
        opa_ready = False
    return {
        "api": "ready",
        "opa_ready": opa_ready,
        "simulation": service.simulation,
        "failure_injection": service.dev_failures,
        "version": "2.0.0",
        "catalogue_cache": service.opa.cache_catalogues,
        "benchmark_instance": os.getenv("BENCHMARK_INSTANCE"),
    }


@app.get("/subjects")
def subjects():
    return [row["attributes"] for row in service.provider.read("users")]


@app.get("/resources")
def resources():
    return [row["attributes"] for row in service.provider.read("resources")]


@app.get("/scenarios")
def scenarios():
    return service.provider.read("scenarios")


@app.post("/evaluate")
def evaluate(request: AccessRequest):
    return service.evaluate(request)


@app.post("/protected")
def protected(request: AccessRequest):
    decision = service.evaluate(request)
    return {
        "authorization": decision,
        "resource": {"content": "Synthetic protected content"}
        if decision["decision"] == "ALLOW"
        else None,
    }
