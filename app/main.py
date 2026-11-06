from typing import Any, Dict
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.schemas import GatewayRequest
from app.engine import (
    ComplianceEngine,
    ComplianceEngineCrashError,
    TokenSmugglingError,
    QuotaExceededError,
)

# Initialize default engine instance
engine_instance = ComplianceEngine()


def get_compliance_engine() -> ComplianceEngine:
    """Dependency provider for ComplianceEngine to facilitate test injection and overrides."""
    return engine_instance


app = FastAPI(
    title="Zero-Trust LLM Compliance Gateway",
    version="1.0.0",
    description="Compliance gateway enforcing zero-trust data contracts, PII masking, and fail-closed availability.",
)


@app.exception_handler(ComplianceEngineCrashError)
async def compliance_engine_crash_handler(request, exc: ComplianceEngineCrashError):
    """
    Fail-closed policy: If the compliance engine crashes or is unavailable,
    immediately reject incoming traffic at the network boundary with HTTP 503.
    """
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": "Compliance Engine is unavailable. Fail-closed policy active.",
            "error": str(exc),
        },
    )


@app.exception_handler(TokenSmugglingError)
async def token_smuggling_handler(request, exc: TokenSmugglingError):
    """
    Fail-closed security policy: Reject manual attempts to smuggle pre-existing tokens with HTTP 400.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": "Security Violation: Token smuggling detected.",
            "error": str(exc),
        },
    )


@app.exception_handler(QuotaExceededError)
async def quota_exceeded_handler(request, exc: QuotaExceededError):
    """
    Fail-closed quota policy: Return HTTP 429 Too Many Requests with Retry-After header.
    """
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit / token quota exceeded.",
            "error": str(exc),
        },
        headers={"Retry-After": "86400"},
    )


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System"])
async def health_check(
    engine: ComplianceEngine = Depends(get_compliance_engine),
) -> Dict[str, Any]:
    """
    Health-check endpoint. Fails closed with HTTP 503 if the compliance engine
    has crashed or reports unhealthy.
    """
    try:
        health_info = await engine.health_check_async(raise_on_crash=True)
        return health_info
    except ComplianceEngineCrashError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Compliance Gateway Unhealthy: {exc}",
        )


@app.post(
    "/mask",
    response_model=GatewayRequest,
    status_code=status.HTTP_200_OK,
    tags=["Compliance"],
)
@app.post(
    "/api/v1/mask",
    response_model=GatewayRequest,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def mask_payload(
    request: GatewayRequest,
    engine: ComplianceEngine = Depends(get_compliance_engine),
) -> GatewayRequest:
    """
    Mask sensitive PII in the prompt with ephemeral session-scoped tokens.
    Fails closed with HTTP 503 if the engine experiences a crash.
    """
    await engine.health_check_async(raise_on_crash=True)
    return await engine.mask_request_async(request)


@app.post(
    "/unmask",
    response_model=GatewayRequest,
    status_code=status.HTTP_200_OK,
    tags=["Compliance"],
)
@app.post(
    "/api/v1/unmask",
    response_model=GatewayRequest,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def unmask_payload(
    request: GatewayRequest,
    engine: ComplianceEngine = Depends(get_compliance_engine),
) -> GatewayRequest:
    """
    Reverse ephemeral session-scoped tokens back into original PII.
    Fails closed with HTTP 503 if the engine experiences a crash.
    """
    await engine.health_check_async(raise_on_crash=True)
    return await engine.unmask_request_async(request)
