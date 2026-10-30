"""FastAPI app: POST /v1/explain and GET /health.

Only codelens-api calls this service, server to server, with a shared secret
in X-CodeLens-Key. With no secret configured, every /v1 route refuses with
503: the service never runs open.

Code snippets and PR titles are never logged.
"""

from __future__ import annotations

import hmac
import logging
from functools import lru_cache

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.llm import FindingExplainer, build_explainer
from app.models import ExplainRequest, ExplainResponse, ExplainResult, HealthResponse

logger = logging.getLogger("ai-service")


class ApiError(Exception):
    """An error with a fixed JSON body, returned as-is (no FastAPI "detail" wrapper)."""

    def __init__(self, status_code: int, body: dict[str, str]) -> None:
        super().__init__(body.get("error", "error"))
        self.status_code = status_code
        self.body = body


app = FastAPI(
    title="CodeLens AI ai-service",
    version="1.0.0",
    # Server-to-server only; no public API explorer.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.exception_handler(ApiError)
async def _api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.body)


def settings_dependency() -> Settings:
    return get_settings()


def require_codelens_key(request: Request, settings: Settings = Depends(settings_dependency)) -> None:
    expected = settings.codelens_shared_key
    if not expected:
        raise ApiError(503, {"error": "not_configured"})
    supplied = request.headers.get("X-CodeLens-Key", "")
    if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        raise ApiError(401, {"error": "unauthorized"})


@lru_cache(maxsize=4)
def _cached_explainer(settings: Settings) -> FindingExplainer | None:
    # Settings is a frozen dataclass, so a config change gets a fresh model.
    return build_explainer(settings)


def explainer_dependency(
    settings: Settings = Depends(settings_dependency),
) -> FindingExplainer | None:
    return _cached_explainer(settings)


@app.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(settings_dependency)) -> HealthResponse:
    return HealthResponse(status="ok", provider=settings.effective_provider)


@app.post(
    "/v1/explain",
    response_model=ExplainResponse,
    dependencies=[Depends(require_codelens_key)],
)
async def explain(
    body: ExplainRequest,
    explainer: FindingExplainer | None = Depends(explainer_dependency),
) -> ExplainResponse:
    if explainer is None:
        raise ApiError(503, {"error": "llm_unavailable"})

    outcomes = await explainer.explain_all(body)

    results = [
        ExplainResult(
            id=o.finding_id,
            explanation=o.value.explanation,
            suggested_fix=o.value.suggested_fix,
            verdict=o.value.verdict,
            verdict_reason=o.value.verdict_reason,
        )
        for o in outcomes
        if o.status == "ok" and o.value is not None
    ]
    for o in outcomes:
        if o.status != "ok":
            logger.info("Finding %s omitted: %s (%s)", o.finding_id, o.status, o.reason)

    # Every call failed at the provider: the LLM is down, not merely wrong.
    if all(o.status == "unavailable" for o in outcomes):
        logger.warning("LLM unavailable for all %d findings", len(outcomes))
        raise ApiError(503, {"error": "llm_unavailable"})

    return ExplainResponse(model=explainer.model_name, results=results)
