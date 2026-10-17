"""Health endpoint using the actual risk-engine model availability."""

from __future__ import annotations

from fastapi import APIRouter

from app.core import config  # Ensures repository root is on sys.path before import.
from app.schemas.scan import HealthResponse
from risk_engine import analyze_url_risk


router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Report ready/degraded based on a real, safe risk-engine probe."""
    result = analyze_url_risk("https://example.com")
    if result.get("model_score") is None:
        return HealthResponse(status="degraded", model_status="unavailable", analysis_mode="heuristic_only")
    return HealthResponse(status="ok", model_status="ready", analysis_mode="ml_and_heuristic")
