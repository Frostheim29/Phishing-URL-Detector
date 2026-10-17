"""Single-URL scan endpoint backed exclusively by risk_engine."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from app.core import config
from app.services.history_service import save_scan
from app.schemas.scan import (
    BatchScanItem,
    BatchScanRequest,
    BatchScanResponse,
    BatchScanSummary,
    ScanRequest,
    ScanResponse,
)
from risk_engine import analyze_url_risk


router = APIRouter(prefix="/api", tags=["scan"])


def make_scan_response(result: dict) -> ScanResponse:
    """Map the risk-engine result to the stable public API contract."""
    model_score = result.get("model_score")
    return ScanResponse(
        url=str(result.get("url", "")),
        risk_score=result.get("risk_score", 0),
        risk_level=str(result.get("risk_level", "Medium")),
        verdict=str(result.get("verdict", "Suspicious")),
        model_score=model_score,
        heuristic_score=result.get("heuristic_score"),
        analysis_mode="ml_and_heuristic" if model_score is not None else "heuristic_only",
        signals=list(result.get("signals", [])),
        positive_signals=list(result.get("positive_signals", [])),
        negative_signals=list(result.get("negative_signals", [])),
        strong_malicious_signals=list(result.get("strong_malicious_signals", [])),
        analysis=dict(result.get("analysis", {})),
        scanned_at=datetime.now(timezone.utc),
    )


@router.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest) -> ScanResponse:
    """Assess one URL and save the result to scan history."""
    try:
        result = analyze_url_risk(payload.url)
        response = make_scan_response(result)

        # Save the completed scan to SQLite.
        save_scan(response.model_dump(mode="json"))

        return response
    except Exception:
        # Do not expose implementation details or stack traces to API clients.
        raise HTTPException(
            status_code=500,
            detail="URL assessment could not be completed.",
        )


@router.post("/scan/batch", response_model=BatchScanResponse)
def scan_urls_batch(payload: BatchScanRequest) -> BatchScanResponse:
    """Assess up to 100 URLs, allowing one failure without stopping the batch."""
    items: list[BatchScanItem] = []

    for url in payload.urls:
        try:
            response = make_scan_response(analyze_url_risk(url))
            save_scan(response.model_dump(mode="json"))
            items.append(BatchScanItem(url=url, success=True, result=response))
        except Exception:
            # Keep individual failures opaque and avoid returning partial or invented scores.
            items.append(
                BatchScanItem(
                    url=url,
                    success=False,
                    error="URL assessment could not be completed.",
                )
            )

    successful = sum(item.success for item in items)
    return BatchScanResponse(
        items=items,
        summary=BatchScanSummary(
            processed=len(items),
            successful=successful,
            failed=len(items) - successful,
        ),
    )
