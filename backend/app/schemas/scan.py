"""Request and response models for URL scanning."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, StrictStr, field_validator


class ScanRequest(BaseModel):
    url: StrictStr = Field(..., min_length=1, max_length=2048, description="URL to assess")

    @field_validator("url")
    @classmethod
    def strip_and_require_content(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL must not be empty.")
        return value


class ScanResponse(BaseModel):
    url: str
    risk_score: int | float
    risk_level: str
    verdict: str
    model_score: float | None
    heuristic_score: int | float | None
    analysis_mode: Literal["ml_and_heuristic", "heuristic_only"]
    signals: list[str]
    positive_signals: list[str]
    negative_signals: list[str]
    strong_malicious_signals: list[str]
    analysis: dict[str, Any]
    scanned_at: datetime


class BatchScanRequest(BaseModel):
    """A bounded group of URLs to assess without making network requests."""

    urls: list[StrictStr] = Field(..., min_length=1, max_length=100, description="1 to 100 URLs to assess")

    @field_validator("urls")
    @classmethod
    def strip_and_require_urls(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value for value in cleaned):
            raise ValueError("Batch URLs must not be empty.")
        return cleaned


class BatchScanItem(BaseModel):
    """One batch input, represented either by an assessment or an error."""

    url: str
    success: bool
    result: ScanResponse | None = None
    error: str | None = None


class BatchScanSummary(BaseModel):
    processed: int
    successful: int
    failed: int


class BatchScanResponse(BaseModel):
    items: list[BatchScanItem]
    summary: BatchScanSummary


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    model_status: Literal["ready", "unavailable"]
    analysis_mode: Literal["ml_and_heuristic", "heuristic_only"]
