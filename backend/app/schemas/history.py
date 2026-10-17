from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class HistoryItem(BaseModel):
    id: int
    url: str
    risk_score: int
    risk_level: str
    verdict: str
    model_score: Optional[float] = None
    heuristic_score: int
    analysis_mode: str
    scanned_at: str


class HistoryResponse(BaseModel):
    items: list[HistoryItem]
    total: int