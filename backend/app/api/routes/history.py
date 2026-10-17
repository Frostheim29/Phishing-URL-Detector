from fastapi import APIRouter, Query

from app.schemas.history import HistoryResponse
from app.services.history_service import get_history, get_history_count


router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("", response_model=HistoryResponse)
async def history(
    limit: int = Query(default=50, ge=1, le=100)
) -> HistoryResponse:
    return HistoryResponse(
        items=get_history(limit),
        total=get_history_count(),
    )