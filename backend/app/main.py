"""FastAPI entry point for the PhishGuard detector API."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import health, history, scan
from app.core.config import allowed_origins
from app.services.history_service import init_database

app = FastAPI(title="PhishGuard API", version="0.1.0")
init_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Return concise JSON validation errors without internal details."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid scan request.", "errors": jsonable_encoder(exc.errors())},
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(_: Request, __: Exception) -> JSONResponse:
    """Keep unexpected server errors opaque to normal API users."""
    return JSONResponse(status_code=500, content={"detail": "An unexpected server error occurred."})


app.include_router(health.router)
app.include_router(scan.router)
app.include_router(history.router)
