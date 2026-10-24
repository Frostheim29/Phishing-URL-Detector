
"""FastAPI entry point for the PhishGuard detector API."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.limits import limiter

from app.api.routes import health, history, scan
from app.core.config import allowed_origins
from app.services.history_service import init_database

logger = logging.getLogger(__name__)

class RequestBodyLimitMiddleware:
    """Reject HTTP request bodies larger than the configured limit."""

    def __init__(self, app, max_body_size: int = 64 * 1024):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    response = JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length header."},
                    )
                    await response(scope, receive, send)
                    return
                break

        if content_length is not None and content_length > self.max_body_size:
            response = JSONResponse(
                status_code=413,
                content={"detail": "Request body is too large."},
            )
            await response(scope, receive, send)
            return

        body_parts = []
        total_size = 0

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")
            total_size += len(chunk)

            if total_size > self.max_body_size:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body is too large."},
                )
                await response(scope, receive, send)
                return

            body_parts.append(chunk)

            if not message.get("more_body", False):
                break

        body = b"".join(body_parts)
        body_sent = False

        async def replay_body():
            nonlocal body_sent

            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            return await receive()

        await self.app(scope, replay_body, send)

app = FastAPI(title="PhishGuard API", version="0.1.0")

app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=64 * 1024,
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)

init_database()

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)



@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add basic browser security headers to API responses."""
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a generic validation error without exposing submitted input."""
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid scan request."},
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Log server-side details while returning a generic error to clients."""
    logger.error(
        "Unhandled server error on %s %s",
        request.method,
        request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )

    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred."},
    )


app.include_router(health.router)
app.include_router(scan.router)
app.include_router(history.router)
