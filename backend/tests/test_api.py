from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services import history_service


def engine_result(url: str, *, model_score: float | None = 12.5) -> dict:
    return {
        "url": url,
        "risk_score": 18,
        "risk_level": "Low",
        "verdict": "Likely Safe",
        "model_score": model_score,
        "heuristic_score": 20,
        "signals": ["Uses HTTPS"],
        "positive_signals": ["Uses HTTPS"],
        "negative_signals": [],
        "strong_malicious_signals": [],
        "analysis": {"valid": True, "host": "example.test"},
    }


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Provide the real app with a fresh on-disk SQLite database per test."""
    monkeypatch.setattr(history_service, "DB_PATH", tmp_path / "phishguard-test.db")
    from app.main import app

    history_service.init_database()
    with TestClient(app) as test_client:
        yield test_client


def test_health_reports_engine_mode_without_network(client: TestClient) -> None:
    with patch("app.api.routes.health.analyze_url_risk", return_value=engine_result("https://example.test")):
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "model_status": "ready", "analysis_mode": "ml_and_heuristic"}


def test_scan_returns_contract_and_persists_history(client: TestClient) -> None:
    with patch("app.api.routes.scan.analyze_url_risk", side_effect=lambda url: engine_result(url)):
        response = client.post("/api/scan", json={"url": "https://example.test"})
    assert response.status_code == 200
    body = response.json()
    assert body["url"] == "https://example.test"
    assert body["risk_score"] == 18
    assert body["analysis_mode"] == "ml_and_heuristic"
    assert body["scanned_at"]
    history = client.get("/api/history?limit=50")
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["items"][0]["url"] == "https://example.test"


@pytest.mark.parametrize("payload", [{}, {"url": "   "}, {"url": "x" * 2049}])
def test_scan_rejects_invalid_payloads(client: TestClient, payload: dict) -> None:
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid scan request."


def test_batch_rejects_more_than_25_urls(client: TestClient) -> None:
    response = client.post("/api/scan/batch", json={"urls": ["https://example.test"] * 26})
    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid scan request."


def test_batch_keeps_successes_when_one_item_fails_and_persists_them(client: TestClient) -> None:
    side_effect = [engine_result("https://good.test"), RuntimeError("unexpected engine failure")]
    with patch("app.api.routes.scan.analyze_url_risk", side_effect=side_effect):
        response = client.post("/api/scan/batch", json={"urls": ["https://good.test", "https://bad.test"]})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == {"processed": 2, "successful": 1, "failed": 1}
    assert body["items"][0]["success"] is True
    assert body["items"][1] == {"url": "https://bad.test", "success": False, "result": None, "error": "URL assessment could not be completed."}
    assert client.get("/api/history?limit=50").json()["total"] == 1


def test_request_body_over_64_kb_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/scan",
        content=b" " * (64 * 1024 + 1),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body is too large."



def test_request_body_over_64_kb_without_content_length_is_rejected() -> None:
    import asyncio

    from app.main import RequestBodyLimitMiddleware

    body = b" " * (64 * 1024 + 1)
    sent_messages = []
    app_called = False

    async def downstream_app(scope, receive, send):
        nonlocal app_called
        app_called = True

    async def receive():
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    async def send(message):
        sent_messages.append(message)

    async def run_test():
        middleware = RequestBodyLimitMiddleware(downstream_app)

        # Deliberately omit the Content-Length header.
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/scan",
            "raw_path": b"/api/scan",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }

        await middleware(scope, receive, send)

    asyncio.run(run_test())

    assert not app_called
    assert sent_messages[0]["status"] == 413

    response_body = sent_messages[1]["body"]
    assert b"Request body is too large." in response_body

 