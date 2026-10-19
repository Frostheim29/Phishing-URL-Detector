"""Minimal configuration for the FastAPI service."""

from __future__ import annotations

import os
import sys
from pathlib import Path


# This location is computed from this file, rather than from the process CWD.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def allowed_origins() -> list[str]:
    """Return comma-separated browser origins from PHISHGUARD_ALLOWED_ORIGINS."""
    defaults = [
        "http://localhost:5173",
        "https://phishing-url-detector-l6tu.onrender.com",
    ]
    value = os.getenv("PHISHGUARD_ALLOWED_ORIGINS")
    origins = value.split(",") if value else defaults
    return [origin.strip().rstrip("/") for origin in origins if origin.strip()]

