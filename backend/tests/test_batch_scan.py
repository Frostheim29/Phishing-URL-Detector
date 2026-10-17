from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from pydantic import ValidationError


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.api.routes.scan import scan_urls_batch
from app.schemas.scan import BatchScanRequest


def engine_result(url: str) -> dict:
    return {
        "url": url, "risk_score": 12, "risk_level": "Low", "verdict": "Likely Safe",
        "model_score": 10.0, "heuristic_score": 15, "signals": [], "positive_signals": ["Uses HTTPS"],
        "negative_signals": [], "strong_malicious_signals": [], "analysis": {"valid": True},
    }


class BatchScanTests(TestCase):
    def test_request_rejects_empty_and_oversized_batches(self) -> None:
        with self.assertRaises(ValidationError):
            BatchScanRequest(urls=[])
        with self.assertRaises(ValidationError):
            BatchScanRequest(urls=["https://example.com"] * 101)
        with self.assertRaises(ValidationError):
            BatchScanRequest(urls=["   "])

    @patch("app.api.routes.scan.save_scan")
    @patch("app.api.routes.scan.analyze_url_risk")
    def test_batch_persists_successful_assessments(self, analyze, save) -> None:
        analyze.side_effect = lambda url: engine_result(url)
        response = scan_urls_batch(BatchScanRequest(urls=["https://one.example", "https://two.example"]))
        self.assertEqual(response.summary.processed, 2)
        self.assertEqual(response.summary.successful, 2)
        self.assertEqual(response.summary.failed, 0)
        self.assertTrue(all(item.success for item in response.items))
        self.assertEqual(save.call_count, 2)

    @patch("app.api.routes.scan.save_scan")
    @patch("app.api.routes.scan.analyze_url_risk")
    def test_one_url_failure_does_not_discard_other_results(self, analyze, save) -> None:
        analyze.side_effect = [engine_result("https://good.example"), RuntimeError("model issue")]
        response = scan_urls_batch(BatchScanRequest(urls=["https://good.example", "https://bad.example"]))
        self.assertEqual(response.summary.successful, 1)
        self.assertEqual(response.summary.failed, 1)
        self.assertTrue(response.items[0].success)
        self.assertIsNotNone(response.items[0].result)
        self.assertFalse(response.items[1].success)
        self.assertIsNone(response.items[1].result)
        self.assertEqual(response.items[1].error, "URL assessment could not be completed.")
        self.assertEqual(save.call_count, 1)
