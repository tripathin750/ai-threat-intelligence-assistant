"""Tests mock requests.get, so they run offline and never call the real
FIRST.org EPSS API.
"""

import unittest
from unittest.mock import MagicMock, patch

from backend import fetch_epss


def _response(payload: object, status_ok: bool = True) -> MagicMock:
    response = MagicMock()
    response.json.return_value = payload
    if not status_ok:
        response.raise_for_status.side_effect = fetch_epss.requests.HTTPError("bad status")
    return response


class FetchEpssScoresTests(unittest.TestCase):
    def test_maps_a_valid_response_to_a_cve_to_score_dict(self) -> None:
        payload = [
            {"cve": "CVE-2026-10001", "epss": "0.123450000", "percentile": "0.5", "date": "2026-09-08"},
            {"cve": "CVE-2026-10002", "epss": "0.987650000", "percentile": "0.99", "date": "2026-09-08"},
        ]
        with patch.object(fetch_epss.requests, "get", return_value=_response(payload)):
            scores = fetch_epss.fetch_epss_scores(["CVE-2026-10001", "CVE-2026-10002"])

        self.assertAlmostEqual(scores["CVE-2026-10001"], 0.12345)
        self.assertAlmostEqual(scores["CVE-2026-10002"], 0.98765)

    def test_a_cve_missing_from_the_response_is_simply_absent(self) -> None:
        payload = [{"cve": "CVE-2026-10001", "epss": "0.5", "percentile": "0.5", "date": "2026-09-08"}]
        with patch.object(fetch_epss.requests, "get", return_value=_response(payload)):
            scores = fetch_epss.fetch_epss_scores(["CVE-2026-10001", "CVE-2026-99999"])

        self.assertEqual(set(scores.keys()), {"CVE-2026-10001"})

    def test_malformed_entries_are_skipped_not_fatal(self) -> None:
        payload = [
            {"cve": "CVE-2026-10001", "epss": "not-a-number"},
            {"cve": None, "epss": "0.5"},
            "not-a-dict",
            {"cve": "CVE-2026-10002", "epss": "0.5"},
        ]
        with patch.object(fetch_epss.requests, "get", return_value=_response(payload)):
            scores = fetch_epss.fetch_epss_scores(["CVE-2026-10001", "CVE-2026-10002"])

        self.assertEqual(set(scores.keys()), {"CVE-2026-10002"})

    def test_a_non_list_response_yields_no_scores(self) -> None:
        with patch.object(fetch_epss.requests, "get", return_value=_response({"status": "OK"})):
            scores = fetch_epss.fetch_epss_scores(["CVE-2026-10001"])

        self.assertEqual(scores, {})

    def test_duplicate_and_blank_ids_are_deduplicated_before_the_request(self) -> None:
        mock_get = MagicMock(return_value=_response([]))
        with patch.object(fetch_epss.requests, "get", mock_get):
            fetch_epss.fetch_epss_scores(["cve-2026-10001", "CVE-2026-10001", "", "  "])

        requested = mock_get.call_args.kwargs["params"]["cve"]
        self.assertEqual(requested, "CVE-2026-10001")

    def test_a_large_batch_is_chunked_into_multiple_requests(self) -> None:
        many_ids = [f"CVE-2026-{10000 + i}" for i in range(150)]
        mock_get = MagicMock(return_value=_response([]))
        with patch.object(fetch_epss.requests, "get", mock_get):
            fetch_epss.fetch_epss_scores(many_ids)

        self.assertEqual(mock_get.call_count, 2)

    def test_a_network_error_raises_epss_request_error(self) -> None:
        with patch.object(fetch_epss.requests, "get", side_effect=fetch_epss.requests.ConnectionError("down")):
            with self.assertRaises(fetch_epss.EpssRequestError):
                fetch_epss.fetch_epss_scores(["CVE-2026-10001"])


if __name__ == "__main__":
    unittest.main()
