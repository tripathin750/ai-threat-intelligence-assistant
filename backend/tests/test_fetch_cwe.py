"""Tests mock requests.get, so they run offline and never call MITRE's real API."""

import unittest
from unittest.mock import MagicMock, patch

from backend import fetch_cwe


def _response(payload: object, status_code: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    if status_code >= 400 and status_code != 404:
        response.raise_for_status.side_effect = fetch_cwe.requests.HTTPError("bad status")
    return response


def _weakness(**overrides: object) -> dict:
    weakness: dict[str, object] = {
        "ID": "79",
        "Name": "Improper Neutralization of Input During Web Page Generation",
        "Description": "The product does not neutralize user-controllable input before output.",
        "CommonConsequences": [
            {"Scope": ["Confidentiality"], "Impact": ["Read Application Data"], "Note": "Session theft."}
        ],
        "PotentialMitigations": [
            {"Strategy": "Output Encoding", "Description": "Encode all output for its context."}
        ],
    }
    weakness.update(overrides)
    return weakness


class FetchCweRecordTests(unittest.TestCase):
    def test_normalizes_a_valid_record(self) -> None:
        with patch.object(fetch_cwe.requests, "get", return_value=_response({"Weaknesses": [_weakness()]})) as get:
            record = fetch_cwe.fetch_cwe_record("CWE-79")

        self.assertTrue(get.call_args.args[0].endswith("/weakness/79"))
        self.assertEqual(record.cwe_id, "CWE-79")
        self.assertIn("Improper Neutralization", record.name)
        self.assertIn("Impact: Read Application Data", record.consequences[0])
        self.assertEqual(record.mitigations, ["Output Encoding: Encode all output for its context."])

    def test_leading_zeros_are_normalized_for_the_upstream_path(self) -> None:
        with patch.object(fetch_cwe.requests, "get", return_value=_response({"Weaknesses": [_weakness()]})) as get:
            fetch_cwe.fetch_cwe_record("CWE-0079")

        self.assertTrue(get.call_args.args[0].endswith("/weakness/79"))

    def test_unknown_id_raises_not_found(self) -> None:
        with patch.object(fetch_cwe.requests, "get", return_value=_response("not found", 404)):
            with self.assertRaises(fetch_cwe.CweNotFoundError):
                fetch_cwe.fetch_cwe_record("CWE-99999")

    def test_network_error_raises_request_error(self) -> None:
        with patch.object(fetch_cwe.requests, "get", side_effect=fetch_cwe.requests.ConnectionError("down")):
            with self.assertRaises(fetch_cwe.CweRequestError):
                fetch_cwe.fetch_cwe_record("CWE-79")

    def test_http_error_raises_request_error(self) -> None:
        with patch.object(fetch_cwe.requests, "get", return_value=_response({}, 500)):
            with self.assertRaises(fetch_cwe.CweRequestError):
                fetch_cwe.fetch_cwe_record("CWE-79")

    def test_unexpected_shape_raises_request_error(self) -> None:
        for bad in ({"Weaknesses": []}, {"Weaknesses": ["x"]}, ["not", "a", "dict"], {}):
            with self.subTest(payload=bad):
                with patch.object(fetch_cwe.requests, "get", return_value=_response(bad)):
                    with self.assertRaises(fetch_cwe.CweRequestError):
                        fetch_cwe.fetch_cwe_record("CWE-79")

    def test_record_without_a_name_or_description_is_rejected(self) -> None:
        with patch.object(fetch_cwe.requests, "get", return_value=_response({"Weaknesses": [_weakness(Name="")]})):
            with self.assertRaises(fetch_cwe.CweRequestError):
                fetch_cwe.fetch_cwe_record("CWE-79")

    def test_oversized_fields_and_lists_are_bounded(self) -> None:
        huge = _weakness(
            Description="x " * 5_000,
            CommonConsequences=[{"Impact": ["Impact"], "Note": "n " * 500} for _ in range(20)],
            PotentialMitigations=[{"Strategy": "S", "Description": "d " * 500} for _ in range(20)],
        )
        with patch.object(fetch_cwe.requests, "get", return_value=_response({"Weaknesses": [huge]})):
            record = fetch_cwe.fetch_cwe_record("CWE-79")

        self.assertLessEqual(len(record.description), fetch_cwe.MAX_DESCRIPTION_CHARS)
        self.assertEqual(len(record.consequences), fetch_cwe.MAX_CONSEQUENCES)
        self.assertEqual(len(record.mitigations), fetch_cwe.MAX_MITIGATIONS)
        self.assertTrue(all(len(item) <= fetch_cwe.MAX_ITEM_CHARS + 100 for item in record.mitigations))

    def test_a_malformed_cwe_id_is_rejected_before_any_request(self) -> None:
        with patch.object(fetch_cwe.requests, "get") as get:
            with self.assertRaises(ValueError):
                fetch_cwe.fetch_cwe_record("CWE-79/../../etc")
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
