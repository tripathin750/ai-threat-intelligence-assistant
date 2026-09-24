"""Tests use an isolated in-memory SQLite database and mocked MITRE/Gemini
calls, so they run offline and never touch real services or the real database.
"""

from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.fetch_cwe import CweNotFoundError, CweRecordSchema, CweRequestError
from backend.models import CweFaultTree
from backend.services import fault_tree_service
from backend.services.llm_service import LLMAnalysisError


def _record(**overrides: object) -> CweRecordSchema:
    data: dict[str, object] = {
        "cwe_id": "CWE-79",
        "name": "Cross-site Scripting",
        "description": "The product does not neutralize user-controllable input.",
        "consequences": ["Impact: Read Application Data, Bypass Protection Mechanism; Scope: Confidentiality; Session theft."],
        "mitigations": [
            "Output Encoding: Encode all output for its context.",
            "Input Validation: Validate input against an allow-list.",
        ],
    }
    data.update(overrides)
    return CweRecordSchema(**data)


def _llm_tree_json() -> str:
    return json.dumps({
        "root_id": "n1",
        "nodes": [
            {"id": "n1", "label": "XSS is exploited", "gate": "AND", "children": ["n2", "n3"]},
            {"id": "n2", "label": "Untrusted input reaches output", "gate": "NONE", "children": []},
            {"id": "n3", "label": "Output is not encoded", "gate": "NONE", "children": []},
        ],
    })


def _enabled():
    return replace(fault_tree_service.settings, gemini_api_key="test-key", enable_llm_analysis=True)


def _disabled():
    return replace(fault_tree_service.settings, gemini_api_key=None, enable_llm_analysis=False)


class FaultTreeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()

    def test_template_tree_is_valid_and_grounded_in_the_record(self) -> None:
        tree = fault_tree_service.build_template_tree(_record())
        labels = [node.label for node in tree.nodes]

        root = next(node for node in tree.nodes if node.id == tree.root_id)
        self.assertEqual(root.gate, "INHIBIT")
        self.assertTrue(root.condition)
        self.assertIn("Read Application Data", root.label)
        gates = {node.gate for node in tree.nodes}
        self.assertTrue({"AND", "OR", "INHIBIT", "NONE"} <= gates)
        self.assertTrue(all(node.reason for node in tree.nodes), "every template node explains itself")
        self.assertTrue(any("Output Encoding" in label for label in labels))
        self.assertTrue(any("Input Validation" in label for label in labels))

    def test_template_tree_is_valid_for_a_record_with_no_mitigations_or_consequences(self) -> None:
        tree = fault_tree_service.build_template_tree(_record(mitigations=[], consequences=[]))

        self.assertGreaterEqual(len(tree.nodes), 6)

    def test_llm_disabled_uses_the_template_and_never_calls_gemini(self) -> None:
        with patch.object(fault_tree_service, "settings", _disabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json") as gemini:
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        gemini.assert_not_called()
        self.assertEqual(result.source, fault_tree_service.TEMPLATE_SOURCE)
        self.assertEqual(result.cwe_name, "Cross-site Scripting")

    def test_llm_result_is_used_and_labelled_when_enabled(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertTrue(result.source.startswith("gemini:"))
        self.assertEqual([node.id for node in result.tree.nodes], ["n1", "n2", "n3"])

    def test_the_prompt_puts_mitre_text_in_a_data_block(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()) as gemini:
            fault_tree_service.get_fault_tree(self.db, "CWE-79")

        system_prompt, user_prompt = gemini.call_args.args[0], gemini.call_args.args[1]
        self.assertIn("never instructions", system_prompt)
        self.assertIn("<cwe_record>", user_prompt)
        self.assertIn("Cross-site Scripting", user_prompt)

    def test_an_invalid_llm_tree_falls_back_and_is_labelled(self) -> None:
        cyclic = json.dumps({
            "root_id": "n1",
            "nodes": [
                {"id": "n1", "label": "top", "gate": "AND", "children": ["n2", "n3"]},
                {"id": "n2", "label": "loop", "gate": "OR", "children": ["n1", "n3"]},
                {"id": "n3", "label": "leaf", "gate": "NONE", "children": []},
            ],
        })
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", return_value=cyclic):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertEqual(result.source, f"{fault_tree_service.TEMPLATE_SOURCE}-fallback")

    def test_an_llm_outage_falls_back_and_is_labelled(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", side_effect=LLMAnalysisError("boom")):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertEqual(result.source, f"{fault_tree_service.TEMPLATE_SOURCE}-fallback")

    def test_an_unexpected_llm_failure_also_falls_back(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", side_effect=RuntimeError("unexpected")):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertEqual(result.source, f"{fault_tree_service.TEMPLATE_SOURCE}-fallback")

    def test_second_request_is_served_from_the_cache(self) -> None:
        with patch.object(fault_tree_service, "settings", _disabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()) as fetch:
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
            fault_tree_service.get_fault_tree(self.db, "cwe-79")

        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.db.query(CweFaultTree).count(), 1)

    def test_refresh_regenerates_and_updates_the_cached_row(self) -> None:
        with patch.object(fault_tree_service, "settings", _disabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()) as fetch:
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()) as fetch, \
             patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79", refresh=True)

        self.assertEqual(fetch.call_count, 1)
        self.assertTrue(result.source.startswith("gemini:"))
        self.assertEqual(self.db.query(CweFaultTree).count(), 1)

    def _age_cached_row(self, minutes: int) -> None:
        from datetime import datetime, timedelta, timezone
        row = self.db.query(CweFaultTree).one()
        row.generated_at = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        self.db.commit()

    def test_a_fresh_fallback_is_served_without_retrying_gemini(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()),              patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()),              patch.object(fault_tree_service, "call_gemini_json", side_effect=LLMAnalysisError("down")) as gemini:
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertEqual(gemini.call_count, 1)
        self.assertTrue(result.source.endswith("-fallback"))

    def test_an_old_fallback_is_retried_and_replaced_by_a_gemini_tree(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()),              patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()),              patch.object(fault_tree_service, "call_gemini_json", side_effect=LLMAnalysisError("down")):
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
        self._age_cached_row(minutes=11)
        with patch.object(fault_tree_service, "settings", _enabled()),              patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()),              patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()) as gemini:
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        gemini.assert_called_once()
        self.assertTrue(result.source.startswith("gemini:"))
        self.assertEqual(self.db.query(CweFaultTree).count(), 1)

    def test_an_old_fallback_is_kept_when_the_llm_is_disabled(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()),              patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()),              patch.object(fault_tree_service, "call_gemini_json", side_effect=LLMAnalysisError("down")):
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
        self._age_cached_row(minutes=60)
        with patch.object(fault_tree_service, "settings", _disabled()),              patch.object(fault_tree_service, "fetch_cwe_record") as fetch:
            fault_tree_service.get_fault_tree(self.db, "CWE-79")

        fetch.assert_not_called()

    def test_a_gemini_tree_is_never_treated_as_stale(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()),              patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()),              patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()) as gemini:
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
            self._age_cached_row(minutes=600)
            fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertEqual(gemini.call_count, 1)

    def test_deferred_mode_answers_with_the_template_at_once_and_never_calls_gemini(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json") as gemini:
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79", defer_llm=True)

        gemini.assert_not_called()
        self.assertTrue(result.upgrading)
        self.assertEqual(result.source, f"{fault_tree_service.TEMPLATE_SOURCE}-fallback")
        self.assertEqual(self.db.query(CweFaultTree).count(), 1)

    def test_deferred_mode_with_a_fresh_gemini_tree_is_not_upgrading(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()):
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79", defer_llm=True)

        self.assertFalse(result.upgrading)
        self.assertTrue(result.source.startswith("gemini:"))

    def test_deferred_refresh_keeps_serving_the_cached_tree_while_upgrading(self) -> None:
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()):
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79", refresh=True, defer_llm=True)

        self.assertTrue(result.upgrading)
        self.assertTrue(result.source.startswith("gemini:"), "the good tree stays visible during the refresh")

    def test_deferred_mode_with_the_llm_disabled_is_immediate_and_not_upgrading(self) -> None:
        with patch.object(fault_tree_service, "settings", _disabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79", defer_llm=True)

        self.assertFalse(result.upgrading)
        self.assertEqual(result.source, fault_tree_service.TEMPLATE_SOURCE)

    def test_upgrade_job_replaces_the_template_with_gemini_and_releases_its_claim(self) -> None:
        maker = sessionmaker(bind=self.engine)
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "SessionLocal", maker), \
             patch.object(fault_tree_service, "call_gemini_json", return_value=_llm_tree_json()) as gemini:
            fault_tree_service.get_fault_tree(self.db, "CWE-79", defer_llm=True)
            self.assertTrue(fault_tree_service.claim_upgrade("CWE-79"))
            self.assertFalse(fault_tree_service.claim_upgrade("CWE-79"), "no second job while one runs")
            fault_tree_service.upgrade_fault_tree("CWE-79")

        self.assertEqual(gemini.call_args.kwargs["timeout"], fault_tree_service.LLM_BACKGROUND_TIMEOUT_SECONDS)
        self.db.expire_all()
        self.assertTrue(self.db.get(CweFaultTree, "CWE-79").source.startswith("gemini:"))
        self.assertFalse(fault_tree_service.is_upgrading("CWE-79"))

    def test_upgrade_job_that_fails_keeps_a_valid_fallback_and_releases_its_claim(self) -> None:
        maker = sessionmaker(bind=self.engine)
        with patch.object(fault_tree_service, "settings", _enabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()), \
             patch.object(fault_tree_service, "SessionLocal", maker), \
             patch.object(fault_tree_service, "call_gemini_json", side_effect=LLMAnalysisError("busy")):
            fault_tree_service.get_fault_tree(self.db, "CWE-79", defer_llm=True)
            fault_tree_service.claim_upgrade("CWE-79")
            fault_tree_service.upgrade_fault_tree("CWE-79")

        self.db.expire_all()
        self.assertTrue(self.db.get(CweFaultTree, "CWE-79").source.endswith("-fallback"))
        self.assertFalse(fault_tree_service.is_upgrading("CWE-79"))

    def test_upgrade_job_releases_its_claim_even_when_mitre_is_down(self) -> None:
        maker = sessionmaker(bind=self.engine)
        with patch.object(fault_tree_service, "fetch_cwe_record", side_effect=CweRequestError("down")), \
             patch.object(fault_tree_service, "SessionLocal", maker):
            fault_tree_service.claim_upgrade("CWE-79")
            fault_tree_service.upgrade_fault_tree("CWE-79")  # must not raise

        self.assertFalse(fault_tree_service.is_upgrading("CWE-79"))

    def test_unknown_cwe_propagates_and_caches_nothing(self) -> None:
        with patch.object(fault_tree_service, "fetch_cwe_record", side_effect=CweNotFoundError("nope")):
            with self.assertRaises(CweNotFoundError):
                fault_tree_service.get_fault_tree(self.db, "CWE-99999")

        self.assertEqual(self.db.query(CweFaultTree).count(), 0)

    def test_mitre_outage_with_no_cache_propagates(self) -> None:
        with patch.object(fault_tree_service, "fetch_cwe_record", side_effect=CweRequestError("down")):
            with self.assertRaises(CweRequestError):
                fault_tree_service.get_fault_tree(self.db, "CWE-79")

    def test_a_cached_tree_still_serves_when_mitre_is_down(self) -> None:
        with patch.object(fault_tree_service, "settings", _disabled()), \
             patch.object(fault_tree_service, "fetch_cwe_record", return_value=_record()):
            fault_tree_service.get_fault_tree(self.db, "CWE-79")
        with patch.object(fault_tree_service, "fetch_cwe_record", side_effect=CweRequestError("down")):
            result = fault_tree_service.get_fault_tree(self.db, "CWE-79")

        self.assertEqual(result.cwe_id, "CWE-79")


if __name__ == "__main__":
    unittest.main()
