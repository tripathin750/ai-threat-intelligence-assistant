import unittest
from datetime import datetime

from pydantic import ValidationError

from backend.schemas import (
    FaultTreeSchema,
    KevEntrySchema,
    SyncResultSchema,
    VulnerabilitySchema,
    VulnerabilityWithKevSchema,
)


class VulnerabilitySchemaTests(unittest.TestCase):
    def test_validates_and_normalizes_a_vulnerability(self) -> None:
        vulnerability = VulnerabilitySchema(
            cve_id="cve-2026-12345",
            description="  Remote code execution  ",
            cvss_score=9.8,
            severity="critical",
            cwe_id="cwe-79",
            published_date="2026-08-20T12:00:00Z",
        )

        self.assertEqual(vulnerability.cve_id, "CVE-2026-12345")
        self.assertEqual(vulnerability.description, "Remote code execution")
        self.assertEqual(vulnerability.severity, "CRITICAL")
        self.assertEqual(vulnerability.cwe_id, "CWE-79")
        self.assertIsInstance(vulnerability.published_date, datetime)

    def test_rejects_an_invalid_cvss_value(self) -> None:
        with self.assertRaises(ValidationError):
            VulnerabilitySchema(
                cve_id="CVE-2026-12345",
                description="Example",
                cvss_score="hello",
            )

    def test_rejects_unexpected_fields_and_invalid_severity(self) -> None:
        with self.assertRaises(ValidationError):
            VulnerabilitySchema(
                cve_id="CVE-2026-12345",
                description="Example",
                severity="URGENT",
                internal_note="must never be exposed",
            )

    def test_validates_sync_response_counts(self) -> None:
        result = SyncResultSchema(
            fetched=5, validated=4, skipped=1, created=2, updated=2
        )
        self.assertEqual(result.validated, 4)


class KevEntrySchemaTests(unittest.TestCase):
    def _kev_kwargs(self, **overrides: object) -> dict:
        defaults: dict[str, object] = {
            "cve_id": "cve-2026-70001",
            "vendor_project": "ExampleCorp",
            "product": "Example Product",
            "vulnerability_name": "Example Vulnerability",
            "date_added": "2026-08-01",
            "short_description": "An example vulnerability.",
            "required_action": "Apply the vendor patch.",
            "due_date": "2026-08-22",
            "known_ransomware_use": "Unknown",
        }
        defaults.update(overrides)
        return defaults

    def test_validates_and_normalizes_a_kev_entry(self) -> None:
        entry = KevEntrySchema(**self._kev_kwargs())
        self.assertEqual(entry.cve_id, "CVE-2026-70001")

    def test_rejects_a_ransomware_value_outside_the_known_enum(self) -> None:
        with self.assertRaises(ValidationError):
            KevEntrySchema(**self._kev_kwargs(known_ransomware_use="Maybe"))


class VulnerabilityWithKevSchemaTests(unittest.TestCase):
    def test_kev_is_optional_and_defaults_to_none(self) -> None:
        vulnerability = VulnerabilityWithKevSchema(cve_id="CVE-2026-12345", description="Example")
        self.assertIsNone(vulnerability.kev)

    def test_accepts_a_nested_kev_entry(self) -> None:
        vulnerability = VulnerabilityWithKevSchema(
            cve_id="CVE-2026-12345",
            description="Example",
            kev={
                "cve_id": "CVE-2026-12345",
                "vendor_project": "ExampleCorp",
                "product": "Example Product",
                "vulnerability_name": "Example Vulnerability",
                "date_added": "2026-08-01",
                "short_description": "An example vulnerability.",
                "required_action": "Apply the vendor patch.",
                "due_date": "2026-08-22",
                "known_ransomware_use": "Known",
            },
        )
        self.assertIsNotNone(vulnerability.kev)
        self.assertEqual(vulnerability.kev.known_ransomware_use, "Known")


def _node(node_id: str, gate: str = "NONE", children: list[str] | None = None) -> dict:
    return {"id": node_id, "label": f"event {node_id}", "gate": gate, "children": children or []}


def _valid_tree() -> dict:
    return {
        "root_id": "top",
        "nodes": [
            _node("top", "AND", ["a", "b"]),
            _node("a", "OR", ["a1", "a2"]),
            _node("a1"),
            _node("a2"),
            _node("b"),
        ],
    }


class FaultTreeSchemaTests(unittest.TestCase):
    def test_accepts_a_well_formed_tree(self) -> None:
        tree = FaultTreeSchema.model_validate(_valid_tree())
        self.assertEqual(tree.root_id, "top")
        self.assertEqual(len(tree.nodes), 5)

    def _assert_rejected(self, mutate, fragment: str) -> None:
        data = _valid_tree()
        mutate(data)
        with self.assertRaises(ValidationError) as ctx:
            FaultTreeSchema.model_validate(data)
        self.assertIn(fragment, str(ctx.exception))

    def test_rejects_an_unknown_root(self) -> None:
        self._assert_rejected(lambda d: d.update(root_id="nope"), "root_id")

    def test_rejects_a_duplicate_node_id(self) -> None:
        self._assert_rejected(lambda d: d["nodes"].append(_node("a1")), "duplicate node id")

    def test_rejects_a_reference_to_an_unknown_child(self) -> None:
        self._assert_rejected(lambda d: d["nodes"][0].update(children=["a", "ghost"]), "unknown child")

    def test_rejects_a_gate_with_a_single_child(self) -> None:
        self._assert_rejected(lambda d: d["nodes"][1].update(children=["a1"]), "at least two children")

    def test_rejects_a_basic_event_with_children(self) -> None:
        self._assert_rejected(lambda d: d["nodes"][4].update(children=["a1"]), "must not have children")

    def test_rejects_a_basic_event_as_the_top_event(self) -> None:
        self._assert_rejected(lambda d: d.update(root_id="b"), "top event")

    def test_rejects_a_node_shared_by_two_parents(self) -> None:
        self._assert_rejected(lambda d: d["nodes"][0].update(children=["a", "a1"]), "more than one path")

    def test_rejects_a_cycle(self) -> None:
        self._assert_rejected(lambda d: d["nodes"][1].update(children=["top", "a2"]), "more than one path")

    def test_rejects_an_unreachable_node(self) -> None:
        self._assert_rejected(lambda d: d["nodes"].append(_node("orphan")), "not reachable")

    def test_rejects_a_tree_that_is_too_deep(self) -> None:
        chain = [_node(f"g{i}", "AND", [f"g{i + 1}", f"leaf{i}"]) for i in range(6)]
        leaves = [_node(f"leaf{i}") for i in range(6)] + [_node("g6")]
        with self.assertRaises(ValidationError) as ctx:
            FaultTreeSchema.model_validate({"root_id": "g0", "nodes": chain + leaves})
        self.assertIn("deeper than", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
