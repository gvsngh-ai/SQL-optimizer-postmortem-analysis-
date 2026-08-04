# -*- coding: utf-8 -*-
"""
test_models.py — unit tests for models.py. Run via:
    python3 -m unittest discover -s tests -p 'test_*.py' -v
"""

import sys
import os
import json
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import (
    SqlForensicBundle, TargetIdentity, PlanStep, ExecutionPlan,
    WaitEventAgg, SerializableMixin,
)


class TestSerializableMixin(unittest.TestCase):
    def test_to_dict_flat_fields(self):
        ident = TargetIdentity(sql_id="abc123", con_id=3, pdb_name="MYPDB", is_cdb=True)
        d = ident.to_dict()
        self.assertEqual(d["sql_id"], "abc123")
        self.assertEqual(d["con_id"], 3)
        self.assertEqual(d["pdb_name"], "MYPDB")
        self.assertTrue(d["is_cdb"])

    def test_to_dict_nested_object(self):
        bundle = SqlForensicBundle(TargetIdentity(sql_id="xyz"))
        d = bundle.to_dict()
        self.assertEqual(d["identity"]["sql_id"], "xyz")

    def test_to_dict_list_of_objects(self):
        bundle = SqlForensicBundle(TargetIdentity(sql_id="xyz"))
        bundle.wait_event_summary.append(
            WaitEventAgg(event="db file sequential read", wait_class="User I/O",
                         total_wait_secs=1.5, sample_count=10, pct_of_total=50.0)
        )
        d = bundle.to_dict()
        self.assertEqual(len(d["wait_event_summary"]), 1)
        self.assertEqual(d["wait_event_summary"][0]["event"], "db file sequential read")

    def test_to_json_is_valid_json(self):
        bundle = SqlForensicBundle(TargetIdentity(sql_id="xyz"))
        bundle.collection_errors.append("something failed")
        raw = bundle.to_json()
        parsed = json.loads(raw)  # must not raise
        self.assertIn("something failed", parsed["collection_errors"])

    def test_to_json_handles_non_serializable_defaults_to_str(self):
        # datetime-like values must not blow up JSON serialization —
        # to_json passes default=str for exactly this reason.
        class FakeDatetime(object):
            def __str__(self):
                return "2026-01-01 00:00:00"

        step = PlanStep({"ID": 1, "OPERATION": "TABLE ACCESS"})
        step.first_load_time = FakeDatetime() if hasattr(step, "first_load_time") else None
        plan = ExecutionPlan(plan_hash_value=1, source="TEST")
        plan.add_step(step)
        bundle = SqlForensicBundle(TargetIdentity(sql_id="xyz"))
        bundle.execution_plans.append(plan)
        raw = bundle.to_json()
        json.loads(raw)  # must not raise


class TestPlanStep(unittest.TestCase):
    def test_prefers_last_output_rows_over_output_rows(self):
        step = PlanStep({"ID": 1, "LAST_OUTPUT_ROWS": 500, "OUTPUT_ROWS": 100})
        self.assertEqual(step.actual_rows, 500)

    def test_falls_back_to_output_rows(self):
        step = PlanStep({"ID": 1, "OUTPUT_ROWS": 100})
        self.assertEqual(step.actual_rows, 100)

    def test_missing_fields_default_to_none(self):
        step = PlanStep({"ID": 1})
        self.assertIsNone(step.cost)
        self.assertIsNone(step.cardinality)


class TestExecutionPlan(unittest.TestCase):
    def test_add_step_appends(self):
        plan = ExecutionPlan(plan_hash_value=123, source="AWR")
        self.assertEqual(len(plan.steps), 0)
        plan.add_step(PlanStep({"ID": 1}))
        plan.add_step(PlanStep({"ID": 2}))
        self.assertEqual(len(plan.steps), 2)


if __name__ == "__main__":
    unittest.main()
