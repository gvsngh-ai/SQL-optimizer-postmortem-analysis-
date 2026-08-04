# -*- coding: utf-8 -*-
"""
test_diagnostic_engine.py — targeted unit tests per expert module.
Each test constructs the minimal bundle needed to trigger (or
deliberately NOT trigger) one specific module's logic, and asserts on
the resulting Finding content — not just "something fired."
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import (
    SqlForensicBundle, TargetIdentity, ExecutionPlan, PlanStep, WaitEventAgg,
    IndexColumnStat, SqlPlanDirectiveInfo, ObjectStatisticsHealth,
    OptimizerEnvDiff, SqlPlanBaselineInfo, SqlTextInfo, AdvisorRecommendation,
)
from diagnostic_engine import (
    CardinalityExpert, JoinStrategyExpert, AccessPathExpert, ParallelismExpert,
    ResourceProfileExpert, PlanStabilityExpert, StatisticsHealthExpert,
    HintAdvisorExpert, SqlPlanDirectivesExpert, SqlTuningAdvisorExpert,
    RegressionPreventionExpert, Synthesizer, Finding, SEV_CRITICAL, SEV_HIGH,
    RISK_MEDIUM,
)


def _bundle(sql_id="test_sql_id"):
    return SqlForensicBundle(TargetIdentity(sql_id=sql_id))


class TestCardinalityExpert(unittest.TestCase):
    def test_fires_on_severe_misestimate(self):
        bundle = _bundle()
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        plan.add_step(PlanStep({"ID": 1, "OPERATION": "TABLE ACCESS", "OPTIONS": "FULL",
                                 "OBJECT_OWNER": "APP", "OBJECT_NAME": "T",
                                 "CARDINALITY": 10, "LAST_OUTPUT_ROWS": 1000000}))
        bundle.execution_plans.append(plan)
        findings = CardinalityExpert().analyze(bundle)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEV_CRITICAL)
        self.assertIn("misestimate", findings[0].title.lower())

    def test_does_not_fire_on_accurate_estimate(self):
        bundle = _bundle()
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        plan.add_step(PlanStep({"ID": 1, "OPERATION": "TABLE ACCESS", "OPTIONS": "FULL",
                                 "OBJECT_OWNER": "APP", "OBJECT_NAME": "T",
                                 "CARDINALITY": 1000, "LAST_OUTPUT_ROWS": 1050}))
        bundle.execution_plans.append(plan)
        findings = CardinalityExpert().analyze(bundle)
        self.assertEqual(len(findings), 0)

    def test_no_plan_no_crash(self):
        bundle = _bundle()
        findings = CardinalityExpert().analyze(bundle)
        self.assertEqual(findings, [])


class TestJoinStrategyExpert(unittest.TestCase):
    def test_fires_on_nested_loops_with_high_actual_volume(self):
        bundle = _bundle()
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        plan.add_step(PlanStep({"ID": 1, "OPERATION": "NESTED LOOPS",
                                 "CARDINALITY": 5, "LAST_OUTPUT_ROWS": 500000}))
        bundle.execution_plans.append(plan)
        findings = JoinStrategyExpert().analyze(bundle)
        titles = [f.title for f in findings]
        self.assertTrue(any("NESTED LOOPS" in t for t in titles))

    def test_does_not_fire_on_small_nested_loops(self):
        bundle = _bundle()
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        plan.add_step(PlanStep({"ID": 1, "OPERATION": "NESTED LOOPS",
                                 "CARDINALITY": 5, "LAST_OUTPUT_ROWS": 6}))
        bundle.execution_plans.append(plan)
        findings = JoinStrategyExpert().analyze(bundle)
        titles = [f.title for f in findings]
        self.assertFalse(any("NESTED LOOPS" in t for t in titles))


class TestAccessPathExpert(unittest.TestCase):
    def test_fires_on_full_scan_with_post_filter(self):
        bundle = _bundle()
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        plan.add_step(PlanStep({"ID": 1, "OPERATION": "TABLE ACCESS", "OPTIONS": "FULL",
                                 "OBJECT_OWNER": "APP", "OBJECT_NAME": "T",
                                 "FILTER_PREDICATES": "X=1", "LAST_OUTPUT_ROWS": 500}))
        bundle.execution_plans.append(plan)
        findings = AccessPathExpert().analyze(bundle)
        self.assertTrue(any("Full table scan" in f.title for f in findings))


class TestParallelismExpert(unittest.TestCase):
    def test_fires_on_px_downgrade(self):
        from models import SqlMonitorReport
        bundle = _bundle()
        bundle.sql_monitor_reports.append(SqlMonitorReport({
            "SQL_ID": "x", "SQL_EXEC_ID": 1, "PX_SERVERS_REQUESTED": 16,
            "PX_SERVERS_ALLOCATED": 2,
        }))
        findings = ParallelismExpert().analyze(bundle)
        self.assertEqual(len(findings), 1)
        self.assertIn("downgrade", findings[0].title.lower())

    def test_no_finding_when_fully_allocated(self):
        from models import SqlMonitorReport
        bundle = _bundle()
        bundle.sql_monitor_reports.append(SqlMonitorReport({
            "SQL_ID": "x", "SQL_EXEC_ID": 1, "PX_SERVERS_REQUESTED": 8,
            "PX_SERVERS_ALLOCATED": 8,
        }))
        findings = ParallelismExpert().analyze(bundle)
        self.assertEqual(len(findings), 0)


class TestResourceProfileExpert(unittest.TestCase):
    def test_identifies_dominant_wait_class(self):
        bundle = _bundle()
        bundle.wait_event_summary.append(
            WaitEventAgg(event="db file scattered read", wait_class="User I/O",
                         total_wait_secs=100, sample_count=100, pct_of_total=80.0)
        )
        findings = ResourceProfileExpert().analyze(bundle)
        self.assertTrue(any("User I/O" in f.title for f in findings))

    def test_detects_temp_spill(self):
        bundle = _bundle()
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        step = PlanStep({"ID": 1, "OPERATION": "HASH JOIN"})
        step.workarea_tempseg = 600 * 1024 * 1024  # 600MB spill
        plan.add_step(step)
        bundle.execution_plans.append(plan)
        findings = ResourceProfileExpert().analyze(bundle)
        self.assertTrue(any("temp" in f.title.lower() for f in findings))
        spill_finding = [f for f in findings if "temp" in f.title.lower()][0]
        self.assertEqual(spill_finding.severity, SEV_HIGH)  # >500MB => HIGH per module logic


class TestStatisticsHealthExpert(unittest.TestCase):
    def test_fires_critical_on_never_analyzed(self):
        bundle = _bundle()
        bundle.object_statistics_health.append(
            ObjectStatisticsHealth({"OWNER": "APP", "OBJECT_NAME": "T",
                                     "OBJECT_TYPE": "TABLE", "LAST_ANALYZED": None})
        )
        findings = StatisticsHealthExpert().analyze(bundle)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEV_CRITICAL)

    def test_fires_high_on_stale(self):
        bundle = _bundle()
        bundle.object_statistics_health.append(
            ObjectStatisticsHealth({"OWNER": "APP", "OBJECT_NAME": "T", "OBJECT_TYPE": "TABLE",
                                     "LAST_ANALYZED": "2020-01-01", "STALE_STATS": "YES"})
        )
        findings = StatisticsHealthExpert().analyze(bundle)
        self.assertTrue(any("STALE" in f.title for f in findings))

    def test_no_finding_on_healthy_stats(self):
        bundle = _bundle()
        bundle.object_statistics_health.append(
            ObjectStatisticsHealth({"OWNER": "APP", "OBJECT_NAME": "T", "OBJECT_TYPE": "TABLE",
                                     "LAST_ANALYZED": "2026-01-01", "STALE_STATS": "NO",
                                     "NUM_ROWS": 1000, "SAMPLE_SIZE": 1000, "GLOBAL_STATS": "YES"})
        )
        findings = StatisticsHealthExpert().analyze(bundle)
        self.assertEqual(len(findings), 0)


class TestHintAdvisorExpert(unittest.TestCase):
    def test_detects_existing_hints(self):
        bundle = _bundle()
        bundle.sql_text_info = SqlTextInfo(
            sql_fulltext="SELECT /*+ FULL(t) PARALLEL(4) */ * FROM t")
        findings = HintAdvisorExpert().analyze(bundle)
        inventory = [f for f in findings if "already contains" in f.title]
        self.assertEqual(len(inventory), 1)
        self.assertIn("FULL", inventory[0].title)
        self.assertIn("PARALLEL", inventory[0].title)

    def test_no_findings_without_sql_text(self):
        bundle = _bundle()
        findings = HintAdvisorExpert().analyze(bundle)
        self.assertEqual(findings, [])

    def test_flags_cardinality_hint_as_symptom(self):
        bundle = _bundle()
        bundle.sql_text_info = SqlTextInfo(
            sql_fulltext="SELECT /*+ CARDINALITY(t 500) */ * FROM t")
        findings = HintAdvisorExpert().analyze(bundle)
        self.assertTrue(any("symptom" in f.title.lower() for f in findings))


class TestSqlPlanDirectivesExpert(unittest.TestCase):
    def test_fires_on_missing_stats_directive(self):
        bundle = _bundle()
        bundle.sql_plan_directives.append(SqlPlanDirectiveInfo({
            "DIRECTIVE_ID": 1, "TYPE": "DYNAMIC_SAMPLING", "STATE": "MISSING_STATS",
            "REASON": "SINGLE TABLE CARDINALITY MISESTIMATE", "ENABLED": "YES",
            "OWNER": "APP", "OBJECT_NAME": "T",
        }))
        findings = SqlPlanDirectivesExpert().analyze(bundle)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEV_HIGH)


class TestSqlTuningAdvisorExpert(unittest.TestCase):
    def test_surfaces_existing_recommendation(self):
        bundle = _bundle()
        bundle.sql_tuning_advisor.has_been_analyzed = True
        bundle.sql_tuning_advisor.tasks = [{"task_name": "t1", "status": "COMPLETED", "created": None}]
        bundle.sql_tuning_advisor.recommendations.append(
            AdvisorRecommendation({"TASK_NAME": "t1", "REC_ID": 1, "TYPE": "SQL Profile",
                                    "BENEFIT": 75, "RANK": 1})
        )
        findings = SqlTuningAdvisorExpert().analyze(bundle)
        self.assertEqual(len(findings), 1)
        self.assertIn("SQL Profile", findings[0].title)

    def test_recommends_running_when_never_analyzed(self):
        bundle = _bundle()
        findings = SqlTuningAdvisorExpert().analyze(bundle)
        self.assertEqual(len(findings), 1)
        self.assertIn("never analyzed", findings[0].title.lower())


class TestRegressionPreventionExpert(unittest.TestCase):
    def test_fires_when_risky_recommendation_present(self):
        bundle = _bundle()
        fake_finding = Finding(
            module="FakeModule", title="fake", severity=SEV_HIGH,
            explanation="fake",
            recommendations=[__import__("diagnostic_engine").Recommendation(
                action="risky change", syntax="ALTER ...", rationale="x", risk=RISK_MEDIUM,
            )],
        )
        findings = RegressionPreventionExpert().analyze(bundle, other_findings=[fake_finding])
        self.assertEqual(len(findings), 1)
        self.assertIn("SPA", findings[0].title)

    def test_no_fire_when_no_risky_recommendations(self):
        bundle = _bundle()
        findings = RegressionPreventionExpert().analyze(bundle, other_findings=[])
        self.assertEqual(findings, [])


class TestSynthesizer(unittest.TestCase):
    def test_report_sorted_by_severity_descending(self):
        bundle = _bundle()
        bundle.object_statistics_health.append(
            ObjectStatisticsHealth({"OWNER": "APP", "OBJECT_NAME": "T",
                                     "OBJECT_TYPE": "TABLE", "LAST_ANALYZED": None})
        )  # CRITICAL
        plan = ExecutionPlan(plan_hash_value=1, source="CURSOR_CACHE_WITH_ACTUALS")
        plan.add_step(PlanStep({"ID": 1, "OPERATION": "NESTED LOOPS",
                                 "CARDINALITY": 5, "LAST_OUTPUT_ROWS": 500000}))  # HIGH
        bundle.execution_plans.append(plan)

        report = Synthesizer().diagnose(bundle)
        severities = [f.severity for f in report.findings]
        self.assertEqual(severities, sorted(severities, reverse=True))

    def test_module_exception_does_not_break_whole_report(self):
        class BrokenModule(object):
            name = "BrokenModule"

            def analyze(self, bundle):
                raise ValueError("simulated failure")

        report = Synthesizer(modules=[BrokenModule()]).diagnose(_bundle())
        self.assertEqual(len(report.findings), 1)
        self.assertIn("could not complete", report.findings[0].explanation)


if __name__ == "__main__":
    unittest.main()
