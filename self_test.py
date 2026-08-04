# -*- coding: utf-8 -*-
"""
self_test.py
-------------
Run this FIRST, before ever pointing the tool at a real database. It
verifies, in order:

  1. Python version is compatible (3.6+)
  2. All product modules import cleanly with no syntax/dependency errors
  3. oracledb is installed (warns, doesn't fail, if missing — you can
     still inspect/read the code without it)
  4. The full pipeline — collection model -> diagnostic engine ->
     JSON/text/HTML report generation — runs correctly end-to-end against
     a synthetic (mock) bundle exercising every expert module at least
     once, with NO database connection required.
  5. Writes sample outputs to ./self_test_output/ so you can open the
     HTML report in a browser and see exactly what a real run will
     produce.

Usage:
    python3 self_test.py

Exit code 0 = everything the tool can verify without a live database is
verified. Exit code 1 = something is broken; fix it before running
against production.
"""

from __future__ import print_function
import sys
import os
import traceback

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

results = []


def check(label, fn):
    try:
        detail = fn()
        results.append((PASS, label, detail or ""))
        print("[{0}] {1}{2}".format(PASS, label, " — " + detail if detail else ""))
        return True
    except Exception as exc:
        results.append((FAIL, label, str(exc)))
        print("[{0}] {1} — {2}".format(FAIL, label, exc))
        if os.environ.get("SELF_TEST_VERBOSE"):
            traceback.print_exc()
        return False


def warn(label, fn):
    try:
        detail = fn()
        results.append((PASS, label, detail or ""))
        print("[{0}] {1}{2}".format(PASS, label, " — " + detail if detail else ""))
        return True
    except Exception as exc:
        results.append((WARN, label, str(exc)))
        print("[{0}] {1} — {2}".format(WARN, label, exc))
        return False


def check_python_version():
    if sys.version_info < (3, 6):
        raise RuntimeError("Python {0} found — 3.6.8+ required".format(sys.version.split()[0]))
    return "Python {0}".format(sys.version.split()[0])


def check_imports():
    import models  # noqa
    import db_connector  # noqa
    import collectors  # noqa
    import diagnostic_engine  # noqa
    import report_html  # noqa
    return "models, db_connector, collectors, diagnostic_engine, report_html all import cleanly"


def check_oracledb_present():
    import oracledb
    return "oracledb {0} found".format(getattr(oracledb, "__version__", "unknown version"))


def build_mock_bundle():
    from models import (
        SqlForensicBundle, TargetIdentity, SqlTextInfo, ExecutionPlan, PlanStep,
        WaitEventAgg, IndexColumnStat, SqlPlanDirectiveInfo, ObjectStatisticsHealth,
        AwrSqlStatSnapshot, OptimizerEnvDiff, SqlPlanBaselineInfo, CursorChildInfo,
        SharedCursorMismatch, SqlMonitorReport,
    )

    bundle = SqlForensicBundle(TargetIdentity(sql_id="7fkxqzj2mkvvb", con_id=3))
    bundle.sql_text_info = SqlTextInfo(
        sql_fulltext="SELECT /*+ FULL(o) CARDINALITY(o 100) */ o.order_id, o.status "
                     "FROM app.orders o WHERE o.status = :b1",
        command_type=3, parsing_schema_name="APP",
    )

    # cursor cache: multiple children, one bind-sensitive, one shared-cursor mismatch
    bundle.cursor_children = [
        CursorChildInfo({"CHILD_NUMBER": 0, "PLAN_HASH_VALUE": 123456, "EXECUTIONS": 40,
                          "IS_BIND_SENSITIVE": "Y", "OPTIMIZER_ENV_HASH_VALUE": 111}),
        CursorChildInfo({"CHILD_NUMBER": 1, "PLAN_HASH_VALUE": 987654, "EXECUTIONS": 12,
                          "IS_BIND_SENSITIVE": "Y", "OPTIMIZER_ENV_HASH_VALUE": 222}),
    ]
    bundle.shared_cursor_mismatches = [
        SharedCursorMismatch(1, ["BIND_MISMATCH", "STATS_ROW_MISMATCH"]),
    ]

    plan = ExecutionPlan(plan_hash_value=123456, source="CURSOR_CACHE_WITH_ACTUALS")
    plan.add_step(PlanStep({
        "ID": 1, "OPERATION": "TABLE ACCESS", "OPTIONS": "FULL",
        "OBJECT_OWNER": "APP", "OBJECT_NAME": "ORDERS", "OBJECT_TYPE": "TABLE",
        "CARDINALITY": 12, "LAST_OUTPUT_ROWS": 3812004,
        "FILTER_PREDICATES": "STATUS=1", "PARTITION_START": "1", "PARTITION_STOP": "12",
    }))
    plan.add_step(PlanStep({
        "ID": 2, "OPERATION": "NESTED LOOPS", "CARDINALITY": 12, "LAST_OUTPUT_ROWS": 3812004,
    }))
    bundle.execution_plans.append(plan)

    bundle.wait_event_summary = [
        WaitEventAgg(event="db file scattered read", wait_class="User I/O",
                     total_wait_secs=340.2, sample_count=680, pct_of_total=68.0),
        WaitEventAgg(event="ON CPU", wait_class="CPU",
                     total_wait_secs=90.0, sample_count=180, pct_of_total=18.0),
    ]

    bundle.index_column_stats = [
        IndexColumnStat({"OWNER": "APP", "TABLE_NAME": "ORDERS", "INDEX_NAME": "IDX_ORDERS_STATUS",
                          "COLUMN_NAME": "STATUS", "COLUMN_POSITION": 1,
                          "CLUSTERING_FACTOR": 480000, "STATUS": "VALID"}),
    ]
    bundle.sql_plan_directives = [
        SqlPlanDirectiveInfo({"DIRECTIVE_ID": 42, "TYPE": "DYNAMIC_SAMPLING",
                               "STATE": "MISSING_STATS", "REASON": "SINGLE TABLE CARDINALITY MISESTIMATE",
                               "ENABLED": "YES", "OWNER": "APP", "OBJECT_NAME": "ORDERS",
                               "OBJECT_TYPE": "TABLE"}),
    ]
    bundle.object_statistics_health = [
        ObjectStatisticsHealth({"OWNER": "APP", "OBJECT_NAME": "ORDERS", "OBJECT_TYPE": "TABLE",
                                 "LAST_ANALYZED": None}),
    ]
    bundle.awr_sqlstat_history = [
        AwrSqlStatSnapshot({"SNAP_ID": 100, "PLAN_HASH_VALUE": 123456, "EXECUTIONS_DELTA": 5,
                             "OPTIMIZER_ENV_HASH_VALUE": 111}),
        AwrSqlStatSnapshot({"SNAP_ID": 101, "PLAN_HASH_VALUE": 987654, "EXECUTIONS_DELTA": 3,
                             "OPTIMIZER_ENV_HASH_VALUE": 222}),
    ]
    bundle.optimizer_env_diffs = [
        OptimizerEnvDiff("optimizer_index_cost_adj", "100", "20", 123456, 987654),
    ]
    bundle.baselines = [
        SqlPlanBaselineInfo({"SQL_HANDLE": "SYS_SQL_abc", "PLAN_NAME": "SYS_SQL_PLAN_xyz",
                              "ORIGIN": "AUTO-CAPTURE", "ENABLED": "YES", "ACCEPTED": "NO",
                              "FIXED": "NO"}),
    ]
    bundle.sql_monitor_reports = [
        SqlMonitorReport({"SQL_ID": "7fkxqzj2mkvvb", "SQL_EXEC_ID": 555, "STATUS": "DONE",
                           "PX_SERVERS_REQUESTED": 8, "PX_SERVERS_ALLOCATED": 2,
                           "PLAN_HASH_VALUE": 123456}),
    ]
    bundle.collection_errors = ["example_collector: DBA_HIST_SQLBIND access denied (informational, "
                                 "self-test only)"]
    return bundle


def run_full_pipeline():
    from diagnostic_engine import Synthesizer
    from report_html import write_report_html

    bundle = build_mock_bundle()
    report = Synthesizer().diagnose(bundle)

    out_dir = "self_test_output"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    with open(os.path.join(out_dir, "sample.bundle.json"), "w") as fh:
        fh.write(bundle.to_json())
    with open(os.path.join(out_dir, "sample.report.json"), "w") as fh:
        fh.write(report.to_json())
    with open(os.path.join(out_dir, "sample.report.txt"), "w") as fh:
        fh.write(report.summary_text())
    write_report_html(report, os.path.join(out_dir, "sample.report.html"),
                       database_context={"banner": "Oracle Database 19c EE (self-test, no live DB)",
                                          "con_name": "MOCKPDB"})

    modules_that_fired = set(f.module for f in report.findings)
    expected_min_modules = {
        "CardinalityExpert", "AccessPathExpert", "StatisticsHealthExpert",
        "SqlPlanDirectivesExpert", "PlanStabilityExpert", "ResourceProfileExpert",
        "HintAdvisorExpert", "ParallelismExpert", "SqlTuningAdvisorExpert",
        "RegressionPreventionExpert",
    }
    missing = expected_min_modules - modules_that_fired
    if missing:
        raise RuntimeError(
            "Expected modules did not fire against the mock bundle: {0}. The "
            "pipeline ran but diagnostic coverage is incomplete — investigate "
            "before trusting live results.".format(", ".join(sorted(missing)))
        )
    return "{0} findings from {1} modules; outputs written to ./{2}/".format(
        len(report.findings), len(modules_that_fired), out_dir)


def run_unit_test_suite():
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir="tests", pattern="test_*.py",
                             top_level_dir=os.path.dirname(os.path.abspath(__file__)) or ".")
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    if not result.wasSuccessful():
        raise RuntimeError(
            "{0} failure(s), {1} error(s) out of {2} unit tests. See output above "
            "for details.".format(len(result.failures), len(result.errors),
                                   result.testsRun)
        )
    return "{0} unit tests passed".format(result.testsRun)


def main():
    print("=" * 70)
    print("Oracle SQL Forensics — Self Test")
    print("=" * 70)

    ok = True
    ok &= check("Python version", check_python_version)
    ok &= check("Module imports", check_imports)
    warn("oracledb driver installed", check_oracledb_present)
    ok &= check("Unit test suite (tests/)", run_unit_test_suite)
    ok &= check("Full pipeline (mock bundle -> diagnosis -> JSON/text/HTML)", run_full_pipeline)

    print("=" * 70)
    fails = [r for r in results if r[0] == FAIL]
    if fails:
        print("RESULT: {0} check(s) FAILED. Do not run against a live database "
              "until these are fixed.".format(len(fails)))
        sys.exit(1)
    else:
        print("RESULT: All checks that can run without a live database PASSED.")
        print("Open ./self_test_output/sample.report.html in a browser to see a "
              "sample report.")
        print("Next step: run_collection.py against a real, non-critical SQL_ID.")
        sys.exit(0)


if __name__ == "__main__":
    main()
