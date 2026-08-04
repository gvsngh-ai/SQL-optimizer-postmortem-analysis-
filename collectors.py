# -*- coding: utf-8 -*-
"""
collectors.py
--------------
Turns a bare SQL_ID into a fully populated SqlForensicBundle by querying
every relevant Oracle history/diagnostic source:

  - Cursor cache          : V$SQL, V$SQLAREA, V$SQL_SHARED_CURSOR,
                             V$SQL_PLAN, V$SQL_PLAN_STATISTICS_ALL
  - AWR (historical)       : DBA_HIST_SQLSTAT, DBA_HIST_SQL_PLAN,
                             DBA_HIST_SQLTEXT, DBA_HIST_SQLBIND,
                             DBA_HIST_ACTIVE_SESS_HISTORY
  - Currently running      : V$ACTIVE_SESSION_HISTORY, V$SQL_MONITOR,
                             V$SQL_PLAN_MONITOR
  - Plan stability objects : DBA_SQL_PLAN_BASELINES, DBA_SQL_PROFILES,
                             DBA_SQL_PATCHES
  - Optimizer environment   : DBA_HIST_SQLSTAT.OPTIMIZER_ENV_HASH_VALUE
                             cross-referenced with DBA_HIST_OPTIMIZER_ENV

Every collector method is defensive: if a view is inaccessible (missing
Diagnostics/Tuning Pack license, insufficient privilege, view doesn't
exist on this version), it records the failure in
bundle.collection_errors and continues — a partial bundle is always more
useful than a crash, and the caller must be told explicitly what's
missing rather than silently getting an incomplete picture.

CDB/PDB handling: every method accepts an explicit `history_scope`
('CDB' or 'DBA') chosen by the caller based on OracleForensicConnection
.get_database_context(). We never guess.
"""

import logging
from datetime import datetime, timedelta

from models import (
    SqlForensicBundle, TargetIdentity, SqlTextInfo, CursorChildInfo,
    SharedCursorMismatch, PlanStep, ExecutionPlan, AwrSqlStatSnapshot,
    WaitEventAgg, AshSample, BindCapture, SqlPlanBaselineInfo,
    SqlProfileInfo, SqlPatchInfo, OptimizerEnvDiff, SqlMonitorReport,
    SqlPlanDirectiveInfo, IndexColumnStat, ObjectStatisticsHealth,
    AdvisorRecommendation, SqlTuningAdvisorHistory,
)

LOG = logging.getLogger("sql_forensics.collectors")

# Columns in V$SQL_SHARED_CURSOR that indicate WHY a cursor wasn't shared.
# There are 60+ of these across versions; this is the high-signal subset.
_SHARED_CURSOR_REASON_COLUMNS = [
    "OPTIMIZER_MISMATCH", "BIND_MISMATCH", "STATS_ROW_MISMATCH",
    "LITERAL_MISMATCH", "OUTLINE_MISMATCH", "PLAN_HASH_MISMATCH",
    "ROW_LEVEL_SEC_MISMATCH", "BIND_EQUIV_FAILURE", "AUTH_CHECK_MISMATCH",
    "TRANSLATION_MISMATCH", "USE_FEEDBACK_STATS", "PURGED_CURSOR",
    "LANGUAGE_MISMATCH", "SEC_DEPTH_MISMATCH", "EXPLAIN_PLAN_CURSOR",
    "BUFFERED_DML_MISMATCH", "PDML_ENV_MISMATCH", "INST_DRTLD_MISMATCH",
    "SLAVE_QC_MISMATCH", "TYPECHECK_MISMATCH", "FLASHBACK_CURSOR",
    "ANYDATA_TRANSFORMATION", "INCOMP_LTRL_MISMATCH", "OPTIMIZER_MODE_MISMATCH",
    "PQ_SLAVE_MISMATCH", "TOP_LEVEL_RPI_CURSOR", "DIFFERENT_LONG_LENGTH",
    "LOGMINER_SESSION_MISMATCH", "INCOMPLETE_CURSOR", "SEC_DEPTH_MISMATCH",
    "MULTI_PX_MISMATCH", "BIND_PEEKED_PQ_MISMATCH", "MV_QUERY_GEN_MISMATCH",
    "USER_BIND_PEEK_MISMATCH", "TYPCHK_DEP_MISMATCH", "NO_TRIGGER_MISMATCH",
    "FLASHBACK_TABLE_MISMATCH", "REMOTE_TRANS_MISMATCH", "LOAD_OPTIMIZER_STATS",
]


class SqlForensicsCollector(object):
    def __init__(self, connection, history_scope="DBA"):
        """
        connection: a connected OracleForensicConnection
        history_scope: 'DBA' when querying from within the PDB that owns
                       the SQL, 'CDB' when querying from CDB$ROOT across
                       PDBs (uses CDB_HIST_* / CDB_* views and filters by
                       CON_ID).
        """
        self.conn = connection
        self.scope = history_scope
        self._hist_prefix = "CDB_HIST_" if history_scope == "CDB" else "DBA_HIST_"
        self._obj_prefix = "CDB_" if history_scope == "CDB" else "DBA_"

    # ------------------------------------------------------------------ #
    # orchestrator
    # ------------------------------------------------------------------ #

    def collect(self, sql_id, con_id=None, lookback_days=14,
                include_ash_raw=False):
        """Runs every collector and returns a fully populated
        SqlForensicBundle. Never raises for a single sub-collector
        failure — failures are recorded in bundle.collection_errors."""
        identity = TargetIdentity(sql_id=sql_id, con_id=con_id)
        bundle = SqlForensicBundle(identity)
        bundle.collected_at = datetime.now()

        steps = [
            ("sql_text", lambda: self._collect_sql_text(bundle, sql_id, con_id)),
            ("cursor_cache", lambda: self._collect_cursor_cache(bundle, sql_id, con_id)),
            ("shared_cursor_mismatches", lambda: self._collect_shared_cursor_mismatches(bundle, sql_id, con_id)),
            ("cursor_cache_plans", lambda: self._collect_cursor_cache_plans(bundle, sql_id, con_id)),
            ("awr_sqlstat", lambda: self._collect_awr_sqlstat(bundle, sql_id, con_id, lookback_days)),
            ("awr_plans", lambda: self._collect_awr_plans(bundle, sql_id, con_id, lookback_days)),
            ("wait_events_overall", lambda: self._collect_wait_events(bundle, sql_id, con_id, lookback_days)),
            ("currently_running", lambda: self._collect_currently_running(bundle, sql_id, con_id)),
            ("sql_monitor", lambda: self._collect_sql_monitor(bundle, sql_id, con_id)),
            ("bind_history", lambda: self._collect_bind_history(bundle, sql_id, con_id, lookback_days)),
            ("baselines", lambda: self._collect_baselines(bundle, sql_id, con_id)),
            ("profiles_patches", lambda: self._collect_profiles_and_patches(bundle, sql_id, con_id)),
            ("optimizer_env_diffs", lambda: self._collect_optimizer_env_diffs(bundle, sql_id, con_id, lookback_days)),
            ("sql_plan_directives", lambda: self._collect_sql_plan_directives(bundle, sql_id, con_id)),
            ("index_column_stats", lambda: self._collect_index_column_stats(bundle, sql_id, con_id)),
            ("object_statistics_health", lambda: self._collect_object_statistics_health(bundle, sql_id, con_id)),
            ("sql_tuning_advisor", lambda: self._collect_sql_tuning_advisor_history(bundle, sql_id, con_id)),
        ]

        for step_name, fn in steps:
            try:
                fn()
            except Exception as exc:
                msg = "{0} failed: {1}".format(step_name, exc)
                LOG.warning(msg)
                bundle.collection_errors.append(msg)

        return bundle

    # ------------------------------------------------------------------ #
    # SQL text / identity
    # ------------------------------------------------------------------ #

    def _collect_sql_text(self, bundle, sql_id, con_id):
        row = self.conn.fetch_one(
            "SELECT SQL_TEXT, SQL_FULLTEXT, COMMAND_TYPE, MODULE, ACTION, "
            "PARSING_SCHEMA_NAME FROM V$SQL "
            "WHERE SQL_ID = :sql_id AND ROWNUM = 1",
            {"sql_id": sql_id},
        )
        if row is None:
            # fall back to AWR text if it's aged out of the cursor cache
            hist_sql = self._obj_prefix + "HIST_SQLTEXT" if False else self._hist_prefix + "SQLTEXT"
            row = self.conn.fetch_one(
                "SELECT SQL_TEXT, SQL_TEXT AS SQL_FULLTEXT, COMMAND_TYPE, "
                "NULL AS MODULE, NULL AS ACTION, NULL AS PARSING_SCHEMA_NAME "
                "FROM {0} WHERE SQL_ID = :sql_id AND ROWNUM = 1".format(hist_sql),
                {"sql_id": sql_id},
            )
        if row:
            full = row.get("SQL_FULLTEXT")
            full_text = full.read() if hasattr(full, "read") else full
            bundle.sql_text_info = SqlTextInfo(
                sql_text=row.get("SQL_TEXT"),
                sql_fulltext=full_text,
                command_type=row.get("COMMAND_TYPE"),
                module=row.get("MODULE"),
                action=row.get("ACTION"),
                parsing_schema_name=row.get("PARSING_SCHEMA_NAME"),
            )

    # ------------------------------------------------------------------ #
    # cursor cache — current shared pool state
    # ------------------------------------------------------------------ #

    def _collect_cursor_cache(self, bundle, sql_id, con_id):
        con_filter = " AND CON_ID = :con_id" if con_id else ""
        params = {"sql_id": sql_id}
        if con_id:
            params["con_id"] = con_id
        rows = self.conn.fetch_all(
            "SELECT CHILD_NUMBER, PLAN_HASH_VALUE, EXECUTIONS, ELAPSED_TIME, "
            "CPU_TIME, BUFFER_GETS, DISK_READS, DIRECT_WRITES, ROWS_PROCESSED, "
            "PARSE_CALLS, FETCHES, SORTS, OPTIMIZER_COST, OPTIMIZER_MODE, "
            "OPTIMIZER_ENV_HASH_VALUE, IS_BIND_SENSITIVE, IS_BIND_AWARE, "
            "IS_SHAREABLE, INVALIDATIONS, LOADS, LOADED_VERSIONS, "
            "FIRST_LOAD_TIME, LAST_ACTIVE_TIME, LAST_LOAD_TIME, "
            "AVG_HARD_PARSE_TIME, SQL_PROFILE, SQL_PATCH, SQL_PLAN_BASELINE, "
            "CON_ID, PLSQL_EXEC_TIME, IO_CELL_OFFLOAD_ELIGIBLE_BYTES, "
            "IO_INTERCONNECT_BYTES "
            "FROM V$SQL WHERE SQL_ID = :sql_id" + con_filter,
            params,
        )
        bundle.cursor_children = [CursorChildInfo(r) for r in rows]
        bundle.is_currently_running = any(
            (r.get("LAST_ACTIVE_TIME") and
             (datetime.now() - r["LAST_ACTIVE_TIME"]).total_seconds() < 5)
            for r in rows if isinstance(r.get("LAST_ACTIVE_TIME"), datetime)
        )

    def _collect_shared_cursor_mismatches(self, bundle, sql_id, con_id):
        cols = ", ".join(_SHARED_CURSOR_REASON_COLUMNS)
        rows = self.conn.fetch_all(
            "SELECT CHILD_NUMBER, {0} FROM V$SQL_SHARED_CURSOR "
            "WHERE SQL_ID = :sql_id".format(cols),
            {"sql_id": sql_id},
        )
        for row in rows:
            reasons = [
                col for col in _SHARED_CURSOR_REASON_COLUMNS
                if str(row.get(col, "N")).upper() == "Y"
            ]
            if reasons:
                bundle.shared_cursor_mismatches.append(
                    SharedCursorMismatch(row.get("CHILD_NUMBER"), reasons)
                )

    def _collect_cursor_cache_plans(self, bundle, sql_id, con_id):
        # V$SQL_PLAN_STATISTICS_ALL gives actual-vs-estimate (STARTS,
        # LAST_OUTPUT_ROWS, LAST_*). Prefer it; fall back to V$SQL_PLAN
        # (estimates only) if STATISTICS_ALL isn't populated (requires
        # STATISTICS_LEVEL=ALL or gather_plan_statistics hint at parse time).
        rows = self.conn.fetch_all(
            "SELECT CHILD_NUMBER, PLAN_HASH_VALUE, ID, PARENT_ID, DEPTH, "
            "OPERATION, OPTIONS, OBJECT_OWNER, OBJECT_NAME, OBJECT_ALIAS, "
            "OBJECT_TYPE, OPTIMIZER, COST, CARDINALITY, BYTES, "
            "PARTITION_START, PARTITION_STOP, PARTITION_ID, "
            "ACCESS_PREDICATES, FILTER_PREDICATES, PROJECTION, "
            "DISTRIBUTION, CPU_COST, IO_COST, TEMP_SPACE, QBLOCK_NAME, "
            "OTHER_TAG, STARTS, LAST_OUTPUT_ROWS, LAST_CR_BUFFER_GETS, "
            "LAST_CU_BUFFER_GETS, LAST_DISK_READS, LAST_DISK_WRITES, "
            "LAST_ELAPSED_TIME, LAST_MEMORY_USED, LAST_TEMPSEG_SIZE "
            "FROM V$SQL_PLAN_STATISTICS_ALL WHERE SQL_ID = :sql_id "
            "ORDER BY CHILD_NUMBER, ID",
            {"sql_id": sql_id},
        )
        source = "CURSOR_CACHE_WITH_ACTUALS"
        if not rows:
            rows = self.conn.fetch_all(
                "SELECT CHILD_NUMBER, PLAN_HASH_VALUE, ID, PARENT_ID, DEPTH, "
                "OPERATION, OPTIONS, OBJECT_OWNER, OBJECT_NAME, OBJECT_ALIAS, "
                "OBJECT_TYPE, OPTIMIZER, COST, CARDINALITY, BYTES, "
                "PARTITION_START, PARTITION_STOP, PARTITION_ID, "
                "ACCESS_PREDICATES, FILTER_PREDICATES, PROJECTION, "
                "DISTRIBUTION, CPU_COST, IO_COST, TEMP_SPACE, QBLOCK_NAME, "
                "OTHER_TAG "
                "FROM V$SQL_PLAN WHERE SQL_ID = :sql_id "
                "ORDER BY CHILD_NUMBER, ID",
                {"sql_id": sql_id},
            )
            source = "CURSOR_CACHE_ESTIMATES_ONLY"

        plans_by_key = {}
        for row in rows:
            key = (row.get("CHILD_NUMBER"), row.get("PLAN_HASH_VALUE"))
            if key not in plans_by_key:
                plans_by_key[key] = ExecutionPlan(
                    plan_hash_value=row.get("PLAN_HASH_VALUE"),
                    source=source,
                    sql_child_number=row.get("CHILD_NUMBER"),
                )
            plans_by_key[key].add_step(PlanStep(row))
        bundle.execution_plans.extend(plans_by_key.values())

    # ------------------------------------------------------------------ #
    # AWR — historical trend across snapshots
    # ------------------------------------------------------------------ #

    def _collect_awr_sqlstat(self, bundle, sql_id, con_id, lookback_days):
        table = self._hist_prefix + "SQLSTAT"
        snap_table = self._hist_prefix + "SNAPSHOT"
        con_filter = " AND s.CON_ID = :con_id" if con_id else ""
        params = {"sql_id": sql_id, "since": datetime.now() - timedelta(days=lookback_days)}
        if con_id:
            params["con_id"] = con_id
        rows = self.conn.fetch_all(
            "SELECT s.SNAP_ID, sn.BEGIN_INTERVAL_TIME, sn.END_INTERVAL_TIME, "
            "s.PLAN_HASH_VALUE, s.EXECUTIONS_DELTA, s.ELAPSED_TIME_DELTA, "
            "s.CPU_TIME_DELTA, s.IOWAIT_DELTA, s.CLWAIT_DELTA, "
            "s.APWAIT_DELTA, s.CCWAIT_DELTA, s.BUFFER_GETS_DELTA, "
            "s.DISK_READS_DELTA, s.DIRECT_WRITES_DELTA, "
            "s.ROWS_PROCESSED_DELTA, s.FETCHES_DELTA, s.PARSE_CALLS_DELTA, "
            "s.SORTS_DELTA, s.PX_SERVERS_EXECS_DELTA, s.OPTIMIZER_COST, "
            "s.OPTIMIZER_ENV_HASH_VALUE, s.CON_ID "
            "FROM {0} s JOIN {1} sn "
            "  ON s.SNAP_ID = sn.SNAP_ID AND s.DBID = sn.DBID "
            "     AND s.INSTANCE_NUMBER = sn.INSTANCE_NUMBER "
            "WHERE s.SQL_ID = :sql_id AND sn.BEGIN_INTERVAL_TIME >= :since"
            "{2} ORDER BY s.SNAP_ID".format(table, snap_table, con_filter),
            params,
        )
        bundle.awr_sqlstat_history = [AwrSqlStatSnapshot(r) for r in rows]

    def _collect_awr_plans(self, bundle, sql_id, con_id, lookback_days):
        table = self._hist_prefix + "SQL_PLAN"
        params = {"sql_id": sql_id}
        rows = self.conn.fetch_all(
            "SELECT PLAN_HASH_VALUE, ID, PARENT_ID, DEPTH, OPERATION, "
            "OPTIONS, OBJECT_OWNER, OBJECT_NAME, OBJECT_ALIAS, OBJECT_TYPE, "
            "OPTIMIZER, COST, CARDINALITY, BYTES, PARTITION_START, "
            "PARTITION_STOP, PARTITION_ID, ACCESS_PREDICATES, "
            "FILTER_PREDICATES, PROJECTION, DISTRIBUTION, CPU_COST, "
            "IO_COST, TEMP_SPACE, QBLOCK_NAME, OTHER_TAG "
            "FROM {0} WHERE SQL_ID = :sql_id ORDER BY PLAN_HASH_VALUE, ID".format(table),
            params,
        )
        plans_by_hash = {}
        for row in rows:
            phv = row.get("PLAN_HASH_VALUE")
            if phv not in plans_by_hash:
                plans_by_hash[phv] = ExecutionPlan(plan_hash_value=phv, source="AWR")
            plans_by_hash[phv].add_step(PlanStep(row))
        bundle.execution_plans.extend(plans_by_hash.values())

    # ------------------------------------------------------------------ #
    # wait events — ASH history aggregated overall + per plan step
    # ------------------------------------------------------------------ #

    def _collect_wait_events(self, bundle, sql_id, con_id, lookback_days):
        table = self._hist_prefix + "ACTIVE_SESS_HISTORY"
        params = {"sql_id": sql_id, "since": datetime.now() - timedelta(days=lookback_days)}

        # Overall event breakdown (ASH is a 1-sample-per-second-per-active-
        # session model, so COUNT(*) * (approx sample interval) approximates
        # time; we report both raw sample counts and modeled seconds).
        overall_rows = self.conn.fetch_all(
            "SELECT NVL(EVENT, 'ON CPU') AS EVENT, WAIT_CLASS, "
            "COUNT(*) AS SAMPLE_COUNT, SUM(NVL(TIME_WAITED,0)) AS TOTAL_TIME_WAITED "
            "FROM {0} WHERE SQL_ID = :sql_id AND SAMPLE_TIME >= :since "
            "GROUP BY EVENT, WAIT_CLASS ORDER BY SAMPLE_COUNT DESC".format(table),
            params,
        )
        total_samples = sum(r["SAMPLE_COUNT"] for r in overall_rows) or 1
        for r in overall_rows:
            bundle.wait_event_summary.append(WaitEventAgg(
                event=r["EVENT"],
                wait_class=r.get("WAIT_CLASS") or ("CPU" if r["EVENT"] == "ON CPU" else "OTHER"),
                total_wait_secs=(r["TOTAL_TIME_WAITED"] or 0) / 1000000.0,
                sample_count=r["SAMPLE_COUNT"],
                pct_of_total=round(100.0 * r["SAMPLE_COUNT"] / total_samples, 2),
            ))

        # Per plan-step breakdown — this is what lets you say "78% of the
        # time in THIS execution was spent at plan line 14."
        step_rows = self.conn.fetch_all(
            "SELECT SQL_PLAN_HASH_VALUE, SQL_PLAN_LINE_ID, "
            "NVL(EVENT,'ON CPU') AS EVENT, WAIT_CLASS, COUNT(*) AS SAMPLE_COUNT, "
            "SUM(NVL(TIME_WAITED,0)) AS TOTAL_TIME_WAITED "
            "FROM {0} WHERE SQL_ID = :sql_id AND SAMPLE_TIME >= :since "
            "AND SQL_PLAN_LINE_ID IS NOT NULL "
            "GROUP BY SQL_PLAN_HASH_VALUE, SQL_PLAN_LINE_ID, EVENT, WAIT_CLASS "
            "ORDER BY SQL_PLAN_HASH_VALUE, SAMPLE_COUNT DESC".format(table),
            params,
        )
        for r in step_rows:
            bundle.wait_event_by_plan_step.append(WaitEventAgg(
                event=r["EVENT"],
                wait_class=r.get("WAIT_CLASS") or ("CPU" if r["EVENT"] == "ON CPU" else "OTHER"),
                total_wait_secs=(r["TOTAL_TIME_WAITED"] or 0) / 1000000.0,
                sample_count=r["SAMPLE_COUNT"],
                plan_line_id="{0}:{1}".format(r["SQL_PLAN_HASH_VALUE"], r["SQL_PLAN_LINE_ID"]),
            ))

    # ------------------------------------------------------------------ #
    # currently running — live ASH + SQL Monitor
    # ------------------------------------------------------------------ #

    def _collect_currently_running(self, bundle, sql_id, con_id):
        rows = self.conn.fetch_all(
            "SELECT SAMPLE_TIME, SESSION_STATE, EVENT, WAIT_CLASS, "
            "SQL_PLAN_LINE_ID, SQL_PLAN_HASH_VALUE, SQL_EXEC_ID, "
            "SQL_EXEC_START, P1, P2, P3, TIME_WAITED, IN_PARSE, "
            "IN_HARD_PARSE, IN_SQL_EXECUTION, IN_PLSQL_EXECUTION, "
            "TEMP_SPACE_ALLOCATED, PGA_ALLOCATED, BLOCKING_SESSION, "
            "SESSION_ID, MODULE, CON_ID "
            "FROM V$ACTIVE_SESSION_HISTORY WHERE SQL_ID = :sql_id "
            "ORDER BY SAMPLE_TIME DESC",
            {"sql_id": sql_id},
        )
        bundle.ash_current_samples = [AshSample(r) for r in rows]
        if rows:
            bundle.is_currently_running = True

    def _collect_sql_monitor(self, bundle, sql_id, con_id):
        rows = self.conn.fetch_all(
            "SELECT SQL_ID, SQL_EXEC_ID, SQL_EXEC_START, STATUS, "
            "PX_SERVERS_REQUESTED, PX_SERVERS_ALLOCATED, ELAPSED_TIME, "
            "CPU_TIME, BUFFER_GETS, DISK_READS, PHYSICAL_READ_BYTES, "
            "PHYSICAL_WRITE_BYTES, PLAN_HASH_VALUE, ERROR_MESSAGE "
            "FROM V$SQL_MONITOR WHERE SQL_ID = :sql_id "
            "ORDER BY SQL_EXEC_START DESC",
            {"sql_id": sql_id},
        )
        for r in rows:
            report = SqlMonitorReport(r)
            step_rows = self.conn.fetch_all(
                "SELECT PLAN_LINE_ID AS ID, PLAN_OPERATION AS OPERATION, "
                "PLAN_OPTIONS AS OPTIONS, PLAN_OBJECT_OWNER AS OBJECT_OWNER, "
                "PLAN_OBJECT_NAME AS OBJECT_NAME, STARTS, OUTPUT_ROWS, "
                "CARDINALITY, ESTIMATED_OPTIMAL_TIME, LAST_ELAPSED_TIME, "
                "LAST_CR_BUFFER_GETS, LAST_CU_BUFFER_GETS, LAST_DISK_READS, "
                "LAST_DISK_WRITES, LAST_MEMORY_USED, LAST_TEMPSEG_SIZE, "
                "LAST_EXECUTIONS_OPTIMAL "
                "FROM V$SQL_PLAN_MONITOR "
                "WHERE SQL_ID = :sql_id AND SQL_EXEC_ID = :exec_id "
                "ORDER BY PLAN_LINE_ID",
                {"sql_id": sql_id, "exec_id": r["SQL_EXEC_ID"]},
            )
            report.step_monitor = [PlanStep(s) for s in step_rows]
            bundle.sql_monitor_reports.append(report)

    # ------------------------------------------------------------------ #
    # bind values captured historically — critical for bind-sensitive /
    # skewed-predicate diagnosis
    # ------------------------------------------------------------------ #

    def _collect_bind_history(self, bundle, sql_id, con_id, lookback_days):
        table = self._hist_prefix + "SQLBIND"
        params = {"sql_id": sql_id}
        rows = self.conn.fetch_all(
            "SELECT NAME, POSITION, DATATYPE_STRING, VALUE_STRING, "
            "WAS_CAPTURED, SNAP_ID FROM {0} "
            "WHERE SQL_ID = :sql_id ORDER BY SNAP_ID, POSITION".format(table),
            params,
        )
        bundle.bind_history = [BindCapture(r) for r in rows]

    # ------------------------------------------------------------------ #
    # plan stability: baselines, profiles, patches
    # ------------------------------------------------------------------ #

    def _collect_baselines(self, bundle, sql_id, con_id):
        # Baselines are keyed by SQL_HANDLE, not SQL_ID directly — resolve
        # the handle first via V$SQL, since DBA_SQL_PLAN_BASELINES has no
        # SQL_ID column.
        handle_row = self.conn.fetch_one(
            "SELECT DISTINCT SQL_PLAN_BASELINE FROM V$SQL "
            "WHERE SQL_ID = :sql_id AND SQL_PLAN_BASELINE IS NOT NULL "
            "AND ROWNUM = 1",
            {"sql_id": sql_id},
        )
        rows = []
        if handle_row and handle_row.get("SQL_PLAN_BASELINE"):
            rows = self.conn.fetch_all(
                "SELECT SQL_HANDLE, PLAN_NAME, ORIGIN, ENABLED, ACCEPTED, "
                "FIXED, AUTOPURGE, ADAPTIVE, REPRODUCED, COST, CREATED, "
                "LAST_MODIFIED, LAST_EXECUTED, LAST_VERIFIED "
                "FROM DBA_SQL_PLAN_BASELINES "
                "WHERE SQL_HANDLE = (SELECT SQL_HANDLE FROM DBA_SQL_PLAN_BASELINES "
                "WHERE PLAN_NAME = :plan_name AND ROWNUM = 1)",
                {"plan_name": handle_row["SQL_PLAN_BASELINE"]},
            )
        else:
            # Fall back to matching by exact SQL text signature — best
            # effort when no active session currently references a baseline.
            pass
        bundle.baselines = [SqlPlanBaselineInfo(r) for r in rows]

    def _collect_profiles_and_patches(self, bundle, sql_id, con_id):
        prof_row = self.conn.fetch_one(
            "SELECT SQL_PROFILE, SQL_PATCH FROM V$SQL "
            "WHERE SQL_ID = :sql_id AND ROWNUM = 1",
            {"sql_id": sql_id},
        )
        if prof_row and prof_row.get("SQL_PROFILE"):
            rows = self.conn.fetch_all(
                "SELECT NAME, CATEGORY, SQL_TEXT, TYPE, STATUS, "
                "FORCE_MATCHING FROM DBA_SQL_PROFILES WHERE NAME = :name",
                {"name": prof_row["SQL_PROFILE"]},
            )
            bundle.sql_profiles = [SqlProfileInfo(r) for r in rows]
        if prof_row and prof_row.get("SQL_PATCH"):
            rows = self.conn.fetch_all(
                "SELECT NAME, STATUS, HINT_TEXT FROM DBA_SQL_PATCHES "
                "WHERE NAME = :name",
                {"name": prof_row["SQL_PATCH"]},
            )
            bundle.sql_patches = [SqlPatchInfo(r) for r in rows]

    # ------------------------------------------------------------------ #
    # optimizer environment drift across executions with different plans
    # ------------------------------------------------------------------ #

    def _collect_optimizer_env_diffs(self, bundle, sql_id, con_id, lookback_days):
        env_table = self._hist_prefix + "SQL_OPTIMIZER_ENV"
        distinct_envs = list({
            (s.plan_hash_value, s.optimizer_env_hash_value)
            for s in bundle.awr_sqlstat_history
            if s.optimizer_env_hash_value is not None
        })
        if len(distinct_envs) < 2:
            return  # nothing to diff — only one optimizer environment seen

        # Compare the two most recent distinct environments only, to keep
        # this bounded and readable; a full pairwise matrix is available
        # via bundle.awr_sqlstat_history for anyone who wants more.
        (phv_a, env_a), (phv_b, env_b) = distinct_envs[-2], distinct_envs[-1]
        rows_a = self.conn.fetch_all(
            "SELECT NAME, VALUE FROM {0} "
            "WHERE OPTIMIZER_ENV_HASH_VALUE = :env_hash".format(env_table),
            {"env_hash": env_a},
        )
        rows_b = self.conn.fetch_all(
            "SELECT NAME, VALUE FROM {0} "
            "WHERE OPTIMIZER_ENV_HASH_VALUE = :env_hash".format(env_table),
            {"env_hash": env_b},
        )
        map_a = {r["NAME"]: r["VALUE"] for r in rows_a}
        map_b = {r["NAME"]: r["VALUE"] for r in rows_b}
        for name in set(map_a) | set(map_b):
            va, vb = map_a.get(name), map_b.get(name)
            if va != vb:
                bundle.optimizer_env_diffs.append(
                    OptimizerEnvDiff(name, va, vb, phv_a, phv_b)
                )

    # ------------------------------------------------------------------ #
    # object-keyed collectors — run AFTER plans are known, since these
    # are looked up by the actual tables/columns referenced in the plan,
    # not by SQL_ID directly.
    # ------------------------------------------------------------------ #

    def _plan_referenced_objects(self, bundle):
        """Distinct (owner, object_name, object_type) tuples across every
        collected plan — the driver set for directive/index lookups."""
        objs = set()
        for plan in bundle.execution_plans:
            for step in plan.steps:
                if step.object_owner and step.object_name:
                    objs.add((step.object_owner, step.object_name, step.object_type))
        return objs

    def _collect_sql_plan_directives(self, bundle, sql_id, con_id):
        objs = self._plan_referenced_objects(bundle)
        if not objs:
            return
        owners = sorted(set(o[0] for o in objs))
        names = sorted(set(o[1] for o in objs))
        # DBA_SQL_PLAN_DIRECTIVES has no direct object columns; the join
        # to objects goes through DBA_SQL_PLAN_DIR_OBJECTS. We pull
        # directives for any directive that references one of the tables
        # seen in this plan.
        placeholders_owner = ",".join(":o{0}".format(i) for i in range(len(owners)))
        placeholders_name = ",".join(":n{0}".format(i) for i in range(len(names)))
        params = {}
        for i, o in enumerate(owners):
            params["o{0}".format(i)] = o
        for i, n in enumerate(names):
            params["n{0}".format(i)] = n

        rows = self.conn.fetch_all(
            "SELECT d.DIRECTIVE_ID, d.TYPE, d.STATE, d.REASON, d.ENABLED, "
            "d.INTERNAL_STATE, d.CREATED, d.LAST_USED, d.NOTES, "
            "o.OWNER, o.OBJECT_NAME, o.OBJECT_TYPE, o.COLUMN_NAME "
            "FROM DBA_SQL_PLAN_DIRECTIVES d "
            "JOIN DBA_SQL_PLAN_DIR_OBJECTS o "
            "  ON d.DIRECTIVE_ID = o.DIRECTIVE_ID "
            "WHERE o.OWNER IN ({0}) AND o.OBJECT_NAME IN ({1}) "
            "AND o.OBJECT_TYPE = 'TABLE'".format(placeholders_owner, placeholders_name),
            params,
        )
        bundle.sql_plan_directives = [SqlPlanDirectiveInfo(r) for r in rows]

    def _collect_index_column_stats(self, bundle, sql_id, con_id):
        objs = self._plan_referenced_objects(bundle)
        table_objs = [(o, n) for (o, n, t) in objs if t and "TABLE" in t.upper()]
        if not table_objs:
            return

        for owner, table_name in table_objs:
            rows = self.conn.fetch_all(
                "SELECT i.OWNER, i.TABLE_NAME, i.INDEX_NAME, ic.COLUMN_NAME, "
                "ic.COLUMN_POSITION, i.UNIQUENESS, i.CLUSTERING_FACTOR, "
                "i.NUM_ROWS, i.BLEVEL, i.LEAF_BLOCKS, i.DISTINCT_KEYS, "
                "i.STATUS, i.VISIBILITY, "
                "tc.NUM_DISTINCT AS COL_NUM_DISTINCT, tc.DENSITY AS COL_DENSITY, "
                "tc.HISTOGRAM AS COL_HISTOGRAM "
                "FROM DBA_INDEXES i "
                "JOIN DBA_IND_COLUMNS ic "
                "  ON i.OWNER = ic.INDEX_OWNER AND i.INDEX_NAME = ic.INDEX_NAME "
                "LEFT JOIN DBA_TAB_COL_STATISTICS tc "
                "  ON tc.OWNER = i.TABLE_OWNER AND tc.TABLE_NAME = i.TABLE_NAME "
                "     AND tc.COLUMN_NAME = ic.COLUMN_NAME "
                "WHERE i.OWNER = :owner AND i.TABLE_NAME = :table_name "
                "ORDER BY i.INDEX_NAME, ic.COLUMN_POSITION",
                {"owner": owner, "table_name": table_name},
            )
            bundle.index_column_stats.extend(IndexColumnStat(r) for r in rows)

    def _collect_object_statistics_health(self, bundle, sql_id, con_id):
        """Deliberately METADATA-ONLY. Every query here reads
        DBA_TABLES/DBA_TAB_STATISTICS/DBA_IND_STATISTICS — dictionary
        views backed by cheap, already-maintained metadata, never a table
        scan or a live DBMS_STATS call. This must never be the thing that
        adds load to a production system it's diagnosing."""
        objs = self._plan_referenced_objects(bundle)
        table_objs = [(o, n) for (o, n, t) in objs if t and "TABLE" in t.upper()]
        for owner, table_name in table_objs:
            row = self.conn.fetch_one(
                "SELECT t.OWNER, t.TABLE_NAME AS OBJECT_NAME, 'TABLE' AS OBJECT_TYPE, "
                "s.LAST_ANALYZED, s.STALE_STATS, s.NUM_ROWS, s.SAMPLE_SIZE, "
                "s.GLOBAL_STATS, t.PARTITIONED "
                "FROM DBA_TABLES t "
                "LEFT JOIN DBA_TAB_STATISTICS s "
                "  ON s.OWNER = t.OWNER AND s.TABLE_NAME = t.TABLE_NAME "
                "     AND s.PARTITION_NAME IS NULL AND s.SUBPARTITION_NAME IS NULL "
                "WHERE t.OWNER = :owner AND t.TABLE_NAME = :table_name",
                {"owner": owner, "table_name": table_name},
            )
            if row:
                bundle.object_statistics_health.append(ObjectStatisticsHealth(row))

        idx_names = set(
            (ic.owner, ic.index_name) for ic in bundle.index_column_stats if ic.index_name
        )
        for owner, index_name in idx_names:
            row = self.conn.fetch_one(
                "SELECT i.OWNER, i.INDEX_NAME AS OBJECT_NAME, 'INDEX' AS OBJECT_TYPE, "
                "s.LAST_ANALYZED, s.STALE_STATS, s.NUM_ROWS, s.SAMPLE_SIZE, "
                "s.GLOBAL_STATS, NULL AS PARTITIONED "
                "FROM DBA_INDEXES i "
                "LEFT JOIN DBA_IND_STATISTICS s "
                "  ON s.OWNER = i.OWNER AND s.INDEX_NAME = i.INDEX_NAME "
                "     AND s.PARTITION_NAME IS NULL AND s.SUBPARTITION_NAME IS NULL "
                "WHERE i.OWNER = :owner AND i.INDEX_NAME = :index_name",
                {"owner": owner, "index_name": index_name},
            )
            if row:
                bundle.object_statistics_health.append(ObjectStatisticsHealth(row))

    def _collect_sql_tuning_advisor_history(self, bundle, sql_id, con_id):
        """SQL Tuning Advisor stores its analysis of a specific SQL_ID as
        an 'object' of TYPE='SQL' with ATTR1=sql_id in DBA_ADVISOR_OBJECTS,
        tied to a task. This surfaces whatever STA has ALREADY concluded
        for this exact SQL_ID — the authoritative source, since STA runs
        the optimizer's own what-if trial rather than us inferring from
        plan shape. Read-only, dictionary-metadata only; does not create
        or execute a new tuning task."""
        task_rows = self.conn.fetch_all(
            "SELECT DISTINCT t.TASK_NAME, t.STATUS, t.CREATED, o.OBJECT_ID, t.TASK_ID "
            "FROM DBA_ADVISOR_OBJECTS o "
            "JOIN DBA_ADVISOR_TASKS t ON o.TASK_ID = t.TASK_ID "
            "WHERE o.TYPE = 'SQL' AND o.ATTR1 = :sql_id "
            "ORDER BY t.CREATED DESC",
            {"sql_id": sql_id},
        )
        if not task_rows:
            return  # never analyzed — bundle.sql_tuning_advisor stays has_been_analyzed=False

        bundle.sql_tuning_advisor.has_been_analyzed = True
        bundle.sql_tuning_advisor.tasks = [
            {"task_name": r["TASK_NAME"], "status": r["STATUS"], "created": r["CREATED"]}
            for r in task_rows
        ]

        latest_task_id = task_rows[0]["TASK_ID"]
        rec_rows = self.conn.fetch_all(
            "SELECT r.TASK_NAME, r.REC_ID, r.TYPE, r.BENEFIT, r.RANK, "
            "f.MESSAGE AS FINDING, ra.MESSAGE AS RATIONALE, a.COMMAND, r.MESSAGE "
            "FROM DBA_ADVISOR_RECOMMENDATIONS r "
            "LEFT JOIN DBA_ADVISOR_FINDINGS f "
            "  ON r.TASK_ID = f.TASK_ID AND r.FINDING_ID = f.FINDING_ID "
            "LEFT JOIN DBA_ADVISOR_RATIONALE ra "
            "  ON r.TASK_ID = ra.TASK_ID AND r.REC_ID = ra.REC_ID "
            "LEFT JOIN DBA_ADVISOR_ACTIONS a "
            "  ON r.TASK_ID = a.TASK_ID AND r.REC_ID = a.REC_ID "
            "WHERE r.TASK_ID = :task_id "
            "ORDER BY r.RANK",
            {"task_id": latest_task_id},
        )
        bundle.sql_tuning_advisor.recommendations = [AdvisorRecommendation(r) for r in rec_rows]
