# -*- coding: utf-8 -*-
"""
models.py
---------
Plain-old Python classes representing the forensic data model for a single
SQL_ID investigation. Deliberately NOT using dataclasses (Py3.7+) so this
stays importable under Python 3.6.8 with zero third-party dependencies.

Every object here is a pure data holder with a to_dict() for JSON/report
serialization. No DB logic lives in this module.
"""

import json


class SerializableMixin(object):
    """Gives every model a stable, ordered, JSON-safe representation."""

    def to_dict(self):
        out = {}
        for key, value in self.__dict__.items():
            if hasattr(value, "to_dict"):
                out[key] = value.to_dict()
            elif isinstance(value, list):
                out[key] = [
                    v.to_dict() if hasattr(v, "to_dict") else v for v in value
                ]
            else:
                out[key] = value
        return out

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, default=str)


class TargetIdentity(SerializableMixin):
    """Identifies exactly which SQL, in which container, we are chasing."""

    def __init__(self, sql_id, con_id=None, pdb_name=None, is_cdb=False):
        self.sql_id = sql_id
        self.con_id = con_id
        self.pdb_name = pdb_name
        self.is_cdb = is_cdb


class SqlTextInfo(SerializableMixin):
    def __init__(self, sql_text=None, sql_fulltext=None, command_type=None,
                 module=None, action=None, parsing_schema_name=None):
        self.sql_text = sql_text
        self.sql_fulltext = sql_fulltext
        self.command_type = command_type
        self.module = module
        self.action = action
        self.parsing_schema_name = parsing_schema_name


class CursorChildInfo(SerializableMixin):
    """One row from V$SQL / V$SQLAREA — one child cursor / plan_hash combo."""

    def __init__(self, row):
        self.child_number = row.get("CHILD_NUMBER")
        self.plan_hash_value = row.get("PLAN_HASH_VALUE")
        self.executions = row.get("EXECUTIONS")
        self.elapsed_time_us = row.get("ELAPSED_TIME")
        self.cpu_time_us = row.get("CPU_TIME")
        self.buffer_gets = row.get("BUFFER_GETS")
        self.disk_reads = row.get("DISK_READS")
        self.direct_writes = row.get("DIRECT_WRITES")
        self.rows_processed = row.get("ROWS_PROCESSED")
        self.parse_calls = row.get("PARSE_CALLS")
        self.fetches = row.get("FETCHES")
        self.sorts = row.get("SORTS")
        self.optimizer_cost = row.get("OPTIMIZER_COST")
        self.optimizer_mode = row.get("OPTIMIZER_MODE")
        self.optimizer_env_hash_value = row.get("OPTIMIZER_ENV_HASH_VALUE")
        self.is_bind_sensitive = row.get("IS_BIND_SENSITIVE")
        self.is_bind_aware = row.get("IS_BIND_AWARE")
        self.is_shareable = row.get("IS_SHAREABLE")
        self.invalidations = row.get("INVALIDATIONS")
        self.loads = row.get("LOADS")
        self.loaded_versions = row.get("LOADED_VERSIONS")
        self.first_load_time = row.get("FIRST_LOAD_TIME")
        self.last_active_time = row.get("LAST_ACTIVE_TIME")
        self.last_load_time = row.get("LAST_LOAD_TIME")
        self.avg_hard_parse_time = row.get("AVG_HARD_PARSE_TIME")
        self.sql_profile = row.get("SQL_PROFILE")
        self.sql_patch = row.get("SQL_PATCH")
        self.sql_plan_baseline = row.get("SQL_PLAN_BASELINE")
        self.con_id = row.get("CON_ID")
        self.plsql_exec_time = row.get("PLSQL_EXEC_TIME")
        self.io_cell_offload_eligible_bytes = row.get("IO_CELL_OFFLOAD_ELIGIBLE_BYTES")
        self.io_interconnect_bytes = row.get("IO_INTERCONNECT_BYTES")


class SharedCursorMismatch(SerializableMixin):
    """From V$SQL_SHARED_CURSOR — WHY a new child cursor was created instead
    of reusing an existing plan. Massively underused diagnostic signal."""

    def __init__(self, child_number, mismatch_reasons):
        self.child_number = child_number
        # list of (column_name, value) where value in ('Y','y', ...)
        self.mismatch_reasons = mismatch_reasons


class PlanStep(SerializableMixin):
    """One row of an execution plan (from V$SQL_PLAN,
    DBA_HIST_SQL_PLAN, or V$SQL_PLAN_STATISTICS_ALL)."""

    def __init__(self, row):
        self.id = row.get("ID")
        self.parent_id = row.get("PARENT_ID")
        self.depth = row.get("DEPTH")
        self.operation = row.get("OPERATION")
        self.options = row.get("OPTIONS")
        self.object_owner = row.get("OBJECT_OWNER")
        self.object_name = row.get("OBJECT_NAME")
        self.object_alias = row.get("OBJECT_ALIAS")
        self.object_type = row.get("OBJECT_TYPE")
        self.optimizer = row.get("OPTIMIZER")
        self.cost = row.get("COST")
        self.cardinality = row.get("CARDINALITY")
        self.bytes = row.get("BYTES")
        self.partition_start = row.get("PARTITION_START")
        self.partition_stop = row.get("PARTITION_STOP")
        self.partition_id = row.get("PARTITION_ID")
        self.access_predicates = row.get("ACCESS_PREDICATES")
        self.filter_predicates = row.get("FILTER_PREDICATES")
        self.projection = row.get("PROJECTION")
        self.distribution = row.get("DISTRIBUTION")   # PQ distribution method
        self.cpu_cost = row.get("CPU_COST")
        self.io_cost = row.get("IO_COST")
        self.temp_space = row.get("TEMP_SPACE")
        self.qblock_name = row.get("QBLOCK_NAME")
        self.other_tag = row.get("OTHER_TAG")
        self.other_xml = row.get("OTHER_XML")   # holds adaptive plan / outline info
        # Actual runtime stats (only from *_STATISTICS_ALL / SQL Monitor)
        self.actual_starts = row.get("STARTS")
        self.actual_rows = row.get("LAST_OUTPUT_ROWS") or row.get("OUTPUT_ROWS")
        self.actual_cr_buffer_gets = row.get("LAST_CR_BUFFER_GETS")
        self.actual_cu_buffer_gets = row.get("LAST_CU_BUFFER_GETS")
        self.actual_disk_reads = row.get("LAST_DISK_READS")
        self.actual_disk_writes = row.get("LAST_DISK_WRITES")
        self.actual_elapsed_time = row.get("LAST_ELAPSED_TIME")
        self.workarea_mem = row.get("LAST_MEMORY_USED")
        self.workarea_tempseg = row.get("LAST_TEMPSEG_SIZE")
        self.workarea_execs_optimal = row.get("LAST_EXECUTIONS_OPTIMAL") \
            if "LAST_EXECUTIONS_OPTIMAL" in row else None


class ExecutionPlan(SerializableMixin):
    """A full plan (all steps) tied to one plan_hash_value + source."""

    def __init__(self, plan_hash_value, source, steps=None, timestamp=None,
                 sql_child_number=None):
        self.plan_hash_value = plan_hash_value
        self.source = source                 # 'CURSOR_CACHE' | 'AWR' | 'SQL_MONITOR' | 'BASELINE'
        self.timestamp = timestamp
        self.sql_child_number = sql_child_number
        self.steps = steps or []             # list[PlanStep]

    def add_step(self, step):
        self.steps.append(step)


class AwrSqlStatSnapshot(SerializableMixin):
    """One row from DBA_HIST_SQLSTAT — per-snapshot delta performance."""

    def __init__(self, row):
        self.snap_id = row.get("SNAP_ID")
        self.begin_interval_time = row.get("BEGIN_INTERVAL_TIME")
        self.end_interval_time = row.get("END_INTERVAL_TIME")
        self.plan_hash_value = row.get("PLAN_HASH_VALUE")
        self.executions_delta = row.get("EXECUTIONS_DELTA")
        self.elapsed_time_delta = row.get("ELAPSED_TIME_DELTA")
        self.cpu_time_delta = row.get("CPU_TIME_DELTA")
        self.iowait_delta = row.get("IOWAIT_DELTA")
        self.clwait_delta = row.get("CLWAIT_DELTA")
        self.apwait_delta = row.get("APWAIT_DELTA")
        self.ccwait_delta = row.get("CCWAIT_DELTA")
        self.buffer_gets_delta = row.get("BUFFER_GETS_DELTA")
        self.disk_reads_delta = row.get("DISK_READS_DELTA")
        self.direct_writes_delta = row.get("DIRECT_WRITES_DELTA")
        self.rows_processed_delta = row.get("ROWS_PROCESSED_DELTA")
        self.fetches_delta = row.get("FETCHES_DELTA")
        self.parse_calls_delta = row.get("PARSE_CALLS_DELTA")
        self.sorts_delta = row.get("SORTS_DELTA")
        # Temp / undo, direct signals of a spill or costly rollback support
        self.px_servers_execs_delta = row.get("PX_SERVERS_EXECS_DELTA")
        self.optimizer_cost = row.get("OPTIMIZER_COST")
        self.optimizer_env_hash_value = row.get("OPTIMIZER_ENV_HASH_VALUE")
        self.con_id = row.get("CON_ID")


class WaitEventAgg(SerializableMixin):
    """Aggregated wait-event contribution (from ASH), attributable to this
    SQL_ID overall or to one plan step."""

    def __init__(self, event, wait_class, total_wait_secs, sample_count,
                 plan_line_id=None, pct_of_total=None, avg_wait_us=None):
        self.event = event
        self.wait_class = wait_class
        self.total_wait_secs = total_wait_secs
        self.sample_count = sample_count
        self.plan_line_id = plan_line_id
        self.pct_of_total = pct_of_total
        self.avg_wait_us = avg_wait_us


class AshSample(SerializableMixin):
    """One (or one aggregated bucket of) ASH sample row — kept lean; we
    normally aggregate before storing thousands of these."""

    def __init__(self, row):
        self.sample_time = row.get("SAMPLE_TIME")
        self.session_state = row.get("SESSION_STATE")   # ON CPU / WAITING
        self.event = row.get("EVENT")
        self.wait_class = row.get("WAIT_CLASS")
        self.sql_plan_line_id = row.get("SQL_PLAN_LINE_ID")
        self.sql_plan_hash_value = row.get("SQL_PLAN_HASH_VALUE")
        self.sql_exec_id = row.get("SQL_EXEC_ID")
        self.sql_exec_start = row.get("SQL_EXEC_START")
        self.p1 = row.get("P1")
        self.p2 = row.get("P2")
        self.p3 = row.get("P3")
        self.time_waited = row.get("TIME_WAITED")
        self.in_parse = row.get("IN_PARSE")
        self.in_hard_parse = row.get("IN_HARD_PARSE")
        self.in_sql_execution = row.get("IN_SQL_EXECUTION")
        self.in_plsql_execution = row.get("IN_PLSQL_EXECUTION")
        self.temp_space_allocated = row.get("TEMP_SPACE_ALLOCATED")
        self.pga_allocated = row.get("PGA_ALLOCATED")
        self.tablespace_number = row.get("CURRENT_OBJ#") if "CURRENT_OBJ#" in row else None
        self.blocking_session = row.get("BLOCKING_SESSION")
        self.session_id = row.get("SESSION_ID")
        self.module = row.get("MODULE")
        self.con_id = row.get("CON_ID")


class BindCapture(SerializableMixin):
    def __init__(self, row):
        self.name = row.get("NAME")
        self.position = row.get("POSITION")
        self.datatype_string = row.get("DATATYPE_STRING")
        self.value_string = row.get("VALUE_STRING")
        self.was_captured = row.get("WAS_CAPTURED")
        self.snap_id = row.get("SNAP_ID")


class SqlPlanBaselineInfo(SerializableMixin):
    def __init__(self, row):
        self.sql_handle = row.get("SQL_HANDLE")
        self.plan_name = row.get("PLAN_NAME")
        self.origin = row.get("ORIGIN")
        self.enabled = row.get("ENABLED")
        self.accepted = row.get("ACCEPTED")
        self.fixed = row.get("FIXED")
        self.autopurge = row.get("AUTOPURGE")
        self.adaptive = row.get("ADAPTIVE")
        self.reproduced = row.get("REPRODUCED")
        self.cost = row.get("COST")
        self.plan_hash_value = row.get("PLAN_HASH_VALUE") if "PLAN_HASH_VALUE" in row else None
        self.created = row.get("CREATED")
        self.last_modified = row.get("LAST_MODIFIED")
        self.last_executed = row.get("LAST_EXECUTED")
        self.last_verified = row.get("LAST_VERIFIED")


class SqlProfileInfo(SerializableMixin):
    def __init__(self, row):
        self.name = row.get("NAME")
        self.category = row.get("CATEGORY")
        self.sql_text = row.get("SQL_TEXT")
        self.type = row.get("TYPE")
        self.status = row.get("STATUS")
        self.force_matching = row.get("FORCE_MATCHING")


class SqlPatchInfo(SerializableMixin):
    def __init__(self, row):
        self.name = row.get("NAME")
        self.status = row.get("STATUS")
        self.hint_text = row.get("HINT_TEXT")


class OptimizerEnvDiff(SerializableMixin):
    """A single optimizer parameter that differs between two plan_hash_value
    executions of the same SQL_ID — a common silent cause of plan flips."""

    def __init__(self, param_name, value_a, value_b, plan_hash_a, plan_hash_b):
        self.param_name = param_name
        self.value_a = value_a
        self.value_b = value_b
        self.plan_hash_a = plan_hash_a
        self.plan_hash_b = plan_hash_b


class SqlMonitorReport(SerializableMixin):
    """Real-time SQL Monitoring summary (V$SQL_MONITOR +
    V$SQL_PLAN_MONITOR) — the single richest live source: actual vs
    estimated rows PER STEP, IO per step, time per step, parallel
    server distribution."""

    def __init__(self, row):
        self.sql_id = row.get("SQL_ID")
        self.sql_exec_id = row.get("SQL_EXEC_ID")
        self.sql_exec_start = row.get("SQL_EXEC_START")
        self.status = row.get("STATUS")
        self.px_servers_requested = row.get("PX_SERVERS_REQUESTED")
        self.px_servers_allocated = row.get("PX_SERVERS_ALLOCATED")
        self.elapsed_time = row.get("ELAPSED_TIME")
        self.cpu_time = row.get("CPU_TIME")
        self.buffer_gets = row.get("BUFFER_GETS")
        self.disk_reads = row.get("DISK_READS")
        self.physical_read_bytes = row.get("PHYSICAL_READ_BYTES")
        self.physical_write_bytes = row.get("PHYSICAL_WRITE_BYTES")
        self.plan_hash_value = row.get("PLAN_HASH_VALUE")
        self.error_message = row.get("ERROR_MESSAGE")
        self.bind_data = row.get("BINDS_XML") if "BINDS_XML" in row else None
        self.step_monitor = []   # list of PlanStep with actual-vs-estimate


class ObjectStatisticsHealth(SerializableMixin):
    """From DBA_TABLES / DBA_TAB_STATISTICS / DBA_TAB_COL_STATISTICS /
    DBA_IND_STATISTICS for one object referenced in the plan — answers
    "are this table's stats trustworthy right now" directly, rather than
    inferring it only from a misestimate downstream."""

    def __init__(self, row):
        self.owner = row.get("OWNER")
        self.object_name = row.get("OBJECT_NAME")
        self.object_type = row.get("OBJECT_TYPE")   # TABLE / INDEX
        self.last_analyzed = row.get("LAST_ANALYZED")
        self.stale_stats = row.get("STALE_STATS")           # from *_TAB_STATISTICS.STALE_STATS
        self.num_rows = row.get("NUM_ROWS")
        self.sample_size = row.get("SAMPLE_SIZE")
        self.global_stats = row.get("GLOBAL_STATS")
        self.partitioned = row.get("PARTITIONED")
        self.stattype_locked = row.get("STATTYPE_LOCKED")
        self.degree_of_stale_pct = row.get("DEGREE_OF_STALE_PCT")  # computed, not a real column
        self.dynamic_sampling_level = row.get("DYNAMIC_SAMPLING_LEVEL")  # from hint/session if detectable


class SqlPlanDirectiveInfo(SerializableMixin):
    """From DBA_SQL_PLAN_DIRECTIVES / DBA_SQL_PLAN_DIR_OBJECTS — records
    that the optimizer itself flagged a misestimate pattern on an object
    and is applying (or planning to apply) dynamic sampling / adaptive
    stats as a correction. Table/column-keyed, not SQL_ID-keyed, so this
    is looked up by the objects referenced in the plan, after the plan
    is known."""

    def __init__(self, row):
        self.directive_id = row.get("DIRECTIVE_ID")
        self.type = row.get("TYPE")                # e.g. 'DYNAMIC_SAMPLING'
        self.state = row.get("STATE")               # NEW / MISSING_STATS / HAS_STATS / PERMANENT / SUPERSEDED
        self.reason = row.get("REASON")              # e.g. 'SINGLE TABLE CARDINALITY MISESTIMATE'
        self.enabled = row.get("ENABLED")
        self.internal_state = row.get("INTERNAL_STATE")
        self.created = row.get("CREATED")
        self.last_used = row.get("LAST_USED")
        self.notes = row.get("NOTES")
        self.owner = row.get("OWNER")
        self.object_name = row.get("OBJECT_NAME")
        self.object_type = row.get("OBJECT_TYPE")
        self.column_name = row.get("COLUMN_NAME")


class IndexColumnStat(SerializableMixin):
    """From DBA_INDEXES / DBA_IND_COLUMNS / DBA_TAB_COL_STATISTICS —
    lets the diagnostic engine answer "should this FILTER predicate
    have been an ACCESS predicate instead" and "is this index well
    clustered for this access pattern" without guessing."""

    def __init__(self, row):
        self.owner = row.get("OWNER")
        self.table_name = row.get("TABLE_NAME")
        self.index_name = row.get("INDEX_NAME")
        self.column_name = row.get("COLUMN_NAME")
        self.column_position = row.get("COLUMN_POSITION")
        self.uniqueness = row.get("UNIQUENESS")
        self.clustering_factor = row.get("CLUSTERING_FACTOR")
        self.num_rows = row.get("NUM_ROWS")
        self.blevel = row.get("BLEVEL")
        self.leaf_blocks = row.get("LEAF_BLOCKS")
        self.distinct_keys = row.get("DISTINCT_KEYS")
        self.status = row.get("STATUS")
        self.visibility = row.get("VISIBILITY")
        self.col_num_distinct = row.get("COL_NUM_DISTINCT")
        self.col_density = row.get("COL_DENSITY")
        self.col_histogram = row.get("COL_HISTOGRAM")


class AdvisorRecommendation(SerializableMixin):
    """One row from DBA_ADVISOR_RECOMMENDATIONS + its rationale, tied to
    a completed SQL Tuning Advisor task for this SQL_ID."""

    def __init__(self, row):
        self.task_name = row.get("TASK_NAME")
        self.rec_id = row.get("REC_ID")
        self.type = row.get("TYPE")             # e.g. 'SQL Profile', 'Index', 'Restructure SQL'
        self.benefit_pct = row.get("BENEFIT")
        self.rank = row.get("RANK")
        self.rationale = row.get("RATIONALE")
        self.finding = row.get("FINDING")
        self.command = row.get("COMMAND")        # from DBA_ADVISOR_ACTIONS, if joined
        self.message = row.get("MESSAGE")


class SqlTuningAdvisorHistory(SerializableMixin):
    """Whether SQL Tuning Advisor has ever analyzed this SQL_ID, and
    what it concluded — the direct, authoritative source, since STA runs
    the optimizer's own what-if analysis rather than us inferring from
    plan shape."""

    def __init__(self):
        self.has_been_analyzed = False
        self.tasks = []                # list of {task_name, status, created}
        self.recommendations = []      # list[AdvisorRecommendation]


class SqlForensicBundle(SerializableMixin):
    """Top level container returned by the Collector — everything gathered
    for one SQL_ID, ready to hand to the diagnostic engine."""

    def __init__(self, identity):
        self.identity = identity
        self.sql_text_info = None
        self.cursor_children = []            # list[CursorChildInfo]
        self.shared_cursor_mismatches = []   # list[SharedCursorMismatch]
        self.execution_plans = []            # list[ExecutionPlan] (cursor cache + AWR + monitor + baseline)
        self.awr_sqlstat_history = []        # list[AwrSqlStatSnapshot]
        self.wait_event_summary = []         # list[WaitEventAgg] (overall)
        self.wait_event_by_plan_step = []    # list[WaitEventAgg] (plan_line_id set)
        self.ash_current_samples = []        # list[AshSample] — currently executing only
        self.bind_history = []               # list[BindCapture]
        self.baselines = []                  # list[SqlPlanBaselineInfo]
        self.sql_profiles = []               # list[SqlProfileInfo]
        self.sql_patches = []                # list[SqlPatchInfo]
        self.optimizer_env_diffs = []        # list[OptimizerEnvDiff]
        self.sql_monitor_reports = []        # list[SqlMonitorReport]
        self.sql_plan_directives = []        # list[SqlPlanDirectiveInfo]
        self.index_column_stats = []         # list[IndexColumnStat]
        self.object_statistics_health = []   # list[ObjectStatisticsHealth]
        self.sql_tuning_advisor = SqlTuningAdvisorHistory()
        self.is_currently_running = False
        self.collection_errors = []          # list[str] — partial-failure notes, never silent
        self.collected_at = None
