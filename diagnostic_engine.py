# -*- coding: utf-8 -*-
"""
diagnostic_engine.py
---------------------
Turns a SqlForensicBundle (raw facts) into a ranked, evidence-backed
diagnosis: what the optimizer did, why it likely did it, what's costing
time, and what to try — with the actual hint/action syntax.

DESIGN: Instead of one giant if/else tree, each "expert" is an
independent DiagnosticModule that looks at the SAME bundle through one
lens (cardinality, join strategy, access paths, predicates, partitioning,
parallelism, resource/wait profile, plan stability, bind sensitivity,
adaptive features, cursor sharing). Each module emits zero or more
Finding objects with a confidence, evidence citations back to concrete
data points, and — where applicable — one or more Recommendation objects
with real hint syntax and a stated risk level.

A Synthesizer then merges everything, resolves duplicate/overlapping
findings, and produces a final ranked report. This mirrors how a room of
real specialists would work: each looks at the whole picture from their
angle, then someone reconciles the findings — rather than 500 hardcoded
"case N" rules that miss interaction effects.

Python 3.6.8 compatible. Zero third-party dependencies — stdlib only.
"""

import re
import logging
from collections import defaultdict

LOG = logging.getLogger("sql_forensics.diagnostics")

# --------------------------------------------------------------------- #
# severity / confidence vocabulary — kept as plain strings + ints so this
# stays trivially serializable and comparable without an enum dependency
# gap on 3.6 (enum exists in 3.6, but plain constants keep this simpler
# to extend from config later).
# --------------------------------------------------------------------- #

SEV_CRITICAL = 4
SEV_HIGH = 3
SEV_MEDIUM = 2
SEV_LOW = 1
SEV_INFO = 0

SEV_LABELS = {
    SEV_CRITICAL: "CRITICAL", SEV_HIGH: "HIGH", SEV_MEDIUM: "MEDIUM",
    SEV_LOW: "LOW", SEV_INFO: "INFO",
}

RISK_SAFE = "SAFE"            # e.g. gathering stats, adding an extended stat
RISK_LOW = "LOW"              # e.g. a hint tested first via EXPLAIN/monitor
RISK_MEDIUM = "MEDIUM"        # e.g. SQL Profile / Plan Baseline changes
RISK_HIGH = "HIGH"            # e.g. structural rewrite, index creation on hot table


class Evidence(object):
    """One concrete, citable data point backing a finding — never a vague
    claim. Every Finding must carry at least one of these."""

    def __init__(self, source, detail):
        self.source = source   # e.g. "V$SQL_PLAN_STATISTICS_ALL step 6"
        self.detail = detail   # e.g. "estimated 12 rows, actual 3,812,004 rows"

    def to_dict(self):
        return {"source": self.source, "detail": self.detail}

    def __str__(self):
        return "[{0}] {1}".format(self.source, self.detail)


class Recommendation(object):
    """A concrete, actionable fix — always with real syntax, a rationale,
    a risk level, and (where estimable) an expected effect."""

    def __init__(self, action, syntax, rationale, risk, expected_effect=None,
                 module_source=None):
        self.action = action                # short label, e.g. "Add USE_HASH hint"
        self.syntax = syntax                # the literal hint/SQL/command text
        self.rationale = rationale
        self.risk = risk
        self.expected_effect = expected_effect
        self.module_source = module_source

    def to_dict(self):
        return {
            "action": self.action, "syntax": self.syntax,
            "rationale": self.rationale, "risk": self.risk,
            "expected_effect": self.expected_effect,
            "module_source": self.module_source,
        }


class Finding(object):
    """One diagnostic conclusion from one expert module."""

    def __init__(self, module, title, severity, explanation, evidence=None,
                 recommendations=None, category=None, plan_step_ref=None):
        self.module = module                # which module produced this, e.g. "CardinalityExpert"
        self.title = title
        self.severity = severity
        self.explanation = explanation
        self.evidence = evidence or []      # list[Evidence]
        self.recommendations = recommendations or []  # list[Recommendation]
        self.category = category or module
        self.plan_step_ref = plan_step_ref  # e.g. "PHV 123456:step 14"

    def to_dict(self):
        return {
            "module": self.module,
            "title": self.title,
            "severity": SEV_LABELS.get(self.severity, self.severity),
            "severity_rank": self.severity,
            "explanation": self.explanation,
            "plan_step_ref": self.plan_step_ref,
            "evidence": [e.to_dict() for e in self.evidence],
            "recommendations": [r.to_dict() for r in self.recommendations],
        }


# --------------------------------------------------------------------- #
# base class every expert module implements
# --------------------------------------------------------------------- #

class DiagnosticModule(object):
    name = "BaseModule"

    def analyze(self, bundle):
        """Returns a list[Finding]. Must never raise — wrap risky logic
        internally; a module that can't reach a conclusion should return
        [] rather than crash the whole diagnosis."""
        raise NotImplementedError


# --------------------------------------------------------------------- #
# helpers shared across modules
# --------------------------------------------------------------------- #

def _latest_plan_with_actuals(bundle):
    """Prefer a plan that has actual runtime stats (cursor cache with
    STATISTICS_ALL, or SQL Monitor) over an estimates-only plan — actuals
    are what let us catch misestimation, which is the single highest-
    value diagnostic signal in Oracle tuning."""
    for plan in bundle.execution_plans:
        if plan.source == "CURSOR_CACHE_WITH_ACTUALS":
            return plan
    for report in bundle.sql_monitor_reports:
        if report.step_monitor:
            fake_plan = type("P", (), {})()
            fake_plan.plan_hash_value = report.plan_hash_value
            fake_plan.source = "SQL_MONITOR"
            fake_plan.steps = report.step_monitor
            return fake_plan
    if bundle.execution_plans:
        return bundle.execution_plans[0]
    return None


def _distinct_plan_hashes(bundle):
    hashes = set()
    for plan in bundle.execution_plans:
        hashes.add(plan.plan_hash_value)
    for snap in bundle.awr_sqlstat_history:
        if snap.plan_hash_value:
            hashes.add(snap.plan_hash_value)
    return hashes


def _misestimate_ratio(estimated, actual):
    """Symmetric-ish ratio so both over- and under-estimates surface.
    Returns None if inputs are unusable."""
    try:
        est = float(estimated) if estimated is not None else None
        act = float(actual) if actual is not None else None
    except (TypeError, ValueError):
        return None
    if est is None or act is None:
        return None
    if est <= 0:
        est = 0.5   # optimizer never truly estimates 0; treat as sub-1 for ratio math
    if act <= 0:
        act = 0.5
    return max(est, act) / min(est, act)


# --------------------------------------------------------------------- #
# EXPERT 1 — Cardinality Estimation
# --------------------------------------------------------------------- #

class CardinalityExpert(DiagnosticModule):
    """The single most common root cause of bad plans in the field:
    the optimizer's row-count estimate at some step is wildly wrong,
    which cascades into wrong join methods, join order, and access
    paths downstream. Catches it directly from actual-vs-estimate."""

    name = "CardinalityExpert"
    MISESTIMATE_THRESHOLD = 10.0   # 10x off is already actionable

    def analyze(self, bundle):
        findings = []
        plan = _latest_plan_with_actuals(bundle)
        if plan is None:
            return findings

        worst = None
        worst_ratio = 0
        for step in plan.steps:
            est = getattr(step, "cardinality", None)
            act = getattr(step, "actual_rows", None)
            ratio = _misestimate_ratio(est, act)
            if ratio and ratio > worst_ratio:
                worst_ratio = ratio
                worst = step

        if worst is not None and worst_ratio >= self.MISESTIMATE_THRESHOLD:
            direction = "under" if (worst.actual_rows or 0) > (worst.cardinality or 0) else "over"
            sev = SEV_CRITICAL if worst_ratio >= 1000 else (SEV_HIGH if worst_ratio >= 100 else SEV_MEDIUM)
            recs = [
                Recommendation(
                    action="Gather fresh / more granular statistics",
                    syntax="EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', tabname=>'{1}', "
                           "method_opt=>'FOR ALL COLUMNS SIZE AUTO', cascade=>TRUE);".format(
                               worst.object_owner or "<owner>", worst.object_name or "<table>"),
                    rationale="Cardinality misestimates of this magnitude are most often stale "
                              "or insufficiently granular object statistics (missing histogram "
                              "on a skewed column, or stale stats after bulk load/purge).",
                    risk=RISK_SAFE,
                    expected_effect="Corrects the optimizer's row-count model at this step, which "
                                    "may change join method/order and access path downstream.",
                    module_source=self.name,
                ),
                Recommendation(
                    action="Consider extended statistics if the skew is column-correlation driven",
                    syntax="EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', tabname=>'{1}', "
                           "method_opt=>'FOR ALL COLUMNS SIZE AUTO FOR COLUMNS "
                           "(col1, col2) SIZE AUTO');".format(
                               worst.object_owner or "<owner>", worst.object_name or "<table>"),
                    rationale="If two or more filtered/joined columns on this object are "
                              "correlated (e.g. STATE and CITY), single-column histograms can't "
                              "capture the joint selectivity — extended stats can.",
                    risk=RISK_SAFE,
                    module_source=self.name,
                ),
                Recommendation(
                    action="If stats can't be fixed in time, pin the plan you know is good",
                    syntax="EXEC DBMS_SPM.LOAD_PLANS_FROM_CURSOR_CACHE(sql_id=>'{0}', "
                           "plan_hash_value=>{1});".format(bundle.identity.sql_id,
                                                            plan.plan_hash_value),
                    rationale="A SQL Plan Baseline is a tactical stopgap while the underlying "
                              "statistics/cardinality issue is fixed — it does not fix the root "
                              "cause, only prevents regression while you do.",
                    risk=RISK_MEDIUM,
                    module_source=self.name,
                ),
            ]
            findings.append(Finding(
                module=self.name,
                title="Severe cardinality misestimate at plan step {0} ({1}x, optimizer "
                      "{2}estimated)".format(worst.id, int(worst_ratio), direction),
                severity=sev,
                explanation=(
                    "At step {0} ({1} on {2}.{3}), the optimizer estimated {4} rows but "
                    "{5} actually flowed through. A misestimate this large routinely causes "
                    "wrong join method selection (e.g. nested loops chosen for what is "
                    "actually a large row source), wrong join order, and can force a plan "
                    "into serial execution or excessive PGA-driven spills to temp."
                ).format(worst.id, worst.operation, worst.object_owner or "?",
                         worst.object_name or "?", worst.cardinality, worst.actual_rows),
                evidence=[Evidence(
                    source="V$SQL_PLAN_STATISTICS_ALL / SQL Monitor, step {0}".format(worst.id),
                    detail="OPERATION={0}, estimated CARDINALITY={1}, actual "
                           "rows={2}".format(worst.operation, worst.cardinality, worst.actual_rows),
                )],
                recommendations=recs,
                plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, worst.id),
            ))

        # Bind-sensitive cursor with multiple children and no adaptive
        # cursor sharing engaged — classic skewed-predicate symptom.
        bind_sensitive_children = [c for c in bundle.cursor_children if c.is_bind_sensitive == "Y"]
        if bind_sensitive_children and len(bundle.cursor_children) > 1:
            distinct_plans = set(c.plan_hash_value for c in bundle.cursor_children)
            if len(distinct_plans) > 1:
                findings.append(Finding(
                    module=self.name,
                    title="Bind-sensitive cursor producing multiple plans across child cursors",
                    severity=SEV_MEDIUM,
                    explanation=(
                        "This SQL_ID is marked bind-sensitive and currently has {0} child "
                        "cursors spanning {1} distinct plan hash values. This means bind "
                        "peeking is choosing different plans for different bind values — "
                        "expected behavior IF the underlying column is genuinely skewed and "
                        "adaptive cursor sharing is working as intended, but worth confirming "
                        "the histogram on the filtered column actually reflects that skew."
                    ).format(len(bundle.cursor_children), len(distinct_plans)),
                    evidence=[Evidence(
                        source="V$SQL",
                        detail="{0} child cursors, {1} distinct PLAN_HASH_VALUE, "
                               "IS_BIND_SENSITIVE=Y on at least one child".format(
                                   len(bundle.cursor_children), len(distinct_plans)),
                    )],
                    recommendations=[Recommendation(
                        action="Verify histogram exists and matches actual data skew",
                        syntax="SELECT column_name, histogram, num_distinct FROM "
                               "dba_tab_col_statistics WHERE owner=:o AND table_name=:t;",
                        rationale="Confirms whether adaptive cursor sharing has accurate "
                                  "skew data to peek against, or is reacting to stale/absent "
                                  "histograms.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 2 — Join Strategy (method + order)
# --------------------------------------------------------------------- #

class JoinStrategyExpert(DiagnosticModule):
    name = "JoinStrategyExpert"

    _JOIN_OPS = {"HASH JOIN", "NESTED LOOPS", "MERGE JOIN"}

    def analyze(self, bundle):
        findings = []
        plan = _latest_plan_with_actuals(bundle)
        if plan is None:
            return findings

        for step in plan.steps:
            op = (step.operation or "").upper()
            if op not in self._JOIN_OPS:
                continue
            act = getattr(step, "actual_rows", None)
            est = getattr(step, "cardinality", None)

            if op == "NESTED LOOPS" and act and est:
                ratio = _misestimate_ratio(est, act)
                if ratio and ratio >= 10 and (act or 0) > 10000:
                    findings.append(Finding(
                        module=self.name,
                        title="NESTED LOOPS join at step {0} processing far more rows "
                              "than the optimizer planned for".format(step.id),
                        severity=SEV_HIGH,
                        explanation=(
                            "NESTED LOOPS is efficient when the outer row source is small "
                            "and the inner side has a selective, well-clustered index access. "
                            "Here the optimizer expected ~{0} rows but {1} actually flowed "
                            "through — at this volume, NESTED LOOPS typically means the inner "
                            "table is being probed far more times than intended, driving "
                            "excessive logical/physical I/O. A HASH JOIN is usually far cheaper "
                            "at this row volume."
                        ).format(est, act),
                        evidence=[Evidence(
                            source="Plan step {0}".format(step.id),
                            detail="NESTED LOOPS, estimated {0} rows, actual {1} rows".format(est, act),
                        )],
                        recommendations=[
                            Recommendation(
                                action="Test forcing a hash join at this join point",
                                syntax="/*+ USE_HASH({0}) */  -- or LEADING()+USE_HASH() to also "
                                       "pin join order".format(step.object_alias or step.object_name or "<alias>"),
                                rationale="Once cardinality is corrected (see CardinalityExpert "
                                          "finding, if present), the optimizer may naturally "
                                          "choose HASH JOIN on its own — treat this hint as a "
                                          "verification/stopgap, not a permanent fix if the root "
                                          "cause is a misestimate.",
                                risk=RISK_LOW,
                                module_source=self.name,
                            ),
                        ],
                        plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                    ))

            if op == "HASH JOIN" and step.workarea_tempseg if hasattr(step, "workarea_tempseg") else None:
                pass  # handled by ResourceExpert (temp spill) to avoid duplicate findings

        # Join order sanity: compare current plan's join order against
        # whether a smaller-first ordering would reduce intermediate rows.
        # We surface this as a lower-confidence, informational nudge — a
        # full cost-based re-derivation is out of scope for a static check.
        row_source_steps = [s for s in plan.steps if s.operation and "TABLE ACCESS" in s.operation.upper()]
        if len(row_source_steps) >= 3:
            sorted_by_est = sorted(
                [s for s in row_source_steps if s.cardinality],
                key=lambda s: s.cardinality,
            )
            if sorted_by_est and sorted_by_est[0].id != row_source_steps[0].id:
                findings.append(Finding(
                    module=self.name,
                    title="Join order may not be starting from the smallest estimated row source",
                    severity=SEV_LOW,
                    explanation=(
                        "As a rule of thumb (not a guarantee — the CBO also weighs join "
                        "selectivity and access path cost, not just source size), starting a "
                        "multi-table join from the smallest-first row source tends to minimize "
                        "intermediate result sizes. The current plan's first accessed table "
                        "does not have the smallest estimated cardinality among the row "
                        "sources in this plan. Worth reviewing with LEADING()/ORDERED if "
                        "other findings point to join order as a contributor."
                    ),
                    evidence=[Evidence(
                        source="Plan steps",
                        detail="Smallest estimated row source is step {0} ({1} rows) but "
                               "first-accessed is step {2} ({3} rows)".format(
                                   sorted_by_est[0].id, sorted_by_est[0].cardinality,
                                   row_source_steps[0].id, row_source_steps[0].cardinality),
                    )],
                    recommendations=[Recommendation(
                        action="Consider testing an explicit join order",
                        syntax="/*+ LEADING({0}) */".format(sorted_by_est[0].object_alias
                                                              or sorted_by_est[0].object_name or "<alias>"),
                        rationale="Only worth testing if this finding co-occurs with a "
                                  "resource/wait finding pointing at this join — join order "
                                  "alone rarely explains slowness in isolation.",
                        risk=RISK_LOW,
                        module_source=self.name,
                    )],
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 3 — Access Path
# --------------------------------------------------------------------- #

class AccessPathExpert(DiagnosticModule):
    name = "AccessPathExpert"

    def analyze(self, bundle):
        findings = []
        plan = _latest_plan_with_actuals(bundle)
        if plan is None:
            return findings

        for step in plan.steps:
            op = (step.operation or "").upper()
            opt = (step.options or "").upper()
            if op == "TABLE ACCESS" and opt == "FULL":
                act = getattr(step, "actual_rows", None)
                filt = step.filter_predicates
                if filt and act and act > 0:
                    findings.append(Finding(
                        module=self.name,
                        title="Full table scan at step {0} with a filter predicate applied "
                              "post-scan".format(step.id),
                        severity=SEV_MEDIUM,
                        explanation=(
                            "Step {0} does a FULL scan of {1}.{2} and applies a FILTER "
                            "predicate ({3}) after reading every row/block — meaning no "
                            "index is being used to eliminate rows during the read. This is "
                            "correct/optimal if the predicate isn't selective enough for an "
                            "index to help, or if the table/partition is small — but is worth "
                            "checking against the actual row count returned."
                        ).format(step.id, step.object_owner or "?", step.object_name or "?", filt),
                        evidence=[Evidence(
                            source="Plan step {0}".format(step.id),
                            detail="FILTER_PREDICATES={0}, actual output rows={1}".format(filt, act),
                        )],
                        recommendations=[Recommendation(
                            action="Check selectivity of the filter predicate and index candidacy",
                            syntax="SELECT column_name, num_distinct, density FROM "
                                   "dba_tab_col_statistics WHERE owner=:o AND table_name=:t "
                                   "AND column_name IN (<filtered columns>);",
                            rationale="If num_distinct is high relative to row count (high "
                                      "selectivity) and no suitable index exists, this is a "
                                      "genuine missing-index candidate. If selectivity is low, "
                                      "the full scan is likely the right call already.",
                            risk=RISK_SAFE,
                            module_source=self.name,
                        )],
                        plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                    ))
            if op == "TABLE ACCESS" and opt in ("BY INDEX ROWID", "BY INDEX ROWID BATCHED"):
                act = getattr(step, "actual_rows", None)
                starts = getattr(step, "actual_starts", None)
                if act and starts and starts > 1 and (act / max(starts, 1)) < 1.5:
                    findings.append(Finding(
                        module=self.name,
                        title="Index-based table access at step {0} executed {1} times "
                              "returning ~1 row each — check for an unnecessary re-probe "
                              "pattern".format(step.id, starts),
                        severity=SEV_LOW,
                        explanation=(
                            "This access path was started {0} times (once per outer-loop row, "
                            "typically), each time returning about 1 row. If the outer row "
                            "source itself is large, this is a very high number of single-row "
                            "index probes — often fine for OLTP-style lookups, but worth "
                            "checking if a batched/hash approach would reduce total I/O calls."
                        ).format(starts),
                        evidence=[Evidence(
                            source="Plan step {0} (STATISTICS_ALL)".format(step.id),
                            detail="STARTS={0}, total actual rows={1}".format(starts, act),
                        )],
                        recommendations=[],
                        plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                    ))

        # Clustering factor / index quality is not directly visible in
        # plan steps; flag it as a check-list item whenever an INDEX
        # RANGE SCAN feeds a TABLE ACCESS BY INDEX ROWID with a high
        # actual-row volume, since clustering factor is the #1 hidden
        # reason an index-based plan still does heavy physical I/O.
        for step in plan.steps:
            if step.operation and "INDEX" in step.operation.upper() and "RANGE SCAN" in (step.options or "").upper():
                act = getattr(step, "actual_rows", None)
                if act and act > 50000:
                    findings.append(Finding(
                        module=self.name,
                        title="High-volume INDEX RANGE SCAN at step {0} — verify clustering "
                              "factor".format(step.id),
                        severity=SEV_LOW,
                        explanation=(
                            "An index range scan returning {0} rows can still be slower than "
                            "a full table scan if the index's CLUSTERING_FACTOR is close to "
                            "the number of rows in the table (poor row-to-block correlation), "
                            "since each ROWID lookup then costs close to a full block read."
                        ).format(act),
                        evidence=[Evidence(
                            source="Plan step {0}".format(step.id),
                            detail="actual rows returned={0}".format(act),
                        )],
                        recommendations=[Recommendation(
                            action="Check clustering factor vs table block count",
                            syntax="SELECT index_name, clustering_factor, num_rows FROM "
                                   "dba_indexes WHERE owner=:o AND table_name=:t; "
                                   "-- compare against DBA_TABLES.BLOCKS",
                            rationale="clustering_factor near num_rows (rather than near "
                                      "blocks) signals a poorly-clustered index for this "
                                      "access pattern — a candidate for a different index "
                                      "or a table reorg, not a hint fix.",
                            risk=RISK_SAFE,
                            module_source=self.name,
                        )],
                        plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                    ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 4 — Predicate Pushdown / Transformation
# --------------------------------------------------------------------- #

class PredicateTransformationExpert(DiagnosticModule):
    """Looks at whether predicates were pushed into views/subqueries,
    whether subqueries were unnested, and whether star transformation or
    view merging happened — the "below the plan" mechanics you flagged."""

    name = "PredicateTransformationExpert"

    def analyze(self, bundle):
        findings = []
        plan = _latest_plan_with_actuals(bundle)
        if plan is None:
            return findings

        qblocks = set(s.qblock_name for s in plan.steps if s.qblock_name)
        if len(qblocks) > 1:
            # Multiple query blocks surviving into the final plan can mean
            # view merging / subquery unnesting did NOT happen — not
            # automatically bad, but worth an explicit check.
            has_filter_subq = any(
                s.operation and s.operation.upper() == "FILTER" for s in plan.steps
            )
            if has_filter_subq:
                findings.append(Finding(
                    module=self.name,
                    title="Un-merged query blocks with a FILTER operation — possible missed "
                          "subquery unnesting",
                    severity=SEV_MEDIUM,
                    explanation=(
                        "The plan retains {0} distinct query blocks and includes a FILTER "
                        "operation, which often means a correlated subquery is being "
                        "evaluated row-by-row against the outer query instead of being "
                        "unnested into a join. This is one of the highest-leverage "
                        "transformations the CBO can miss — check whether UNNEST is "
                        "possible for the subquery in question."
                    ).format(len(qblocks)),
                    evidence=[Evidence(
                        source="Plan steps",
                        detail="QBLOCK_NAMEs present: {0}; FILTER operation present in "
                               "plan".format(", ".join(sorted(qblocks))),
                    )],
                    recommendations=[
                        Recommendation(
                            action="Force subquery unnesting",
                            syntax="/*+ UNNEST */  -- placed inside the subquery block",
                            rationale="If unnesting is blocked by a correctness concern "
                                      "(e.g. subquery can return duplicates changing semantics "
                                      "under certain join types), the optimizer may be correctly "
                                      "avoiding it — verify semantic equivalence before forcing.",
                            risk=RISK_MEDIUM,
                            module_source=self.name,
                        ),
                        Recommendation(
                            action="Check the 10053 trace for the specific unnesting decision",
                            syntax="ALTER SESSION SET EVENTS "
                                   "'10053 trace name context forever, level 1'; "
                                   "-- run EXPLAIN PLAN FOR <sql>, then disable the event",
                            rationale="The 10053 trace states explicitly why a transformation "
                                      "was or wasn't applied (cost comparison, "
                                      "correctness/legality check failed, etc.) — the "
                                      "authoritative source, more reliable than inference from "
                                      "the plan shape alone.",
                            risk=RISK_SAFE,
                            module_source=self.name,
                        ),
                    ],
                ))

        for step in plan.steps:
            if step.filter_predicates and not step.access_predicates:
                idx_cols_for_table = [
                    ic for ic in bundle.index_column_stats
                    if ic.owner == step.object_owner and ic.table_name == step.object_name
                    and ic.column_position == 1
                ]
                for ic in idx_cols_for_table:
                    if ic.column_name and re.search(
                        r'\b{0}\b'.format(re.escape(ic.column_name)),
                        step.filter_predicates, re.IGNORECASE
                    ):
                        findings.append(Finding(
                            module=self.name,
                            title="Filter predicate on {0} could potentially be an ACCESS "
                                  "predicate via index {1}".format(ic.column_name, ic.index_name),
                            severity=SEV_MEDIUM,
                            explanation=(
                                "Step {0} applies '{1}' as a FILTER (post-fetch check) rather "
                                "than an ACCESS predicate, but {2} is the leading column of "
                                "index {3} on this table. If the predicate is sargable (no "
                                "function wrapping, no implicit datatype conversion) and this "
                                "index isn't being chosen for a cost-based reason worth "
                                "verifying, using it could push the filter into the index "
                                "probe itself instead of applying it after every row is "
                                "fetched."
                            ).format(step.id, step.filter_predicates, ic.column_name, ic.index_name),
                            evidence=[Evidence(
                                source="Plan step {0} + DBA_IND_COLUMNS".format(step.id),
                                detail="FILTER_PREDICATES={0}; index {1} leads with column "
                                       "{2} (clustering_factor={3}, "
                                       "status={4})".format(
                                           step.filter_predicates, ic.index_name,
                                           ic.column_name, ic.clustering_factor, ic.status),
                            )],
                            recommendations=[Recommendation(
                                action="Verify the predicate is sargable and test the index",
                                syntax="/*+ INDEX({0} {1}) */".format(
                                    step.object_alias or step.object_name, ic.index_name),
                                rationale="Confirm the predicate isn't wrapped in a function "
                                          "or subject to implicit conversion (both silently "
                                          "block index usage), then compare cost/actual "
                                          "performance against the current full-scan-plus-"
                                          "filter approach — the optimizer may already have a "
                                          "valid cost-based reason to prefer the current path "
                                          "(e.g. low selectivity), so this is a verify-before-"
                                          "force recommendation.",
                                risk=RISK_LOW,
                                module_source=self.name,
                            )],
                            plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                        ))
                        break  # one finding per step is enough signal

        star_transform_steps = [s for s in plan.steps if s.other_tag and "STAR" in (s.other_tag or "").upper()]
        bitmap_steps = [s for s in plan.steps if s.operation and "BITMAP" in s.operation.upper()]
        if bitmap_steps and not star_transform_steps:
            fact_like_steps = [
                s for s in plan.steps
                if s.operation and "TABLE ACCESS" in s.operation.upper()
                and getattr(s, "actual_rows", 0) and s.actual_rows > 1000000
            ]
            if fact_like_steps:
                findings.append(Finding(
                    module=self.name,
                    title="Bitmap index access present on a large table without star "
                          "transformation — verify this is a star-schema fact table query",
                    severity=SEV_INFO,
                    explanation=(
                        "Bitmap operations are present but STAR_TRANSFORMATION does not "
                        "appear to have been applied. If this query is a classic star-schema "
                        "fact-to-dimension join with multiple single-column bitmap indexes on "
                        "the fact table, star transformation is often significantly cheaper "
                        "than the current plan shape — worth checking "
                        "STAR_TRANSFORMATION_ENABLED and whether bitmap indexes exist on all "
                        "the relevant FK columns."
                    ),
                    evidence=[Evidence(
                        source="Plan steps",
                        detail="{0} BITMAP operation(s), 0 STAR_TRANSFORMATION marker(s), "
                               "large row source(s) present".format(len(bitmap_steps)),
                    )],
                    recommendations=[Recommendation(
                        action="Test star transformation explicitly",
                        syntax="/*+ STAR_TRANSFORMATION */",
                        rationale="Only applicable to genuine star-schema shapes; a "
                                  "no-op/regression on non-star queries.",
                        risk=RISK_LOW,
                        module_source=self.name,
                    )],
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 5 — Partitioning
# --------------------------------------------------------------------- #

class PartitioningExpert(DiagnosticModule):
    name = "PartitioningExpert"

    def analyze(self, bundle):
        findings = []
        plan = _latest_plan_with_actuals(bundle)
        if plan is None:
            return findings

        for step in plan.steps:
            pstart, pstop = step.partition_start, step.partition_stop
            if pstart is None and pstop is None:
                continue
            if str(pstart).upper() == "KEY" or str(pstop).upper() == "KEY":
                findings.append(Finding(
                    module=self.name,
                    title="Runtime (KEY) partition pruning at step {0} — confirm it's "
                          "actually narrow at execution".format(step.id),
                    severity=SEV_INFO,
                    explanation=(
                        "PARTITION_START/STOP = KEY means pruning happens at runtime based "
                        "on a bind value or join key, not at parse time — the plan itself "
                        "can't tell you how many partitions were actually touched. Cross-"
                        "check against SQL Monitor / ASH for this execution to confirm "
                        "pruning is as narrow as expected; a wide KEY prune silently defeats "
                        "the purpose of partitioning."
                    ),
                    evidence=[Evidence(
                        source="Plan step {0}".format(step.id),
                        detail="PARTITION_START={0}, PARTITION_STOP={1}".format(pstart, pstop),
                    )],
                    recommendations=[],
                    plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                ))
            elif pstart == pstop and pstart is not None and str(pstart).upper() not in ("KEY", "ALL"):
                pass  # single-partition prune already optimal — no finding needed
            elif str(pstart).upper() == "1" and pstop is not None and str(pstop).upper() not in ("1", "KEY"):
                act = getattr(step, "actual_rows", None)
                findings.append(Finding(
                    module=self.name,
                    title="Step {0} scans a wide partition range (no pruning) on "
                          "{1}.{2}".format(step.id, step.object_owner or "?", step.object_name or "?"),
                    severity=SEV_MEDIUM,
                    explanation=(
                        "This step's PARTITION_START/STOP spans multiple partitions with no "
                        "pruning applied. If the query has a filter on the partition key that "
                        "isn't being recognized (e.g. wrapped in a function, or an implicit "
                        "datatype conversion), pruning is being silently defeated."
                    ),
                    evidence=[Evidence(
                        source="Plan step {0}".format(step.id),
                        detail="PARTITION_START={0}, PARTITION_STOP={1}, actual rows={2}".format(
                            pstart, pstop, act),
                    )],
                    recommendations=[Recommendation(
                        action="Check for function-wrapped or implicitly-converted partition "
                               "key predicates",
                        syntax="-- Review the WHERE clause for TRUNC(date_col), TO_CHAR(...), "
                               "or a bind variable with a mismatched datatype against the "
                               "partition key column",
                        rationale="Any transformation applied to the partition-key column in "
                                  "the predicate prevents static and often dynamic pruning.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                    plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 6 — Parallelism
# --------------------------------------------------------------------- #

class ParallelismExpert(DiagnosticModule):
    name = "ParallelismExpert"

    def analyze(self, bundle):
        findings = []
        for report in bundle.sql_monitor_reports:
            requested = report.px_servers_requested or 0
            allocated = report.px_servers_allocated or 0
            if requested > 0 and allocated < requested:
                pct = round(100.0 * allocated / requested, 1) if requested else 0
                findings.append(Finding(
                    module=self.name,
                    title="Parallel Query downgrade: requested {0} servers, got "
                          "{1} ({2}%)".format(requested, allocated, pct),
                    severity=SEV_HIGH if pct < 50 else SEV_MEDIUM,
                    explanation=(
                        "The optimizer's cost model for this plan assumed {0}-way "
                        "parallelism, but only {1} parallel servers were actually allocated "
                        "at execution time — almost always because the parallel_max_servers "
                        "pool was exhausted by concurrent PQ demand, or "
                        "PARALLEL_DEGREE_POLICY/resource manager limits kicked in. The "
                        "elapsed time you're seeing reflects the DOWNGRADED degree, not the "
                        "plan's estimated cost, which assumed full parallelism."
                    ).format(requested, allocated),
                    evidence=[Evidence(
                        source="V$SQL_MONITOR",
                        detail="PX_SERVERS_REQUESTED={0}, PX_SERVERS_ALLOCATED={1}".format(
                            requested, allocated),
                    )],
                    recommendations=[
                        Recommendation(
                            action="Check PQ pool saturation at execution time",
                            syntax="SELECT * FROM V$PX_PROCESS_SYSSTAT WHERE "
                                   "STATISTIC LIKE 'Servers%';",
                            rationale="Confirms whether this is a systemic PQ pool sizing "
                                      "issue (affecting many queries) versus a one-off "
                                      "contention spike.",
                            risk=RISK_SAFE,
                            module_source=self.name,
                        ),
                        Recommendation(
                            action="Consider a fixed, lower DOP if downgrades are chronic",
                            syntax="/*+ PARALLEL(4) */",
                            rationale="A consistently-honored lower DOP can outperform a "
                                      "higher DOP that's chronically downgraded, since the "
                                      "optimizer's plan shape (e.g. distribution method "
                                      "choice) was costed for the full requested degree.",
                            risk=RISK_LOW,
                            module_source=self.name,
                        ),
                    ],
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 7 — Resource / Wait Profile (CPU, I/O, temp spills)
# --------------------------------------------------------------------- #

class ResourceProfileExpert(DiagnosticModule):
    name = "ResourceProfileExpert"

    def analyze(self, bundle):
        findings = []
        if bundle.wait_event_summary:
            by_class = defaultdict(float)
            for w in bundle.wait_event_summary:
                by_class[w.wait_class] += (w.pct_of_total or 0)

            top_class = max(by_class.items(), key=lambda kv: kv[1]) if by_class else (None, 0)
            if top_class[0] and top_class[1] >= 40:
                wait_class, pct = top_class
                if wait_class == "User I/O":
                    findings.append(Finding(
                        module=self.name,
                        title="Execution time dominated by User I/O waits ({0}% of "
                              "samples)".format(round(pct, 1)),
                        severity=SEV_HIGH,
                        explanation=(
                            "Most of the sampled activity for this SQL_ID is spent waiting on "
                            "User I/O (physical reads). Cross-reference this with the plan's "
                            "access paths: a full scan misestimate, a poorly-clustered index, or "
                            "genuinely large data volume with an undersized buffer cache are the "
                            "usual suspects — check the CardinalityExpert and AccessPathExpert "
                            "findings for this SQL_ID alongside this one."
                        ),
                        evidence=[Evidence(
                            source="ASH wait event aggregation",
                            detail="wait_class=User I/O accounts for {0}% of sampled "
                                   "activity".format(round(pct, 1)),
                        )],
                        recommendations=[],
                    ))
                elif wait_class == "CPU" or wait_class == "ON CPU":
                    findings.append(Finding(
                        module=self.name,
                        title="Execution time dominated by CPU ({0}% of samples) — data volume "
                              "already reduced, cost is in processing".format(round(pct, 1)),
                        severity=SEV_MEDIUM,
                        explanation=(
                            "This SQL_ID spends most of its time ON CPU rather than waiting on "
                            "I/O or other resources — meaning I/O reduction techniques (better "
                            "indexing, partition pruning) will have limited impact. Look instead "
                            "at row-by-row PL/SQL context switching (if any), complex expression "
                            "evaluation, regex/analytic function cost, or excessive sorting."
                        ),
                        evidence=[Evidence(
                            source="ASH wait event aggregation",
                            detail="wait_class=CPU accounts for {0}% of sampled activity".format(round(pct, 1)),
                        )],
                        recommendations=[],
                    ))
                elif wait_class == "Concurrency":
                    findings.append(Finding(
                        module=self.name,
                        title="Execution time dominated by Concurrency waits ({0}%) — likely "
                              "latch/mutex/library-cache contention, not this SQL's own "
                              "logic".format(round(pct, 1)),
                        severity=SEV_HIGH,
                        explanation=(
                            "Concurrency-class waits (cursor: pin S wait on X, library cache "
                            "lock, row cache lock, etc.) mean this SQL is being delayed by "
                            "contention elsewhere in the instance — frequent hard parsing, "
                            "DDL on referenced objects during execution, or a hot library cache "
                            "object. Tuning the SQL text/plan itself will not fix this."
                        ).format(round(pct, 1)),
                        evidence=[Evidence(
                            source="ASH wait event aggregation",
                            detail="wait_class=Concurrency accounts for {0}% of sampled "
                                   "activity".format(round(pct, 1)),
                        )],
                        recommendations=[Recommendation(
                            action="Identify the specific concurrency event and blockers",
                            syntax="SELECT event, p1, p2, p3, blocking_session, COUNT(*) FROM "
                                   "dba_hist_active_sess_history WHERE sql_id=:sql_id "
                                   "AND wait_class='Concurrency' GROUP BY event, p1, p2, p3, "
                                   "blocking_session ORDER BY COUNT(*) DESC;",
                            rationale="P1/P2/P3 identify the exact latch/mutex/lock; "
                                      "BLOCKING_SESSION often points directly at the offending "
                                      "session or a shared-pool sizing problem if it's cursor "
                                      "pin/library cache related.",
                            risk=RISK_SAFE,
                            module_source=self.name,
                        )],
                    ))

        # Temp spill detection — independent of wait-event availability;
        # runs whenever plan-step actuals are present, even if ASH data
        # for this SQL_ID happens to be sparse or unavailable.
        for plan in bundle.execution_plans:
            for step in plan.steps:
                tempseg = getattr(step, "workarea_tempseg", None)
                if tempseg and tempseg > 0:
                    execs_optimal = getattr(step, "workarea_execs_optimal", None)
                    findings.append(Finding(
                        module=self.name,
                        title="Workarea spilled to temp (disk sort/hash) at plan step "
                              "{0}".format(step.id),
                        severity=SEV_HIGH if tempseg > 500 * 1024 * 1024 else SEV_MEDIUM,
                        explanation=(
                            "Step {0} ({1}) used {2:.1f} MB of temp segment space — the "
                            "sort/hash workarea for this operation did not fit in PGA and "
                            "spilled to disk (a 'multi-pass' or at best 'one-pass' operation "
                            "rather than 'optimal'). This shows up directly as TEMP tablespace "
                            "I/O and is one of the more fixable resource-consumption "
                            "patterns."
                        ).format(step.id, step.operation, tempseg / 1024.0 / 1024.0),
                        evidence=[Evidence(
                            source="V$SQL_PLAN_STATISTICS_ALL / SQL Monitor, step {0}".format(step.id),
                            detail="LAST_TEMPSEG_SIZE={0} bytes, "
                                   "LAST_EXECUTIONS_OPTIMAL={1}".format(tempseg, execs_optimal),
                        )],
                        recommendations=[
                            Recommendation(
                                action="Check if this is driven by a cardinality "
                                       "misestimate feeding an oversized workarea",
                                syntax="-- cross-reference CardinalityExpert findings for "
                                       "this same plan step",
                                rationale="An underestimated row count leads PGA_AGGREGATE "
                                          "sizing/auto-memory-management to allocate too "
                                          "little workarea for the ACTUAL data volume — fixing "
                                          "the estimate often eliminates the spill without any "
                                          "memory parameter change.",
                                risk=RISK_SAFE,
                                module_source=self.name,
                            ),
                            Recommendation(
                                action="If estimate is accurate and spill is inherent to data "
                                       "volume, evaluate PGA_AGGREGATE_TARGET / "
                                       "PGA_AGGREGATE_LIMIT headroom",
                                syntax="SELECT name, value FROM v$pgastat WHERE name IN "
                                       "('aggregate PGA target parameter', 'total PGA "
                                       "allocated', 'total freeable PGA memory');",
                                rationale="A genuinely large sort/hash operation may simply "
                                          "need more PGA headroom instance-wide — a capacity "
                                          "question, not a SQL-tuning one, if cardinality is "
                                          "already accurate.",
                                risk=RISK_MEDIUM,
                                module_source=self.name,
                            ),
                        ],
                        plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                    ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 8 — Plan Stability (baselines, profiles, plan flips)
# --------------------------------------------------------------------- #

class PlanStabilityExpert(DiagnosticModule):
    name = "PlanStabilityExpert"

    def analyze(self, bundle):
        findings = []

        distinct_hashes = _distinct_plan_hashes(bundle)
        if len(distinct_hashes) > 1:
            findings.append(Finding(
                module=self.name,
                title="Plan has flipped across {0} distinct PLAN_HASH_VALUEs in the "
                      "lookback window".format(len(distinct_hashes)),
                severity=SEV_MEDIUM,
                explanation=(
                    "Multiple distinct plans have been used for this SQL_ID recently. This "
                    "is expected/healthy if driven by legitimately different bind-value "
                    "selectivity (adaptive cursor sharing working correctly). It's a problem "
                    "if it's driven by stats refresh timing, an optimizer parameter change, "
                    "or object stats volatility causing an unstable plan for what should be "
                    "a consistent workload. Check optimizer_env_diffs on this bundle if "
                    "populated — that pinpoints exactly which session/system parameter "
                    "differed between two of these plans."
                ),
                evidence=[Evidence(
                    source="V$SQL / DBA_HIST_SQLSTAT",
                    detail="Distinct PLAN_HASH_VALUEs observed: {0}".format(
                        ", ".join(str(h) for h in distinct_hashes)),
                )],
                recommendations=[],
            ))

        for diff in bundle.optimizer_env_diffs:
            findings.append(Finding(
                module=self.name,
                title="Optimizer environment parameter '{0}' differs between plan "
                      "executions".format(diff.param_name),
                severity=SEV_MEDIUM,
                explanation=(
                    "Between the execution that produced PLAN_HASH_VALUE {0} and the one "
                    "that produced {1}, the session/system parameter '{2}' had different "
                    "values ('{3}' vs '{4}'). This is a common, easy-to-miss cause of "
                    "unexplained plan changes — session-level ALTER SESSION statements, "
                    "different application connection pools with different NLS/optimizer "
                    "settings, or a system parameter change are the usual sources."
                ).format(diff.plan_hash_a, diff.plan_hash_b, diff.param_name,
                         diff.value_a, diff.value_b),
                evidence=[Evidence(
                    source="DBA_HIST_SQL_OPTIMIZER_ENV",
                    detail="{0}: '{1}' (PHV {2}) vs '{3}' (PHV {4})".format(
                        diff.param_name, diff.value_a, diff.plan_hash_a,
                        diff.value_b, diff.plan_hash_b),
                )],
                recommendations=[Recommendation(
                    action="Trace which sessions/connection pools set this parameter "
                           "differently",
                    syntax="-- grep application connection pool init SQL / logon triggers "
                           "for ALTER SESSION SET {0}".format(diff.param_name),
                    rationale="Standardizing this parameter (or explicitly deciding it "
                              "should vary) resolves the ambiguity driving plan instability.",
                    risk=RISK_SAFE,
                    module_source=self.name,
                )],
            ))

        for baseline in bundle.baselines:
            if baseline.accepted != "YES":
                findings.append(Finding(
                    module=self.name,
                    title="SQL Plan Baseline '{0}' exists but is NOT accepted".format(
                        baseline.plan_name),
                    severity=SEV_LOW,
                    explanation=(
                        "An unaccepted baseline plan exists for this SQL statement — it was "
                        "captured (e.g. via automatic capture or a plan evolution candidate) "
                        "but has not been verified as at-least-as-good as the accepted "
                        "plan(s), so it is not eligible for use yet."
                    ),
                    evidence=[Evidence(
                        source="DBA_SQL_PLAN_BASELINES",
                        detail="PLAN_NAME={0}, ACCEPTED={1}, ORIGIN={2}".format(
                            baseline.plan_name, baseline.accepted, baseline.origin),
                    )],
                    recommendations=[Recommendation(
                        action="Evolve the baseline if the unaccepted plan is actually better",
                        syntax="SELECT DBMS_SPM.EVOLVE_SQL_PLAN_BASELINE(sql_handle=>'{0}', "
                               "plan_name=>'{1}') FROM DUAL;".format(
                                   baseline.sql_handle, baseline.plan_name),
                        rationale="EVOLVE re-verifies the candidate plan's performance and "
                                  "accepts it only if it holds up — safe to run, does not "
                                  "change production behavior until acceptance completes.",
                        risk=RISK_LOW,
                        module_source=self.name,
                    )],
                ))
            if baseline.fixed == "YES":
                findings.append(Finding(
                    module=self.name,
                    title="A FIXED baseline is pinning this SQL to plan "
                          "'{0}'".format(baseline.plan_name),
                    severity=SEV_INFO,
                    explanation=(
                        "This SQL is locked to a specific fixed baseline plan, overriding "
                        "normal cost-based plan selection. If any tuning finding above "
                        "suggests a different plan shape would help, it will have NO effect "
                        "until this fixed baseline is addressed — the optimizer will keep "
                        "using the pinned plan regardless."
                    ),
                    evidence=[Evidence(
                        source="DBA_SQL_PLAN_BASELINES",
                        detail="PLAN_NAME={0}, FIXED=YES".format(baseline.plan_name),
                    )],
                    recommendations=[],
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 9 — Cursor Sharing / Hard Parse Overhead
# --------------------------------------------------------------------- #

class CursorSharingExpert(DiagnosticModule):
    name = "CursorSharingExpert"

    _HIGH_VALUE_REASONS = {
        "BIND_MISMATCH": "Bind variable metadata (type/length/precision) differs between "
                          "executions — often a bind that isn't consistently declared the "
                          "same way by the application.",
        "STATS_ROW_MISMATCH": "Object statistics changed between parses, forcing a new "
                               "child cursor rather than reusing the plan.",
        "LITERAL_MISMATCH": "Literal values are being used instead of binds, or "
                             "CURSOR_SHARING isn't normalizing them — check for "
                             "unparameterized SQL generation in the application layer.",
        "OPTIMIZER_MISMATCH": "A session-level optimizer parameter differs between "
                               "sessions issuing this same SQL text.",
        "PLAN_HASH_MISMATCH": "Adaptive cursor sharing chose a different plan for "
                               "different bind values — expected if driven by genuine "
                               "data skew.",
    }

    def analyze(self, bundle):
        findings = []
        if len(bundle.cursor_children) <= 3:
            return findings   # a handful of children is normal and not worth flagging

        reason_counts = defaultdict(int)
        for mismatch in bundle.shared_cursor_mismatches:
            for reason in mismatch.mismatch_reasons:
                reason_counts[reason] += 1

        if not reason_counts:
            findings.append(Finding(
                module=self.name,
                title="{0} child cursors exist with no V$SQL_SHARED_CURSOR mismatch "
                      "reason recorded".format(len(bundle.cursor_children)),
                severity=SEV_LOW,
                explanation=(
                    "A high child-cursor count with no mismatch reason populated usually "
                    "means the cursors aged out of V$SQL_SHARED_CURSOR's tracking, or the "
                    "mismatch is one of the less common reasons not covered by this check. "
                    "Still worth a manual review if hard-parse overhead is suspected."
                ),
                evidence=[Evidence(
                    source="V$SQL",
                    detail="{0} child cursors for this SQL_ID".format(len(bundle.cursor_children)),
                )],
                recommendations=[],
            ))
            return findings

        top_reason, count = max(reason_counts.items(), key=lambda kv: kv[1])
        explanation = self._HIGH_VALUE_REASONS.get(
            top_reason, "See Oracle documentation for V$SQL_SHARED_CURSOR.{0}".format(top_reason))
        findings.append(Finding(
            module=self.name,
            title="High child-cursor count ({0}) driven primarily by "
                  "{1}".format(len(bundle.cursor_children), top_reason),
            severity=SEV_MEDIUM if count >= 5 else SEV_LOW,
            explanation=(
                "{0} of the recorded mismatches are '{1}'. {2} Excess child cursors mean "
                "repeated hard or soft parsing overhead, and can also mean the plan you're "
                "analyzing isn't the only one in play — always check whether other child "
                "cursors have materially different performance."
            ).format(count, top_reason, explanation),
            evidence=[Evidence(
                source="V$SQL_SHARED_CURSOR",
                detail="{0} child cursor(s) flagged with {1}=Y".format(count, top_reason),
            )],
            recommendations=[Recommendation(
                action="Review all child cursors' performance, not just the latest",
                syntax="SELECT child_number, plan_hash_value, executions, "
                       "elapsed_time/DECODE(executions,0,1,executions) avg_elapsed "
                       "FROM v$sql WHERE sql_id = :sql_id ORDER BY child_number;",
                rationale="If one child cursor is dramatically slower than the others, the "
                          "fix may be eliminating that specific mismatch cause (e.g. "
                          "standardizing a bind declaration) rather than tuning the SQL "
                          "logic itself.",
                risk=RISK_SAFE,
                module_source=self.name,
            )],
        ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 10 — Adaptive Optimization Features (19c/23ai)
# --------------------------------------------------------------------- #

class AdaptiveFeaturesExpert(DiagnosticModule):
    """Looks for signals of adaptive plans / adaptive statistics
    (dynamic statistics, SQL Plan Directives) which are 12c+ features
    still highly relevant to 19c and materially extended in 23ai."""

    name = "AdaptiveFeaturesExpert"

    def analyze(self, bundle):
        findings = []
        plan = _latest_plan_with_actuals(bundle)
        if plan is None:
            return findings

        for step in plan.steps:
            xml = getattr(step, "other_xml", None) or ""
            if isinstance(xml, str) and "adaptive" in xml.lower():
                findings.append(Finding(
                    module=self.name,
                    title="Adaptive plan resolution detected in OTHER_XML at step "
                          "{0}".format(step.id),
                    severity=SEV_INFO,
                    explanation=(
                        "This plan contains adaptive-plan markers in OTHER_XML — meaning "
                        "the optimizer built in alternative sub-plans (e.g. NESTED LOOPS "
                        "vs HASH JOIN) and resolved which to use based on actual "
                        "statistics collected during the early rows of execution. Use "
                        "DBMS_XPLAN.DISPLAY_CURSOR(format=>'+ADAPTIVE') to see the full "
                        "set of plan alternatives that were considered, not just the one "
                        "that was finally used."
                    ),
                    evidence=[Evidence(
                        source="Plan step {0} OTHER_XML".format(step.id),
                        detail="Adaptive plan marker present",
                    )],
                    recommendations=[Recommendation(
                        action="View full adaptive plan resolution detail",
                        syntax="SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY_CURSOR("
                               "sql_id=>'{0}', format=>'ADAPTIVE +COST +PREDICATE'));".format(
                                   bundle.identity.sql_id),
                        rationale="Shows which alternative was rejected and why — useful "
                                  "when the FINAL choice still looks suboptimal, since it "
                                  "reveals what the optimizer was choosing between.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                    plan_step_ref="PHV {0}:step {1}".format(plan.plan_hash_value, step.id),
                ))
                break  # one finding is enough; avoid duplicate noise per step

        # SQL Plan Directives are stored in DBA_SQL_PLAN_DIRECTIVES /
        # DBA_SQL_PLAN_DIR_OBJECTS, not in the bundle by default (would
        # require a dedicated collector call keyed by table, not SQL_ID) —
        # flagged here as a known extension point rather than guessed at.
        return findings


# --------------------------------------------------------------------- #
# EXPERT 11 — SQL Plan Directives
# --------------------------------------------------------------------- #

class SqlPlanDirectivesExpert(DiagnosticModule):
    """SQL Plan Directives are the optimizer's own memory of past
    misestimates on an object — it flagged the problem itself. This is
    often the single most authoritative signal available: the CBO is
    telling you, in its own diagnostic data, exactly which object it
    got wrong before."""

    name = "SqlPlanDirectivesExpert"

    def analyze(self, bundle):
        findings = []
        for directive in bundle.sql_plan_directives:
            if directive.state in ("MISSING_STATS", "HAS_STATS", "NEW"):
                sev = SEV_HIGH if directive.state == "MISSING_STATS" else SEV_MEDIUM
                findings.append(Finding(
                    module=self.name,
                    title="SQL Plan Directive on {0}.{1} (reason: {2}, state: "
                          "{3})".format(directive.owner, directive.object_name,
                                        directive.reason, directive.state),
                    severity=sev,
                    explanation=(
                        "The optimizer previously detected a misestimate pattern on "
                        "{0}.{1}{2} and recorded a directive of type '{3}' as a result. "
                        "State '{4}' means: {5} This is the optimizer's own record that "
                        "it got the cardinality wrong here before — corroborating evidence "
                        "if a CardinalityExpert finding also points at this object."
                    ).format(
                        directive.owner, directive.object_name,
                        " (column {0})".format(directive.column_name) if directive.column_name else "",
                        directive.type, directive.state,
                        self._state_explanation(directive.state),
                    ),
                    evidence=[Evidence(
                        source="DBA_SQL_PLAN_DIRECTIVES / DBA_SQL_PLAN_DIR_OBJECTS",
                        detail="DIRECTIVE_ID={0}, TYPE={1}, STATE={2}, REASON={3}, "
                               "ENABLED={4}".format(directive.directive_id, directive.type,
                                                     directive.state, directive.reason,
                                                     directive.enabled),
                    )],
                    recommendations=[Recommendation(
                        action="Let dynamic sampling do its job, or gather stats to "
                               "supersede the directive permanently",
                        syntax="EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', "
                               "tabname=>'{1}', method_opt=>'FOR ALL COLUMNS SIZE "
                               "AUTO');  -- a directive in HAS_STATS/MISSING_STATS state "
                               "is superseded once real stats capture the pattern it "
                               "flagged".format(directive.owner, directive.object_name),
                        rationale="A directive in MISSING_STATS state means dynamic "
                                  "sampling is compensating at every hard parse — real "
                                  "extended/histogram stats are cheaper long-term than "
                                  "repeated dynamic sampling overhead.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                ))
        return findings

    @staticmethod
    def _state_explanation(state):
        return {
            "NEW": "the directive was just created and hasn't yet triggered dynamic "
                   "sampling on a hard parse.",
            "MISSING_STATS": "dynamic sampling is actively compensating for missing "
                              "statistics on every relevant hard parse — an ongoing "
                              "parse-time cost.",
            "HAS_STATS": "statistics now exist that address what this directive flagged, "
                          "but the directive itself hasn't been purged yet.",
            "PERMANENT": "this directive is permanently active for this object/reason.",
            "SUPERSEDED": "this directive has been superseded by another mechanism.",
        }.get(state, "state meaning not mapped — see Oracle documentation.")


# --------------------------------------------------------------------- #
# EXPERT 12 — Statistics Health (direct, not inferred)
# --------------------------------------------------------------------- #

class StatisticsHealthExpert(DiagnosticModule):
    """Checks DBA_TAB_STATISTICS/DBA_IND_STATISTICS directly for every
    object referenced in the plan. This is the "did anyone even check
    whether the stats are trustworthy" module — deliberately independent
    of whether a misestimate was actually observed, because a table can
    have stale stats and still get lucky with a correct estimate; that
    doesn't mean the stats are safe to rely on going forward."""

    name = "StatisticsHealthExpert"

    def analyze(self, bundle):
        findings = []
        for obj in bundle.object_statistics_health:
            if obj.last_analyzed is None:
                findings.append(Finding(
                    module=self.name,
                    title="{0} {1}.{2} has NEVER been analyzed — no statistics "
                          "exist".format(obj.object_type, obj.owner, obj.object_name),
                    severity=SEV_CRITICAL,
                    explanation=(
                        "There are no optimizer statistics at all for this {0}. The CBO is "
                        "either falling back to dynamic sampling on every hard parse (parse-"
                        "time overhead on every execution) or, worse, using default/guessed "
                        "selectivity constants that have no relationship to actual data "
                        "volume. This is the single most fixable, highest-confidence finding "
                        "this tool can produce."
                    ).format(obj.object_type.lower()),
                    evidence=[Evidence(
                        source="DBA_TAB_STATISTICS" if obj.object_type == "TABLE" else "DBA_IND_STATISTICS",
                        detail="LAST_ANALYZED is NULL for {0}.{1}".format(obj.owner, obj.object_name),
                    )],
                    recommendations=[Recommendation(
                        action="Gather statistics now",
                        syntax=(
                            "EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', tabname=>'{1}', "
                            "method_opt=>'FOR ALL COLUMNS SIZE AUTO', cascade=>TRUE);".format(
                                obj.owner, obj.object_name)
                            if obj.object_type == "TABLE" else
                            "EXEC DBMS_STATS.GATHER_INDEX_STATS(ownname=>'{0}', "
                            "indname=>'{1}');".format(obj.owner, obj.object_name)
                        ),
                        rationale="No downside to gathering stats on an object that has "
                                  "none — there is no 'current good state' being disturbed.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                ))
                continue

            if obj.stale_stats == "YES":
                findings.append(Finding(
                    module=self.name,
                    title="{0} {1}.{2} statistics are marked STALE".format(
                        obj.object_type, obj.owner, obj.object_name),
                    severity=SEV_HIGH,
                    explanation=(
                        "Oracle's own staleness tracking (monitored DML since last gather "
                        "exceeding the staleness threshold, default ~10% of rows) has "
                        "flagged this object's statistics as no longer representative of "
                        "current data. Last analyzed: {0}. Every cost/cardinality "
                        "calculation involving this object is working from a stale picture "
                        "of the data."
                    ).format(obj.last_analyzed),
                    evidence=[Evidence(
                        source="DBA_TAB_STATISTICS.STALE_STATS" if obj.object_type == "TABLE"
                               else "DBA_IND_STATISTICS.STALE_STATS",
                        detail="STALE_STATS=YES, LAST_ANALYZED={0}, NUM_ROWS at last "
                               "gather={1}".format(obj.last_analyzed, obj.num_rows),
                    )],
                    recommendations=[Recommendation(
                        action="Refresh statistics",
                        syntax=(
                            "EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', tabname=>'{1}', "
                            "method_opt=>'FOR ALL COLUMNS SIZE AUTO', cascade=>TRUE);".format(
                                obj.owner, obj.object_name)
                            if obj.object_type == "TABLE" else
                            "EXEC DBMS_STATS.GATHER_INDEX_STATS(ownname=>'{0}', "
                            "indname=>'{1}');".format(obj.owner, obj.object_name)
                        ),
                        rationale="If this object churns heavily and predictably (e.g. a "
                                  "staging/interface table), also consider "
                                  "DBMS_STATS.LOCK_TABLE_STATS with a representative "
                                  "snapshot, or a scheduled gather timed to the churn "
                                  "pattern, rather than relying solely on the automatic "
                                  "nightly job.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                ))

            if obj.object_type == "TABLE" and obj.sample_size and obj.num_rows and obj.num_rows > 0:
                sample_pct = 100.0 * obj.sample_size / obj.num_rows
                if sample_pct < 1.0 and obj.num_rows > 1000000:
                    findings.append(Finding(
                        module=self.name,
                        title="{0}.{1} statistics were gathered from a very small sample "
                              "({2:.3f}% of rows)".format(obj.owner, obj.object_name, sample_pct),
                        severity=SEV_LOW,
                        explanation=(
                            "On a table this large, a sub-1% sample can miss skew that "
                            "AUTO_SAMPLE_SIZE's hash-based algorithm would normally catch — "
                            "worth confirming this wasn't gathered with an explicit small "
                            "ESTIMATE_PERCENT override rather than AUTO_SAMPLE_SIZE."
                        ),
                        evidence=[Evidence(
                            source="DBA_TAB_STATISTICS",
                            detail="SAMPLE_SIZE={0} of NUM_ROWS={1} ({2:.3f}%)".format(
                                obj.sample_size, obj.num_rows, sample_pct),
                        )],
                        recommendations=[Recommendation(
                            action="Re-gather with AUTO_SAMPLE_SIZE if a manual percent was used",
                            syntax="EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', "
                                   "tabname=>'{1}', estimate_percent=>"
                                   "DBMS_STATS.AUTO_SAMPLE_SIZE, method_opt=>'FOR ALL "
                                   "COLUMNS SIZE AUTO', cascade=>TRUE);".format(
                                       obj.owner, obj.object_name),
                            rationale="AUTO_SAMPLE_SIZE's hash-based algorithm (11g+) is "
                                      "both faster AND more accurate than most manual "
                                      "percentages people historically hardcoded — rarely "
                                      "any reason to override it on current versions.",
                            risk=RISK_SAFE,
                            module_source=self.name,
                        )],
                    ))

            if obj.object_type == "TABLE" and obj.partitioned == "YES" and obj.global_stats == "NO":
                findings.append(Finding(
                    module=self.name,
                    title="{0}.{1} is partitioned but lacks GLOBAL statistics".format(
                        obj.owner, obj.object_name),
                    severity=SEV_MEDIUM,
                    explanation=(
                        "GLOBAL_STATS=NO means table-level (global) statistics are either "
                        "missing or were derived/estimated from partition-level stats rather "
                        "than gathered directly. Any query that can't prune to a single "
                        "partition (e.g. a full table aggregate, or a predicate that doesn't "
                        "hit the partition key) will cost using these potentially unreliable "
                        "global numbers."
                    ),
                    evidence=[Evidence(
                        source="DBA_TAB_STATISTICS",
                        detail="GLOBAL_STATS=NO, PARTITIONED=YES",
                    )],
                    recommendations=[Recommendation(
                        action="Gather global stats explicitly (not just partition-level)",
                        syntax="EXEC DBMS_STATS.GATHER_TABLE_STATS(ownname=>'{0}', "
                               "tabname=>'{1}', granularity=>'GLOBAL AND PARTITION', "
                               "cascade=>TRUE);".format(obj.owner, obj.object_name),
                        rationale="INCREMENTAL=TRUE partitioned tables (if enabled) can "
                                  "synchronize global stats efficiently from partition "
                                  "synopses without a full-table scan — check "
                                  "DBA_TAB_STATS_PREFS before assuming this requires an "
                                  "expensive full gather.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    )],
                ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 13 — Hint Advisor (top known-effective hints, cross-referenced
# against findings already raised, so it never recommends blind)
# --------------------------------------------------------------------- #

# A reference set of the hints most consistently documented across
# Oracle's own hint reference and widely-published tuning literature
# (Lewis, Antognini, Poder, Osborne and others' public material) as
# high-value for manual query tuning. This is a REFERENCE TABLE, not a
# rule that fires blindly — HintAdvisorExpert only surfaces a hint here
# when another module's finding already established the specific problem
# that hint addresses; it never suggests a hint "just because it's
# popular."
TOP_HINTS_REFERENCE = {
    "USE_HASH": "Force a hash join between specified row sources.",
    "USE_NL": "Force a nested-loops join, typically for small-outer/selective-inner shapes.",
    "USE_MERGE": "Force a sort-merge join, useful when both sides are already sorted "
                 "or a hash join's memory footprint is undesirable.",
    "LEADING": "Fix the join order starting from the specified table(s).",
    "ORDERED": "Force join order to match the FROM clause exactly (legacy; LEADING preferred).",
    "INDEX": "Force use of a specific index for access.",
    "FULL": "Force a full table scan, overriding index access paths.",
    "PARALLEL": "Force a specific (or default) degree of parallelism for an object/statement.",
    "NO_PARALLEL": "Suppress parallelism, e.g. to avoid a chronic PQ downgrade.",
    "GATHER_PLAN_STATISTICS": "Diagnostic hint — collects actual row counts per plan step "
                               "for DBMS_XPLAN.DISPLAY_CURSOR(format=>'ALLSTATS LAST'); "
                               "zero risk, essential for this kind of investigation.",
    "DYNAMIC_SAMPLING": "Force a specific dynamic sampling level for this statement, "
                         "independent of the object-level/system default.",
    "CARDINALITY": "Manually override the optimizer's cardinality estimate for a row "
                    "source — a blunt instrument, best as a temporary stopgap while the "
                    "real stats/histogram issue is fixed.",
    "OPT_ESTIMATE": "Fine-grained cardinality/selectivity correction, more surgical than "
                     "CARDINALITY and the mechanism SQL Profiles use internally.",
    "UNNEST": "Force subquery unnesting into a join.",
    "NO_UNNEST": "Prevent subquery unnesting, e.g. when unnesting changes result "
                 "semantics undesirably or performs worse.",
    "PUSH_PRED": "Force predicate pushing into a view.",
    "NO_MERGE": "Prevent view merging, e.g. to preserve an inline view as a materialized "
                "intermediate step.",
    "STAR_TRANSFORMATION": "Force star-schema bitmap-index transformation for fact/"
                            "dimension joins.",
    "RESULT_CACHE": "Cache the statement's result set in the SQL Result Cache — high "
                     "value for expensive, frequently-repeated, rarely-changing queries.",
    "MONITOR": "Force this statement into Real-Time SQL Monitoring even below the "
               "default 5-second threshold — diagnostic, zero execution-plan impact.",
    "NO_INDEX": "Prevent use of a specific index, forcing the optimizer to consider "
                "alternatives (often paired with FULL or another INDEX hint).",
}


class HintAdvisorExpert(DiagnosticModule):
    """Deliberately runs LAST in the module list conceptually (order in
    DEFAULT_MODULES doesn't enforce this, but the logic depends on other
    findings already existing on the report — see Synthesizer, which
    calls modules independently; this module instead operates directly
    on the bundle's SQL text to detect existing hints, and leaves
    problem-specific hint recommendations to the module that diagnosed
    that specific problem, e.g. JoinStrategyExpert recommending USE_HASH.
    This module's job is narrower and non-overlapping: inventory what
    hints are ALREADY in play, and flag hint/reality mismatches."""

    name = "HintAdvisorExpert"
    _HINT_BLOCK_RE = re.compile(r'/\*\+(.*?)\*/', re.DOTALL)
    _HINT_TOKEN_RE = re.compile(r'\b([A-Z_]+)\s*\(')

    def analyze(self, bundle):
        findings = []
        if not bundle.sql_text_info or not bundle.sql_text_info.sql_fulltext:
            return findings

        text = bundle.sql_text_info.sql_fulltext
        hint_blocks = self._HINT_BLOCK_RE.findall(text)
        if not hint_blocks:
            return findings

        found_hints = set()
        for block in hint_blocks:
            for token in self._HINT_TOKEN_RE.findall(block.upper()):
                if token in TOP_HINTS_REFERENCE:
                    found_hints.add(token)
            # also catch no-arg hints like FULL, PARALLEL without parens edge cases
            for word in re.findall(r'\b[A-Z_]{3,}\b', block.upper()):
                if word in TOP_HINTS_REFERENCE:
                    found_hints.add(word)

        if found_hints:
            descriptions = "; ".join(
                "{0} ({1})".format(h, TOP_HINTS_REFERENCE[h]) for h in sorted(found_hints)
            )
            findings.append(Finding(
                module=self.name,
                title="SQL text already contains {0} recognized tuning hint(s): "
                      "{1}".format(len(found_hints), ", ".join(sorted(found_hints))),
                severity=SEV_INFO,
                explanation=(
                    "Inventory only — these hints are already embedded in the statement "
                    "text and are actively shaping the plan the other modules analyzed. "
                    "{0}"
                ).format(descriptions),
                evidence=[Evidence(
                    source="V$SQL.SQL_FULLTEXT",
                    detail="Hint block(s) found: {0}".format(" | ".join(hb.strip() for hb in hint_blocks)),
                )],
                recommendations=[],
            ))

            if "CARDINALITY" in found_hints or "OPT_ESTIMATE" in found_hints:
                findings.append(Finding(
                    module=self.name,
                    title="A manual cardinality override hint is in use — treat as a "
                          "symptom, not a fix",
                    severity=SEV_LOW,
                    explanation=(
                        "CARDINALITY/OPT_ESTIMATE hints are frequently left in place long "
                        "after the underlying statistics/histogram problem they were "
                        "papering over has drifted further, or even after it was separately "
                        "fixed — making the hint's forced number wrong in a NEW way. Confirm "
                        "this override is still needed by testing without it if the object's "
                        "statistics are otherwise healthy (see StatisticsHealthExpert "
                        "findings)."
                    ),
                    evidence=[],
                    recommendations=[],
                ))

        if "GATHER_PLAN_STATISTICS" not in found_hints and not any(
            p.source == "CURSOR_CACHE_WITH_ACTUALS" for p in bundle.execution_plans
        ):
            findings.append(Finding(
                module=self.name,
                title="No actual-vs-estimate data available — consider "
                      "GATHER_PLAN_STATISTICS for the next test run",
                severity=SEV_INFO,
                explanation=(
                    "This diagnosis only had access to estimated plan data (no "
                    "STATISTICS_ALL / SQL Monitor actuals), which means cardinality-"
                    "misestimate findings could not be checked directly for this "
                    "execution. Re-run the suspect query once with GATHER_PLAN_STATISTICS "
                    "(or ensure STATISTICS_LEVEL=ALL for the session) and re-collect for a "
                    "much sharper diagnosis."
                ),
                evidence=[],
                recommendations=[Recommendation(
                    action="Add GATHER_PLAN_STATISTICS for one diagnostic run",
                    syntax="SELECT /*+ GATHER_PLAN_STATISTICS */ ...",
                    rationale="Zero effect on the plan chosen — purely instructs the "
                              "engine to also track actual rows/time per step, which is "
                              "otherwise only reliably available via SQL Monitoring "
                              "(5-second/parallel threshold) or STATISTICS_LEVEL=ALL.",
                    risk=RISK_SAFE,
                    module_source=self.name,
                )],
            ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 14 — SQL Tuning Advisor cross-reference
# --------------------------------------------------------------------- #

class SqlTuningAdvisorExpert(DiagnosticModule):
    """SQL Tuning Advisor runs the optimizer's own what-if trial engine
    against real execution — it is authoritative in a way inference from
    plan shape can never be. This module surfaces what STA has ALREADY
    concluded if it's been run, and otherwise recommends running it
    when other modules have raised HIGH/CRITICAL findings — STA is
    exactly the tool for confirming a hypothesis this engine can only
    infer."""

    name = "SqlTuningAdvisorExpert"

    def analyze(self, bundle):
        findings = []
        sta = bundle.sql_tuning_advisor

        if sta.has_been_analyzed:
            if sta.recommendations:
                for rec in sta.recommendations:
                    findings.append(Finding(
                        module=self.name,
                        title="SQL Tuning Advisor already recommends: {0} "
                              "(estimated benefit: {1}%)".format(
                                  rec.type, rec.benefit_pct if rec.benefit_pct is not None else "n/a"),
                        severity=SEV_HIGH if (rec.benefit_pct or 0) >= 50 else SEV_MEDIUM,
                        explanation=(
                            "Task '{0}' already analyzed this exact SQL statement and "
                            "produced this recommendation. {1}{2}"
                        ).format(
                            rec.task_name,
                            "Finding: {0} ".format(rec.finding) if rec.finding else "",
                            "Rationale: {0}".format(rec.rationale) if rec.rationale else "",
                        ),
                        evidence=[Evidence(
                            source="DBA_ADVISOR_RECOMMENDATIONS / DBA_ADVISOR_RATIONALE",
                            detail="TASK_NAME={0}, REC_ID={1}, TYPE={2}, "
                                   "BENEFIT={3}%".format(rec.task_name, rec.rec_id,
                                                          rec.type, rec.benefit_pct),
                        )],
                        recommendations=[Recommendation(
                            action="Review and implement via the advisor's own apply path",
                            syntax=(
                                rec.command if rec.command else
                                "SELECT DBMS_SQLTUNE.REPORT_TUNING_TASK('{0}') FROM "
                                "DUAL;  -- view full report before implementing".format(rec.task_name)
                            ),
                            rationale="If this is a SQL Profile recommendation, "
                                      "DBMS_SQLTUNE.ACCEPT_SQL_PROFILE is the standard, "
                                      "reversible way to apply it (ALTER to DISABLE / DROP "
                                      "the profile at any time if it regresses).",
                            risk=RISK_MEDIUM if rec.type and "profile" in rec.type.lower() else RISK_LOW,
                            module_source=self.name,
                        )],
                    ))
            else:
                findings.append(Finding(
                    module=self.name,
                    title="SQL Tuning Advisor has analyzed this SQL_ID with no outstanding "
                          "recommendations",
                    severity=SEV_INFO,
                    explanation=(
                        "Task(s) {0} already ran against this exact statement and found "
                        "nothing further to recommend at that time. If findings from other "
                        "modules in this report suggest a problem STA didn't catch, the "
                        "data STA analyzed may be stale — consider re-running it."
                    ).format(", ".join(t["task_name"] for t in sta.tasks)),
                    evidence=[Evidence(
                        source="DBA_ADVISOR_TASKS",
                        detail="{0} prior task(s): {1}".format(
                            len(sta.tasks), ", ".join(t["task_name"] for t in sta.tasks)),
                    )],
                    recommendations=[],
                ))
        else:
            findings.append(Finding(
                module=self.name,
                title="SQL Tuning Advisor has never analyzed this SQL_ID",
                severity=SEV_LOW,
                explanation=(
                    "No DBA_ADVISOR task has ever run against this exact statement. Given "
                    "the findings elsewhere in this report, running SQL Tuning Advisor "
                    "would cross-check this tool's inferences against the optimizer's own "
                    "what-if trial engine — the authoritative confirmation step before "
                    "committing to a fix. Requires the Diagnostics and Tuning Pack license."
                ),
                evidence=[],
                recommendations=[Recommendation(
                    action="Run SQL Tuning Advisor against this SQL_ID",
                    syntax=(
                        "DECLARE\n"
                        "  l_task VARCHAR2(30);\n"
                        "BEGIN\n"
                        "  l_task := DBMS_SQLTUNE.CREATE_TUNING_TASK(\n"
                        "    sql_id => '{0}', scope => 'COMPREHENSIVE', time_limit => 60,\n"
                        "    task_name => 'forensics_{0}');\n"
                        "  DBMS_SQLTUNE.EXECUTE_TUNING_TASK(task_name => 'forensics_{0}');\n"
                        "END;\n"
                        "/\n"
                        "SELECT DBMS_SQLTUNE.REPORT_TUNING_TASK('forensics_{0}') FROM DUAL;"
                    ).format(bundle.identity.sql_id),
                    rationale="COMPREHENSIVE scope includes SQL Profile analysis "
                              "(what-if execution with corrected cardinality estimates) — "
                              "the closest thing to a direct experimental confirmation of "
                              "a cardinality-misestimate hypothesis without touching "
                              "production plan selection.",
                    risk=RISK_LOW,
                    module_source=self.name,
                )],
            ))
        return findings


# --------------------------------------------------------------------- #
# EXPERT 15 — Regression Prevention (SPA / STS workflow guidance)
# --------------------------------------------------------------------- #

class RegressionPreventionExpert(DiagnosticModule):
    """Doesn't diagnose the SQL itself — diagnoses the SAFETY of applying
    the other modules' recommendations. Fires whenever this report
    contains a MEDIUM+ risk recommendation, and reminds the operator of
    the standard Oracle regression-prevention workflow (SQL Tuning Sets
    + SQL Performance Analyzer) before any plan-affecting change goes to
    production — directly answering "make sure this doesn't cause a
    performance issue" at the point where a human is about to act on
    this report's output."""

    name = "RegressionPreventionExpert"

    def analyze(self, bundle, other_findings=None):
        findings = []
        risky_recs = []
        for f in (other_findings or []):
            for r in f.recommendations:
                if r.risk in (RISK_MEDIUM, RISK_HIGH):
                    risky_recs.append((f, r))

        if risky_recs:
            findings.append(Finding(
                module=self.name,
                title="{0} recommendation(s) in this report carry MEDIUM/HIGH risk — "
                      "validate via SPA before production rollout".format(len(risky_recs)),
                severity=SEV_MEDIUM,
                explanation=(
                    "Before applying any plan-affecting change from this report "
                    "(baselines, profiles, structural hints, index changes) to a "
                    "production workload, capture this and related SQL into a SQL Tuning "
                    "Set and run SQL Performance Analyzer to measure the actual before/"
                    "after impact under realistic conditions — this is the standard "
                    "Oracle mechanism for proving a change is a net improvement (and for "
                    "catching if it regresses OTHER SQL sharing the same object/index) "
                    "before it's irreversible in practice."
                ),
                evidence=[Evidence(
                    source="This report",
                    detail="Risky recommendation(s): {0}".format(
                        "; ".join("{0} [{1}]".format(r.action, r.risk) for _, r in risky_recs)),
                )],
                recommendations=[
                    Recommendation(
                        action="Capture this SQL into a SQL Tuning Set",
                        syntax=(
                            "BEGIN\n"
                            "  DBMS_SQLTUNE.CREATE_SQLSET(sqlset_name => 'forensics_regression_check');\n"
                            "  DBMS_SQLTUNE.CAPTURE_CURSOR_CACHE_SQLSET(\n"
                            "    sqlset_name => 'forensics_regression_check',\n"
                            "    basic_filter => q'[sql_id = '{0}']', time_limit => 300);\n"
                            "END;\n/"
                        ).format(bundle.identity.sql_id),
                        rationale="An STS is a durable, reusable baseline workload "
                                  "snapshot — capture it once, reuse it for every SPA "
                                  "comparison as you iterate on a fix.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    ),
                    Recommendation(
                        action="Run SQL Performance Analyzer: before vs after comparison",
                        syntax=(
                            "DECLARE\n"
                            "  l_task VARCHAR2(30);\n"
                            "BEGIN\n"
                            "  l_task := DBMS_SQLPA.CREATE_ANALYSIS_TASK(\n"
                            "    sqlset_name => 'forensics_regression_check',\n"
                            "    task_name => 'forensics_spa_task');\n"
                            "  DBMS_SQLPA.EXECUTE_ANALYSIS_TASK(task_name => 'forensics_spa_task',\n"
                            "    execution_type => 'test execute');\n"
                            "  -- apply the proposed fix (baseline/profile/parameter) here, "
                            "then:\n"
                            "  DBMS_SQLPA.EXECUTE_ANALYSIS_TASK(task_name => 'forensics_spa_task',\n"
                            "    execution_type => 'test execute', execution_name => 'after_fix');\n"
                            "  DBMS_SQLPA.EXECUTE_ANALYSIS_TASK(task_name => 'forensics_spa_task',\n"
                            "    execution_type => 'compare performance');\n"
                            "END;\n/"
                        ),
                        rationale="SPA's 'test execute' mode captures execution "
                                  "statistics WITHOUT requiring production data changes, "
                                  "and the comparison report quantifies improvement or "
                                  "regression in DB time — turning 'I think this will help' "
                                  "into a measured number before it ships. Requires the "
                                  "Real Application Testing option.",
                        risk=RISK_SAFE,
                        module_source=self.name,
                    ),
                ],
            ))
        return findings


# --------------------------------------------------------------------- #
# Synthesizer — merges all module findings into one ranked report
# --------------------------------------------------------------------- #

DEFAULT_MODULES = [
    CardinalityExpert(),
    JoinStrategyExpert(),
    AccessPathExpert(),
    PredicateTransformationExpert(),
    PartitioningExpert(),
    ParallelismExpert(),
    ResourceProfileExpert(),
    PlanStabilityExpert(),
    CursorSharingExpert(),
    AdaptiveFeaturesExpert(),
    SqlPlanDirectivesExpert(),
    StatisticsHealthExpert(),
    HintAdvisorExpert(),
    SqlTuningAdvisorExpert(),
    RegressionPreventionExpert(),
]


class DiagnosticReport(object):
    def __init__(self, sql_id, findings):
        self.sql_id = sql_id
        self.findings = sorted(findings, key=lambda f: -f.severity)

    def to_dict(self):
        return {
            "sql_id": self.sql_id,
            "finding_count": len(self.findings),
            "findings_by_severity": {
                SEV_LABELS[s]: len([f for f in self.findings if f.severity == s])
                for s in SEV_LABELS
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent=2):
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def summary_text(self):
        lines = []
        lines.append("SQL Forensic Diagnosis — {0}".format(self.sql_id))
        lines.append("{0} finding(s)".format(len(self.findings)))
        lines.append("")
        for f in self.findings:
            lines.append("[{0}] {1} ({2})".format(SEV_LABELS[f.severity], f.title, f.module))
            lines.append("  {0}".format(f.explanation))
            for e in f.evidence:
                lines.append("  evidence: {0}".format(e))
            for r in f.recommendations:
                lines.append("  -> [{0} risk] {1}: {2}".format(r.risk, r.action, r.syntax))
            lines.append("")
        return "\n".join(lines)


class Synthesizer(object):
    def __init__(self, modules=None):
        self.modules = modules if modules is not None else DEFAULT_MODULES

    def diagnose(self, bundle):
        all_findings = []
        for module in self.modules:
            try:
                if isinstance(module, RegressionPreventionExpert):
                    findings = module.analyze(bundle, other_findings=all_findings)
                else:
                    findings = module.analyze(bundle)
                all_findings.extend(findings)
            except Exception as exc:
                LOG.warning("Diagnostic module %s failed: %s", module.name, exc)
                all_findings.append(Finding(
                    module=module.name,
                    title="Diagnostic module error",
                    severity=SEV_INFO,
                    explanation="This module could not complete analysis: {0}".format(exc),
                ))
        return DiagnosticReport(bundle.identity.sql_id, all_findings)
