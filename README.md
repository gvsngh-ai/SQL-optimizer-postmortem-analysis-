# Oracle SQL Forensics — Optimizer Postmortem Engine

Given a SQL_ID, this tool pulls its complete diagnostic history from an
Oracle 19c / 23ai / Autonomous Database (multitenant-aware), and runs it
through 13 independent diagnostic modules that behave like a panel of
specialists each looking at the problem through one lens — cardinality,
join strategy, access paths, predicate transformation, partitioning,
parallelism, resource/wait profile, plan stability, cursor sharing,
adaptive features, SQL Plan Directives, statistics health, and hint
usage — then produces a ranked report: what's wrong, the evidence for
it, and exactly what to try, with real hint/command syntax and an
explicit risk rating for each fix.

See `PANEL.md` for how each module's technique maps to publicly known
Oracle performance methodology (Lewis, Colgan, Bayliss, Antognini, and
others) — used as an honest attribution of *technique provenance*, not a
simulation of these people.

## Files in this product

| File | What it does |
|---|---|
| `models.py` | Data model — every artifact collected (plans, wait events, stats, directives, baselines...) as plain Python classes, JSON-serializable. Zero dependencies. |
| `db_connector.py` | Connection layer. `python-oracledb` thin mode (pure Python, password auth) or thick mode (required for `/ as sysdba` OS auth). Three-layer read-only enforcement — this tool can never mutate the database it's diagnosing. |
| `collectors.py` | Pulls everything: cursor cache, AWR history, live ASH, SQL Monitor, baselines/profiles/patches, SQL Plan Directives, index/statistics health. Every collector fails soft with a logged error — partial data beats a crash. |
| `diagnostic_engine.py` | The 13 expert modules + the Synthesizer that ranks their findings into one report. |
| `report_html.py` | Renders a self-contained HTML report — no CDN, no JS framework, opens on an air-gapped server. |
| `run_collection.py` | The CLI entry point. One command: SQL_ID in, full report out — optionally emailed. |
| `mailer.py` | SMTP delivery of the finished report (stdlib only — smtplib/email.mime, no dependency). |
| `tests/` | Real `unittest` suite — 60+ targeted test cases, not just a smoke test. Run via `self_test.py` or directly. |
| `self_test.py` | **Run this first.** Runs the unit test suite + verifies the whole pipeline against a synthetic bundle — no database required. |
| `PANEL.md` | Methodology provenance — which module maps to which publicly documented technique. |

## Installation

```bash
# On the target server, as the oracle OS user (or wherever this will run):
pip install oracledb --break-system-packages   # or inside a venv, no flag needed

# Copy all .py files + PANEL.md into one directory, e.g.:
mkdir -p /opt/sql_forensics
cp *.py PANEL.md /opt/sql_forensics/
cd /opt/sql_forensics
```

`oracledb` is the ONLY dependency, and only strictly required for
`db_connector.py`/`collectors.py`/`run_collection.py`. `models.py`,
`diagnostic_engine.py`, and `report_html.py` are pure stdlib and will
run/self-test even without it installed.

## Step 1 — Verify the product before touching a real database

```bash
python3 self_test.py
```

This must print `RESULT: All checks that can run without a live
database PASSED.` before you go near production. It exercises every
diagnostic module against a synthetic bundle and writes sample outputs
to `./self_test_output/` — open `sample.report.html` in a browser to
see exactly what a real report looks like.

If `oracledb` isn't installed yet, you'll see a `WARN` (not a `FAIL`)
on that line — the rest of the tool is still fully verified.

## Step 2 — Run it against a real SQL_ID

Matches the exact operating pattern you use today (`. CHSOPRD.env` +
`sqlplus / as sysdba`), replacing it with OS-authenticated sysdba via
thick mode — no password ever touches this tool:

```bash
python3 run_collection.py \
  --env-file /home/oracle/CHSOPRD.env \
  --pdb CHSPRD_PDB1 \
  --sql-id 7fkxqzj2mkvvb \
  --lookback-days 14 \
  --out /tmp/7fkxqzj2mkvvb \
  --format all
```

This produces:
- `/tmp/7fkxqzj2mkvvb.bundle.json` — every raw fact collected
- `/tmp/7fkxqzj2mkvvb.report.json` — the ranked diagnosis, machine-readable
- `/tmp/7fkxqzj2mkvvb.report.txt` — the ranked diagnosis, plain text
- `/tmp/7fkxqzj2mkvvb.report.html` — the ranked diagnosis, open in a browser

Run `python3 run_collection.py --help` for all options (`--scope CDB`
if AWR is only licensed at the root, `--skip-diagnosis` to just collect
and diagnose later, `-v` for verbose logging).

**Important constraint:** local bequeath sysdba connections (`--dsn`
omitted) only work when run ON the DB host, under the same OS account
that owns the instance — same as running `sqlplus / as sysdba` directly.

## Step 3 — Email the report (optional)

Give the tool a SQL_ID and it will email you the finished report — no
need to go find the files afterward:

```bash
export SMTP_HOST=smtp.yourcompany.com
export SMTP_PORT=587
export SMTP_USE_TLS=1
export SMTP_USER=sql-forensics@yourcompany.com   # omit if relay needs no auth
export SMTP_PASSWORD=...                          # omit if relay needs no auth
export SMTP_FROM=sql-forensics@yourcompany.com

python3 run_collection.py \
  --env-file /home/oracle/CHSOPRD.env --pdb CHSPRD_PDB1 \
  --sql-id 7fkxqzj2mkvvb --out /tmp/7fkxqzj2mkvvb \
  --email dba-team@yourcompany.com --email-cc you@yourcompany.com
```

The email contains the HTML report inlined in the body (readable
without opening an attachment) plus all three formats attached. SMTP
credentials are read from the environment only — never from the
command line — so they never appear in `ps` output or shell history.
If email delivery fails, the report files are still safely on disk at
the `--out` path; only the email step failed, not the diagnosis.

For scheduled/unattended use, wrap the command above in a cron entry or
a Tag/Slack-triggered job — "give me a SQL_ID and get a report by
email" is exactly the `--sql-id ... --email ...` invocation, nothing
further to build for that workflow specifically.

## Testing — what's actually verified, and what isn't

Run this to see the current state of automated testing yourself:

```bash
python3 self_test.py
```

This runs three layers in one command: import/dependency checks, a full
`unittest` suite (`tests/`, 60+ cases), and an end-to-end mock pipeline
run producing sample outputs.

**What the test suite covers (unit-level, SDLC "build/test" stage):**
- `tests/test_db_connector.py` — the read-only guard specifically:
  every DML/DDL keyword variant, comment-based smuggling attempts,
  container-identifier injection attempts. This is the most
  safety-critical logic in the product and has the most exhaustive
  coverage.
- `tests/test_diagnostic_engine.py` — targeted assertions per expert
  module: each fires on the specific condition it should, and does
  NOT fire on data that shouldn't trigger it (both directions tested,
  not just "does it produce output").
- `tests/test_models.py` — serialization round-trip correctness,
  including edge cases (missing fields, non-JSON-serializable values).
- `tests/test_report_and_mailer.py` — HTML rendering, XSS-class
  escaping of finding content, and mailer message construction (SMTP
  send itself is mocked — the suite never sends real email).

This test suite already did its job once during development: it caught
a real bug where the temp-spill detector was unreachable whenever wait-
event data happened to be empty, and a header-encoding issue in the
mailer — both fixed before this build, not found by you in production.

**What is NOT covered, stated plainly rather than implied to be fine:**
- **Integration testing against a real Oracle instance.** Every test
  above uses synthetic/mock data. Dictionary view column availability
  across 19c vs 23ai, privilege grants, NULL-handling and casing in
  real result sets — none of this can be verified without a live run.
- **Load/concurrency testing.** What happens if this tool is invoked
  against 50 SQL_IDs simultaneously, or against a SQL_ID with an
  unusually large number of plan children/AWR history, hasn't been
  measured.
- **Security review of the codebase as a whole** (beyond the read-only
  guard's own test coverage) — e.g. a formal review of the SMTP
  credential handling path, or a penetration test of the tool's own
  attack surface.
- **User acceptance testing** — nobody besides this build process has
  run it yet.

**Recommended path to close those gaps, in order:** (1) run against one
non-critical, read-heavy SQL_ID in a non-production PDB, comparing its
`.report.html` findings against what a human DBA would independently
conclude from the same SQL_ID; (2) if available, a second pass in a
QA/staging environment with production-like data volume; (3) only then,
first production use against a genuinely low-risk, well-understood
SQL_ID — not the first time you reach for it during an active incident.

## Why this won't hurt the database it's diagnosing

This came up explicitly, so it's stated plainly rather than assumed:

1. **Every query is a SELECT.** `db_connector.py` enforces this at
   three independent layers: `ALTER SESSION SET READ ONLY` at connect
   time, a regex guard that inspects every SQL string before execution
   and rejects anything that isn't `SELECT`/`WITH`, and the fact that
   there is no free-form SQL execution path exposed anywhere in the
   codebase — only a fixed set of whitelisted collector queries.
2. **Every data source is metadata or already-sampled history.** Object
   statistics checks read `DBA_TAB_STATISTICS`/`DBA_IND_STATISTICS`
   (dictionary metadata, not table scans). Wait-event analysis reads
   ASH (`V$ACTIVE_SESSION_HISTORY`/`DBA_HIST_ACTIVE_SESS_HISTORY`),
   which Oracle already samples and stores regardless of this tool.
   Nothing here is heavier than a single AWR report generation.
3. **Nothing is fixed automatically.** Every remediation is a
   `Recommendation` object with literal syntax you review and run
   yourself — `DBMS_STATS.GATHER_TABLE_STATS`, a hint to test, an
   `EVOLVE_SQL_PLAN_BASELINE` call. The tool never executes any of
   these on your behalf.

## What "assurance this will work" actually means here

Concretely, verified as of this build:
- All 7 product files parse as valid Python 3.6.8-compatible syntax (no
  dataclasses, walrus operator, or 3.7+-only stdlib features used).
- All modules import cleanly together with no circular dependencies.
- The full pipeline — mock collection → all 13 diagnostic modules →
  JSON + text + HTML report generation — runs end-to-end and produces
  correct, evidence-backed findings (confirmed via `self_test.py`).

What is **not** yet verified, and should be treated as the actual next
step rather than assumed: a live run against a real instance. Dictionary
view column availability, privilege grants, and casing/NULL edge cases
in real data can only be confirmed by running it — start with one
non-critical, read-heavy SQL_ID in a non-production PDB if one is
available, before CHSOPRD.
