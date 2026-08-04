# -*- coding: utf-8 -*-
"""
run_collection.py
------------------
Example / reference CLI entry point tying db_connector.py and
collectors.py together for the exact operating pattern you described:

    oracle-CHSOPRD1@reg-prod-db-qvzwg1 > . CHSOPRD.env
    oracle-CHSOPRD1@reg-prod-db-qvzwg1 > sqlplus / as sysdba

...replaced by:

    python3 run_collection.py --env-file /home/oracle/CHSOPRD.env \
        --pdb CHSPRD_PDB1 --sql-id 7fkxqzj2mkvvb --out /tmp/7fkxqzj2mkvvb.json

Nothing here prompts for or accepts a password — connectivity is 100%
OS-authenticated `/ as sysdba`, matching how CHSOPRD.env is actually used
on that host. This must run AS the `oracle` OS user (or another account
in the same OS group with sysdba OS authentication) ON the DB host,
since bequeath connections (dsn=None) go through the local IPC/shared
memory path, not the listener.

Python 3.6.8 compatible. Only dependency: oracledb (thick mode requires
the Oracle Client already present at $ORACLE_HOME — which it is, per
your env file, since sqlplus runs from there today).
"""

import sys
import argparse
import logging

from db_connector import ConnectionConfig, OracleForensicConnection
from collectors import SqlForensicsCollector
from diagnostic_engine import Synthesizer
from report_html import write_report_html
from mailer import MailerConfig, send_report_email


def main():
    parser = argparse.ArgumentParser(
        description="Collect complete SQL_ID forensic history from an "
                     "Oracle multitenant database via OS-authenticated "
                     "sysdba (thick mode)."
    )
    parser.add_argument(
        "--env-file", required=True,
        help="Path to the per-database .env file, e.g. "
             "/home/oracle/CHSOPRD.env — provides ORACLE_HOME, "
             "ORACLE_SID, TNS_ADMIN, LD_LIBRARY_PATH."
    )
    parser.add_argument(
        "--pdb", required=True,
        help="PDB_NAME to switch into after connecting to CDB$ROOT "
             "as sysdba. This is what makes the tool multitenant-aware: "
             "the SQL_ID you're chasing lives in this PDB, and "
             "DBA_HIST_*/DBA_SQL_PLAN_BASELINES etc. must be queried "
             "from inside it (or from CDB_HIST_* at the root with a "
             "CON_ID filter — see --scope)."
    )
    parser.add_argument(
        "--scope", choices=["DBA", "CDB"], default="DBA",
        help="DBA (default): switch into the PDB and query DBA_HIST_* "
             "there directly. CDB: stay at CDB$ROOT and query CDB_HIST_* "
             "filtered by CON_ID instead (use this if AWR is only "
             "licensed/gathered at the root)."
    )
    parser.add_argument("--sql-id", required=True, help="The SQL_ID to investigate.")
    parser.add_argument(
        "--lookback-days", type=int, default=14,
        help="How many days of AWR/ASH history to pull (default 14)."
    )
    parser.add_argument(
        "--dsn", default=None,
        help="Optional easy-connect/tnsnames alias for a remote "
             "sysdba connection. Omit for local bequeath (recommended, "
             "matches how you run sqlplus today: dsn defaults to "
             "$ORACLE_SID)."
    )
    parser.add_argument("--out", default=None, help="Base output path (no extension) for the bundle/report. Default: sql_id in the current directory.")
    parser.add_argument("--format", choices=["json", "html", "text", "all"], default="all",
                         help="Which output(s) to write: raw JSON bundle, HTML diagnostic "
                              "report, plain-text diagnostic summary, or all three "
                              "(default).")
    parser.add_argument("--skip-diagnosis", action="store_true",
                         help="Collect only — skip running the diagnostic engine (useful "
                              "for building a bundle library to diagnose later/offline).")
    parser.add_argument("--email", default=None,
                         help="Comma-separated recipient address(es). If set, emails the "
                              "HTML report (inlined + attached) plus JSON/text attachments "
                              "after diagnosis completes. Requires SMTP_HOST (and optionally "
                              "SMTP_PORT/SMTP_USE_TLS/SMTP_USER/SMTP_PASSWORD/SMTP_FROM) set "
                              "in the environment — see mailer.py. Forces --format all.")
    parser.add_argument("--email-cc", default=None, help="Comma-separated CC address(es).")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("sql_forensics.cli")

    config = ConnectionConfig.sysdba_local(env_file_path=args.env_file, dsn=args.dsn)

    with OracleForensicConnection(config) as conn:
        ctx = conn.get_database_context()
        log.info("Connected: %s | is_cdb=%s | awr_accessible=%s | autonomous=%s",
                  ctx["banner"], ctx["is_cdb"], ctx["awr_accessible"], ctx["is_autonomous"])

        if not ctx["is_cdb"]:
            log.warning(
                "V$DATABASE.CDB = NO — this is not a multitenant "
                "database, --pdb will be ignored."
            )
        else:
            conn.switch_container(args.pdb)
            ctx = conn.get_database_context()
            log.info("Now in container: %s (con_id=%s)", ctx["con_name"], ctx["con_id"])

        if not ctx["awr_accessible"]:
            log.warning(
                "DBA_HIST_SNAPSHOT is not queryable here — either the "
                "Diagnostics Pack isn't licensed/enabled, or this "
                "account lacks SELECT_CATALOG_ROLE-equivalent access. "
                "sysdba should always have access; if this fires, check "
                "CONTROL_MANAGEMENT_PACK_ACCESS on the instance. "
                "AWR-sourced history will be skipped/empty."
            )

        collector = SqlForensicsCollector(conn, history_scope=args.scope)
        bundle = collector.collect(
            sql_id=args.sql_id,
            con_id=ctx.get("con_id"),
            lookback_days=args.lookback_days,
        )

    if bundle.collection_errors:
        log.warning("Partial collection — %d sub-collector(s) failed:",
                     len(bundle.collection_errors))
        for err in bundle.collection_errors:
            log.warning("  - %s", err)

    log.info("Collected: %d execution plan(s), %d AWR snapshot(s), %d wait-event "
              "row(s), %d SQL Monitor report(s), %d SQL Plan Directive(s)",
              len(bundle.execution_plans), len(bundle.awr_sqlstat_history),
              len(bundle.wait_event_summary), len(bundle.sql_monitor_reports),
              len(bundle.sql_plan_directives))

    base_out = args.out or bundle.identity.sql_id
    formats = ["json", "html", "text"] if (args.format == "all" or args.email) else [args.format]

    if args.email and args.skip_diagnosis:
        log.error("--email requires diagnosis to run — remove --skip-diagnosis.")
        sys.exit(2)

    if "json" in formats:
        json_path = base_out + ".bundle.json"
        with open(json_path, "w") as fh:
            fh.write(bundle.to_json())
        log.info("Raw forensic bundle written to %s", json_path)

    if not args.skip_diagnosis:
        report = Synthesizer().diagnose(bundle)
        log.info("Diagnosis complete: %d finding(s) — %s",
                  len(report.findings),
                  ", ".join("{0}={1}".format(k, v) for k, v in
                             report.to_dict()["findings_by_severity"].items() if v))

        if "json" in formats:
            report_json_path = base_out + ".report.json"
            with open(report_json_path, "w") as fh:
                fh.write(report.to_json())
            log.info("Diagnostic report (JSON) written to %s", report_json_path)

        if "text" in formats:
            text_path = base_out + ".report.txt"
            with open(text_path, "w") as fh:
                fh.write(report.summary_text())
            log.info("Diagnostic report (text) written to %s", text_path)

        if "html" in formats:
            html_path = base_out + ".report.html"
            write_report_html(report, html_path, database_context=ctx)
            log.info("Diagnostic report (HTML) written to %s", html_path)

        if args.email:
            to_addrs = [a.strip() for a in args.email.split(",") if a.strip()]
            cc_addrs = [a.strip() for a in args.email_cc.split(",") if a.strip()] if args.email_cc else []
            try:
                mail_config = MailerConfig.from_env()
                send_report_email(
                    mail_config, to_addrs, bundle.identity.sql_id, report,
                    html_path=base_out + ".report.html",
                    json_bundle_path=base_out + ".bundle.json",
                    json_report_path=base_out + ".report.json",
                    text_report_path=base_out + ".report.txt",
                    cc_addrs=cc_addrs,
                )
                log.info("Report emailed to %s", ", ".join(to_addrs))
            except Exception as exc:
                # Email failure must never be silent AND must never make the
                # caller think the diagnosis itself failed — the report
                # files are already safely on disk at this point.
                log.error("Email delivery FAILED (report files are still on disk at "
                          "%s.*): %s", base_out, exc)
                sys.exit(3)
    else:
        log.info("Diagnosis skipped (--skip-diagnosis) — bundle collected only.")


if __name__ == "__main__":
    main()
