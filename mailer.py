# -*- coding: utf-8 -*-
"""
mailer.py
----------
Delivers a diagnostic run's outputs (HTML report inline + all three
formats as attachments) via SMTP. Stdlib only (smtplib, email.mime) —
no third-party dependency, works with any SMTP relay (internal relay,
Office365, Gmail SMTP, Sendgrid SMTP endpoint, etc).

Deliberately separated from run_collection.py so email delivery can
fail without affecting the collection/diagnosis result — the report
files are already written to disk before mailer.py is ever invoked.

SECURITY NOTE: SMTP credentials (if the relay requires auth) are read
from environment variables, never from command-line arguments or
hardcoded — command-line args are visible in `ps` output and shell
history; env vars set via a protected .env file are not.
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate

LOG = logging.getLogger("sql_forensics.mailer")


class MailerConfig(object):
    def __init__(self, smtp_host, smtp_port=25, use_tls=False, username=None,
                 password=None, from_addr=None, timeout_seconds=30):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.from_addr = from_addr or (username if username else "sql-forensics@localhost")
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls):
        """Reads SMTP_HOST, SMTP_PORT, SMTP_USE_TLS, SMTP_USER,
        SMTP_PASSWORD, SMTP_FROM from the process environment. Raises if
        SMTP_HOST is missing — that's the one setting with no sane
        default, since it identifies your mail relay."""
        host = os.environ.get("SMTP_HOST")
        if not host:
            raise RuntimeError(
                "SMTP_HOST is not set. Set it (and optionally SMTP_PORT, "
                "SMTP_USE_TLS=1, SMTP_USER, SMTP_PASSWORD, SMTP_FROM) in the "
                "environment before using --email, e.g. via the same .env "
                "pattern used for ORACLE_HOME."
            )
        return cls(
            smtp_host=host,
            smtp_port=int(os.environ.get("SMTP_PORT", "25")),
            use_tls=os.environ.get("SMTP_USE_TLS", "0") in ("1", "true", "True", "YES", "yes"),
            username=os.environ.get("SMTP_USER"),
            password=os.environ.get("SMTP_PASSWORD"),
            from_addr=os.environ.get("SMTP_FROM"),
        )


def send_report_email(config, to_addrs, sql_id, report, html_path=None,
                       json_bundle_path=None, json_report_path=None,
                       text_report_path=None, cc_addrs=None):
    """
    config: a MailerConfig
    to_addrs: list[str] of recipient email addresses
    sql_id: for the subject line
    report: the diagnostic_engine.DiagnosticReport (used for subject-line
            severity summary and the inline plain-text body)
    *_path: paths to already-written output files to attach — pass None
            to skip attaching a given format. The HTML report, if
            provided, is BOTH attached and inlined in the message body
            so it's readable directly in the mail client without opening
            an attachment.
    """
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]
    cc_addrs = cc_addrs or []

    counts = report.to_dict()["findings_by_severity"]
    severity_bits = ", ".join(
        "{0}={1}".format(k, v) for k, v in counts.items() if v
    ) or "no findings"

    msg = MIMEMultipart("mixed")
    msg["Subject"] = "SQL Forensics Report - {0} ({1})".format(sql_id, severity_bits)
    msg["From"] = config.from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Date"] = formatdate(localtime=True)

    body_related = MIMEMultipart("alternative")
    plain_body = (
        "SQL Forensics diagnosis for {0}\n\n"
        "{1} finding(s): {2}\n\n"
        "Full HTML report is attached and inlined below (if your mail "
        "client renders HTML). Raw JSON bundle and plain-text summary "
        "are attached for offline/automated use.\n\n"
        "This is an automated diagnostic output. No changes have been "
        "made to any database — every recommendation in the report "
        "requires manual review and execution.\n"
    ).format(sql_id, len(report.findings), severity_bits)
    body_related.attach(MIMEText(plain_body, "plain"))

    if html_path and os.path.isfile(html_path):
        with open(html_path, "r") as fh:
            html_content = fh.read()
        body_related.attach(MIMEText(html_content, "html"))

    msg.attach(body_related)

    for path, mime_subtype in (
        (html_path, "html"),
        (json_bundle_path, "json"),
        (json_report_path, "json"),
        (text_report_path, "plain"),
    ):
        if path and os.path.isfile(path):
            with open(path, "rb") as fh:
                part = MIMEApplication(fh.read(), _subtype=mime_subtype)
            part.add_header("Content-Disposition", "attachment",
                             filename=os.path.basename(path))
            msg.attach(part)

    all_recipients = to_addrs + cc_addrs
    server = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=config.timeout_seconds)
    try:
        server.ehlo()
        if config.use_tls:
            server.starttls()
            server.ehlo()
        if config.username and config.password:
            server.login(config.username, config.password)
        server.sendmail(config.from_addr, all_recipients, msg.as_string())
        LOG.info("Report emailed to %s (cc: %s)", ", ".join(to_addrs), ", ".join(cc_addrs) or "-")
    finally:
        server.quit()
