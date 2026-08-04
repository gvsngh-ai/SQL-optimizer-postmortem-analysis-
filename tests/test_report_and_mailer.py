# -*- coding: utf-8 -*-
"""
test_report_and_mailer.py — HTML rendering correctness and mailer
message construction (SMTP send itself is mocked; we never want a unit
test suite actually sending email).
"""

import sys
import os
import unittest

try:
    from unittest import mock
except ImportError:  # Python 2 fallback, not expected but harmless
    import mock  # noqa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import SqlForensicBundle, TargetIdentity
from diagnostic_engine import DiagnosticReport, Finding, Evidence, Recommendation, SEV_CRITICAL, RISK_SAFE
from report_html import render_report_html


def _sample_report():
    finding = Finding(
        module="TestModule",
        title="<script>alert(1)</script> should be escaped",
        severity=SEV_CRITICAL,
        explanation="Some explanation with <b>tags</b> that must be escaped.",
        evidence=[Evidence(source="test source", detail="test detail")],
        recommendations=[Recommendation(
            action="Do the thing", syntax="EXEC something('x');",
            rationale="Because reasons", risk=RISK_SAFE,
        )],
    )
    return DiagnosticReport("test_sql_id", [finding])


class TestReportHtml(unittest.TestCase):
    def test_renders_without_error(self):
        html = render_report_html(_sample_report())
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("test_sql_id", html)

    def test_escapes_html_in_finding_content(self):
        html = render_report_html(_sample_report())
        # the raw <script> tag must NOT appear unescaped — this is an
        # XSS-class check, since finding text ultimately originates from
        # SQL_TEXT / object names that could theoretically contain
        # attacker-influenced strings in a shared environment.
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_no_findings_case_renders_positive_message(self):
        empty_report = DiagnosticReport("test_sql_id", [])
        html = render_report_html(empty_report)
        self.assertIn("No findings", html)

    def test_database_context_appears_in_subtitle(self):
        html = render_report_html(_sample_report(), database_context={
            "banner": "Oracle Database 19c EE", "con_name": "MYPDB",
        })
        self.assertIn("Oracle Database 19c EE", html)
        self.assertIn("MYPDB", html)


class TestMailer(unittest.TestCase):
    def test_mailer_config_from_env_requires_smtp_host(self):
        from mailer import MailerConfig
        env_backup = dict(os.environ)
        try:
            os.environ.pop("SMTP_HOST", None)
            with self.assertRaises(RuntimeError):
                MailerConfig.from_env()
        finally:
            os.environ.clear()
            os.environ.update(env_backup)

    def test_send_report_email_builds_and_sends_without_real_network(self):
        from mailer import MailerConfig, send_report_email
        config = MailerConfig(smtp_host="localhost", smtp_port=25)
        report = _sample_report()

        with mock.patch("smtplib.SMTP") as mock_smtp_cls:
            mock_server = mock.MagicMock()
            mock_smtp_cls.return_value = mock_server
            send_report_email(config, ["ops@example.com"], "test_sql_id", report)
            mock_server.sendmail.assert_called_once()
            args = mock_server.sendmail.call_args[0]
            self.assertEqual(args[0], config.from_addr)
            self.assertIn("ops@example.com", args[1])
            self.assertIn("test_sql_id", args[2])  # subject line in raw message

    def test_send_report_email_uses_tls_when_configured(self):
        from mailer import MailerConfig, send_report_email
        config = MailerConfig(smtp_host="localhost", smtp_port=587, use_tls=True,
                               username="u", password="p")
        report = _sample_report()
        with mock.patch("smtplib.SMTP") as mock_smtp_cls:
            mock_server = mock.MagicMock()
            mock_smtp_cls.return_value = mock_server
            send_report_email(config, ["ops@example.com"], "test_sql_id", report)
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("u", "p")


if __name__ == "__main__":
    unittest.main()
