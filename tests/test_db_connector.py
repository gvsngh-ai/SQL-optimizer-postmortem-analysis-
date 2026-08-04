# -*- coding: utf-8 -*-
"""
test_db_connector.py — unit tests for the read-only enforcement guard.
This is the single most safety-critical piece of code in the product:
it is the reason this tool cannot mutate the database it diagnoses.
Every case here MUST pass before this tool ever runs against a
database that matters.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db_connector import OracleForensicConnection, ConnectionConfig, ReadOnlyViolation


class _TestableConn(OracleForensicConnection):
    """Skips OracleForensicConnection.__init__ (which requires the
    oracledb driver to be installed) so the pure-string guard logic can
    be unit tested in total isolation, with or without oracledb present."""

    def __init__(self):
        self.config = ConnectionConfig(dsn="fake", user="fake", password="fake")
        self._conn = None
        self._current_con_id = None


class TestReadOnlyGuard(unittest.TestCase):
    def setUp(self):
        self.conn = _TestableConn()

    # -- statements that MUST be allowed --

    def test_allows_plain_select(self):
        self.conn._assert_select_only("SELECT * FROM v$sql WHERE sql_id = :sql_id")

    def test_allows_with_clause(self):
        self.conn._assert_select_only("WITH x AS (SELECT 1 FROM dual) SELECT * FROM x")

    def test_allows_lowercase_select(self):
        self.conn._assert_select_only("select * from dual")

    def test_allows_select_with_leading_whitespace(self):
        self.conn._assert_select_only("   \n  SELECT 1 FROM dual")

    def test_allows_container_switch_special_case(self):
        self.conn._assert_select_only("ALTER SESSION SET CONTAINER = MYPDB")

    # -- statements that MUST be rejected --

    def test_rejects_insert(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("INSERT INTO t VALUES (1)")

    def test_rejects_update(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("UPDATE t SET x = 1")

    def test_rejects_delete(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("DELETE FROM t")

    def test_rejects_drop(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("DROP TABLE t")

    def test_rejects_truncate(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("TRUNCATE TABLE t")

    def test_rejects_create(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("CREATE TABLE t (x NUMBER)")

    def test_rejects_grant(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("GRANT SELECT ON t TO u")

    def test_rejects_execute_immediate(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;")

    def test_rejects_non_select_leading_word(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("MERGE INTO t USING s ON (1=1) WHEN MATCHED THEN UPDATE SET x=1")

    def test_rejects_smuggled_dml_via_select_prefix_comment_trick(self):
        # A statement that starts with SELECT syntactically but embeds a
        # forbidden keyword anywhere must still be rejected — the
        # keyword blacklist runs in addition to the prefix check.
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only(
                "SELECT 1 FROM dual; DROP TABLE t"
            )

    def test_rejects_empty_string(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("")

    def test_rejects_call_statement(self):
        with self.assertRaises(ReadOnlyViolation):
            self.conn._assert_select_only("CALL some_procedure()")


class TestContainerIdentifierGuard(unittest.TestCase):
    def test_rejects_unsafe_container_name(self):
        with self.assertRaises(ValueError):
            OracleForensicConnection._quote_identifier("MYPDB; DROP TABLE t --")

    def test_accepts_normal_identifier(self):
        result = OracleForensicConnection._quote_identifier("MYPDB1")
        self.assertEqual(result, "MYPDB1")

    def test_accepts_cdb_root(self):
        result = OracleForensicConnection._quote_identifier("CDB$ROOT")
        self.assertEqual(result, "CDB$ROOT")


class TestConnectionConfig(unittest.TestCase):
    def test_sysdba_forces_thick_mode(self):
        config = ConnectionConfig(dsn=None, sysdba=True, mode="thin")
        self.assertEqual(config.mode, "thick")

    def test_password_auth_respects_requested_mode(self):
        config = ConnectionConfig(dsn="host:1521/svc", user="u", password="p", mode="thin")
        self.assertEqual(config.mode, "thin")


if __name__ == "__main__":
    unittest.main()
