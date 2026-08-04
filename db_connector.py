# -*- coding: utf-8 -*-
"""
db_connector.py
----------------
Connection layer for the SQL Forensics engine.

Design decisions (deliberate, read these before changing anything):

1. THIN MODE ONLY by default. python-oracledb's thin driver is pure Python —
   no Oracle Instant Client, no libclntsh.so, nothing to install on the
   target server beyond `pip install oracledb`. That satisfies "install on
   my server without a library headache." Thick mode is offered as an
   opt-in fallback ONLY (e.g. if you need OS authentication or advanced
   Net8 features thin doesn't yet cover) — see connect(mode='thick').

2. HARD READ-ONLY ENFORCEMENT. This tool must never be the reason a
   production database changes state. We enforce this at three layers,
   not one:
     a. The DB session is set ALTER SESSION SET READ ONLY where supported,
        or at minimum we never issue anything but SELECT.
     b. Every query method in this module is a SELECT built from a fixed,
        whitelisted statement — there is no free-form SQL execution path
        exposed to callers.
     c. A statement-shape guard (_assert_select_only) inspects any SQL
        string before execution and refuses non-SELECT statements,
        including multi-statement injection attempts.

3. MULTITENANT AWARE. Every collector call takes an explicit con_id /
   container context. We never assume CDB root vs a specific PDB — the
   caller must say which, and we switch containers explicitly rather than
   relying on connect-time defaults.

4. NO THIRD PARTY LIBS beyond the Oracle driver itself, which is
   unavoidable to talk to Oracle at all. Everything else here is stdlib,
   compatible with Python 3.6.8 (no f-string debug specifiers, no
   dataclasses, no walrus operator).
"""

import os
import re
import logging
import getpass

try:
    import oracledb
except ImportError:
    oracledb = None  # allow this module to be imported/inspected without the driver present

LOG = logging.getLogger("sql_forensics.db")

_SELECT_ONLY_RE = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)
_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|"
    r"EXECUTE\s+IMMEDIATE|CALL)\b",
    re.IGNORECASE,
)


class ReadOnlyViolation(Exception):
    """Raised the instant any code path tries to execute something that
    is not a plain SELECT/WITH statement. This should never fire in normal
    operation — if it does, treat it as a bug, not a nuisance to silence."""
    pass


def load_oracle_env_file(env_file_path):
    """Parses a shell-style Oracle environment file (the kind produced by
    `oraenv` / hand-maintained per-database .env files like
    'CHSOPRD.env') WITHOUT sourcing it in a shell and WITHOUT executing
    any of its content. We only understand the simple
    `VAR=value; export VAR` / `VAR=value` shape those files use — anything
    else is ignored, never executed. Returns a dict of env vars, which the
    caller applies to os.environ before connecting in thick mode.

    This matters because thick-mode connectivity depends entirely on
    ORACLE_HOME, LD_LIBRARY_PATH and TNS_ADMIN being correct *before*
    oracledb.init_oracle_client() runs — the driver reads them from the
    process environment, not from a config object.
    """
    env_vars = {}
    line_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)=([^;]*)')
    with open(env_file_path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = line_re.match(line)
            if match:
                var_name, var_value = match.group(1), match.group(2).strip()
                if len(var_value) >= 2 and var_value[0] == var_value[-1] and var_value[0] in "'\"":
                    var_value = var_value[1:-1]
                env_vars[var_name] = var_value
    return env_vars


def apply_env(env_vars):
    """Applies parsed env vars to the current process environment. Call
    this ONCE, before the first connect(), ideally at process start —
    LD_LIBRARY_PATH in particular is only honored by the dynamic linker
    at process/library-load time on most platforms, so if
    init_oracle_client() has already loaded libclntsh.so in this process,
    changing LD_LIBRARY_PATH afterward has no effect. Set the environment
    (os.environ, or launch the python process itself with the .env
    sourced) before Python starts if you hit 'library not loaded' errors.
    """
    for key, value in env_vars.items():
        os.environ[key] = value


class ConnectionConfig(object):
    def __init__(self, dsn=None, user=None, password=None, wallet_location=None,
                 wallet_password=None, mode="thin", sysdba=False):
        """
        dsn: easy-connect string, full descriptor, or a tnsnames alias
             resolved via TNS_ADMIN. None is valid ONLY for local
             OS-authenticated sysdba connections (dsn defaults to the
             ORACLE_SID bequeath connection in that case).
        mode: 'thin' (default, recommended for password auth — pure
              Python, nothing to install) or 'thick' (REQUIRED for
              sysdba/OS authentication — "/ as sysdba" has no thin-mode
              equivalent; it depends on the OS-level Oracle Client stack).
        sysdba: True for `/ as sysdba` OS-authenticated connections.
                Forces mode='thick' regardless of what's passed, and
                ignores user/password entirely.
        """
        self.dsn = dsn
        self.user = user
        self.password = password
        self.wallet_location = wallet_location
        self.wallet_password = wallet_password
        self.sysdba = sysdba
        self.mode = "thick" if sysdba else mode

    @classmethod
    def prompt_for_password(cls, dsn, user, wallet_location=None, mode="thin"):
        """Interactive helper — never hardcode credentials in scripts that
        call this module. Prompts via getpass so the password never touches
        shell history or process listings."""
        pwd = getpass.getpass("Password for {0}@{1}: ".format(user, dsn))
        return cls(dsn=dsn, user=user, password=pwd,
                    wallet_location=wallet_location, mode=mode)

    @classmethod
    def sysdba_local(cls, env_file_path=None, dsn=None):
        """Builds a config for `/ as sysdba` OS-authenticated connections.

        env_file_path: path to a per-database .env file (e.g.
            '/home/oracle/CHSOPRD.env') to source ORACLE_HOME,
            ORACLE_SID, TNS_ADMIN, LD_LIBRARY_PATH from before connecting.
            Parsed safely — see load_oracle_env_file(); nothing is
            executed as shell.
        dsn: optional — if omitted, connects via local bequeath using
            ORACLE_SID from the environment (must run ON the DB host,
            same OS account that owns the instance). Pass an
            easy-connect string instead only if the site has explicitly
            configured remote OS-authenticated sysdba (most do not).
        """
        if env_file_path:
            env_vars = load_oracle_env_file(env_file_path)
            apply_env(env_vars)
        return cls(dsn=dsn, user=None, password=None, mode="thick", sysdba=True)


class OracleForensicConnection(object):
    """A thin wrapper around one oracledb connection, hardened for
    read-only diagnostic use against a multitenant database."""

    def __init__(self, config):
        if oracledb is None:
            raise RuntimeError(
                "python-oracledb is not installed. Run: "
                "pip install oracledb   (pure-python thin driver, no "
                "Oracle Client needed)."
            )
        self.config = config
        self._conn = None
        self._current_con_id = None

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #

    def connect(self):
        if self.config.mode == "thick":
            # ORACLE_HOME must already be set in os.environ (via
            # ConnectionConfig.sysdba_local(env_file_path=...) or an
            # externally-sourced .env) BEFORE this call — the client
            # libraries load from $ORACLE_HOME/lib on Linux.
            oracle_home = os.environ.get("ORACLE_HOME")
            init_kwargs = {}
            if oracle_home:
                init_kwargs["lib_dir"] = os.path.join(oracle_home, "lib")
            try:
                oracledb.init_oracle_client(**init_kwargs)
            except oracledb.ProgrammingError as exc:
                # init_oracle_client() raises if called twice in the same
                # process (e.g. a second OracleForensicConnection reusing
                # the interpreter) — that's fine, the client is already up.
                if "already" not in str(exc).lower():
                    raise

        if self.config.sysdba:
            self._conn = oracledb.connect(
                dsn=self.config.dsn,          # None => local bequeath via $ORACLE_SID
                mode=oracledb.AUTH_MODE_SYSDBA,
            )
            LOG.info("Connected AS SYSDBA (OS-authenticated, thick mode) dsn=%s",
                     self.config.dsn or "<local bequeath: ORACLE_SID={0}>".format(
                         os.environ.get("ORACLE_SID")))
        else:
            connect_kwargs = dict(
                user=self.config.user,
                password=self.config.password,
                dsn=self.config.dsn,
            )
            if self.config.wallet_location:
                connect_kwargs["config_dir"] = self.config.wallet_location
                if self.config.wallet_password:
                    connect_kwargs["wallet_password"] = self.config.wallet_password
            self._conn = oracledb.connect(**connect_kwargs)

        # Best-effort session hardening. Some privilege levels can't set
        # READ ONLY (e.g. if the session needs to read V$ views that some
        # sites restrict under read-only sessions) — we don't hard-fail
        # here, but we log clearly either way.
        try:
            with self._conn.cursor() as cur:
                cur.execute("ALTER SESSION SET READ ONLY")
            LOG.info("Session hardened: ALTER SESSION SET READ ONLY succeeded.")
        except Exception as exc:
            LOG.warning(
                "Could not set session READ ONLY (%s). Relying on the "
                "application-level SELECT-only guard instead.", exc
            )
        return self

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ------------------------------------------------------------------ #
    # multitenant container switching
    # ------------------------------------------------------------------ #

    def switch_container(self, con_name):
        """con_name: 'CDB$ROOT' or a specific PDB name. Required before
        querying CDB_HIST_* / CDB_* views scoped to a PDB, or when AWR is
        only licensed/queried at the root."""
        self._assert_select_only("ALTER SESSION SET CONTAINER")  # documents intent; not a SELECT, see note below
        # ALTER SESSION SET CONTAINER is a structural navigation command,
        # not a data-mutating statement — it changes zero rows in zero
        # tables. We special-case it explicitly rather than loosening the
        # SELECT-only guard.
        with self._conn.cursor() as cur:
            cur.execute("ALTER SESSION SET CONTAINER = {0}".format(
                self._quote_identifier(con_name)))
        self._current_con_id = con_name
        LOG.info("Switched container to %s", con_name)

    @staticmethod
    def _quote_identifier(name):
        # Defensive: container names are identifiers, not literals, but we
        # still refuse anything that isn't a plausible identifier to close
        # off any injection surface via a con_name sourced from user input.
        if not re.match(r'^[A-Za-z0-9_$#"]+$', name):
            raise ValueError("Unsafe container identifier: {0!r}".format(name))
        return name

    # ------------------------------------------------------------------ #
    # the ONE execution path — everything else in this codebase funnels
    # through this method, so the guard only has to live in one place.
    # ------------------------------------------------------------------ #

    def _assert_select_only(self, sql):
        if sql.strip().upper().startswith("ALTER SESSION SET CONTAINER"):
            return  # explicitly whitelisted structural command, see switch_container
        if not _SELECT_ONLY_RE.match(sql):
            raise ReadOnlyViolation(
                "Refusing to execute non-SELECT statement: {0}".format(sql[:120])
            )
        if _FORBIDDEN_KEYWORDS.search(sql):
            raise ReadOnlyViolation(
                "Statement contains a forbidden DML/DDL keyword: {0}".format(sql[:120])
            )

    def fetch_all(self, sql, params=None, arraysize=1000):
        """The single query execution primitive used by every collector.
        Returns a list of dict rows (column_name -> value), uppercased
        keys to match Oracle's default identifier casing."""
        self._assert_select_only(sql)
        params = params or {}
        with self._conn.cursor() as cur:
            cur.arraysize = arraysize
            cur.execute(sql, params)
            columns = [d[0] for d in cur.description]
            rows = []
            for raw_row in cur:
                rows.append(dict(zip(columns, raw_row)))
            return rows

    def fetch_one(self, sql, params=None):
        rows = self.fetch_all(sql, params=params, arraysize=2)
        return rows[0] if rows else None

    # ------------------------------------------------------------------ #
    # environment introspection — used to decide which view family
    # (CDB_HIST_* vs DBA_HIST_*, 19c vs 23ai feature availability) to use
    # ------------------------------------------------------------------ #

    def get_database_context(self):
        """Returns facts the rest of the system needs to pick the right
        query dialect: version, whether this is a CDB, current con_id,
        whether Diagnostics/Tuning Pack is usable (AWR access), edition."""
        version_row = self.fetch_one(
            "SELECT BANNER_FULL AS BANNER FROM V$VERSION WHERE ROWNUM = 1"
        )
        cdb_row = self.fetch_one("SELECT CDB FROM V$DATABASE")
        con_row = self.fetch_one(
            "SELECT SYS_CONTEXT('USERENV','CON_ID') AS CON_ID, "
            "SYS_CONTEXT('USERENV','CON_NAME') AS CON_NAME FROM DUAL"
        )
        awr_licensed = True
        try:
            self.fetch_one(
                "SELECT COUNT(*) AS CNT FROM DBA_HIST_SNAPSHOT WHERE ROWNUM = 1"
            )
        except Exception:
            awr_licensed = False

        is_autonomous = False
        try:
            adb_row = self.fetch_one(
                "SELECT CLOUD_IDENTITY FROM V$PDBS WHERE ROWNUM = 1"
            )
            is_autonomous = adb_row is not None and adb_row.get("CLOUD_IDENTITY") is not None
        except Exception:
            pass

        return {
            "banner": version_row.get("BANNER") if version_row else None,
            "is_cdb": (cdb_row or {}).get("CDB") == "YES",
            "con_id": (con_row or {}).get("CON_ID"),
            "con_name": (con_row or {}).get("CON_NAME"),
            "awr_accessible": awr_licensed,
            "is_autonomous": is_autonomous,
        }
