"""Database access layer.

MySQL (mysql-connector-python, pooled) is the supported backend. A SQLite backend
exists purely so the automated test-suite and offline demos run on machines
without a MySQL server. SQL is written once with ``%s`` placeholders; the SQLite
adapter rewrites them. All values are always passed as bound parameters.
"""
import logging
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
SCHEMA_FILE = Path(__file__).with_name("schema.sql")

sqlite3.register_adapter(datetime, lambda d: d.strftime("%Y-%m-%d %H:%M:%S"))


def utcnow():
    """Naive UTC timestamp without microseconds (stored format)."""
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


class DatabaseError(Exception):
    """Raised for connection / query failures (message is safe to show)."""


def _to_sqlite_sql(sql):
    return sql.replace("%s", "?")


def _mysql_schema_to_sqlite(text):
    text = re.sub(r"\)\s*ENGINE=InnoDB[^;]*;", ");", text)
    text = re.sub(r"(?:BIG)?INT AUTO_INCREMENT PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT", text)
    return text


def split_statements(text):
    text = re.sub(r"--[^\n]*", "", text)
    return [s.strip() for s in text.split(";") if s.strip()]


class _Executor:
    """Shared query helpers over a DB-API connection."""

    def __init__(self, conn, backend):
        self._conn = conn
        self._backend = backend

    def _cursor(self):
        if self._backend == "mysql":
            return self._conn.cursor(dictionary=True)
        return self._conn.cursor()

    def _prep(self, sql):
        return _to_sqlite_sql(sql) if self._backend == "sqlite" else sql

    def query_all(self, sql, params=()):
        cur = self._cursor()
        try:
            cur.execute(self._prep(sql), tuple(params))
            rows = cur.fetchall()
        finally:
            cur.close()
        return [dict(r) for r in rows]

    def query_one(self, sql, params=()):
        rows = self.query_all(sql, params)
        return rows[0] if rows else None

    def execute(self, sql, params=()):
        """Execute a write; returns (lastrowid, rowcount)."""
        cur = self._cursor()
        try:
            cur.execute(self._prep(sql), tuple(params))
            return cur.lastrowid, cur.rowcount
        finally:
            cur.close()


class Database:
    def __init__(self, cfg):
        self.backend = cfg["DB_BACKEND"]
        self.cfg = cfg
        self._pool = None
        self._lock = threading.Lock()
        if self.backend not in ("mysql", "sqlite"):
            raise DatabaseError(f"Unsupported DB_BACKEND '{self.backend}'")

    # ---- connections -----------------------------------------------------
    def _mysql_kwargs(self, with_db=True):
        kw = dict(host=self.cfg["MYSQL_HOST"], port=self.cfg["MYSQL_PORT"],
                  user=self.cfg["MYSQL_USER"], password=self.cfg["MYSQL_PASSWORD"],
                  connection_timeout=10, charset="utf8mb4", use_pure=True)
        if with_db:
            kw["database"] = self.cfg["MYSQL_DATABASE"]
        return kw

    def _get_conn(self):
        if self.backend == "sqlite":
            conn = sqlite3.connect(self.cfg["SQLITE_PATH"], timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        import mysql.connector
        from mysql.connector import pooling
        try:
            with self._lock:
                if self._pool is None:
                    self._pool = pooling.MySQLConnectionPool(
                        pool_name="mlids", pool_size=int(self.cfg["MYSQL_POOL_SIZE"]),
                        **self._mysql_kwargs())
            return self._pool.get_connection()
        except mysql.connector.Error as exc:
            log.error("MySQL connection failed: %s", exc.msg if hasattr(exc, "msg") else exc)
            raise DatabaseError("Cannot connect to the MySQL database. Check the MYSQL_* settings.") from exc

    @contextmanager
    def transaction(self):
        """Yield an executor; commit on success, roll back on error."""
        conn = self._get_conn()
        try:
            yield _Executor(conn, self.backend)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- single statements ----------------------------------------------
    def query_all(self, sql, params=()):
        with self.transaction() as tx:
            return tx.query_all(sql, params)

    def query_one(self, sql, params=()):
        with self.transaction() as tx:
            return tx.query_one(sql, params)

    def execute(self, sql, params=()):
        with self.transaction() as tx:
            return tx.execute(sql, params)

    # ---- health / schema -------------------------------------------------
    def ping(self):
        try:
            self.query_one("SELECT 1 AS ok")
            return True
        except Exception as exc:  # noqa: BLE001 - health probe
            log.warning("DB ping failed: %s", exc)
            return False

    def schema_exists(self):
        try:
            self.query_one("SELECT 1 FROM users LIMIT 1")
            return True
        except Exception:  # noqa: BLE001
            return False

    def init_schema(self, create_database=False):
        """Create the database (MySQL) and apply schema.sql if tables are missing."""
        if self.backend == "mysql" and create_database:
            import mysql.connector
            try:
                conn = mysql.connector.connect(**self._mysql_kwargs(with_db=False))
                cur = conn.cursor()
                name = self.cfg["MYSQL_DATABASE"]
                if not re.fullmatch(r"[A-Za-z0-9_]+", name):
                    raise DatabaseError("MYSQL_DATABASE may only contain letters, digits and underscores.")
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                conn.commit()
                cur.close()
                conn.close()
            except mysql.connector.Error as exc:
                raise DatabaseError(f"Could not create database: {exc}") from exc
        if self.schema_exists():
            return False
        text = SCHEMA_FILE.read_text(encoding="utf-8")
        if self.backend == "sqlite":
            text = _mysql_schema_to_sqlite(text)
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            for stmt in split_statements(text):
                cur.execute(stmt)
            conn.commit()
        finally:
            conn.close()
        log.info("Database schema created.")
        return True


_db = None


def init_db(cfg):
    global _db
    _db = Database(cfg)
    return _db


def use_db(db):
    """Re-bind the process-wide database (used by tests that juggle several app instances)."""
    global _db
    _db = db


def get_db():
    if _db is None:
        raise DatabaseError("Database not initialised")
    return _db
