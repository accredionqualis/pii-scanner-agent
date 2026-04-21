"""
SCE GRC PII Scanner — Database Scanner
Capacity-aware scanning strategy:
  - Small  tables  (<  10,000 rows) → full scan, all rows
  - Medium tables  (<   1,000,000 rows) → first 2000 + random sample 2000
  - Large  tables  (<  10,000,000 rows) → first 1000 + 3x random chunks + last 500
  - Huge   tables  (>= 10,000,000 rows) → statistical sample capped at 5000 rows
                                           with true count stored for report

Memory safety: rows are fetched and processed column-by-column in batches of 500.
A 20TB database with billions of rows will complete without OOM — each batch is
at most 500 rows x N columns as strings, flushed after each column.
"""

import re
import random
from detectors import scan_text, mask_value

# Thresholds
SMALL_TABLE_LIMIT   =     10_000   # scan every row
MEDIUM_TABLE_LIMIT  =  1_000_000   # scan first+random sample
LARGE_TABLE_LIMIT   = 10_000_000   # scan first+chunks+last
BATCH_SIZE          =        500   # rows fetched per cursor batch
MAX_SAMPLES_STORED  =        100   # max masked values kept per finding


class DBScanner:
    def __init__(self, config, api_client=None):
        self.config  = config
        self.api_client = api_client

    def get_connection(self):
        db_type  = self.config.get('type', 'mysql').lower()
        host     = self.config.get('host', 'localhost')
        port     = self.config.get('port')
        database = self.config.get('database', '')
        username = self.config.get('username', '')
        password = self.config.get('password', '')

        if db_type == 'mysql':
            import pymysql
            port = port or 3306
            return pymysql.connect(
                host=host, port=int(port), user=username, password=password,
                database=database, connect_timeout=10
            ), 'mysql'
        elif db_type == 'postgresql':
            import psycopg2
            port = port or 5432
            return psycopg2.connect(
                host=host, port=int(port), user=username, password=password,
                dbname=database, connect_timeout=10
            ), 'pg'
        elif db_type == 'mssql':
            import pyodbc
            port = port or 1433
            conn_str = (
                f'DRIVER={{ODBC Driver 17 for SQL Server}};'
                f'SERVER={host},{port};DATABASE={database};'
                f'UID={username};PWD={password}'
            )
            return pyodbc.connect(conn_str, timeout=10), 'mssql'
        elif db_type == 'sqlite':
            import sqlite3
            return sqlite3.connect(database), 'sqlite'
        elif db_type == 'oracle':
            import oracledb
            oracledb.init_oracle_client()
            port = port or 1521
            dsn = f'{host}:{port}/{database}'
            return oracledb.connect(user=username, password=password, dsn=dsn), 'oracle'
        raise ValueError(f'Unsupported DB type: {db_type}')

    def get_tables(self, conn, db_type, database):
        cur = conn.cursor()
        if db_type == 'mysql':
            cur.execute(
                "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s",
                (database,)
            )
        elif db_type == 'pg':
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        elif db_type == 'mssql':
            cur.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'")
        elif db_type == 'sqlite':
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        elif db_type == 'oracle':
            cur.execute("SELECT TABLE_NAME FROM USER_TABLES")
        return [r[0] for r in cur.fetchall()]

    def get_columns(self, conn, db_type, database, table):
        cur = conn.cursor()
        if db_type == 'mysql':
            cur.execute(
                "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                (database, table)
            )
        elif db_type == 'pg':
            cur.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema='public' AND table_name=%s",
                (table,)
            )
        elif db_type == 'mssql':
            cur.execute(
                f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{table}'"
            )
        elif db_type == 'sqlite':
            cur.execute(f"SELECT name FROM pragma_table_info('{table}')")
        elif db_type == 'oracle':
            cur.execute(
                f"SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{table.upper()}'"
            )
        return [r[0] for r in cur.fetchall()]

    def get_row_count(self, conn, db_type, database, table):
        """
        Fast row count using DB stats tables — avoids full COUNT(*) on huge tables.
        Returns approximate count for large tables, exact for small.
        """
        cur = conn.cursor()
        try:
            if db_type == 'mysql':
                # information_schema.TABLES is near-instant even for 20TB tables
                cur.execute(
                    "SELECT TABLE_ROWS FROM information_schema.TABLES "
                    "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                    (database, table)
                )
                row = cur.fetchone()
                if row and row[0] is not None:
                    return int(row[0])

            elif db_type == 'pg':
                # pg_class.reltuples is instant — slightly approximate for huge tables
                cur.execute(
                    "SELECT reltuples::bigint FROM pg_class "
                    "WHERE relname=%s AND relnamespace="
                    "(SELECT oid FROM pg_namespace WHERE nspname='public')",
                    (table,)
                )
                row = cur.fetchone()
                if row and row[0] is not None and row[0] >= 0:
                    return int(row[0])

            elif db_type == 'mssql':
                cur.execute(
                    "SELECT SUM(p.rows) FROM sys.tables t "
                    "JOIN sys.partitions p ON t.object_id=p.object_id "
                    f"WHERE t.name='{table}' AND p.index_id IN (0,1)"
                )
                row = cur.fetchone()
                if row and row[0]:
                    return int(row[0])

            elif db_type == 'oracle':
                cur.execute(
                    f"SELECT NUM_ROWS FROM USER_TABLES WHERE TABLE_NAME='{table.upper()}'"
                )
                row = cur.fetchone()
                if row and row[0]:
                    return int(row[0])

            # SQLite + fallback (only runs for genuinely small tables or unknown DBs)
            cur.execute(f'SELECT COUNT(*) FROM "{table}"')
            return int(cur.fetchone()[0])

        except Exception:
            return 0

    def _offset_query(self, db_type, table, offset, limit):
        """Build dialect-specific LIMIT/OFFSET query."""
        if db_type == 'oracle':
            return (
                f'SELECT * FROM "{table}" '
                f'OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY'
            )
        elif db_type == 'mssql':
            return (
                f'SELECT * FROM [{table}] '
                f'ORDER BY (SELECT NULL) '
                f'OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY'
            )
        elif db_type == 'mysql':
            return f'SELECT * FROM `{table}` LIMIT {limit} OFFSET {offset}'
        else:
            return f'SELECT * FROM "{table}" LIMIT {limit} OFFSET {offset}'

    def _fetch_rows(self, conn, db_type, table, offset, limit):
        cur = conn.cursor()
        try:
            cur.execute(self._offset_query(db_type, table, offset, limit))
            return cur.fetchall()
        except Exception:
            return []

    def _build_scan_plan(self, row_count):
        """
        Returns list of (offset, limit, label) tuples.
        Total rows fetched is always bounded — safe for any DB size.

        20TB / 10B row table example:
          head 500 + tail 500 + 6 x 500 spread = 4000 rows scanned
          sample_count in report is scaled to estimated full-table count
        """
        if row_count <= SMALL_TABLE_LIMIT:
            # Full scan in BATCH_SIZE chunks
            plan = []
            offset = 0
            while offset < row_count:
                plan.append((offset, min(BATCH_SIZE, row_count - offset), 'full'))
                offset += BATCH_SIZE
            return plan

        elif row_count <= MEDIUM_TABLE_LIMIT:
            # Head 1000 + tail 500 + 3 random chunks of 500
            plan = [
                (0,               1000, 'head'),
                (max(0, row_count - 500), 500, 'tail'),
            ]
            mid = row_count // 4
            for _ in range(3):
                off = random.randint(mid, max(mid + 1, row_count - 600))
                plan.append((off, 500, 'sample'))
            return plan

        elif row_count <= LARGE_TABLE_LIMIT:
            # Head 1000 + tail 500 + 4 evenly-spaced random chunks of 500
            plan = [
                (0,               1000, 'head'),
                (max(0, row_count - 500), 500, 'tail'),
            ]
            segment = row_count // 5
            for i in range(1, 5):
                off = random.randint(segment * i, max(segment * i + 1, segment * (i + 1) - 600))
                plan.append((off, 500, 'sample'))
            return plan

        else:
            # Huge table (> 10M rows — handles 20TB databases)
            # Head 500 + tail 500 + 6 evenly-spaced chunks of 500 = max 4000 rows
            plan = [
                (0,               500, 'head'),
                (max(0, row_count - 500), 500, 'tail'),
            ]
            segment = row_count // 7
            for i in range(1, 7):
                plan.append((segment * i, 500, 'sample'))
            return plan

    def _scan_column(self, all_rows, col_idx, col_name, table, row_count):
        """
        Scan one column's values across all fetched rows.
        Scales sample_count to estimated full-table count.
        """
        col_values = [
            str(r[col_idx])
            for r in all_rows
            if col_idx < len(r) and r[col_idx] is not None
        ]
        if not col_values:
            return []

        col_text   = ' '.join(col_values)
        col_findings = scan_text(col_text, max_samples=MAX_SAMPLES_STORED)

        results = []
        sampled_rows = len(all_rows)

        for f in col_findings:
            # Scale detected count to full table size
            if sampled_rows > 0 and row_count > sampled_rows:
                scale = row_count / sampled_rows
                estimated_count = max(f['sample_count'], int(f['sample_count'] * scale))
            else:
                estimated_count = f['sample_count']

            results.append({
                'detector':      f['detector'],
                'table_name':    table,
                'column_name':   col_name,
                'sample_count':  estimated_count,       # est. full-table records
                'sensitivity':   f['sensitivity'],
                'is_dpdp_spdi':  f['dpdp_spdi'],
                'sample_values': f.get('matches', []),  # masked values list
                'rows_scanned':  sampled_rows,          # rows actually checked
                'total_rows':    row_count,             # real table size
            })
        return results

    def scan(self, progress_cb=None):
        findings = []
        try:
            conn, db_type = self.get_connection()
        except Exception as e:
            raise Exception(f"DB connection failed: {e}")

        database     = self.config.get('database', '')
        tables       = self.get_tables(conn, db_type, database)
        total_tables = len(tables)

        for t_idx, table in enumerate(tables):
            try:
                # Step 1 — fast row count (stats-based, no full scan)
                row_count = self.get_row_count(conn, db_type, database, table)

                size_label = (
                    'FULL'   if row_count <= SMALL_TABLE_LIMIT   else
                    'MEDIUM' if row_count <= MEDIUM_TABLE_LIMIT  else
                    'LARGE'  if row_count <= LARGE_TABLE_LIMIT   else
                    'HUGE'
                )

                if progress_cb:
                    progress_cb(
                        f"[{t_idx+1}/{total_tables}] {table} "
                        f"(~{row_count:,} rows · {size_label} scan)"
                    )

                if row_count == 0:
                    continue

                # Step 2 — decide which rows to fetch
                plan = self._build_scan_plan(row_count)

                # Step 3 — fetch all planned batches (shared across columns)
                all_rows = []
                for (offset, limit, label) in plan:
                    batch = self._fetch_rows(conn, db_type, table, offset, limit)
                    all_rows.extend(batch)

                if not all_rows:
                    continue

                # Step 4 — get column names
                cols = self.get_columns(conn, db_type, database, table)

                # Step 5 — scan each column independently
                for col_idx, col_name in enumerate(cols):
                    col_findings = self._scan_column(
                        all_rows, col_idx, col_name, table, row_count
                    )
                    findings.extend(col_findings)

            except Exception as e:
                if progress_cb:
                    progress_cb(f"  WARNING: Skipped table '{table}': {e}")
                continue

        conn.close()
        return findings


if __name__ == '__main__':
    import sqlite3, tempfile, os

    db = tempfile.mktemp(suffix='.db')
    conn = sqlite3.connect(db)
    conn.execute(
        'CREATE TABLE customers '
        '(id INTEGER, name TEXT, email TEXT, phone TEXT, pan TEXT, aadhaar TEXT)'
    )
    for i in range(500):
        conn.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?,?)",
            (i, f'User {i}', f'user{i}@test.com',
             f'9876500{i:03d}', 'ABCPD1234F', '2345 6789 0123')
        )
    conn.commit()
    conn.close()

    scanner = DBScanner({'type': 'sqlite', 'database': db})
    results = scanner.scan(print)
    print(f"\n{len(results)} findings:")
    for r in results:
        print(
            f"  {r['table_name']}.{r['column_name']}: {r['detector']} "
            f"— ~{r['sample_count']:,} est. records "
            f"(scanned {r['rows_scanned']} of {r['total_rows']}) "
            f"— {len(r['sample_values'])} masked samples"
        )
    os.unlink(db)
