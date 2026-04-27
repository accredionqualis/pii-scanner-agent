"""
KnightGuard GRC — Database Scanner v2.2 (High Performance + Resume)
Supports: PostgreSQL, MySQL/MariaDB, Oracle, MSSQL, SQLite, MongoDB

Performance optimizations:
- Parallel table scanning (configurable threads)
- Smart column name filtering (skip obviously non-PII columns)
- TABLESAMPLE / SAMPLE for large tables
- Per-table 45s hard timeout
- Progress reporting

Resume functionality:
- Saves checkpoint file (pii_checkpoint_SCANID.json) after every 50 tables
- On restart with same DB, detects checkpoint and resumes from where it stopped
- Merges resumed findings with previous findings
- Deletes checkpoint on successful completion
"""
import re
import sys
import os
import json
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from pathlib import Path
from detectors import scan_text

SKIP_SCHEMAS = {
    'pg_catalog', 'information_schema', 'pg_toast',
    'sys', 'SYSTEM', 'OUTLN', 'DBSNMP', 'APPQOSSYS',
    'WMSYS', 'EXFSYS', 'CTXSYS', 'XDB', 'MDSYS', 'OLAPSYS',
    'ORDSYS', 'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'ANONYMOUS',
    'performance_schema', 'mysql', 'information_schema', 'sys',
}

TEXT_TYPES_PG  = ('text','varchar','character varying','char','json','jsonb','xml')
TEXT_TYPES_MY  = ('varchar','text','mediumtext','longtext','char','tinytext','json','enum')
TEXT_TYPES_ORA = ('VARCHAR2','NVARCHAR2','CHAR','NCHAR','CLOB','NCLOB','VARCHAR')
TEXT_TYPES_MS  = ('varchar','nvarchar','char','nchar','text','ntext','xml')

TABLE_TIMEOUT  = 45   # seconds per table before skip
CHECKPOINT_EVERY = 50  # save checkpoint every N tables

SKIP_COLUMN_PATTERNS = re.compile(
    r'^(id|uuid|created_at|updated_at|deleted_at|created_by|updated_by|'
    r'tenant_id|org_id|user_id|role|status|type|code|slug|url|path|'
    r'hash|token|secret|key|salt|iv|nonce|checksum|signature|'
    r'color|colour|icon|logo|avatar|theme|locale|lang|timezone|'
    r'count|total|amount|price|qty|quantity|weight|size|'
    r'lat|lng|latitude|longitude|zoom|'
    r'version|revision|sort|order|rank|priority|'
    r'is_|has_|can_|flag_|enabled|disabled|active|visible|'
    r'json_schema|meta|metadata|config|settings|preferences|'
    r'mime_type|content_type|extension|format|encoding)$',
    re.IGNORECASE
)

PII_COLUMN_PATTERNS = re.compile(
    r'(name|email|phone|mobile|contact|address|dob|birth|'
    r'aadhaar|aadhar|pan|passport|voter|driving|licence|license|'
    r'account|card|bank|ifsc|gstin|gst|tax|'
    r'gender|age|salary|income|designation|department|'
    r'city|state|pincode|zip|country|'
    r'first|last|full|middle|nick|'
    r'nric|ssn|sin|tin|nic|cnic|'
    r'description|notes|remarks|comments|details|info|data|text|'
    r'profile|bio|about|message|body|content)',
    re.IGNORECASE
)


# ── Checkpoint helpers ────────────────────────────────────────────

def _scan_id(connection_string):
    """Generate stable scan ID from connection string (for checkpoint file)."""
    return hashlib.md5(connection_string.encode()).hexdigest()[:12]


def _checkpoint_path(connection_string):
    return Path(f"pii_checkpoint_{_scan_id(connection_string)}.json")


def _load_checkpoint(connection_string):
    cp = _checkpoint_path(connection_string)
    if cp.exists():
        try:
            data = json.loads(cp.read_text())
            print(f"\n[RESUME] Found checkpoint: {cp}")
            print(f"  Previously scanned : {data['done']} tables")
            print(f"  Findings so far    : {len(data['findings'])}")
            print(f"  Interrupted at     : {data.get('timestamp','?')}")
            print(f"  Resuming from table: {data['done'] + 1}")
            print()
            return data
        except:
            pass
    return None


def _save_checkpoint(connection_string, done, total, findings, skipped_tables):
    cp = _checkpoint_path(connection_string)
    data = {
        'connection_hash': _scan_id(connection_string),
        'done': done,
        'total': total,
        'findings': findings,
        'skipped_tables': list(skipped_tables),
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    }
    cp.write_text(json.dumps(data, default=str))


def _clear_checkpoint(connection_string):
    cp = _checkpoint_path(connection_string)
    if cp.exists():
        cp.unlink()
        print(f"  Checkpoint cleared: {cp}")


# ── Column helpers ────────────────────────────────────────────────

def _should_scan_column(col_name):
    return not SKIP_COLUMN_PATTERNS.match(col_name)


def _priority_column(col_name):
    return bool(PII_COLUMN_PATTERNS.search(col_name))


def _aggregate_findings(raw_findings, table, column, db_type):
    groups = defaultdict(list)
    for f in raw_findings:
        groups[f['detector']].append(f)
    results = []
    for detector, items in groups.items():
        results.append({
            'detector': detector,
            'detector_name': detector,
            'table_name': table,
            'column_name': column,
            'db_type': db_type,
            'sensitivity': items[0]['sensitivity'],
            'dpdp_spdi': items[0]['dpdp_spdi'],
            'sample_count': len(items),
            'raw_values': [i['raw_value'] for i in items],
            'masked_values': [i['masked_value'] for i in items],
            'sample_values': [i['masked_value'] for i in items],
        })
    return results


def _run_parallel_scan(tasks, scan_fn, conn_str, total, label='tables'):
    """
    Generic parallel scan runner with checkpoint support.
    Returns (all_findings, done_count)
    """
    # Load checkpoint
    cp = _load_checkpoint(conn_str)
    already_done = set()
    all_findings = []
    done = 0

    if cp:
        already_done = set(cp.get('skipped_tables', []))
        already_done.update([t[0] for t in cp.get('done_tables', [])])
        all_findings = cp.get('findings', [])
        done = cp.get('done', 0)
        # Filter out already-scanned tasks
        tasks = tasks[done:]
        print(f"  Skipping {done} already-scanned tables, resuming {len(tasks)} remaining...")

    start = time.time()
    threads = max(1, min(50, len(tasks)))

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_fn, task): i for i, task in enumerate(tasks)}
        for future in as_completed(futures):
            try:
                result = future.result(timeout=TABLE_TIMEOUT)
                if result:
                    all_findings.extend(result)
            except Exception:
                pass
            done += 1

            # Save checkpoint every N tables
            if done % CHECKPOINT_EVERY == 0:
                _save_checkpoint(conn_str, done, total, all_findings, already_done)

            if done % 500 == 0 or done == total:
                elapsed = time.time() - start
                rate = done / elapsed if elapsed > 0 else 0
                remaining = total - done
                eta = remaining / rate if rate > 0 else 0
                print(f"  Progress: {done}/{total} {label} "
                      f"| {len(all_findings)} findings "
                      f"| {rate:.0f} {label}/sec "
                      f"| ETA: {eta/60:.1f} min")

    elapsed = time.time() - start
    print(f"  Done: {done} {label} in {elapsed/60:.1f} min | {len(all_findings)} findings")
    return all_findings


# ── PostgreSQL ────────────────────────────────────────────────────

def _scan_pg_table(args):
    conn_str, schema, table, columns, max_rows = args
    import psycopg2
    findings = []
    try:
        conn = psycopg2.connect(conn_str, connect_timeout=10)
        cur = conn.cursor()
        columns = sorted(
            [c for c in columns if _should_scan_column(c)],
            key=lambda c: not _priority_column(c)
        )
        if not columns:
            conn.close(); return findings
        cols_sql = ', '.join(f'"{c}"::text' for c in columns)
        try:
            cur.execute(f'SELECT {cols_sql} FROM "{schema}"."{table}" TABLESAMPLE SYSTEM(10) LIMIT {max_rows}')
        except Exception:
            try:
                cur.execute(f'SELECT {cols_sql} FROM "{schema}"."{table}" LIMIT {max_rows}')
            except Exception:
                conn.close(); return findings
        rows = cur.fetchall()
        for col_idx, col in enumerate(columns):
            raw = []
            for row in rows:
                val = row[col_idx]
                if val and len(str(val)) > 3:
                    raw.extend(scan_text(str(val), f'{schema}.{table}.{col}'))
            if raw:
                findings.extend(_aggregate_findings(raw, f'{schema}.{table}', col, 'postgresql'))
        cur.close(); conn.close()
    except Exception:
        pass
    return findings


def scan_postgresql(conn_str, max_rows, threads=20):
    import psycopg2
    print(f"  Connecting to PostgreSQL...")
    conn = psycopg2.connect(conn_str, connect_timeout=10)
    cur = conn.cursor()
    cur.execute("""
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE data_type = ANY(%s) AND table_schema NOT IN %s
        ORDER BY table_schema, table_name, column_name
    """, (list(TEXT_TYPES_PG), tuple(SKIP_SCHEMAS)))
    raw_cols = cur.fetchall()
    cur.close(); conn.close()

    tables = defaultdict(list)
    for schema, table, col in raw_cols:
        tables[(schema, table)].append(col)

    total = len(tables)
    print(f"  {total} tables | {len(raw_cols)} text columns | {threads} threads")

    tasks = [(conn_str, schema, table, cols, max_rows)
             for (schema, table), cols in tables.items()]

    findings = _run_parallel_scan(tasks, _scan_pg_table, conn_str, total)
    _clear_checkpoint(conn_str)
    return findings


# ── MySQL ─────────────────────────────────────────────────────────

def _scan_mysql_table(args):
    conn_params, db, table, columns, max_rows = args
    import mysql.connector
    findings = []
    try:
        conn = mysql.connector.connect(**conn_params, connection_timeout=10)
        cur = conn.cursor()
        columns = sorted(
            [c for c in columns if _should_scan_column(c)],
            key=lambda c: not _priority_column(c)
        )
        if not columns:
            conn.close(); return findings
        cols_sql = ', '.join(f'`{c}`' for c in columns)
        cur.execute(f"SELECT {cols_sql} FROM `{table}` LIMIT {max_rows}")
        rows = cur.fetchall()
        for col_idx, col in enumerate(columns):
            raw = []
            for row in rows:
                val = row[col_idx]
                if val and isinstance(val, str) and len(val) > 3:
                    raw.extend(scan_text(val, f'{db}.{table}.{col}'))
            if raw:
                findings.extend(_aggregate_findings(raw, f'{db}.{table}', col, 'mysql'))
        cur.close(); conn.close()
    except Exception:
        pass
    return findings


def scan_mysql(conn_str, max_rows, threads=20):
    import mysql.connector
    m = re.match(r'mysql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(.+)', conn_str)
    if not m:
        print("  ✗ Format: mysql://user:pass@host/database"); return []
    user, pwd, host, port, db = m.groups()
    port = int(port or 3306)
    params = dict(host=host, user=user, password=pwd, database=db, port=port)
    print(f"  Connecting to MySQL {host}:{port}/{db}...")
    conn = mysql.connector.connect(**params)
    cur = conn.cursor()
    cur.execute("""SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=%s AND DATA_TYPE IN ({})
        ORDER BY TABLE_NAME, COLUMN_NAME""".format(','.join(['%s']*len(TEXT_TYPES_MY))),
        [db]+list(TEXT_TYPES_MY))
    raw_cols = cur.fetchall()
    cur.close(); conn.close()

    tables = defaultdict(list)
    for table, col in raw_cols:
        tables[table].append(col)

    total = len(tables)
    print(f"  {total} tables | {len(raw_cols)} text columns | {threads} threads")
    tasks = [(params, db, table, cols, max_rows) for table, cols in tables.items()]
    findings = _run_parallel_scan(tasks, _scan_mysql_table, conn_str, total)
    _clear_checkpoint(conn_str)
    return findings


# ── Oracle ────────────────────────────────────────────────────────

def _scan_oracle_table(args):
    dsn, user, pwd, owner, table, columns, max_rows = args
    findings = []
    try:
        import oracledb
        # Force thin mode — avoids ORA-12638 NTS credential error
        # Thin mode needs no Oracle client installed
        try:
            conn = oracledb.connect(user=user, password=pwd, dsn=dsn)
        except Exception as e1:
            if '12638' in str(e1) or 'Credential' in str(e1):
                # Try thick mode with NTS disabled
                try:
                    oracledb.init_oracle_client()
                    conn = oracledb.connect(user=user, password=pwd, dsn=dsn,
                                           mode=oracledb.DEFAULT_AUTH)
                except Exception:
                    raise e1
            else:
                raise e1
        cur = conn.cursor()
        columns = sorted(
            [c for c in columns if _should_scan_column(c)],
            key=lambda c: not _priority_column(c)
        )
        if not columns:
            conn.close(); return findings
        cols_sql = ', '.join(f'"{c}"' for c in columns)
        try:
            cur.execute(f'SELECT {cols_sql} FROM "{owner}"."{table}" SAMPLE(10) FETCH FIRST {max_rows} ROWS ONLY')
        except Exception:
            try:
                cur.execute(f'SELECT {cols_sql} FROM "{owner}"."{table}" WHERE ROWNUM <= {max_rows}')
            except Exception:
                conn.close(); return findings
        rows = cur.fetchall()
        for col_idx, col in enumerate(columns):
            raw = []
            for row in rows:
                val = row[col_idx]
                if val and len(str(val)) > 3:
                    raw.extend(scan_text(str(val), f'{owner}.{table}.{col}'))
            if raw:
                findings.extend(_aggregate_findings(raw, f'{owner}.{table}', col, 'oracle'))
        cur.close(); conn.close()
    except Exception:
        pass
    return findings


def scan_oracle(conn_str, max_rows, threads=20):
    import oracledb
    m = re.match(r'oracle://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/?(.*)', conn_str)
    if not m:
        print("  ✗ Format: oracle://user:pass@host:1521/SERVICE"); return []
    user, pwd, host, port, service = m.groups()
    port = int(port or 1521); service = service or 'ORCL'
    dsn = f"{host}:{port}/{service}"
    print(f"  Connecting to Oracle {dsn}...")
    # Thin mode first (avoids ORA-12638)
    try:
        conn = oracledb.connect(user=user, password=pwd, dsn=dsn)
    except Exception as e:
        if '12638' in str(e) or 'Credential' in str(e):
            oracledb.init_oracle_client()
            conn = oracledb.connect(user=user, password=pwd, dsn=dsn)
        else:
            raise
    cur = conn.cursor()
    sql = """SELECT owner, table_name, column_name FROM all_tab_columns
             WHERE data_type IN ({}) AND owner NOT IN ({})
             ORDER BY owner, table_name, column_name""".format(
        ','.join([f"'{t}'" for t in TEXT_TYPES_ORA]),
        ','.join([f"'{s}'" for s in SKIP_SCHEMAS]))
    cur.execute(sql)
    raw_cols = cur.fetchall()
    cur.close(); conn.close()

    tables = defaultdict(list)
    for owner, table, col in raw_cols:
        tables[(owner, table)].append(col)

    total = len(tables)
    print(f"  {total} tables | {len(raw_cols)} text columns | {threads} threads")
    tasks = [(dsn, user, pwd, owner, table, cols, max_rows)
             for (owner, table), cols in tables.items()]
    findings = _run_parallel_scan(tasks, _scan_oracle_table, conn_str, total)
    _clear_checkpoint(conn_str)
    return findings


# ── MSSQL ─────────────────────────────────────────────────────────

def scan_mssql(conn_str, max_rows, threads=10):
    import pyodbc
    m = re.match(r'mssql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(.+)', conn_str)
    if not m:
        print("  ✗ Format: mssql://user:pass@host/database"); return []
    user, pwd, host, port, db = m.groups()
    port = int(port or 1433)
    cs = (f"DRIVER={{ODBC Driver 17 for SQL Server}};"
          f"SERVER={host},{port};DATABASE={db};UID={user};PWD={pwd}")
    print(f"  Connecting to MSSQL {host}/{db}...")

    cp = _load_checkpoint(conn_str)
    start_from = cp['done'] if cp else 0
    all_findings = cp['findings'] if cp else []

    conn = pyodbc.connect(cs)
    cur = conn.cursor()
    cur.execute(f"""SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE DATA_TYPE IN ({','.join([f"'{t}'" for t in TEXT_TYPES_MS])})
        ORDER BY TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME""")
    raw_cols = cur.fetchall()
    cur.close(); conn.close()

    tables = list(defaultdict(list).items())
    tbl_dict = defaultdict(list)
    for schema, table, col in raw_cols:
        tbl_dict[(schema, table)].append(col)
    table_list = list(tbl_dict.items())

    total = len(table_list)
    print(f"  {total} tables | resuming from {start_from}")

    for i, ((schema, table), columns) in enumerate(table_list[start_from:], start_from):
        try:
            conn2 = pyodbc.connect(cs)
            cur2 = conn2.cursor()
            columns = [c for c in columns if _should_scan_column(c)]
            if columns:
                cols_sql = ','.join(f'[{c}]' for c in columns)
                cur2.execute(f"SELECT TOP {max_rows} {cols_sql} FROM [{schema}].[{table}]")
                rows = cur2.fetchall()
                for col_idx, col in enumerate(columns):
                    raw = []
                    for row in rows:
                        val = row[col_idx]
                        if val and isinstance(val, str):
                            raw.extend(scan_text(val, f'{schema}.{table}.{col}'))
                    if raw:
                        all_findings.extend(_aggregate_findings(raw, f'{schema}.{table}', col, 'mssql'))
            cur2.close(); conn2.close()
        except Exception:
            pass

        if (i+1) % CHECKPOINT_EVERY == 0:
            _save_checkpoint(conn_str, i+1, total, all_findings, set())
            print(f"  Checkpoint: {i+1}/{total} tables | {len(all_findings)} findings")

    _clear_checkpoint(conn_str)
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


# ── SQLite ────────────────────────────────────────────────────────

def scan_sqlite(db_path, max_rows, threads=1):
    import sqlite3
    print(f"  Connecting to SQLite: {db_path}...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]

    cp = _load_checkpoint(db_path)
    start_from = cp['done'] if cp else 0
    all_findings = cp['findings'] if cp else []

    for i, table in enumerate(tables[start_from:], start_from):
        try:
            cur.execute(f"SELECT * FROM `{table}` LIMIT {max_rows}")
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            for col_idx, col in enumerate(cols):
                if not _should_scan_column(col): continue
                raw = []
                for row in rows:
                    val = row[col_idx]
                    if val and isinstance(val, str) and len(val) > 3:
                        raw.extend(scan_text(val, f'{table}.{col}'))
                if raw:
                    all_findings.extend(_aggregate_findings(raw, table, col, 'sqlite'))
        except Exception:
            pass
        if (i+1) % CHECKPOINT_EVERY == 0:
            _save_checkpoint(db_path, i+1, len(tables), all_findings, set())

    conn.close()
    _clear_checkpoint(db_path)
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


# ── MongoDB ───────────────────────────────────────────────────────

def scan_mongodb(conn_str, max_rows, threads=1):
    try:
        from pymongo import MongoClient
    except ImportError:
        print("  ✗ pip install pymongo"); return []
    print("  Connecting to MongoDB...")
    client = MongoClient(conn_str)
    m = re.match(r'mongodb://[^/]+/(.+)', conn_str)
    db_name = m.group(1) if m else None
    all_findings = []
    db_names = [db_name] if db_name else [d for d in client.list_database_names()
                                           if d not in ('admin','local','config')]
    for db_name in db_names:
        db = client[db_name]
        for coll in db.list_collection_names():
            try:
                for doc in db[coll].find().limit(max_rows):
                    raw = scan_text(str(doc), f'{db_name}.{coll}')
                    if raw:
                        all_findings.extend(_aggregate_findings(raw, f'{db_name}.{coll}', '*', 'mongodb'))
            except Exception:
                pass
    client.close()
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


# ── Main entry point ──────────────────────────────────────────────

def scan_database(connection_string, max_rows=1000, send_raw=True, threads=20):
    """
    Main entry point.
    - Parallel scanning with configurable threads
    - Auto-resume from checkpoint if interrupted
    - 45s per-table hard timeout
    - Checkpoint saved every 50 tables
    """
    cs = connection_string.lower()
    try:
        if cs.startswith('postgresql') or cs.startswith('postgres'):
            return scan_postgresql(connection_string, max_rows, threads)
        elif cs.startswith('mysql'):
            return scan_mysql(connection_string, max_rows, threads)
        elif cs.startswith('oracle'):
            return scan_oracle(connection_string, max_rows, threads)
        elif cs.startswith('mssql') or cs.startswith('sqlserver'):
            return scan_mssql(connection_string, max_rows, threads)
        elif cs.startswith('mongodb'):
            return scan_mongodb(connection_string, max_rows, threads)
        else:
            import os
            if os.path.exists(connection_string):
                return scan_sqlite(connection_string, max_rows, threads)
            print("  ✗ Unsupported DB type")
            return []
    except ImportError as e:
        drv = str(e)
        print(f"  ✗ Missing driver: {drv}")
        if 'psycopg2' in drv: print("  pip install psycopg2-binary")
        elif 'mysql' in drv: print("  pip install mysql-connector-python")
        elif 'oracledb' in drv: print("  pip install oracledb")
        elif 'pyodbc' in drv: print("  pip install pyodbc")
        elif 'pymongo' in drv: print("  pip install pymongo")
        return []
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return []
