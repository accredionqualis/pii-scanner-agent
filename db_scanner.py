"""
KnightGuard GRC — Database Scanner v2.0
Supports: PostgreSQL, MySQL/MariaDB, Oracle, MSSQL, SQLite, MongoDB
Sends full raw PII values (feature #7).
"""
import re
import sys
from detectors import scan_text


SKIP_SCHEMAS = {
    'pg_catalog', 'information_schema', 'pg_toast',
    'sys', 'SYSTEM', 'OUTLN', 'DBSNMP', 'APPQOSSYS',
    'WMSYS', 'EXFSYS', 'CTXSYS', 'XDB', 'MDSYS', 'OLAPSYS',
    'ORDSYS', 'ORDPLUGINS', 'SI_INFORMTN_SCHEMA', 'ANONYMOUS',
    'performance_schema', 'mysql', 'information_schema', 'sys',
}

TEXT_TYPES_PG = ('text', 'varchar', 'character varying', 'char', 'json', 'jsonb', 'xml')
TEXT_TYPES_MY = ('varchar', 'text', 'mediumtext', 'longtext', 'char', 'tinytext', 'json', 'enum')
TEXT_TYPES_ORA = ('VARCHAR2', 'NVARCHAR2', 'CHAR', 'NCHAR', 'CLOB', 'NCLOB', 'VARCHAR')
TEXT_TYPES_MS = ('varchar', 'nvarchar', 'char', 'nchar', 'text', 'ntext', 'xml')


def _aggregate_findings(raw_findings, table, column, db_type):
    """Group raw findings by detector+table+column, collecting all values."""
    from collections import defaultdict
    groups = defaultdict(list)
    for f in raw_findings:
        key = (f['detector'], table, column)
        groups[key].append(f)

    results = []
    for (detector, tbl, col), items in groups.items():
        results.append({
            'detector': detector,
            'detector_name': detector,
            'table_name': tbl,
            'column_name': col,
            'db_type': db_type,
            'sensitivity': items[0]['sensitivity'],
            'dpdp_spdi': items[0]['dpdp_spdi'],
            'sample_count': len(items),
            # Feature #7: ALL raw values
            'raw_values': [i['raw_value'] for i in items],
            'masked_values': [i['masked_value'] for i in items],
            'sample_values': [i['masked_value'] for i in items],  # backward compat
        })
    return results


def scan_postgresql(conn_str, max_rows):
    import psycopg2
    print(f"  Connecting to PostgreSQL...")
    conn = psycopg2.connect(conn_str)
    cur = conn.cursor()

    cur.execute("""
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE data_type = ANY(%s)
        AND table_schema NOT IN %s
        ORDER BY table_schema, table_name, column_name
    """, (list(TEXT_TYPES_PG), tuple(SKIP_SCHEMAS)))
    columns = cur.fetchall()
    print(f"  Connected. Scanning {len(columns)} text columns...")

    all_findings = []
    scanned = 0
    for schema, table, col in columns:
        try:
            cur.execute(f'SELECT "{col}" FROM "{schema}"."{table}" LIMIT {max_rows}')
            rows = cur.fetchall()
            raw = []
            for row in rows:
                if row[0]:
                    raw.extend(scan_text(str(row[0]), f'{schema}.{table}.{col}'))
            if raw:
                all_findings.extend(_aggregate_findings(raw, f'{schema}.{table}', col, 'postgresql'))
            scanned += 1
            if scanned % 50 == 0:
                print(f"  Scanned {scanned}/{len(columns)} columns, {len(all_findings)} findings...")
        except Exception:
            pass

    cur.close(); conn.close()
    print(f"  Done: {scanned} columns, {len(all_findings)} findings")
    return all_findings


def scan_mysql(conn_str, max_rows):
    import mysql.connector
    m = re.match(r'mysql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(.+)', conn_str)
    if not m:
        print("  ✗ Format: mysql://user:pass@host/database")
        return []
    user, pwd, host, port, db = m.groups()
    port = int(port or 3306)
    print(f"  Connecting to MySQL {host}:{port}/{db}...")
    conn = mysql.connector.connect(host=host, user=user, password=pwd, database=db, port=port)
    cur = conn.cursor()

    cur.execute("""
        SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s AND DATA_TYPE IN ({})
        ORDER BY TABLE_NAME, COLUMN_NAME
    """.format(','.join(['%s'] * len(TEXT_TYPES_MY))), [db] + list(TEXT_TYPES_MY))
    columns = cur.fetchall()
    print(f"  Connected. Scanning {len(columns)} text columns...")

    all_findings = []
    for table, col in columns:
        try:
            cur.execute(f"SELECT `{col}` FROM `{table}` LIMIT {max_rows}")
            raw = []
            for (val,) in cur.fetchall():
                if val:
                    raw.extend(scan_text(str(val), f'{db}.{table}.{col}'))
            if raw:
                all_findings.extend(_aggregate_findings(raw, f'{db}.{table}', col, 'mysql'))
        except Exception:
            pass

    cur.close(); conn.close()
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


def scan_oracle(conn_str, max_rows):
    import oracledb
    m = re.match(r'oracle://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/?(.*)', conn_str)
    if not m:
        print("  ✗ Format: oracle://user:pass@host:1521/SERVICE")
        return []
    user, pwd, host, port, service = m.groups()
    port = int(port or 1521)
    service = service or 'ORCL'
    print(f"  Connecting to Oracle {host}:{port}/{service}...")

    try:
        oracledb.init_oracle_client()
    except Exception:
        pass  # thin mode fallback

    conn = oracledb.connect(user=user, password=pwd, dsn=f"{host}:{port}/{service}")
    cur = conn.cursor()

    sql = """SELECT owner, table_name, column_name FROM all_tab_columns
             WHERE data_type IN ({})
             AND owner NOT IN ({})
             ORDER BY owner, table_name, column_name""".format(
        ','.join([f"'{t}'" for t in TEXT_TYPES_ORA]),
        ','.join([f"'{s}'" for s in SKIP_SCHEMAS])
    )
    cur.execute(sql)
    columns = cur.fetchall()
    print(f"  Connected. Scanning {len(columns)} text columns...")

    all_findings = []
    scanned = 0
    for owner, table, col in columns:
        try:
            cur.execute(f'SELECT "{col}" FROM "{owner}"."{table}" WHERE ROWNUM <= {max_rows}')
            raw = []
            for (val,) in cur.fetchall():
                if val:
                    raw.extend(scan_text(str(val), f'{owner}.{table}.{col}'))
            if raw:
                all_findings.extend(_aggregate_findings(raw, f'{owner}.{table}', col, 'oracle'))
            scanned += 1
            if scanned % 50 == 0:
                print(f"  Scanned {scanned}/{len(columns)} columns, {len(all_findings)} findings...")
        except Exception:
            pass

    cur.close(); conn.close()
    print(f"  Done: {scanned} columns, {len(all_findings)} findings")
    return all_findings


def scan_mssql(conn_str, max_rows):
    import pyodbc
    m = re.match(r'mssql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(.+)', conn_str)
    if not m:
        print("  ✗ Format: mssql://user:pass@host/database")
        return []
    user, pwd, host, port, db = m.groups()
    port = int(port or 1433)
    print(f"  Connecting to MSSQL {host}:{port}/{db}...")
    conn = pyodbc.connect(
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={host},{port};DATABASE={db};UID={user};PWD={pwd}"
    )
    cur = conn.cursor()

    cur.execute("""
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE DATA_TYPE IN ({})
        ORDER BY TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME
    """.format(','.join([f"'{t}'" for t in TEXT_TYPES_MS])))
    columns = cur.fetchall()
    print(f"  Connected. Scanning {len(columns)} text columns...")

    all_findings = []
    for schema, table, col in columns:
        try:
            cur.execute(f"SELECT TOP {max_rows} [{col}] FROM [{schema}].[{table}]")
            raw = []
            for (val,) in cur.fetchall():
                if val:
                    raw.extend(scan_text(str(val), f'{schema}.{table}.{col}'))
            if raw:
                all_findings.extend(_aggregate_findings(raw, f'{schema}.{table}', col, 'mssql'))
        except Exception:
            pass

    cur.close(); conn.close()
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


def scan_sqlite(db_path, max_rows):
    import sqlite3
    print(f"  Connecting to SQLite: {db_path}...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    print(f"  Connected. Found {len(tables)} tables...")

    all_findings = []
    for table in tables:
        try:
            cur.execute(f"SELECT * FROM `{table}` LIMIT {max_rows}")
            cols = [d[0] for d in cur.description]
            raw = []
            for row in cur.fetchall():
                for i, val in enumerate(row):
                    if val and isinstance(val, str):
                        raw.extend(scan_text(val, f'{table}.{cols[i]}'))
            if raw:
                all_findings.extend(_aggregate_findings(raw, table, '*', 'sqlite'))
        except Exception:
            pass

    conn.close()
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


def scan_mongodb(conn_str, max_rows):
    try:
        from pymongo import MongoClient
    except ImportError:
        print("  ✗ pymongo not installed. Run: pip install pymongo")
        return []

    print(f"  Connecting to MongoDB...")
    m = re.match(r'mongodb://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/?(.*)', conn_str)
    if m:
        user, pwd, host, port, db_name = m.groups()
        client = MongoClient(conn_str)
    else:
        client = MongoClient(conn_str)
        db_name = None

    all_findings = []
    db_names = [db_name] if db_name else client.list_database_names()

    for db_name in db_names:
        if db_name in ('admin', 'local', 'config'):
            continue
        db = client[db_name]
        for coll_name in db.list_collection_names():
            try:
                for doc in db[coll_name].find().limit(max_rows):
                    text = str(doc)
                    raw = scan_text(text, f'{db_name}.{coll_name}')
                    if raw:
                        all_findings.extend(_aggregate_findings(raw, f'{db_name}.{coll_name}', '*', 'mongodb'))
            except Exception:
                pass

    client.close()
    print(f"  Done: {len(all_findings)} findings")
    return all_findings


def scan_database(connection_string, max_rows=1000, send_raw=True):
    """Main entry point — detects DB type from connection string."""
    cs = connection_string.lower()

    try:
        if cs.startswith('postgresql') or cs.startswith('postgres'):
            return scan_postgresql(connection_string, max_rows)
        elif cs.startswith('mysql'):
            return scan_mysql(connection_string, max_rows)
        elif cs.startswith('oracle'):
            return scan_oracle(connection_string, max_rows)
        elif cs.startswith('mssql') or cs.startswith('sqlserver'):
            return scan_mssql(connection_string, max_rows)
        elif cs.startswith('mongodb'):
            return scan_mongodb(connection_string, max_rows)
        elif cs.endswith('.db') or cs.endswith('.sqlite') or cs.endswith('.sqlite3'):
            return scan_sqlite(connection_string, max_rows)
        else:
            import os
            if os.path.exists(connection_string):
                return scan_sqlite(connection_string, max_rows)
            print(f"  ✗ Unsupported DB type. Supported: postgresql, mysql, oracle, mssql, mongodb, sqlite")
            print(f"  Examples:")
            print(f"    postgresql://user:pass@host/dbname")
            print(f"    mysql://user:pass@host/dbname")
            print(f"    oracle://user:pass@host:1521/ORCL")
            print(f"    mssql://user:pass@host/dbname")
            print(f"    mongodb://user:pass@host/dbname")
            print(f"    /path/to/file.db")
            return []
    except ImportError as e:
        drv = str(e)
        print(f"  ✗ Missing driver: {drv}")
        if 'psycopg2' in drv: print("  Install: pip install psycopg2-binary")
        elif 'mysql' in drv: print("  Install: pip install mysql-connector-python")
        elif 'oracledb' in drv: print("  Install: pip install oracledb")
        elif 'pyodbc' in drv: print("  Install: pip install pyodbc")
        elif 'pymongo' in drv: print("  Install: pip install pymongo")
        return []
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        return []
