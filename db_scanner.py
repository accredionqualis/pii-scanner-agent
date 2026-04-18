import re
from detectors import scan_text

class DBScanner:
    def __init__(self, config, api_client=None):
        self.config = config
        self.api_client = api_client

    def get_connection(self):
        db_type = self.config.get('type','mysql').lower()
        host = self.config.get('host','localhost')
        port = self.config.get('port')
        database = self.config.get('database','')
        username = self.config.get('username','')
        password = self.config.get('password','')

        if db_type == 'mysql':
            import pymysql
            port = port or 3306
            return pymysql.connect(host=host,port=int(port),user=username,password=password,database=database,connect_timeout=10), 'mysql'
        elif db_type == 'postgresql':
            import psycopg2
            port = port or 5432
            return psycopg2.connect(host=host,port=int(port),user=username,password=password,dbname=database,connect_timeout=10), 'pg'
        elif db_type == 'mssql':
            import pyodbc
            port = port or 1433
            conn_str = f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={host},{port};DATABASE={database};UID={username};PWD={password}'
            return pyodbc.connect(conn_str,timeout=10), 'mssql'
        elif db_type == 'sqlite':
            import sqlite3
            return sqlite3.connect(database), 'sqlite'
        elif db_type == 'oracle':
            import oracledb
            oracledb.init_oracle_client()
            port = port or 1521
            dsn = f'{host}:{port}/{database}'
            return oracledb.connect(user=username,password=password,dsn=dsn), 'oracle'
        raise ValueError(f'Unsupported DB type: {db_type}')

    def get_tables(self, conn, db_type, database):
        cur = conn.cursor()
        if db_type in ('mysql',):
            cur.execute("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s", (database,))
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
            cur.execute("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s", (database, table))
        elif db_type == 'pg':
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=%s", (table,))
        elif db_type in ('mssql','sqlite'):
            cur.execute(f"SELECT name FROM pragma_table_info('{table}')" if db_type=='sqlite' else f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{table}'")
        elif db_type == 'oracle':
            cur.execute(f"SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{table.upper()}'")
        return [r[0] for r in cur.fetchall()]

    def scan(self, progress_cb=None):
        findings = []
        try:
            conn, db_type = self.get_connection()
            database = self.config.get('database','')
            tables = self.get_tables(conn, db_type, database)
            total = len(tables)
            for i, table in enumerate(tables):
                if progress_cb:
                    progress_cb(f"Scanning {table} ({i+1}/{total})")
                try:
                    cols = self.get_columns(conn, db_type, database, table)
                    cur = conn.cursor()
                    if db_type == 'oracle':
                        cur.execute(f'SELECT * FROM "{table}" WHERE ROWNUM <= 100')
                    elif db_type == 'mssql':
                        cur.execute(f'SELECT TOP 100 * FROM [{table}]')
                    else:
                        cur.execute(f'SELECT * FROM `{table}` LIMIT 100' if db_type=='mysql' else f'SELECT * FROM "{table}" LIMIT 100')
                    rows = cur.fetchall()
                    for col_idx, col_name in enumerate(cols):
                        col_text = ' '.join(str(r[col_idx]) for r in rows if r[col_idx] is not None)
                        col_findings = scan_text(col_text)
                        for f in col_findings:
                            findings.append({
                                'detector': f['detector'],
                                'table_name': table,
                                'column_name': col_name,
                                'sample_count': f['sample_count'],
                                'sensitivity': f['sensitivity'],
                                'is_dpdp_spdi': f['dpdp_spdi'],
                            })
                except Exception as e:
                    pass
            conn.close()
        except Exception as e:
            raise Exception(f"DB connection failed: {e}")
        return findings

if __name__ == '__main__':
    import sqlite3, tempfile, os
    # Create test DB
    db = tempfile.mktemp(suffix='.db')
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE users (id INTEGER, name TEXT, email TEXT, phone TEXT, pan TEXT)')
    conn.execute("INSERT INTO users VALUES (1,'Rahul Kumar','rahul@test.com','9876543210','ABCPD1234F')")
    conn.commit()
    conn.close()
    scanner = DBScanner({'type':'sqlite','database':db})
    results = scanner.scan(print)
    for r in results:
        print(f"  {r['table_name']}.{r['column_name']}: {r['detector']} ({r['sensitivity']})")
    os.unlink(db)
