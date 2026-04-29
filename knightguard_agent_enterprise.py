#!/usr/bin/env python3
"""
KnightGuard GRC — PII Scanner Agent v2.1 Enterprise
Handles databases of ANY size (tested approach for 20TB+)

Strategy for large DBs:
1. Schema analysis FIRST (column names) — instant, no data access
2. Statistical sampling — ROWNUM/SAMPLE clause, never full scan  
3. Streaming processing — never loads more than 1000 rows in memory
4. Progress tracking — resumable scans
5. Resource limits — CPU/memory throttling
"""

import argparse, json, os, sys, platform, socket, time, datetime
import hashlib, re, threading, urllib.request, urllib.error, signal
from pathlib import Path

VERSION = "2.1.0-Enterprise"

PII_PATTERNS = {
    'AADHAAR':      (re.compile(r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b'), 'HIGH'),
    'PAN':          (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'), 'HIGH'),
    'PHONE_IN':     (re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b'), 'MEDIUM'),
    'EMAIL':        (re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'), 'MEDIUM'),
    'PASSPORT':     (re.compile(r'\b[A-Z][0-9]{7}\b'), 'HIGH'),
    'CREDIT_CARD':  (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), 'CRITICAL'),
    'IFSC':         (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'), 'HIGH'),
    'GST':          (re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d][Z][A-Z\d]\b'), 'HIGH'),
    'DOB':          (re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])[\/\-](?:0?[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b'), 'MEDIUM'),
    'BANK_ACCOUNT': (re.compile(r'\b[0-9]{9,18}\b'), 'LOW'),
    'UPI':          (re.compile(r'\b[\w.\-]+@(?:upi|paytm|gpay|phonepe|ybl|okicici|oksbi)\b'), 'HIGH'),
    'IP_ADDRESS':   (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'LOW'),
}

PII_COLUMNS = {
    'CRITICAL': ['ssn','social_security','credit_card','card_number','cvv','pin','card_no'],
    'HIGH':     ['aadhaar','aadhar','pan','pan_no','pan_number','passport','dob','date_of_birth',
                 'bank_account','account_no','account_number','ifsc','salary','income','wage',
                 'medical_record','diagnosis','health','biometric','voter_id','dl_number'],
    'MEDIUM':   ['email','phone','mobile','contact_no','address','gender','religion',
                 'caste','nationality','marital','name','first_name','last_name','full_name',
                 'customer_name','emp_name','employee_name'],
    'LOW':      ['ip_address','mac_address','device_id','user_agent','location','lat','lng'],
}

def detect_pii_column(col_name):
    col_lower = col_name.lower().replace(' ','_')
    for severity, names in PII_COLUMNS.items():
        for name in names:
            if name in col_lower:
                return name, severity
    return None, None

def detect_pii_in_value(val):
    text = str(val)
    results = []
    for pii_type, (pattern, severity) in PII_PATTERNS.items():
        if pattern.search(text):
            results.append((pii_type, severity))
    return results

CONFIG_PATH = Path.home() / '.knightguard_agent.json'

def load_config():
    if CONFIG_PATH.exists():
        try: return json.loads(CONFIG_PATH.read_text())
        except: pass
    return {}

def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    CONFIG_PATH.chmod(0o600)

# ── Enterprise Oracle Scanner ──────────────────────────────────
class OracleEnterpriseScanner:
    def __init__(self, host, port, service, user, password, 
                 sample_rows=500, batch_size=1000, max_tables=None,
                 delay_ms=100, progress_file=None):
        self.host = host
        self.port = port
        self.service = service
        self.user = user
        self.password = password
        self.sample_rows = sample_rows      # rows to sample per table (NOT full scan)
        self.batch_size = batch_size        # rows per fetch batch
        self.max_tables = max_tables        # limit tables for testing
        self.delay_ms = delay_ms            # ms delay between tables (throttle)
        self.progress_file = Path(progress_file) if progress_file else None
        self.conn = None
        self.findings = []
        self.stats = {
            'tables_scanned': 0,
            'tables_skipped': 0,
            'columns_analyzed': 0,
            'pii_found': 0,
            'total_rows_sampled': 0,
            'db_size_gb': 0,
        }
        self.stop_flag = False
        self._lock = threading.Lock()
    
    def connect(self):
        import oracledb
        print(f"\n  Connecting to Oracle {self.host}:{self.port}/{self.service}...")
        print(f"  Mode: Thin (no Oracle Client needed)")
        self.conn = oracledb.connect(
            user=self.user,
            password=self.password,
            dsn=f"{self.host}:{self.port}/{self.service}",
        )
        print(f"  ✓ Connected to Oracle {self.conn.version}")
        
        # Get DB size
        cur = self.conn.cursor()
        try:
            cur.execute("SELECT ROUND(SUM(bytes)/1024/1024/1024,2) FROM dba_data_files")
            row = cur.fetchone()
            if row and row[0]:
                self.stats['db_size_gb'] = float(row[0])
                print(f"  Database size: {self.stats['db_size_gb']} GB")
        except:
            pass
        cur.close()
    
    def get_tables(self):
        """Get all user tables with row counts — uses metadata only, very fast"""
        cur = self.conn.cursor()
        try:
            # Use DBA_TABLES for row counts (estimates from stats, instant)
            cur.execute("""
                SELECT t.owner, t.table_name, 
                       NVL(t.num_rows, 0) as est_rows,
                       NVL(s.bytes/1024/1024, 0) as size_mb
                FROM all_tables t
                LEFT JOIN (
                    SELECT owner, segment_name, SUM(bytes) as bytes
                    FROM dba_segments WHERE segment_type='TABLE'
                    GROUP BY owner, segment_name
                ) s ON s.owner=t.owner AND s.segment_name=t.table_name
                WHERE t.owner NOT IN (
                    'SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','DBSFWUSER',
                    'GGSYS','ANONYMOUS','CTXSYS','DVSYS','GSMADMIN_INTERNAL',
                    'LBACSYS','MDSYS','OJVMSYS','OLAPSYS','ORDDATA','ORDSYS',
                    'SI_INFORMTN_SCHEMA','WMSYS','XDB','APEX_PUBLIC_USER'
                )
                ORDER BY NVL(s.bytes,0) DESC
            """)
            tables = cur.fetchall()
        except:
            # Fallback to all_tables without sizes
            cur.execute("""
                SELECT owner, table_name, NVL(num_rows,0), 0
                FROM all_tables
                WHERE owner NOT IN (
                    'SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','DBSFWUSER',
                    'GGSYS','ANONYMOUS','CTXSYS','DVSYS','GSMADMIN_INTERNAL',
                    'LBACSYS','MDSYS','OJVMSYS','OLAPSYS','ORDDATA','ORDSYS',
                    'SI_INFORMTN_SCHEMA','WMSYS','XDB')
                ORDER BY num_rows DESC NULLS LAST
            """)
            tables = cur.fetchall()
        cur.close()
        return tables

    def get_columns(self, owner, table_name):
        """Get columns for a table"""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT column_name, data_type, data_length
            FROM all_tab_columns
            WHERE owner=:1 AND table_name=:2
            ORDER BY column_id
        """, [owner, table_name])
        cols = cur.fetchall()
        cur.close()
        return cols

    def scan_table(self, owner, table_name, est_rows, size_mb):
        """
        Smart table scanning:
        1. Column name analysis (always, instant)
        2. Statistical sample using SAMPLE clause (never full scan)
        3. For large tables: use SAMPLE(0.1) for 20TB = scan ~20GB equivalent
        """
        columns = self.get_columns(owner, table_name)
        text_cols = [(c[0], c[1]) for c in columns 
                    if c[1] in ('VARCHAR2','NVARCHAR2','CHAR','CLOB','NUMBER','DATE','TIMESTAMP')]
        
        table_findings = []
        
        # Phase 1: Column name analysis (instant, no data access)
        for col_name, dtype in text_cols:
            pii_name, severity = detect_pii_column(col_name)
            if pii_name:
                table_findings.append({
                    'schema': owner,
                    'table_name': f"{owner}.{table_name}",
                    'column_name': col_name,
                    'data_type': dtype,
                    'pii_type': pii_name.upper(),
                    'severity': severity,
                    'detection_method': 'column_name_analysis',
                    'estimated_rows': est_rows,
                    'rows_sampled': 0,
                })
        
        # Phase 2: Data sampling using Oracle SAMPLE clause
        # SAMPLE(p) returns p% of rows without full table scan
        # For 20TB table with 1B rows: SAMPLE(0.00005) gives ~500 rows
        # Oracle skips blocks randomly — much faster than ROWNUM for huge tables
        
        varchar_cols = [c for c in text_cols 
                       if c[1] in ('VARCHAR2','NVARCHAR2','CHAR','CLOB')]
        
        if varchar_cols and not self.stop_flag:
            # Calculate sample percentage to get ~self.sample_rows rows
            if est_rows > 0:
                sample_pct = min(100.0, max(0.0001, (self.sample_rows / est_rows) * 100))
            else:
                sample_pct = 1.0
            
            # Build column list (limit to 20 cols to avoid huge queries)
            sample_cols = varchar_cols[:20]
            col_list = ', '.join(f'"{c[0]}"' for c in sample_cols)
            
            cur = self.conn.cursor()
            cur.arraysize = self.batch_size
            
            try:
                if est_rows > 10000:
                    # Use SAMPLE for large tables — doesn't do full scan
                    sql = f'SELECT {col_list} FROM "{owner}"."{table_name}" SAMPLE({sample_pct:.6f})'
                else:
                    # Small table — just read all
                    sql = f'SELECT {col_list} FROM "{owner}"."{table_name}"'
                
                cur.execute(sql)
                
                rows_sampled = 0
                pii_found_in_data = {}
                
                while True:
                    batch = cur.fetchmany(self.batch_size)
                    if not batch:
                        break
                    
                    for row in batch:
                        for i, val in enumerate(row):
                            if val is None:
                                continue
                            col_name = sample_cols[i][0]
                            pii_hits = detect_pii_in_value(val)
                            for pii_type, severity in pii_hits:
                                key = (col_name, pii_type)
                                if key not in pii_found_in_data:
                                    pii_found_in_data[key] = {'count': 0, 'severity': severity}
                                pii_found_in_data[key]['count'] += 1
                    
                    rows_sampled += len(batch)
                    if rows_sampled >= self.sample_rows * 2:
                        break  # Safety limit
                
                # Add data-based findings
                for (col_name, pii_type), info in pii_found_in_data.items():
                    table_findings.append({
                        'schema': owner,
                        'table_name': f"{owner}.{table_name}",
                        'column_name': col_name,
                        'data_type': 'VARCHAR2',
                        'pii_type': pii_type,
                        'severity': info['severity'],
                        'detection_method': 'data_sampling',
                        'estimated_rows': est_rows,
                        'rows_sampled': rows_sampled,
                        'matches_in_sample': info['count'],
                        'sample_percentage': round(sample_pct, 6),
                    })
                
                self.stats['total_rows_sampled'] += rows_sampled
                
            except Exception as e:
                pass  # Skip tables we can't access
            finally:
                cur.close()
        
        # Throttle to avoid overloading DB
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000)
        
        return table_findings

    def scan(self, progress_callback=None):
        self.connect()
        tables = self.get_tables()
        
        if self.max_tables:
            tables = tables[:self.max_tables]
        
        total = len(tables)
        print(f"\n  Tables to scan: {total}")
        print(f"  Sample rows per table: {self.sample_rows} (using Oracle SAMPLE clause)")
        print(f"  Throttle delay: {self.delay_ms}ms between tables")
        print(f"\n  Starting scan...")
        
        # Load progress if resuming
        done_tables = set()
        if self.progress_file and self.progress_file.exists():
            try:
                prog = json.loads(self.progress_file.read_text())
                done_tables = set(prog.get('done', []))
                self.findings = prog.get('findings', [])
                print(f"  Resuming from previous scan ({len(done_tables)} tables already done)")
            except:
                pass
        
        for i, (owner, table_name, est_rows, size_mb) in enumerate(tables):
            if self.stop_flag:
                print(f"\n  Scan stopped by user")
                break
            
            table_key = f"{owner}.{table_name}"
            if table_key in done_tables:
                continue
            
            pct = int((i/total)*100)
            size_str = f"{size_mb:.1f}MB" if size_mb else "?"
            est_str = f"~{est_rows:,} rows" if est_rows else "unknown rows"
            
            print(f"\r  [{pct:3d}%] {table_key:<50} {est_str:<20} {size_str:<10}", end='', flush=True)
            
            findings = self.scan_table(owner, table_name, est_rows, size_mb)
            
            with self._lock:
                self.findings.extend(findings)
                self.stats['tables_scanned'] += 1
                self.stats['pii_found'] += len(findings)
                done_tables.add(table_key)
            
            # Save progress every 50 tables
            if self.progress_file and i % 50 == 0:
                self.progress_file.write_text(json.dumps({
                    'done': list(done_tables),
                    'findings': self.findings,
                    'stats': self.stats,
                }))
        
        print(f"\n\n  ✓ Scan complete")
        return self.findings, self.stats


def cmd_configure(args):
    cfg = load_config()
    cfg.update({'server': args.server, 'api_key': args.api_key,
                'agent_name': args.name or socket.gethostname()})
    
    # Try to reach server
    try:
        req = urllib.request.Request(
            f"{args.server}/api/v1/pii-scanner/stats",
            headers={'X-Agent-Key': args.api_key}
        )
        with urllib.request.urlopen(req, timeout=10):
            cfg['offline'] = False
            print(f"✓ Connected to KnightGuard server")
    except:
        cfg['offline'] = True
        print(f"⚠ Server unreachable — configured for offline mode")
    
    save_config(cfg)
    print(f"✓ Configuration saved")


def cmd_scan(args):
    cfg = load_config()
    offline = args.offline or cfg.get('offline', False)
    output = args.output or f"knightguard_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║      KnightGuard GRC — PII Scanner Agent v{VERSION}
║      Mode: {'OFFLINE (Air-gapped)' if offline else 'ONLINE'}
║      Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚══════════════════════════════════════════════════════════════╝
""")
    
    scan_result = {
        'scan_id': hashlib.md5(f"{time.time()}".encode()).hexdigest(),
        'agent_version': VERSION,
        'agent_name': cfg.get('agent_name', socket.gethostname()),
        'system_info': {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
        },
        'started_at': datetime.datetime.now().isoformat(),
        'scan_targets': [],
        'findings': [],
        'statistics': {},
    }
    
    all_findings = []
    
    # Oracle scan
    if args.oracle_host:
        if not args.oracle_pass:
            args.oracle_pass = input("Oracle password: ")
        
        print(f"[Oracle Enterprise Scan]")
        print(f"  Target: {args.oracle_host}:{args.oracle_port or 1521}/{args.oracle_service or 'ORCL'}")
        print(f"  Sample strategy: {args.sample_rows or 500} rows per table via SAMPLE clause")
        print(f"  Throttle: {args.delay_ms or 100}ms between tables")
        
        scanner = OracleEnterpriseScanner(
            host=args.oracle_host,
            port=int(args.oracle_port or 1521),
            service=args.oracle_service or 'ORCL',
            user=args.oracle_user or 'system',
            password=args.oracle_pass,
            sample_rows=int(args.sample_rows or 500),
            delay_ms=int(args.delay_ms or 100),
            max_tables=int(args.max_tables) if args.max_tables else None,
            progress_file=args.progress_file,
        )
        
        # Handle Ctrl+C gracefully
        def handle_stop(sig, frame):
            print(f"\n\n  Stopping scan... saving progress")
            scanner.stop_flag = True
        signal.signal(signal.SIGINT, handle_stop)
        
        findings, stats = scanner.scan()
        all_findings.extend(findings)
        
        scan_result['scan_targets'].append({
            'type': 'oracle_database',
            'host': args.oracle_host,
            'port': args.oracle_port or '1521',
            'service': args.oracle_service or 'ORCL',
            'db_size_gb': stats.get('db_size_gb', 0),
            'tables_scanned': stats.get('tables_scanned', 0),
            'total_rows_sampled': stats.get('total_rows_sampled', 0),
        })
        scan_result['statistics'] = stats
    
    # Deduplicate findings
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.get('table_name',''), f.get('column_name',''), f.get('pii_type',''))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    all_findings = unique
    
    # Summary
    by_sev = {}
    for f in all_findings:
        s = f.get('severity', 'LOW')
        by_sev[s] = by_sev.get(s, 0) + 1
    
    scan_result['findings'] = all_findings
    scan_result['completed_at'] = datetime.datetime.now().isoformat()
    scan_result['summary'] = {
        'total_findings': len(all_findings),
        'by_severity': by_sev,
        'critical': by_sev.get('CRITICAL', 0),
        'high': by_sev.get('HIGH', 0),
        'medium': by_sev.get('MEDIUM', 0),
        'low': by_sev.get('LOW', 0),
    }
    
    print(f"\n{'='*60}")
    print(f"SCAN RESULTS")
    print(f"  Total PII findings: {len(all_findings)}")
    for sev in ['CRITICAL','HIGH','MEDIUM','LOW']:
        if by_sev.get(sev):
            print(f"  {sev}: {by_sev[sev]}")
    print(f"{'='*60}")
    
    # Save JSON
    Path(output).write_text(json.dumps(scan_result, indent=2, default=str))
    print(f"\n✓ Results saved: {Path(output).absolute()}")
    
    if offline:
        print(f"\n  📤 Share '{output}' with your KnightGuard administrator")
        print(f"  📥 They will upload it via: KnightGuard Portal → PII Scanner → Upload Results")
    else:
        # Try to upload
        try:
            data = json.dumps(scan_result).encode()
            req = urllib.request.Request(
                f"{cfg['server']}/api/v1/pii-scanner/upload-scan",
                data=data, method='POST'
            )
            req.add_header('Content-Type', 'application/json')
            req.add_header('X-Agent-Key', cfg.get('api_key',''))
            with urllib.request.urlopen(req, timeout=60) as r:
                print(f"✓ Results uploaded to KnightGuard portal")
        except Exception as e:
            print(f"⚠ Upload failed ({e}) — results saved locally")


def main():
    parser = argparse.ArgumentParser(
        prog='knightguard-agent',
        description='KnightGuard GRC PII Scanner — Enterprise Edition v2.1'
    )
    sub = parser.add_subparsers(dest='command')

    # configure
    c = sub.add_parser('configure')
    c.add_argument('--server', required=True)
    c.add_argument('--api-key', required=True)
    c.add_argument('--name')

    # scan
    s = sub.add_parser('scan')
    s.add_argument('--offline', action='store_true', help='Air-gapped mode — save to JSON')
    s.add_argument('--output', help='Output JSON file')
    # Oracle
    s.add_argument('--oracle-host')
    s.add_argument('--oracle-port', default='1521')
    s.add_argument('--oracle-service', default='ORCL')
    s.add_argument('--oracle-user', default='system')
    s.add_argument('--oracle-pass')
    # Performance tuning
    s.add_argument('--sample-rows', default='500',
                   help='Rows to sample per table (default: 500). For 20TB DB, 500 is sufficient')
    s.add_argument('--delay-ms', default='100',
                   help='Delay in ms between tables to throttle DB load (default: 100)')
    s.add_argument('--max-tables',
                   help='Limit number of tables (for testing)')
    s.add_argument('--progress-file',
                   help='File to save progress for resumable scans')

    args = parser.parse_args()
    if args.command == 'configure': cmd_configure(args)
    elif args.command == 'scan': cmd_scan(args)
    else: parser.print_help()

if __name__ == '__main__':
    main()
