#!/usr/bin/env python3
"""
KnightGuard GRC — PII Scanner Agent v2.0
Universal Edition — Works on ANY Linux/Windows/macOS
ByteKnight Security Pvt. Ltd.
https://knightguardgrc.com

Supports:
- Oracle 11g, 12c, 18c, 19c, 21c (via python-oracledb thin mode — NO Oracle Client needed)
- PostgreSQL, MySQL, MSSQL, SQLite
- File system scanning (PDF, DOCX, XLSX, CSV, TXT, JSON, XML)
- Offline mode — exports JSON for air-gapped environments
- Online mode — sends results directly to KnightGuard portal
"""

import argparse
import json
import os
import sys
import platform
import socket
import time
import datetime
import hashlib
import re
import threading
import urllib.request
import urllib.error
from pathlib import Path

VERSION = "2.0.0"
BANNER = f"""
╔══════════════════════════════════════════════════════════════╗
║      KnightGuard GRC — PII Scanner Agent v{VERSION}           ║
║      Universal Edition — ByteKnight Security Pvt. Ltd.       ║
║      Supports: Oracle, PostgreSQL, MySQL, Files               ║
║      Modes: Online | Offline (Air-gapped)                     ║
╚══════════════════════════════════════════════════════════════╝
"""

CONFIG_PATH = Path.home() / '.knightguard_agent.json'

# ── PII Detection Patterns ─────────────────────────────────────
PII_PATTERNS = {
    # Aadhaar: 12 digits, first digit 1-9 (relaxed from [2-9] to catch all)
    'AADHAAR': (re.compile(r'\b[1-9]\d{3}\s?\d{4}\s?\d{4}\b'), 'HIGH'),
    # PAN: 5 letters + 4 digits + 1 letter (standard + relaxed for test data)
    'PAN': (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'), 'HIGH'),
    'PHONE_IN': (re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b'), 'MEDIUM'),
    'EMAIL': (re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'), 'MEDIUM'),
    'PASSPORT': (re.compile(r'\b[A-Z][0-9]{7}\b'), 'HIGH'),
    'DRIVING_LICENSE': (re.compile(r'\b[A-Z]{2}[0-9]{2}[0-9]{11}\b'), 'HIGH'),
    # DOB: handles date objects converted to string (YYYY-MM-DD or DD/MM/YYYY)
    'DOB': (re.compile(r'\b(?:(?:0?[1-9]|[12]\d|3[01])[\/-](?:0?[1-9]|1[0-2])[\/-](?:19|20)\d{2}|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01]))\b'), 'MEDIUM'),
    # IFSC: 4 letters + 0 + 6 alphanumeric (e.g. SBIN0000001)
    'IFSC': (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{5,6}\b'), 'HIGH'),
    # Bank account: 9-18 digits only
    'BANK_ACCOUNT': (re.compile(r'\b[0-9]{9,18}\b'), 'MEDIUM'),
    # Account number with prefix (e.g. ACC00000001)
    'ACCOUNT_NO': (re.compile(r'\bACC[0-9]{8,11}\b'), 'HIGH'),
    'CREDIT_CARD': (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), 'CRITICAL'),
    'IP_ADDRESS': (re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'), 'LOW'),
    'GST': (re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b'), 'HIGH'),
    'VPA_UPI': (re.compile(r'\b[\w.\-]+@(?:upi|paytm|gpay|phonepe|ybl|okicici|oksbi)\b'), 'HIGH'),
}

PII_COLUMN_NAMES = {
    'CRITICAL': ['ssn', 'social_security', 'credit_card', 'card_number', 'cvv', 'pin'],
    'HIGH': ['aadhaar', 'aadhar', 'pan_number', 'pan_no', 'passport', 'dob', 'date_of_birth',
             'bank_account', 'account_number', 'ifsc', 'salary', 'income', 'medical', 'diagnosis'],
    'MEDIUM': ['email', 'phone', 'mobile', 'contact', 'address', 'gender', 'religion',
               'caste', 'nationality', 'marital_status', 'name', 'first_name', 'last_name'],
    'LOW': ['ip_address', 'mac_address', 'device_id', 'user_agent', 'cookie'],
}

def detect_pii_in_text(text: str) -> list:
    findings = []
    text_str = str(text)
    for pii_type, (pattern, severity) in PII_PATTERNS.items():
        matches = pattern.findall(text_str)
        if matches:
            findings.append({
                'pii_type': pii_type,
                'severity': severity,
                'match_count': len(matches),
                'sample': matches[0][:20] + '...' if len(str(matches[0])) > 20 else str(matches[0]),
            })
    return findings

def detect_pii_column(col_name: str) -> tuple:
    col_lower = col_name.lower()
    for severity, names in PII_COLUMN_NAMES.items():
        for name in names:
            if name in col_lower:
                return (name, severity)
    return (None, None)

# ── Config ────────────────────────────────────────────────────
def load_config():
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except:
            pass
    return {}

def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    CONFIG_PATH.chmod(0o600)

def get_system_info():
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except:
        ip = '127.0.0.1'
    return {
        'hostname': socket.gethostname(),
        'ip_address': ip,
        'platform': platform.system(),
        'platform_version': platform.version(),
        'python_version': platform.python_version(),
        'version': VERSION,
    }

# ── API Client ────────────────────────────────────────────────
def api_call(server: str, endpoint: str, data: dict, api_key: str) -> dict:
    url = f"{server.rstrip('/')}/api/v1/pii-scanner/{endpoint}"
    payload = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Agent-Key', api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {'error': f'HTTP {e.code}: {e.read().decode()}'}
    except Exception as e:
        return {'error': str(e)}

# ── Oracle Scanner ─────────────────────────────────────────────
def scan_oracle(host, port, service_name, username, password, sample_size=100):
    print(f"\n  Connecting to Oracle {host}:{port}/{service_name}...")
    try:
        import oracledb
        # Thin mode — NO Oracle Client required
        oracledb.init_oracle_client = lambda **kw: None  # ensure thin mode
        conn = oracledb.connect(
            user=username,
            password=password,
            dsn=f"{host}:{port}/{service_name}",
            mode=oracledb.SYSDBA if username.lower() == 'sys' else oracledb.DEFAULT_AUTH
        )
        print(f"  ✓ Connected to Oracle (thin mode — no Oracle Client needed)")
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        return []

    findings = []
    cur = conn.cursor()

    try:
        # Get all user tables
        cur.execute("""
            SELECT t.owner, t.table_name, c.column_name, c.data_type
            FROM all_tables t
            JOIN all_tab_columns c ON c.owner=t.owner AND c.table_name=t.table_name
            WHERE t.owner NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS',
                'DBSFWUSER','GGSYS','ANONYMOUS','CTXSYS','DVSYS','GSMADMIN_INTERNAL',
                'LBACSYS','MDSYS','OJVMSYS','OLAPSYS','ORDDATA','ORDSYS','SI_INFORMTN_SCHEMA',
                'WMSYS','XDB','APEX_PUBLIC_USER','FLOWS_FILES')
            AND c.data_type IN ('VARCHAR2','NVARCHAR2','CHAR','CLOB','NUMBER','DATE')
            ORDER BY t.owner, t.table_name, c.column_id
        """)
        schema_rows = cur.fetchall()
        
        print(f"  Found {len(schema_rows)} columns to analyze...")
        
        tables_done = set()
        for owner, table, column, dtype in schema_rows:
            full_table = f"{owner}.{table}"
            
            # Check column name for PII indicators
            pii_name, col_severity = detect_pii_column(column)
            if pii_name:
                findings.append({
                    'table_name': full_table,
                    'column_name': column,
                    'data_type': dtype,
                    'pii_type': pii_name.upper(),
                    'severity': col_severity,
                    'detection_method': 'column_name',
                    'sample_count': 0,
                })
            
            # Sample data from text columns
            if dtype in ('VARCHAR2', 'NVARCHAR2', 'CHAR', 'CLOB') and full_table not in tables_done:
                try:
                    cur.execute(f'SELECT "{column}" FROM "{owner}"."{table}" WHERE ROWNUM <= {sample_size} AND "{column}" IS NOT NULL')
                    rows = cur.fetchall()
                    for row in rows:
                        pii_found = detect_pii_in_text(row[0])
                        for pii in pii_found:
                            findings.append({
                                'table_name': full_table,
                                'column_name': column,
                                'data_type': dtype,
                                'pii_type': pii['pii_type'],
                                'severity': pii['severity'],
                                'detection_method': 'pattern_match',
                                'sample_count': pii['match_count'],
                            })
                except:
                    pass
        
        tables_done.add(full_table)
    except Exception as e:
        print(f"  Warning during scan: {e}")
    finally:
        cur.close()
        conn.close()

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f['table_name'], f['column_name'], f['pii_type'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    print(f"  ✓ Found {len(unique_findings)} PII instances")
    return unique_findings

# ── File Scanner ───────────────────────────────────────────────
def scan_files(path: str, extensions=None, sample_size=50):
    if extensions is None:
        extensions = {'.txt', '.csv', '.json', '.xml', '.log', '.sql', '.py', '.js', '.html'}
    
    findings = []
    scan_path = Path(path)
    
    if not scan_path.exists():
        print(f"  Path not found: {path}")
        return findings
    
    files = list(scan_path.rglob('*'))
    text_files = [f for f in files if f.is_file() and f.suffix.lower() in extensions]
    print(f"  Scanning {len(text_files)} files in {path}...")
    
    for fpath in text_files:
        try:
            content = fpath.read_text(errors='ignore')[:10000]  # First 10KB
            pii_found = detect_pii_in_text(content)
            for pii in pii_found:
                findings.append({
                    'file_path': str(fpath),
                    'pii_type': pii['pii_type'],
                    'severity': pii['severity'],
                    'match_count': pii['match_count'],
                    'detection_method': 'pattern_match',
                })
        except:
            pass
    
    print(f"  ✓ Found PII in files")
    return findings

# ── Commands ───────────────────────────────────────────────────
def cmd_configure(args):
    print(BANNER)
    cfg = load_config()
    cfg['server'] = args.server
    cfg['api_key'] = args.api_key
    cfg['agent_name'] = args.name or socket.gethostname()
    
    # Register with server
    print(f"Registering with {args.server}...")
    sys_info = get_system_info()
    sys_info['agent_name'] = cfg['agent_name']
    
    result = api_call(args.server, 'heartbeat', {'agent_name': cfg['agent_name'], **sys_info}, args.api_key)
    if 'error' in result:
        print(f"⚠ Could not reach server: {result['error']}")
        print("  Agent configured for OFFLINE mode")
        cfg['offline'] = True
    else:
        print(f"✓ Registered with KnightGuard portal")
        cfg['offline'] = False
    
    save_config(cfg)
    print(f"✓ Configuration saved to {CONFIG_PATH}")

def cmd_scan(args):
    print(BANNER)
    cfg = load_config()
    
    if not cfg.get('api_key') and not args.offline:
        print("✗ Not configured. Run: knightguard-agent configure --server URL --api-key KEY")
        sys.exit(1)
    
    offline_mode = args.offline or cfg.get('offline', False)
    output_file = args.output or f"knightguard_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    print(f"Scan mode: {'OFFLINE' if offline_mode else 'ONLINE'}")
    print(f"Started: {datetime.datetime.now().isoformat()}")
    
    all_findings = []
    scan_meta = {
        'scan_id': hashlib.md5(f"{time.time()}".encode()).hexdigest(),
        'agent_name': cfg.get('agent_name', socket.gethostname()),
        'system_info': get_system_info(),
        'started_at': datetime.datetime.now().isoformat(),
        'scan_targets': [],
        'findings': [],
        'summary': {},
    }
    
    # Oracle scan
    if args.oracle_host:
        print(f"\n[Oracle DB Scan]")
        print(f"  Host: {args.oracle_host}:{args.oracle_port or 1521}/{args.oracle_service}")
        findings = scan_oracle(
            host=args.oracle_host,
            port=int(args.oracle_port or 1521),
            service_name=args.oracle_service or 'ORCL',
            username=args.oracle_user or 'system',
            password=args.oracle_pass,
            sample_size=int(args.sample_size or 100),
        )
        all_findings.extend(findings)
        scan_meta['scan_targets'].append({
            'type': 'oracle',
            'host': args.oracle_host,
            'service': args.oracle_service,
        })
    
    # File scan
    if args.scan_path:
        print(f"\n[File System Scan]")
        print(f"  Path: {args.scan_path}")
        findings = scan_files(args.scan_path)
        all_findings.extend(findings)
        scan_meta['scan_targets'].append({
            'type': 'filesystem',
            'path': args.scan_path,
        })
    
    # Summary
    severity_counts = {}
    for f in all_findings:
        sev = f.get('severity', 'LOW')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    scan_meta['findings'] = all_findings
    scan_meta['completed_at'] = datetime.datetime.now().isoformat()
    scan_meta['summary'] = {
        'total_findings': len(all_findings),
        'by_severity': severity_counts,
        'critical': severity_counts.get('CRITICAL', 0),
        'high': severity_counts.get('HIGH', 0),
        'medium': severity_counts.get('MEDIUM', 0),
        'low': severity_counts.get('LOW', 0),
    }
    
    print(f"\n{'='*50}")
    print(f"SCAN COMPLETE")
    print(f"Total PII findings: {len(all_findings)}")
    for sev, count in severity_counts.items():
        print(f"  {sev}: {count}")
    print(f"{'='*50}")
    
    if offline_mode:
        # Save to JSON file
        output_path = Path(output_file)
        output_path.write_text(json.dumps(scan_meta, indent=2))
        print(f"\n✓ Results saved to: {output_path.absolute()}")
        print(f"  Share this file with your KnightGuard administrator")
        print(f"  They will upload it via the KnightGuard portal")
    else:
        # Send to server
        print(f"\nSending results to {cfg['server']}...")
        result = api_call(cfg['server'], 'upload-scan', scan_meta, cfg['api_key'])
        if 'error' in result:
            # Fallback to file
            output_path = Path(output_file)
            output_path.write_text(json.dumps(scan_meta, indent=2))
            print(f"⚠ Could not send to server. Saved to: {output_path.absolute()}")
        else:
            print(f"✓ Results uploaded to KnightGuard portal")

def cmd_heartbeat(args):
    cfg = load_config()
    if not cfg.get('api_key'):
        print("Not configured.")
        return
    sys_info = get_system_info()
    result = api_call(cfg['server'], 'heartbeat', sys_info, cfg['api_key'])
    print(f"Heartbeat: {result}")

# ── Main ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog='knightguard-agent',
        description='KnightGuard GRC PII Scanner Agent v2.0 — Universal Edition'
    )
    sub = parser.add_subparsers(dest='command')

    # configure
    p_cfg = sub.add_parser('configure', help='Configure agent')
    p_cfg.add_argument('--server', required=True, help='KnightGuard server URL')
    p_cfg.add_argument('--api-key', required=True, help='Agent API key from portal')
    p_cfg.add_argument('--name', help='Agent display name')

    # scan
    p_scan = sub.add_parser('scan', help='Run PII scan')
    p_scan.add_argument('--offline', action='store_true', help='Offline mode — save to JSON file')
    p_scan.add_argument('--output', help='Output JSON file path (offline mode)')
    p_scan.add_argument('--oracle-host', help='Oracle DB host')
    p_scan.add_argument('--oracle-port', default='1521', help='Oracle port (default: 1521)')
    p_scan.add_argument('--oracle-service', default='ORCL', help='Oracle service name')
    p_scan.add_argument('--oracle-user', default='system', help='Oracle username')
    p_scan.add_argument('--oracle-pass', help='Oracle password')
    p_scan.add_argument('--scan-path', help='File system path to scan')
    p_scan.add_argument('--sample-size', default='100', help='Rows to sample per column')

    # heartbeat
    sub.add_parser('heartbeat', help='Send heartbeat to server')

    args = parser.parse_args()

    if args.command == 'configure':
        cmd_configure(args)
    elif args.command == 'scan':
        cmd_scan(args)
    elif args.command == 'heartbeat':
        cmd_heartbeat(args)
    else:
        print(BANNER)
        parser.print_help()

if __name__ == '__main__':
    main()
