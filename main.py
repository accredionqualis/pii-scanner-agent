#!/usr/bin/env python3
"""
SCE GRC PII Scanner Agent v1.1
ScudoCyber Solutions Pvt. Ltd.

Supports two modes:
  ONLINE  — scan and push findings to SCE GRC server immediately
  OFFLINE — scan in air-gapped environment, save to JSON file,
             upload later with: pii-scanner upload --file <file>
"""
import json
import os
import sys
import argparse
from datetime import datetime

CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.pii_agent_config.json')
AGENT_VERSION = '1.1.0'


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


# ── Helpers ───────────────────────────────────────────────────────────────────

def save_offline_report(scan_type, target, findings, label='scan'):
    """Save scan results to a local JSON file for later upload."""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f"pii_{label}_{ts}.json"
    payload = {
        'scan_type': scan_type,
        'target': target,
        'findings': findings,
        'scanned_at': datetime.now().isoformat(),
        'agent_version': AGENT_VERSION,
        'offline': True,
    }
    with open(report_file, 'w') as f:
        json.dump(payload, f, indent=2)
    return report_file


def print_findings_summary(findings):
    by_sens = {}
    for f in findings:
        by_sens.setdefault(f['sensitivity'], []).append(f)
    for sens in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sens in by_sens:
            print(f"\n  {sens} ({len(by_sens[sens])}):")
            for f in by_sens[sens][:5]:
                loc = f"{f['table_name']}.{f['column_name']}" if f.get('table_name') else f.get('file_path', '')
                spdi = ' [DPDP-SPDI]' if f.get('is_dpdp_spdi') else ''
                count = f.get('sample_count', 0)
                print(f"    {f['detector']}: {loc} (~{count:,} records){spdi}")
    if not by_sens:
        print("  No PII found.")


def submit_to_server(config, scan_type, target, findings):
    """Try to submit findings to server. Returns (success, scan_id)."""
    from api_client import PIIAgentClient
    try:
        client = PIIAgentClient(config['server_url'], config['api_key'])
        result = client.submit_findings(scan_type, target, findings)
        if result and result.get('scan_id'):
            return True, result['scan_id']
        return False, None
    except Exception as e:
        print(f"  Submit error: {e}")
        return False, None


# ── Commands ──────────────────────────────────────────────────────────────────

def configure(args):
    config = load_config()
    if args.server:
        config['server_url'] = args.server
    if args.api_key:
        config['api_key'] = args.api_key
    save_config(config)
    print(f"Config saved to {CONFIG_FILE}")
    print(f"  Server:  {config.get('server_url', 'not set')}")
    print(f"  API Key: {config.get('api_key', 'not set')[:8]}..." if config.get('api_key') else "  API Key: not set")


def test_connection(args):
    config = load_config()
    if not config.get('server_url') or not config.get('api_key'):
        print("ERROR: Run 'configure' first")
        return False
    from api_client import PIIAgentClient
    client = PIIAgentClient(config['server_url'], config['api_key'])
    print(f"Testing connection to {config['server_url']}...")
    if client.test_connection():
        print("SUCCESS: Connected and authenticated")
        return True
    else:
        print("FAILED: Could not connect")
        return False


def scan_database(args):
    config = load_config()
    from db_scanner import DBScanner

    db_config = {
        'type': args.type,
        'host': args.host,
        'port': args.port,
        'database': args.database,
        'username': args.username,
        'password': args.password,
    }
    target  = f"{args.host}/{args.database}"
    offline = getattr(args, 'offline', False)

    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner v{AGENT_VERSION} — Database Scan")
    print(f"Target:  {args.type}://{target}")
    print(f"Mode:    {'OFFLINE — results saved locally for upload later' if offline else 'ONLINE'}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    scanner  = DBScanner(db_config)
    findings = scanner.scan(lambda msg: print(f"  → {msg}"))

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE — {len(findings)} findings")
    print(f"{'='*60}")
    print_findings_summary(findings)

    # Always save a local JSON (audit trail + offline fallback)
    report_file = save_offline_report('database', target, findings, 'db')
    print(f"\n  Local report saved: {report_file}")

    if offline:
        print(f"\n  OFFLINE MODE — Findings NOT submitted to server.")
        print(f"  When your laptop is back online, run:")
        print(f"    pii-scanner upload --file {report_file}")
    elif config.get('server_url') and config.get('api_key'):
        print(f"\n  Submitting to SCE GRC server...")
        ok, scan_id = submit_to_server(config, 'database', target, findings)
        if ok:
            print(f"  SUCCESS: Scan ID {scan_id}")
            dashboard = config['server_url'].replace('api.', '').replace('-api.', '.').rstrip('/')
            print(f"  Dashboard: {dashboard}/privacy/pii-scanner")
        else:
            print(f"  WARNING: Server unreachable. Run when connected:")
            print(f"    pii-scanner upload --file {report_file}")
    else:
        print("\n  Note: Run 'pii-scanner configure' to set server connection.")
        print(f"  Then upload: pii-scanner upload --file {report_file}")


def scan_files(args):
    config  = load_config()
    offline = getattr(args, 'offline', False)
    from file_scanner import FileScanner

    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner v{AGENT_VERSION} — File Scan")
    print(f"Path:    {args.path}")
    print(f"Mode:    {'OFFLINE — results saved locally for upload later' if offline else 'ONLINE'}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    scanner  = FileScanner(args.path)
    findings = scanner.scan(lambda msg: print(f"  → {msg}"))

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE — {len(findings)} findings")
    print(f"{'='*60}")
    print_findings_summary(findings)

    report_file = save_offline_report('file', args.path, findings, 'files')
    print(f"\n  Local report saved: {report_file}")

    if offline:
        print(f"\n  OFFLINE MODE — run when connected:")
        print(f"    pii-scanner upload --file {report_file}")
    elif config.get('server_url') and config.get('api_key'):
        print(f"\n  Submitting to SCE GRC server...")
        ok, scan_id = submit_to_server(config, 'file', args.path, findings)
        if ok:
            print(f"  SUCCESS: Scan ID {scan_id}")
        else:
            print(f"  WARNING: Server unreachable.")
            print(f"    pii-scanner upload --file {report_file}")


def upload_report(args):
    """
    Upload a previously saved offline scan JSON to the SCE GRC server.
    Works for any scan type (database, file, api).
    Supports uploading multiple files at once.
    """
    config = load_config()

    if not config.get('server_url') or not config.get('api_key'):
        print("ERROR: Not configured. Run: pii-scanner configure --server URL --api-key KEY")
        sys.exit(1)

    files = args.file  # list of files

    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner v{AGENT_VERSION} — Upload Offline Scan(s)")
    print(f"Server: {config['server_url']}")
    print(f"Files:  {len(files)} to upload")
    print(f"{'='*60}\n")

    # Test connectivity first
    from api_client import PIIAgentClient
    client = PIIAgentClient(config['server_url'], config['api_key'])
    print("  Testing server connection...")
    if not client.test_connection():
        print("  ERROR: Cannot reach server. Check internet connection and try again.")
        sys.exit(1)
    print("  Connection OK\n")

    success_count = 0
    fail_count    = 0

    for file_path in files:
        if not os.path.exists(file_path):
            print(f"  ERROR: File not found: {file_path}")
            fail_count += 1
            continue

        print(f"  Uploading: {file_path}")
        try:
            with open(file_path) as f:
                payload = json.load(f)
        except Exception as e:
            print(f"    ERROR: Could not read file: {e}")
            fail_count += 1
            continue

        scan_type = payload.get('scan_type', 'database')
        target    = payload.get('target', '')
        findings  = payload.get('findings', [])
        scanned_at = payload.get('scanned_at', 'unknown')

        print(f"    Scan type:  {scan_type}")
        print(f"    Target:     {target}")
        print(f"    Scanned at: {scanned_at}")
        print(f"    Findings:   {len(findings)}")

        ok, scan_id = submit_to_server(config, scan_type, target, findings)
        if ok:
            print(f"    SUCCESS: Scan ID {scan_id}")
            # Mark file as uploaded so it's not accidentally re-uploaded
            uploaded_file = file_path.replace('.json', '_uploaded.json')
            os.rename(file_path, uploaded_file)
            print(f"    File renamed to: {uploaded_file}")
            success_count += 1
        else:
            print(f"    FAILED: Could not submit. File kept at: {file_path}")
            fail_count += 1

        print()

    print(f"{'='*60}")
    print(f"Upload complete: {success_count} succeeded, {fail_count} failed")
    if success_count > 0:
        dashboard = config['server_url'].replace('api.', '').replace('-api.', '.').rstrip('/')
        print(f"View results at: {dashboard}/privacy/pii-scanner")
    print(f"{'='*60}\n")


def scan_network(args):
    from network_scanner import scan_network as do_scan
    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner v{AGENT_VERSION} — Network Discovery")
    print(f"CIDR: {args.cidr}")
    print(f"{'='*60}\n")
    results = do_scan(args.cidr, lambda msg: print(f"  → {msg}"))
    print(f"\nDiscovered {len(results)} database services:")
    for r in results:
        print(f"  {r['host']}:{r['port']} — {r['service']}")


def scan_api(args):
    config = load_config()
    if not config.get('server_url') or not config.get('api_key'):
        print('Not configured. Run: pii-scanner configure --server URL --api-key KEY')
        return

    offline   = getattr(args, 'offline', False)
    endpoints = [e.strip() for e in args.endpoints.split(',') if e.strip()]
    headers   = {}
    if args.token:
        headers['Authorization'] = args.token if args.token.startswith('Bearer') else f'Bearer {args.token}'
    if args.header:
        for h in args.header:
            k, v = h.split(':', 1)
            headers[k.strip()] = v.strip()

    from api_scanner import scan_api_endpoints
    findings, results = scan_api_endpoints(args.url, endpoints, headers=headers)

    print(f"\nAPI scan complete — {len(findings)} findings")
    print_findings_summary(findings)

    report_file = save_offline_report('api', args.url, findings, 'api')
    print(f"\n  Local report saved: {report_file}")

    if offline:
        print(f"\n  OFFLINE MODE — run when connected:")
        print(f"    pii-scanner upload --file {report_file}")
    elif findings:
        ok, scan_id = submit_to_server(config, 'api', args.url, findings)
        if ok:
            print(f"  SUCCESS: Scan ID {scan_id}")
        else:
            print(f"  WARNING: pii-scanner upload --file {report_file}")
    else:
        print('  No PII found in API responses')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f'SCE GRC PII Scanner Agent v{AGENT_VERSION} — ScudoCyber Solutions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ONLINE mode (default):
  pii-scanner configure --server https://api.scegrc.com --api-key YOUR_KEY
  pii-scanner db --type mysql --host 192.168.1.10 --database mydb --username root --password pass

OFFLINE mode (air-gapped environment):
  pii-scanner db --type oracle --host 10.0.0.5 --database PROD --username dba --password pass --offline
  pii-scanner files --path /var/data --offline
  [disconnect from segregated environment, connect laptop to internet]
  pii-scanner upload --file pii_db_20240115_143022.json

Upload multiple files at once:
  pii-scanner upload --file scan1.json --file scan2.json --file scan3.json
        """
    )
    subparsers = parser.add_subparsers(dest='command')

    # Configure
    cfg = subparsers.add_parser('configure', help='Set server URL and API key')
    cfg.add_argument('--server', help='SCE GRC server URL (e.g. https://api.scegrc.com)')
    cfg.add_argument('--api-key', dest='api_key', help='Agent API key from dashboard')

    # Test
    subparsers.add_parser('test', help='Test server connectivity')

    # DB scan
    db = subparsers.add_parser('db', help='Scan a database for PII')
    db.add_argument('--type', required=True, choices=['mysql','postgresql','mssql','sqlite','oracle'])
    db.add_argument('--host', required=True, help='Database host IP or hostname')
    db.add_argument('--port', type=int, help='Port (defaults: mysql=3306, pg=5432, etc.)')
    db.add_argument('--database', required=True, help='Database / schema name')
    db.add_argument('--username', default='', help='DB username')
    db.add_argument('--password', default='', help='DB password')
    db.add_argument('--offline', action='store_true',
                    help='Air-gapped mode: save results locally, do NOT connect to internet')

    # File scan
    fs = subparsers.add_parser('files', help='Scan files/folders for PII')
    fs.add_argument('--path', required=True, help='File or directory path to scan')
    fs.add_argument('--offline', action='store_true',
                    help='Air-gapped mode: save results locally, do NOT connect to internet')

    # Upload offline scan
    up = subparsers.add_parser('upload', help='Upload offline scan file(s) to SCE GRC server')
    up.add_argument('--file', required=True, action='append', metavar='FILE',
                    help='Path to saved scan JSON. Repeat for multiple files: --file a.json --file b.json')

    # Network discovery
    net = subparsers.add_parser('network', help='Discover database services on a network')
    net.add_argument('--cidr', required=True, help='Network CIDR range e.g. 192.168.1.0/24')

    # API scanner
    api_p = subparsers.add_parser('api', help='Scan REST API endpoints for PII')
    api_p.add_argument('--url', required=True, help='Base API URL')
    api_p.add_argument('--endpoints', required=True, help='Comma-separated endpoints e.g. /users,/customers')
    api_p.add_argument('--token', help='Bearer token for auth')
    api_p.add_argument('--header', action='append', help='Custom header Key:Value (repeatable)')
    api_p.add_argument('--offline', action='store_true',
                       help='Air-gapped mode: save results locally, do NOT connect to internet')

    args = parser.parse_args()

    if args.command == 'configure':
        configure(args)
    elif args.command == 'test':
        test_connection(args)
    elif args.command == 'db':
        scan_database(args)
    elif args.command == 'files':
        scan_files(args)
    elif args.command == 'upload':
        upload_report(args)
    elif args.command == 'network':
        scan_network(args)
    elif args.command == 'api':
        scan_api(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
