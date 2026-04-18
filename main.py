#!/usr/bin/env python3
"""
SCE GRC PII Scanner Agent v1.0
ScudoCyber Solutions Pvt. Ltd.
"""
import json
import os
import sys
import argparse
from datetime import datetime

CONFIG_FILE = os.path.join(os.path.expanduser('~'), '.pii_agent_config.json')

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def configure(args):
    config = load_config()
    if args.server:
        config['server_url'] = args.server
    if args.api_key:
        config['api_key'] = args.api_key
    save_config(config)
    print(f"Config saved to {CONFIG_FILE}")
    print(f"  Server: {config.get('server_url','not set')}")
    print(f"  API Key: {config.get('api_key','not set')[:8]}..." if config.get('api_key') else "  API Key: not set")

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
    from api_client import PIIAgentClient

    db_config = {
        'type': args.type,
        'host': args.host,
        'port': args.port,
        'database': args.database,
        'username': args.username,
        'password': args.password,
    }

    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner — Database Scan")
    print(f"Target: {args.type}://{args.host}/{args.database}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    scanner = DBScanner(db_config)
    findings = scanner.scan(lambda msg: print(f"  → {msg}"))

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE — {len(findings)} findings")
    print(f"{'='*60}")

    # Group by sensitivity
    by_sens = {}
    for f in findings:
        s = f['sensitivity']
        by_sens.setdefault(s, []).append(f)

    for sens in ['CRITICAL','HIGH','MEDIUM','LOW']:
        if sens in by_sens:
            print(f"\n{sens} ({len(by_sens[sens])}):")
            for f in by_sens[sens][:5]:
                loc = f"{f['table_name']}.{f['column_name']}" if f.get('table_name') else f.get('file_path','')
                spdi = ' [DPDP-SPDI]' if f.get('is_dpdp_spdi') else ''
                print(f"  {f['detector']}: {loc} ({f['sample_count']} samples){spdi}")

    # Submit to server
    if config.get('server_url') and config.get('api_key'):
        print(f"\nSubmitting to SCE GRC server...")
        client = PIIAgentClient(config['server_url'], config['api_key'])
        result = client.submit_findings('database', f"{args.host}/{args.database}", findings)
        if result:
            print(f"SUCCESS: Scan ID {result.get('scan_id','')}")
        else:
            print("WARNING: Could not submit to server (findings saved locally)")
    else:
        print("\nNote: Configure server to submit findings automatically")

    # Save local report
    report_file = f"pii_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({'target': f"{args.host}/{args.database}", 'findings': findings, 'scanned_at': datetime.now().isoformat()}, f, indent=2)
    print(f"Report saved: {report_file}")

def scan_files(args):
    config = load_config()
    from file_scanner import FileScanner
    from api_client import PIIAgentClient

    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner — File Scan")
    print(f"Path: {args.path}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    scanner = FileScanner(args.path)
    findings = scanner.scan(lambda msg: print(f"  → {msg}"))

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE — {len(findings)} findings")
    print(f"{'='*60}")

    for f in findings[:10]:
        spdi = ' [DPDP-SPDI]' if f.get('is_dpdp_spdi') else ''
        print(f"  {f['detector']}: {f.get('file_path','')[-50:]} ({f['sample_count']} samples){spdi}")

    if config.get('server_url') and config.get('api_key'):
        print(f"\nSubmitting to SCE GRC server...")
        client = PIIAgentClient(config['server_url'], config['api_key'])
        result = client.submit_findings('file', args.path, findings)
        if result:
            print(f"SUCCESS: Scan ID {result.get('scan_id','')}")

    report_file = f"pii_file_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump({'path': args.path, 'findings': findings, 'scanned_at': datetime.now().isoformat()}, f, indent=2)
    print(f"Report saved: {report_file}")

def scan_network(args):
    from network_scanner import scan_network as do_scan
    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner — Network Discovery")
    print(f"CIDR: {args.cidr}")
    print(f"{'='*60}\n")
    results = do_scan(args.cidr, lambda msg: print(f"  → {msg}"))
    print(f"\nDiscovered {len(results)} database services:")
    for r in results:
        print(f"  {r['host']}:{r['port']} — {r['service']}")

def main():
    parser = argparse.ArgumentParser(
        description='SCE GRC PII Scanner Agent — ScudoCyber Solutions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Configure agent:
    pii-scanner configure --server https://api.scegrc.com --api-key YOUR_KEY

  Scan a database:
    pii-scanner db --type mysql --host 192.168.1.10 --database mydb --username root --password pass

  Scan files:
    pii-scanner files --path /var/data

  Discover databases on network:
    pii-scanner network --cidr 192.168.1.0/24

  Test connection:
    pii-scanner test
        """
    )
    subparsers = parser.add_subparsers(dest='command')

    # Configure
    cfg = subparsers.add_parser('configure', help='Configure server connection')
    cfg.add_argument('--server', help='SCE GRC server URL')
    cfg.add_argument('--api-key', dest='api_key', help='Agent API key')

    # Test
    subparsers.add_parser('test', help='Test server connection')

    # DB scan
    db = subparsers.add_parser('db', help='Scan a database for PII')
    db.add_argument('--type', required=True, choices=['mysql','postgresql','mssql','sqlite','oracle'])
    db.add_argument('--host', required=True)
    db.add_argument('--port', type=int)
    db.add_argument('--database', required=True)
    db.add_argument('--username', default='')
    db.add_argument('--password', default='')

    # File scan
    fs = subparsers.add_parser('files', help='Scan files/folders for PII')
    fs.add_argument('--path', required=True, help='Path to scan')

    # Network scan
    net = subparsers.add_parser('network', help='Discover databases on network')
    net.add_argument('--cidr', required=True, help='Network CIDR e.g. 192.168.1.0/24')

    args = parser.parse_args()

    if args.command == 'configure':
        configure(args)
    elif args.command == 'test':
        test_connection(args)
    elif args.command == 'db':
        scan_database(args)
    elif args.command == 'files':
        scan_files(args)
    elif args.command == 'network':
        scan_network(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
