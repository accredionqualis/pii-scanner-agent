#!/usr/bin/env python3
"""
KnightGuard GRC — PII Scanner Agent v1.1
ByteKnight Security Pvt. Ltd.
https://knightguardgrc.com
"""

import argparse
import json
import os
import sys
import platform
import socket
import time
import threading
from pathlib import Path

VERSION = "1.1.0"
BANNER = f"""
╔═══════════════════════════════════════════════════════╗
║         KnightGuard GRC — PII Scanner Agent           ║
║         v{VERSION}  ·  ByteKnight Security Pvt. Ltd.       ║
║         https://knightguardgrc.com                    ║
╚═══════════════════════════════════════════════════════╝
"""

CONFIG_PATH = Path.home() / '.knightguard_agent.json'

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
    return {
        'hostname': socket.gethostname(),
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'platform': platform.system(),
        'platform_version': platform.version(),
        'python_version': platform.python_version(),
        'version': VERSION,
    }

def cmd_configure(args):
    cfg = load_config()
    if args.server:
        cfg['server_url'] = args.server.rstrip('/')
    if args.api_key:
        cfg['api_key'] = args.api_key
    save_config(cfg)
    print(f"✓ Configuration saved to {CONFIG_PATH}")
    print(f"  Server : {cfg.get('server_url', 'not set')}")
    print(f"  API Key: {cfg.get('api_key', 'not set')[:8]}...")

def cmd_status(args):
    print(BANNER)
    cfg = load_config()
    info = get_system_info()
    print(f"  Host     : {info['hostname']} ({info['ip_address']})")
    print(f"  Platform : {info['platform']} {info['platform_version'][:30]}")
    print(f"  Server   : {cfg.get('server_url', '⚠ not configured')}")
    print(f"  API Key  : {cfg.get('api_key', '⚠ not set')[:8]}..." if cfg.get('api_key') else "  API Key  : ⚠ not configured")
    print()
    if not cfg.get('server_url') or not cfg.get('api_key'):
        print("⚠  Run 'configure' first:")
        print(f"   python agent.py configure --server https://api.knightguardgrc.com --api-key YOUR_KEY")
        return
    from api_client import PIIAgentClient
    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    print(f"Testing connection to {cfg['server_url']}...")
    ok, msg = client.test_connection()
    if ok:
        print(f"✓ Connected successfully")
    else:
        print(f"✗ Connection failed: {msg}")

def cmd_scan(args):
    print(BANNER)
    cfg = load_config()
    if not cfg.get('server_url') or not cfg.get('api_key'):
        print("✗ Not configured. Run: python agent.py configure --server URL --api-key KEY")
        sys.exit(1)

    from api_client import PIIAgentClient
    from file_scanner import FileScanner
    from db_scanner import DBScanner

    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    sysinfo = get_system_info()

    # Send heartbeat
    client.heartbeat(sysinfo)

    findings = []

    if args.path:
        print(f"\n📁 Scanning files: {args.path}")
        scanner = FileScanner(args.path, max_files=args.max_files or 1000)
        findings = scanner.scan()
        print(f"   Found {len(findings)} PII findings")

    elif args.db:
        print(f"\n🗄  Scanning database: {args.db}")
        scanner = DBScanner(args.db)
        findings = scanner.scan()
        print(f"   Found {len(findings)} PII findings")

    else:
        print("✗ Specify --path /dir/to/scan or --db 'postgresql://user:pass@host/dbname'")
        sys.exit(1)

    if findings:
        print(f"\n📤 Submitting {len(findings)} findings to KnightGuard GRC...")
        ok, msg = client.submit_findings(findings, sysinfo)
        if ok:
            print(f"✓ Findings submitted successfully")
        else:
            print(f"✗ Submission failed: {msg}")
            # Save locally as fallback
            out = Path(f"pii_scan_{time.strftime('%Y%m%d_%H%M%S')}.json")
            out.write_text(json.dumps({'findings': findings, 'system': sysinfo}, indent=2))
            print(f"  Saved locally: {out}")
    else:
        print("✓ No PII findings detected")

def cmd_daemon(args):
    """Run as background daemon sending heartbeats"""
    cfg = load_config()
    if not cfg.get('server_url') or not cfg.get('api_key'):
        print("✗ Not configured.")
        sys.exit(1)
    from api_client import PIIAgentClient
    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    sysinfo = get_system_info()
    interval = args.interval or 300
    print(f"✓ Daemon started — heartbeat every {interval}s (Ctrl+C to stop)")
    try:
        while True:
            ok, msg = client.heartbeat(sysinfo)
            status = "✓" if ok else "✗"
            print(f"[{time.strftime('%H:%M:%S')}] {status} Heartbeat {'sent' if ok else f'failed: {msg}'}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nDaemon stopped.")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog='knightguard-agent',
        description='KnightGuard GRC PII Scanner Agent'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # configure
    p_cfg = sub.add_parser('configure', help='Set server URL and API key')
    p_cfg.add_argument('--server', required=True, help='KnightGuard API URL (e.g. https://api.knightguardgrc.com)')
    p_cfg.add_argument('--api-key', required=True, help='Agent API key from KnightGuard platform')
    p_cfg.set_defaults(func=cmd_configure)

    # status
    p_st = sub.add_parser('status', help='Show agent status and test connection')
    p_st.set_defaults(func=cmd_status)

    # scan
    p_sc = sub.add_parser('scan', help='Run a PII scan')
    p_sc.add_argument('--path', help='Directory path to scan for files')
    p_sc.add_argument('--db', help='Database connection string')
    p_sc.add_argument('--max-files', type=int, default=1000, help='Max files to scan (default: 1000)')
    p_sc.set_defaults(func=cmd_scan)

    # daemon
    p_dm = sub.add_parser('daemon', help='Run as background agent with heartbeat')
    p_dm.add_argument('--interval', type=int, default=300, help='Heartbeat interval in seconds (default: 300)')
    p_dm.set_defaults(func=cmd_daemon)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
