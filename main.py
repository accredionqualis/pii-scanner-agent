#!/usr/bin/env python3
"""
KnightGuard GRC — PII Scanner Agent v2.0
ByteKnight Security Pvt. Ltd.
https://knightguardgrc.com
"""
import json, os, sys, argparse, platform, socket, time
from datetime import datetime
from pathlib import Path

CONFIG_FILE = Path.home() / '.knightguard_agent.json'
AGENT_VERSION = '2.1.0'
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║   KnightGuard GRC — PII Scanner Agent v2.0                  ║
║   ByteKnight Security Pvt. Ltd. | knightguardgrc.com         ║
╚══════════════════════════════════════════════════════════════╝
"""

def load_config():
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text())
        except: pass
    return {}

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); ip = s.getsockname()[0]; s.close(); return ip
    except: return socket.gethostbyname(socket.gethostname())

def _ts(): return datetime.now().strftime('%H:%M:%S')

def save_offline_report(scan_type, target, findings):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f"pii_{scan_type}_{ts}.json"
    payload = {
        'scan_type': scan_type, 'target': target,
        'hostname': socket.gethostname(), 'ip_address': _get_local_ip(),
        'platform': platform.system(), 'agent_version': AGENT_VERSION,
        'scanned_at': datetime.now().isoformat(), 'offline': True,
        'findings': findings, 'total_findings': len(findings),
    }
    Path(fname).write_text(json.dumps(payload, indent=2, default=str))
    return fname

def _print_summary(findings):
    if not findings: return
    from collections import Counter
    by_sev = Counter(f.get('sensitivity','LOW') for f in findings)
    by_type = Counter(f.get('detector', f.get('detector_name','?')) for f in findings)
    print(f"  Severity : " + " | ".join(f"{k}={v}" for k,v in sorted(by_sev.items())))
    print(f"  Top types: " + ", ".join(f"{k}={v}" for k,v in by_type.most_common(5)))

def _check_active(cfg):
    from api_client import PIIAgentClient
    if not cfg.get('server_url') or not cfg.get('api_key'):
        print("✗ Not configured. Run: pii-scanner configure --server URL --api-key KEY"); sys.exit(1)
    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    ok, msg = client.check_activation()
    if ok is False:
        print("✗ This agent has been DEACTIVATED by your administrator."); sys.exit(1)

def _submit_or_save(findings, scan_type, target, cfg, offline):
    _print_summary(findings)
    if offline or not findings:
        fname = save_offline_report(scan_type, target, findings)
        print(f"\n[SAVED] → {fname}")
        if offline: print(f"  Upload: pii-scanner upload --file {fname}")
        return
    from api_client import PIIAgentClient
    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    ok, msg = client.submit_findings(scan_type, target, findings)
    if ok: print(f"\n[OK] Submitted to KnightGuard GRC platform")
    else:
        fname = save_offline_report(scan_type, target, findings)
        print(f"\n[WARN] Submit failed ({msg}) — saved to {fname}")

# ── COMMANDS ──────────────────────────────────────────────────────

def cmd_configure(args):
    cfg = load_config()
    cfg['server_url'] = args.server.rstrip('/')
    cfg['api_key'] = args.api_key
    save_config(cfg)
    print(f"✓ Saved to {CONFIG_FILE}")
    print(f"  Server : {cfg['server_url']}")
    print(f"  Key    : {cfg['api_key'][:8]}...")

def cmd_status(args):
    from api_client import PIIAgentClient
    cfg = load_config()
    ip = _get_local_ip()
    print(f"  Host     : {socket.gethostname()} ({ip})")
    print(f"  OS       : {platform.system()} {platform.release()}")
    print(f"  Version  : {AGENT_VERSION}")
    print(f"  Server   : {cfg.get('server_url','⚠ not configured')}")
    print(f"  API Key  : {cfg['api_key'][:8]}..." if cfg.get('api_key') else "  API Key  : ⚠ not configured")
    if cfg.get('server_url') and cfg.get('api_key'):
        client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
        ok, msg = client.check_activation()
        if ok is None:
            # Send heartbeat so dashboard shows ONLINE
            client.heartbeat()
            print("  Status   : ✓ Connected — ACTIVE")
        elif ok is False: print("  Status   : ✗ DEACTIVATED — contact admin")
        else: print(f"  Status   : ✗ Connection failed: {msg}")

def cmd_scan_db(args):
    from db_scanner import scan_database
    cfg = load_config()
    if not args.offline: _check_active(cfg)
    threads = args.threads or 20
    print(f"\n[DB SCAN] {args.db}")
    print(f"  Threads : {threads} parallel")
    print(f"  Mode    : {'OFFLINE — saving to JSON' if args.offline else 'ONLINE — uploading to platform'}")

    findings = scan_database(args.db, max_rows=args.max_rows or 1000, send_raw=True, threads=threads)

    print(f"\n[RESULT] {len(findings)} PII findings")

    # Always save JSON locally first (safety net)
    fname = save_offline_report('database', args.db, findings)
    print(f"[SAVED] Local backup → {fname}")

    if args.offline:
        print(f"  Upload: pii-scanner upload --file {fname}")
        _print_summary(findings)
        return

    # Online: upload then optionally delete local file
    _print_summary(findings)
    from api_client import PIIAgentClient
    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    ok, msg = client.submit_findings('database', args.db, findings)
    if ok:
        print(f"[OK] Uploaded to KnightGuard GRC platform")
        # Keep local JSON as audit trail
        print(f"[INFO] Local backup kept at: {fname}")
    else:
        print(f"[WARN] Upload failed ({msg})")
        print(f"[INFO] Use local backup: pii-scanner upload --file {fname}")

def cmd_scan_files(args):
    from file_scanner import scan_files
    cfg = load_config()
    if not args.offline: _check_active(cfg)
    print(f"\n[FILE SCAN] {args.path}")
    findings = scan_files(args.path, max_files=args.max_files or 5000,
                          ocr_images=not args.no_ocr, send_raw=True)
    print(f"\n[RESULT] {len(findings)} PII findings")
    _submit_or_save(findings, 'file', args.path, cfg, args.offline)

def cmd_discover(args):
    from network_scanner import discover_network
    subnet = args.subnet or '.'.join(_get_local_ip().split('.')[:3])
    print(f"\n[DISCOVER] Scanning {subnet}.1–254 (timeout={args.timeout or 0.3}s)")
    results = discover_network(subnet, timeout=args.timeout or 0.3, dbs_only=args.dbs_only)
    dbs = [r for r in results if r['type']=='database']
    eps = [r for r in results if r['type']=='endpoint']
    print(f"\n[FOUND] {len(dbs)} database servers, {len(eps)} endpoints\n")
    for d in dbs:
        print(f"  [{d['db_type']:15s}] {d['ip']}:{d['port']}")
        print(f"    → pii-scanner scan-db --db \"{d['connect_hint']}\"")
    if eps:
        print(f"\n  Endpoints:")
        for e in eps: print(f"  [{e['ip']:15s}] {e.get('hostname','')} {e.get('os','')}")
        ips = ','.join(e['ip'] for e in eps[:10])
        print(f"\n  → pii-scanner scan-endpoint --targets {ips}")
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f"discovery_{ts}.json"
    Path(fname).write_text(json.dumps(results, indent=2))
    print(f"\n[SAVED] → {fname}")

def cmd_scan_endpoint(args):
    from file_scanner import scan_files
    cfg = load_config()
    if not args.offline: _check_active(cfg)
    targets = [t.strip() for t in args.targets.split(',')]
    all_findings = []
    for target in targets:
        print(f"\n[ENDPOINT] {target}")
        if platform.system() == 'Windows':
            share = f"\\\\{target}\\C$"
        else:
            share = f"/tmp/pii_mnt_{target.replace('.','_')}"
            os.makedirs(share, exist_ok=True)
            if args.smb_user:
                ret = os.system(f"mount -t cifs //{target}/C$ {share} "
                               f"-o username={args.smb_user},password={args.smb_pass or ''} 2>/dev/null")
                if ret != 0:
                    print(f"  ✗ Mount failed — deploy agent directly on {target}"); continue
            else:
                print(f"  ℹ Use --smb-user / --smb-pass for remote Windows access"); continue
        if os.path.exists(share):
            findings = scan_files(share, max_files=args.max_files or 2000,
                                  ocr_images=not args.no_ocr, send_raw=True)
            for f in findings: f['endpoint_ip'] = target
            all_findings.extend(findings)
            print(f"  Found {len(findings)} PII items")
        else:
            print(f"  ✗ Cannot access {target}")
    print(f"\n[RESULT] {len(all_findings)} total findings")
    _submit_or_save(all_findings, 'endpoint', args.targets, cfg, args.offline)

def cmd_upload(args):
    from api_client import PIIAgentClient
    cfg = load_config()
    server = args.server or cfg.get('server_url')
    api_key = args.api_key or cfg.get('api_key')
    if not server or not api_key:
        print("✗ Configure first or pass --server and --api-key"); sys.exit(1)
    fpath = Path(args.file)
    if not fpath.exists():
        print(f"✗ File not found: {args.file}"); sys.exit(1)
    data = json.loads(fpath.read_text())
    findings = data.get('findings', [])
    print(f"[UPLOAD] {args.file}: {len(findings)} findings, type={data.get('scan_type')}")
    client = PIIAgentClient(server, api_key)
    ok, msg = client.submit_findings(data.get('scan_type','unknown'), data.get('target','unknown'),
                                      findings, offline_data=data)
    if ok: print("[OK] Uploaded successfully!")
    else: print(f"[FAIL] {msg}"); sys.exit(1)

def cmd_daemon(args):
    from api_client import PIIAgentClient
    cfg = load_config()
    if not cfg.get('server_url'): print("✗ Not configured"); sys.exit(1)
    client = PIIAgentClient(cfg['server_url'], cfg['api_key'])
    interval = args.interval or 300
    print(f"[DAEMON] Heartbeat every {interval}s. Ctrl+C to stop.")
    try:
        while True:
            ok, msg = client.check_activation()
            if ok is False: print(f"[{_ts()}] ✗ DEACTIVATED — stopping"); sys.exit(0)
            hb_ok, hb_msg = client.heartbeat()
            print(f"[{_ts()}] {'✓ Online' if hb_ok else f'✗ {hb_msg}'}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[DAEMON] Stopped.")

# ── MAIN ──────────────────────────────────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(prog='pii-scanner',
                                     description='KnightGuard GRC PII Scanner Agent v2.0')
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('configure', help='Set server URL and API key')
    p.add_argument('--server', required=True); p.add_argument('--api-key', required=True)
    p.set_defaults(func=cmd_configure)

    p = sub.add_parser('status', help='Show status and test connection')
    p.set_defaults(func=cmd_status)

    p = sub.add_parser('scan-db', help='Scan database for PII')
    p.add_argument('--db', required=True,
        help='postgresql://u:p@h/db | oracle://u:p@h:1521/SID | mysql://u:p@h/db | /path/to.db')
    p.add_argument('--max-rows', type=int, default=1000)
    p.add_argument('--threads', type=int, default=20, help='Parallel threads (default 20, max 50)')
    p.add_argument('--offline', action='store_true')
    p.set_defaults(func=cmd_scan_db)

    p = sub.add_parser('scan-files', help='Scan files/dirs/images for PII')
    p.add_argument('--path', required=True)
    p.add_argument('--max-files', type=int, default=5000)
    p.add_argument('--no-ocr', action='store_true', help='Skip OCR on images')
    p.add_argument('--offline', action='store_true')
    p.set_defaults(func=cmd_scan_files)

    p = sub.add_parser('discover', help='Discover databases and endpoints on network')
    p.add_argument('--subnet', help='e.g. 192.168.1 (auto-detected)')
    p.add_argument('--timeout', type=float, default=0.3)
    p.add_argument('--dbs-only', action='store_true')
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser('scan-endpoint', help='Scan remote PCs/laptops for PII')
    p.add_argument('--targets', required=True, help='192.168.1.10,192.168.1.11')
    p.add_argument('--smb-user'); p.add_argument('--smb-pass')
    p.add_argument('--max-files', type=int, default=2000)
    p.add_argument('--no-ocr', action='store_true')
    p.add_argument('--offline', action='store_true')
    p.set_defaults(func=cmd_scan_endpoint)

    p = sub.add_parser('upload', help='Upload offline scan results')
    p.add_argument('--file', required=True)
    p.add_argument('--server'); p.add_argument('--api-key')
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser('daemon', help='Run background heartbeat')
    p.add_argument('--interval', type=int, default=300)
    p.set_defaults(func=cmd_daemon)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
