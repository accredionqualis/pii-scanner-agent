"""
KnightGuard GRC — Network Scanner v2.0
Discovers databases and endpoints (laptops/desktops/servers) on network.
Multi-threaded — scans all 254 hosts in parallel.
"""
import socket
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_PORTS = {
    5432: ('PostgreSQL', 'postgresql://USER:PASS@{ip}/DATABASE'),
    3306: ('MySQL/MariaDB', 'mysql://USER:PASS@{ip}/DATABASE'),
    1433: ('Microsoft SQL Server', 'mssql://USER:PASS@{ip}/DATABASE'),
    1521: ('Oracle Database', 'oracle://USER:PASS@{ip}:1521/ORCL'),
    1522: ('Oracle (alt)', 'oracle://USER:PASS@{ip}:1522/ORCL'),
    27017: ('MongoDB', 'mongodb://USER:PASS@{ip}/DATABASE'),
    5984: ('CouchDB', 'http://{ip}:5984'),
    9200: ('Elasticsearch', 'http://{ip}:9200'),
    6379: ('Redis', 'redis://{ip}:6379'),
}

ENDPOINT_PORTS = {
    445: 'Windows SMB',
    139: 'Windows NetBIOS',
    22: 'SSH (Linux/Mac)',
    3389: 'Windows RDP',
    5900: 'VNC',
}


def _check_port(ip, port, timeout=0.3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except:
        return False


def _get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ''


def _detect_os(ip, open_ports):
    """Guess OS from open ports."""
    if 445 in open_ports or 3389 in open_ports:
        return 'Windows'
    if 22 in open_ports:
        return 'Linux/Mac'
    return 'Unknown'


def _scan_host(ip, timeout, dbs_only):
    """Scan a single host for all relevant ports."""
    results = []
    all_ports = list(DB_PORTS.keys()) + ([] if dbs_only else list(ENDPOINT_PORTS.keys()))

    open_ports = []
    for port in all_ports:
        if _check_port(ip, port, timeout):
            open_ports.append(port)

    for port in open_ports:
        if port in DB_PORTS:
            db_name, hint_template = DB_PORTS[port]
            results.append({
                'type': 'database',
                'ip': ip,
                'port': port,
                'db_type': db_name,
                'connect_hint': hint_template.replace('{ip}', ip),
            })

    if not dbs_only:
        ep_ports = [p for p in open_ports if p in ENDPOINT_PORTS]
        if ep_ports:
            hostname = _get_hostname(ip)
            os_guess = _detect_os(ip, ep_ports)
            results.append({
                'type': 'endpoint',
                'ip': ip,
                'hostname': hostname,
                'os': os_guess,
                'open_ports': [ENDPOINT_PORTS[p] for p in ep_ports],
            })

    return results


def discover_network(subnet, timeout=0.3, dbs_only=False):
    """
    Scan all 254 hosts on subnet.xxx.1–254 in parallel.
    Returns list of discovered databases and endpoints.
    """
    results = []
    ips = [f"{subnet}.{i}" for i in range(1, 255)]

    print(f"  Scanning {len(ips)} hosts with 100 parallel threads...")
    found = 0

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(_scan_host, ip, timeout, dbs_only): ip for ip in ips}
        done = 0
        for future in as_completed(futures):
            done += 1
            host_results = future.result()
            if host_results:
                results.extend(host_results)
                found += 1
                for r in host_results:
                    if r['type'] == 'database':
                        print(f"  ✓ [{r['db_type']:15s}] {r['ip']}:{r['port']}")
                    else:
                        print(f"  ✓ [Endpoint       ] {r['ip']} {r.get('hostname','')} ({r.get('os','')})")
            if done % 50 == 0:
                print(f"  Progress: {done}/254 hosts scanned, {found} found...")

    return results
