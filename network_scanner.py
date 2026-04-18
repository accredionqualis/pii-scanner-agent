import socket
import concurrent.futures
from datetime import datetime

DB_PORTS = {
    3306: 'MySQL',
    5432: 'PostgreSQL', 
    1433: 'MSSQL',
    1521: 'Oracle',
    27017: 'MongoDB',
    6379: 'Redis',
    9200: 'Elasticsearch',
    5984: 'CouchDB',
    7474: 'Neo4j',
    8086: 'InfluxDB',
}

def scan_port(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_host(host):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan_port, host, port): (port, name) for port, name in DB_PORTS.items()}
        for future in concurrent.futures.as_completed(futures):
            port, name = futures[future]
            if future.result():
                found.append({'host': host, 'port': port, 'service': name, 'discovered_at': datetime.now().isoformat()})
    return found

def scan_network(cidr, progress_cb=None):
    import ipaddress
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())[:254]  # max 254
    all_found = []
    for i, host in enumerate(hosts):
        if progress_cb and i % 10 == 0:
            progress_cb(f"Scanning {host} ({i+1}/{len(hosts)})")
        found = scan_host(str(host))
        all_found.extend(found)
    return all_found

if __name__ == '__main__':
    print("Scanning localhost...")
    results = scan_host('127.0.0.1')
    for r in results:
        print(f"  {r['host']}:{r['port']} - {r['service']}")
    print(f"Found {len(results)} services")
