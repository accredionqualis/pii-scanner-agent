"""
KnightGuard GRC — PII Agent API Client v2.1
Handles: heartbeat, activation check, findings submission (chunked)
"""
import json
import platform
import socket
import time
from datetime import datetime

AGENT_VERSION = '2.1.0'
CHUNK_SIZE = 500  # findings per batch upload


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'


class PIIAgentClient:
    def __init__(self, server_url, api_key):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/json',
            'User-Agent': f'KnightGuard-Agent/{AGENT_VERSION}',
        }

    def _post(self, path, data, timeout=60):
        import urllib.request, urllib.error
        body = json.dumps(data, default=str).encode()
        req = urllib.request.Request(
            f"{self.server_url}{path}",
            data=body, headers=self.headers, method='POST'
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode()
            except:
                err_body = ''
            return e.code, err_body
        except Exception as ex:
            return 0, str(ex)

    def _get(self, path, timeout=10):
        import urllib.request, urllib.error
        req = urllib.request.Request(
            f"{self.server_url}{path}",
            headers=self.headers, method='GET'
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception as ex:
            return 0, str(ex)

    def check_activation(self):
        code, resp = self._get('/api/v1/pii-scanner/heartbeat/check')
        if code in (200, 201):
            if isinstance(resp, dict) and resp.get('active') is False:
                return False, 'Deactivated by admin'
            return None, None
        elif code == 403:
            return False, 'Deactivated'
        return True, f'HTTP {code}'

    def heartbeat(self):
        data = {
            'hostname': socket.gethostname(),
            'ip_address': _get_local_ip(),
            'platform': platform.system(),
            'os_version': platform.release(),
            'version': AGENT_VERSION,
            'status': 'online',
            'timestamp': datetime.now().isoformat(),
        }
        code, resp = self._post('/api/v1/pii-scanner/heartbeat', data)
        return code in (200, 201), resp

    def submit_findings(self, scan_type, target, findings, offline_data=None):
        """
        Submit findings in chunks of CHUNK_SIZE to avoid timeouts.
        Large scans (44k tables) can produce thousands of findings —
        sending all at once causes the connection to hang/timeout.
        """
        if not findings:
            # Still create a scan record with 0 findings
            payload = self._build_payload(scan_type, target, [], offline_data,
                                          chunk=1, total_chunks=1,
                                          total_findings=0)
            code, resp = self._post('/api/v1/pii-scanner/findings', payload)
            return code in (200, 201), resp

        total = len(findings)
        chunks = [findings[i:i+CHUNK_SIZE] for i in range(0, total, CHUNK_SIZE)]
        total_chunks = len(chunks)

        if total_chunks == 1:
            print(f"  Uploading {total} findings...")
        else:
            print(f"  Uploading {total} findings in {total_chunks} batches of {CHUNK_SIZE}...")

        scan_id = None
        for i, chunk in enumerate(chunks, 1):
            payload = self._build_payload(
                scan_type, target, chunk, offline_data,
                chunk=i, total_chunks=total_chunks,
                total_findings=total,
                scan_id=scan_id  # link subsequent chunks to same scan
            )
            # Retry up to 3 times per chunk
            for attempt in range(3):
                code, resp = self._post('/api/v1/pii-scanner/findings', payload, timeout=60)
                if code in (200, 201):
                    # Capture scan_id from first chunk response
                    if scan_id is None and isinstance(resp, dict):
                        scan_id = resp.get('scan_id')
                    if total_chunks > 1:
                        print(f"  Batch {i}/{total_chunks} uploaded ({len(chunk)} findings) ✓")
                    break
                else:
                    if attempt < 2:
                        print(f"  Batch {i} attempt {attempt+1} failed ({code}) — retrying...")
                        time.sleep(2)
                    else:
                        print(f"  Batch {i} failed after 3 attempts: {code} {resp}")
                        return False, f'Chunk {i} failed: HTTP {code}'

        print(f"  All {total} findings uploaded successfully ✓")
        return True, {'scan_id': scan_id, 'total': total}

    def _build_payload(self, scan_type, target, findings, offline_data,
                       chunk=1, total_chunks=1, total_findings=0, scan_id=None):
        payload = {
            'scan_type': scan_type,
            'target': target,
            'hostname': socket.gethostname(),
            'ip_address': _get_local_ip(),
            'platform': platform.system(),
            'agent_version': AGENT_VERSION,
            'scanned_at': datetime.now().isoformat(),
            'total_findings': total_findings,
            'findings': findings,
            'chunk': chunk,
            'total_chunks': total_chunks,
        }
        if scan_id:
            payload['scan_id'] = scan_id
        if offline_data:
            payload['original_scan_time'] = offline_data.get('scanned_at')
            payload['offline_upload'] = True
        return payload
