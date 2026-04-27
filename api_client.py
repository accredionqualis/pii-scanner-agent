"""
KnightGuard GRC — PII Agent API Client v2.0
Handles: heartbeat, activation check, findings submission
"""
import json
import platform
import socket
import time
from datetime import datetime

AGENT_VERSION = '2.0.0'


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

    def _post(self, path, data, timeout=30):
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
            return e.code, {}
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
        """
        Returns:
          (None, None)  — active and connected
          (False, msg)  — deactivated by admin
          (True,  msg)  — error connecting
        """
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
        Submit findings — sends FULL PII values (feature #7).
        findings: list of dicts each containing actual scanned values.
        """
        payload = {
            'scan_type': scan_type,
            'target': target,
            'hostname': socket.gethostname(),
            'ip_address': _get_local_ip(),
            'platform': platform.system(),
            'agent_version': AGENT_VERSION,
            'scanned_at': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': findings,  # full data including raw values
        }
        if offline_data:
            payload['original_scan_time'] = offline_data.get('scanned_at')
            payload['offline_upload'] = True

        code, resp = self._post('/api/v1/pii-scanner/findings', payload, timeout=120)
        if code in (200, 201):
            return True, resp
        return False, f'HTTP {code}: {resp}'
