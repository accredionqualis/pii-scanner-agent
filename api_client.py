"""
KnightGuard GRC PII Scanner Agent — API Client
"""
import json
import socket
import platform
import requests
from typing import Tuple

class PIIAgentClient:
    def __init__(self, server_url: str, api_key: str):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/json',
            'User-Agent': f'KnightGuard-PII-Agent/1.1 ({platform.system()})',
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def test_connection(self) -> Tuple[bool, str]:
        try:
            r = self.session.get(f'{self.server_url}/api/v1/health', timeout=10)
            if r.status_code == 200:
                return True, 'OK'
            return False, f'HTTP {r.status_code}'
        except Exception as e:
            return False, str(e)

    def heartbeat(self, sysinfo: dict) -> Tuple[bool, str]:
        try:
            payload = {
                'hostname': sysinfo.get('hostname', ''),
                'ip_address': sysinfo.get('ip_address', ''),
                'platform': sysinfo.get('platform', ''),
                'version': sysinfo.get('version', '1.1.0'),
                'status': 'online',
            }
            r = self.session.post(
                f'{self.server_url}/api/v1/pii-agent/heartbeat',
                json=payload, timeout=10
            )
            if r.status_code in (200, 201):
                return True, 'OK'
            return False, f'HTTP {r.status_code}: {r.text[:100]}'
        except Exception as e:
            return False, str(e)

    def submit_findings(self, findings: list, sysinfo: dict) -> Tuple[bool, str]:
        try:
            payload = {
                'hostname': sysinfo.get('hostname', ''),
                'ip_address': sysinfo.get('ip_address', ''),
                'platform': sysinfo.get('platform', ''),
                'target': sysinfo.get('target', 'file-system'),
                'findings': findings,
                'total_findings': len(findings),
                'scan_duration': sysinfo.get('scan_duration', 0),
            }
            r = self.session.post(
                f'{self.server_url}/api/v1/pii-agent/findings',
                json=payload, timeout=30
            )
            if r.status_code in (200, 201):
                return True, 'OK'
            return False, f'HTTP {r.status_code}: {r.text[:200]}'
        except Exception as e:
            return False, str(e)
