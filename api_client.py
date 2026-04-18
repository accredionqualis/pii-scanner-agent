import requests
import json
import socket
import platform

class PIIAgentClient:
    def __init__(self, server_url, api_key):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.headers = {'x-api-key': api_key, 'Content-Type': 'application/json'}

    def heartbeat(self):
        try:
            data = {
                'hostname': socket.gethostname(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'version': '1.0.0',
                'platform': platform.system()
            }
            r = requests.post(f'{self.server_url}/api/v1/pii-agent/heartbeat',
                json=data, headers=self.headers, timeout=10)
            return r.status_code == 200 or r.status_code == 201
        except Exception as e:
            print(f"Heartbeat failed: {e}")
            return False

    def submit_findings(self, scan_type, target, findings):
        try:
            data = {
                'scan_type': scan_type,
                'target': target,
                'findings': findings
            }
            r = requests.post(f'{self.server_url}/api/v1/pii-agent/findings',
                json=data, headers=self.headers, timeout=30)
            return r.json()
        except Exception as e:
            print(f"Submit failed: {e}")
            return None

    def test_connection(self):
        return self.heartbeat()

if __name__ == '__main__':
    client = PIIAgentClient('https://uat-api.scegrc.com', 'test-key')
    print("API client ready")
