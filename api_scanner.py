#!/usr/bin/env python3
"""
SCE GRC PII Scanner - API Endpoint Scanner
Scans REST API endpoints for PII data in responses
"""
import requests
import json
import re
from detectors import get_all_detectors

def scan_json(obj, path='', detectors=None):
    """Recursively scan JSON object for PII"""
    if detectors is None:
        detectors = get_all_detectors()
    findings = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            findings.extend(scan_json(v, f"{path}.{k}" if path else k, detectors))
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:10]):  # limit to first 10 items
            findings.extend(scan_json(item, f"{path}[{i}]", detectors))
    elif isinstance(obj, str) and obj.strip():
        text = obj
        for name, detector in detectors.items():
            matches = detector(text)
            if matches:
                raw = matches[:3]
                masked = []
                for s in raw:
                    s = str(s)
                    if len(s) > 4:
                        masked.append(s[:2] + '*'*(len(s)-4) + s[-2:])
                    else:
                        masked.append('****')
                findings.append({
                    'detector': name,
                    'json_path': path,
                    'sample_count': len(matches),
                    'sensitivity': 'CRITICAL' if name in ['aadhaar','pan','passport','credit_card'] else 'HIGH',
                    'is_dpdp_spdi': name in ['aadhaar','pan','passport','dob','mobile'],
                    'sample_values': masked,
                })
    return findings


def scan_api_endpoints(base_url, endpoints, headers=None, verify_ssl=True):
    """Scan list of API endpoints for PII"""
    if headers is None:
        headers = {}
    detectors = get_all_detectors()
    all_findings = []
    results = []

    print(f"\n{'='*60}")
    print(f"SCE GRC PII Scanner - API Endpoint Scanner")
    print(f"Base URL: {base_url}")
    print(f"Endpoints: {len(endpoints)}")
    print(f"{'='*60}")

    for endpoint in endpoints:
        url = base_url.rstrip('/') + '/' + endpoint.lstrip('/')
        print(f"\n  Scanning: {url}")
        try:
            resp = requests.get(url, headers=headers, timeout=15, verify=verify_ssl)
            status = resp.status_code
            print(f"  Status: {status}")
            if status != 200:
                results.append({
                    'endpoint': endpoint,
                    'url': url,
                    'status': status,
                    'findings': [],
                    'error': f'HTTP {status}'
                })
                continue

            # Try to parse as JSON
            try:
                data = resp.json()
            except Exception:
                data = resp.text

            # Scan the response
            if isinstance(data, (dict, list)):
                findings = scan_json(data, detectors=detectors)
            else:
                findings = []
                for name, detector in detectors.items():
                    matches = detector(str(data))
                    if matches:
                        masked = [str(m)[:2]+'****'+str(m)[-2:] for m in matches[:3]]
                        findings.append({
                            'detector': name,
                            'json_path': 'response_body',
                            'sample_count': len(matches),
                            'sensitivity': 'HIGH',
                            'is_dpdp_spdi': name in ['aadhaar','pan','passport'],
                            'sample_values': masked,
                        })

            print(f"  Findings: {len(findings)}")
            for f in findings:
                print(f"    [{f['sensitivity']}] {f['detector']} at {f['json_path']} ({f['sample_count']} matches)")

            # Convert to submission format
            for f in findings:
                all_findings.append({
                    'detector': f['detector'],
                    'table_name': endpoint,
                    'column_name': f['json_path'],
                    'file_path': url,
                    'sample_count': f['sample_count'],
                    'sensitivity': f['sensitivity'],
                    'is_dpdp_spdi': f['is_dpdp_spdi'],
                    'sample_values': f['sample_values'],
                })

            results.append({
                'endpoint': endpoint,
                'url': url,
                'status': status,
                'findings': findings,
            })

        except requests.exceptions.ConnectionError:
            print(f"  ERROR: Cannot connect to {url}")
            results.append({'endpoint': endpoint, 'url': url, 'status': 0, 'findings': [], 'error': 'Connection failed'})
        except requests.exceptions.Timeout:
            print(f"  ERROR: Timeout on {url}")
            results.append({'endpoint': endpoint, 'url': url, 'status': 0, 'findings': [], 'error': 'Timeout'})
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({'endpoint': endpoint, 'url': url, 'status': 0, 'findings': [], 'error': str(e)})

    print(f"\n{'='*60}")
    print(f"Total PII findings: {len(all_findings)}")
    print(f"{'='*60}\n")
    return all_findings, results
