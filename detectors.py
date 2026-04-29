"""
KnightGuard GRC PII Scanner Agent — PII Detectors
Indian PII patterns with validation
"""
import re
from typing import List, Dict

# ── Patterns ──────────────────────────────────────────────────────
PATTERNS = {
    'aadhaar': {
        'pattern': r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b',
        'severity': 'critical',
        'description': 'Aadhaar Number',
    },
    'pan': {
        'pattern': r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        'severity': 'critical',
        'description': 'PAN Card Number',
    },
    'passport': {
        'pattern': r'\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b',
        'severity': 'high',
        'description': 'Indian Passport Number',
    },
    'mobile_in': {
        'pattern': r'(?<!\d)(\+91[\-\s]?)?[6-9]\d{9}(?!\d)',
        'severity': 'medium',
        'description': 'Indian Mobile Number',
    },
    'email': {
        'pattern': r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        'severity': 'medium',
        'description': 'Email Address',
    },
    'gstin': {
        'pattern': r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b',
        'severity': 'medium',
        'description': 'GSTIN',
    },
    'voter_id': {
        'pattern': r'\b[A-Z]{3}\d{7}\b',
        'severity': 'high',
        'description': 'Voter ID',
    },
    'driving_licence': {
        'pattern': r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b',
        'severity': 'high',
        'description': 'Driving Licence',
    },
    'credit_card': {
        'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        'severity': 'critical',
        'description': 'Credit/Debit Card Number',
    },
    'ifsc': {
        'pattern': r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        'severity': 'low',
        'description': 'IFSC Code',
    },
    'abha': {
        'pattern': r'\b\d{2}-\d{4}-\d{4}-\d{4}\b',
        'severity': 'high',
        'description': 'ABHA Health ID',
    },
    'ip_address': {
        'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'severity': 'low',
        'description': 'IP Address',
    },
    'bank_account': {
        'pattern': r'\b[0-9]{9,18}\b',
        'severity': 'critical',
        'description': 'Potential Bank Account Number',
    },
    'dob': {
        'pattern': r'\b(?:0[1-9]|[12][0-9]|3[01])[-/.](?:0[1-9]|1[012])[-/.](?:19|20)\d\d\b',
        'severity': 'medium',
        'description': 'Date of Birth',
    },
}

def detect_pii(text: str, context: str = '') -> List[Dict]:
    findings = []
    for pii_type, info in PATTERNS.items():
        matches = re.finditer(info['pattern'], text)
        for match in matches:
            # Get surrounding context
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            snippet = text[start:end].strip()
            # Mask the actual value
            value = match.group()
            masked = mask_value(value, pii_type)
            findings.append({
                'pii_type': pii_type,
                'description': info['description'],
                'severity': info['severity'],
                'masked_value': masked,
                'context': context,
                'snippet': snippet[:100],
            })
    return findings

def mask_value(value: str, pii_type: str) -> str:
    """Mask PII value for safe reporting"""
    clean = re.sub(r'[\s\-]', '', value)
    if len(clean) <= 4:
        return '*' * len(clean)
    visible = 2
    return clean[:visible] + '*' * (len(clean) - visible * 2) + clean[-visible:]
