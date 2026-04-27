"""
KnightGuard GRC — PII Detectors v2.0
Verhoeff/Luhn validated. Returns full raw values + masked values.
"""
import re


def verhoeff_check(number):
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
         [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
         [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
         [9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
         [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
         [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    c = 0
    for i, n in enumerate(reversed(number)):
        c = d[c][p[i % 8][int(n)]]
    return c == 0


def luhn_check(number):
    digits = [int(d) for d in str(number) if d.isdigit()]
    odd = digits[-1::-2]
    even = [sum(divmod(d * 2, 10)) for d in digits[-2::-2]]
    return (sum(odd) + sum(even)) % 10 == 0


def mask_value(val):
    """Mask middle portion of value for safe display."""
    v = re.sub(r'[\s\-]', '', str(val))
    if len(v) <= 4:
        return '*' * len(v)
    show = max(2, len(v) // 4)
    return v[:show] + '*' * (len(v) - show * 2) + v[-show:]


def _validate_bank_account(number):
    """
    Reject obvious false positives:
    - Pure sequential numbers (123456789)
    - All same digit (999999999)
    - Common patterns (timestamps, phone numbers already caught by Mobile detector)
    - Numbers that look like years/dates
    - Numbers starting with 0000
    """
    n = str(number).strip()
    if len(n) < 9 or len(n) > 18:
        return False
    # Reject all same digits
    if len(set(n)) == 1:
        return False
    # Reject sequential ascending (123456789)
    if n == ''.join(str(i % 10) for i in range(int(n[0]), int(n[0]) + len(n))):
        return False
    # Reject sequential descending (987654321)
    if n == ''.join(str(abs(9 - i) % 10) for i in range(len(n))):
        return False
    # Reject if starts with 0000
    if n.startswith('0000'):
        return False
    # Reject obvious phone numbers (already caught by Mobile detector)
    if len(n) == 10 and n[0] in '6789':
        return False
    # Reject 10-digit numbers starting with +91 prefix patterns
    if len(n) == 12 and n[:2] == '91' and n[2] in '6789':
        return False
    # Must have at least 3 different digits to be a real account number
    if len(set(n)) < 3:
        return False
    return True


DETECTORS = [
    {
        'name': 'Aadhaar',
        'pattern': r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m: verhoeff_check(re.sub(r'\s', '', m)),
    },
    {
        'name': 'PAN',
        'pattern': r'\b[A-Z]{3}[ABCFGHLJPTF][A-Z]\d{4}[A-Z]\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m: True,
    },
    {
        'name': 'Passport',
        'pattern': r'\b[A-PR-WY][1-9]\d{7}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m: True,
    },
    {
        'name': 'VoterID',
        'pattern': r'\b[A-Z]{3}\d{7}\b',
        'sensitivity': 'HIGH',
        'dpdp_spdi': True,
        'validate': lambda m: True,
    },
    {
        'name': 'DrivingLicence',
        'pattern': r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b',
        'sensitivity': 'HIGH',
        'dpdp_spdi': True,
        'validate': lambda m: True,
    },
    {
        'name': 'CreditCard',
        'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m: luhn_check(re.sub(r'\s', '', m)),
    },
    {
        'name': 'BankAccount',
        'pattern': r'\b[0-9]{9,18}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m: True,
    },
    {
        'name': 'IFSC',
        'pattern': r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m: True,
    },
    {
        'name': 'Mobile',
        'pattern': r'(?<!\d)(\+91[\-\s]?)?[6-9]\d{9}(?!\d)',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m: True,
    },
    {
        'name': 'Email',
        'pattern': r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        'sensitivity': 'LOW',
        'dpdp_spdi': False,
        'validate': lambda m: True,
    },
    {
        'name': 'GSTIN',
        'pattern': r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m: True,
    },
    {
        'name': 'ABHA',
        'pattern': r'\b\d{2}-\d{4}-\d{4}-\d{4}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m: True,
    },
    {
        'name': 'DOB',
        'pattern': r'\b(?:0[1-9]|[12][0-9]|3[01])[-/.](?:0[1-9]|1[012])[-/.](?:19|20)\d{2}\b',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m: True,
    },
    {
        'name': 'IPAddress',
        'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'sensitivity': 'LOW',
        'dpdp_spdi': False,
        'validate': lambda m: True,
    },
]


# Columns where bank account numbers are likely
BANK_LIKELY_COLS = re.compile(
    r'(account|acct|acc|bank|ifsc|iban|bsb|routing|sort.?code|'
    r'beneficiar|remit|payment|transfer|debit|credit|saving|current)',
    re.IGNORECASE
)

# Detectors to skip in non-PII contexts
CONTEXT_RESTRICTED = {'BankAccount'}


def scan_text(text, context=''):
    """
    Scan text and return list of findings.
    Each finding includes: raw_value, masked_value, detector, sensitivity, context.
    Feature #7: raw_value contains the actual scanned data.
    Context-aware: BankAccount only flagged in bank-related columns.
    """
    results = []
    text = str(text)
    seen = set()
    is_bank_context = bool(BANK_LIKELY_COLS.search(context))

    for det in DETECTORS:
        for match in re.finditer(det['pattern'], text):
            raw = match.group()
            clean = re.sub(r'[\s\-]', '', raw)
            key = (det['name'], clean)
            if key in seen:
                continue
            try:
                if not det['validate'](clean):
                    continue
            except:
                continue
            # Skip BankAccount in non-bank columns to reduce false positives
            if det['name'] in CONTEXT_RESTRICTED and not is_bank_context:
                continue
            seen.add(key)
            results.append({
                'detector': det['name'],
                'detector_name': det['name'],
                'raw_value': raw,           # FULL actual value — feature #7
                'masked_value': mask_value(raw),
                'sensitivity': det['sensitivity'],
                'dpdp_spdi': det['dpdp_spdi'],
                'context': context,
            })

    return results
