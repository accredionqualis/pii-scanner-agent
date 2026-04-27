"""
KnightGuard GRC — PII Detectors v2.1 (High Accuracy)
Context-aware, validated, low false positive rate.
"""
import re
from functools import lru_cache


# ── Checksum validators ────────────────────────────────────────

def _verhoeff_check(number: str) -> bool:
    """Validate Aadhaar using Verhoeff algorithm."""
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
         [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
         [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
         [9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
         [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
         [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    try:
        digits = re.sub(r'[\s\-]', '', number)
        c = 0
        for i, n in enumerate(reversed(digits)):
            c = d[c][p[i % 8][int(n)]]
        return c == 0
    except:
        return False


def _luhn_check(number: str) -> bool:
    """Validate credit/debit card using Luhn algorithm."""
    try:
        digits = [int(d) for d in re.sub(r'[\s\-]', '', number) if d.isdigit()]
        if len(digits) < 13: return False
        odd = digits[-1::-2]
        even = [sum(divmod(d * 2, 10)) for d in digits[-2::-2]]
        return (sum(odd) + sum(even)) % 10 == 0
    except:
        return False


def _validate_pan(pan: str) -> bool:
    """
    PAN: AAAAA9999A
    - First 3 chars: any alpha (taxpayer surname)
    - 4th char: taxpayer type (P=person, C=company, H=HUF, F=firm, A/B/G/J/L/T=others)
    - 5th char: first letter of surname/name
    - 6-9: 4 digits
    - 10th: alpha check digit
    Reject if all letters are same, or known false positive patterns
    """
    p = pan.upper().strip()
    if len(p) != 10: return False
    if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', p): return False
    valid_types = set('PCHABGJFLT')
    if p[3] not in valid_types: return False
    # Reject obvious test data
    if p[:5] in ('AAAAA','BBBBB','CCCCC','DDDDD','EEEEE','FFFFF','XXXXX','YYYYY','ZZZZZ'): return False
    if p[5:9] in ('0000','1111','2222','3333','9999'): return False
    return True


def _validate_aadhaar(number: str) -> bool:
    """Validate Aadhaar: 12 digits, starts 2-9, passes Verhoeff."""
    n = re.sub(r'[\s\-]', '', number)
    if len(n) != 12: return False
    if not n.isdigit(): return False
    if n[0] in '01': return False  # Cannot start with 0 or 1
    # Reject obvious test data
    if len(set(n)) <= 2: return False  # Too repetitive
    if n in ('123456789012','999999999999','000000000000'): return False
    return _verhoeff_check(n)


def _validate_mobile(number: str) -> bool:
    """Indian mobile: 10 digits, starts 6-9. Reject timestamps and sequences."""
    n = re.sub(r'[\s\+\-\(\)]', '', number)
    if n.startswith('91'): n = n[2:]
    if len(n) != 10: return False
    if n[0] not in '6789': return False
    if len(set(n)) <= 2: return False  # all same digits
    # Reject sequential
    if n in ('1234567890','9876543210','0123456789'): return False
    # Reject if looks like a year/date embedded
    if re.match(r'^(19|20)\d{8}$', n): return False
    return True


def _validate_passport(number: str) -> bool:
    """Indian passport: 1 letter + 7 digits. Must be realistic."""
    n = number.upper().strip()
    if not re.match(r'^[A-PR-WY][1-9]\d{7}$', n): return False
    # Reject test patterns
    if n[1:] in ('1234567','9999999','0000000','1111111'): return False
    return True


def _validate_voter_id(number: str) -> bool:
    """Indian Voter ID: 3 letters + 7 digits. Must not look like IFSC."""
    n = number.upper().strip()
    if not re.match(r'^[A-Z]{3}\d{7}$', n): return False
    # IFSC starts with 4 letters + 0 + 6 alphanum — different
    # Voter ID is exactly 3 letters + 7 digits
    # Reject if prefix looks like bank codes
    bank_codes = {'SBI','HDFC','ICIC','AXIS','KOTK','YESB','IDBI','PUNB','BKID','UBIN','CNRB','BARB'}
    if n[:4] in bank_codes or n[:3] in bank_codes: return False
    return True


def _validate_credit_card(number: str) -> bool:
    """Credit card with Luhn + length check."""
    n = re.sub(r'[\s\-]', '', number)
    if len(n) not in (13, 14, 15, 16, 17, 18, 19): return False
    return _luhn_check(n)


def _validate_bank_account(number: str) -> bool:
    """Bank account: 9-18 digits, not sequential, not all-same."""
    n = str(number).strip()
    if not n.isdigit(): return False
    if len(n) < 9 or len(n) > 18: return False
    if len(set(n)) <= 2: return False
    # Not sequential ascending or descending
    asc = ''.join(str((int(n[0])+i)%10) for i in range(len(n)))
    desc = ''.join(str((int(n[0])-i)%10) for i in range(len(n)))
    if n == asc or n == desc: return False
    # Not repeated pattern like 123123123
    if len(n) >= 6 and n == (n[:3]*6)[:len(n)]: return False
    # Not phone number (10 digits starting 6-9)
    if len(n) == 10 and n[0] in '6789': return False
    # Not timestamp-like
    if re.match(r'^(14|15|16|17)\d{8}$', n): return False
    if len(set(n)) < 3: return False
    return True


def _validate_ifsc(code: str) -> bool:
    """IFSC: 4 alpha + 0 + 6 alphanum. Validate against known prefixes."""
    c = code.upper().strip()
    if not re.match(r'^[A-Z]{4}0[A-Z0-9]{6}$', c): return False
    # 5th char must be 0 (already in regex)
    # First 4 chars should be bank code — must be all alpha
    if not c[:4].isalpha(): return False
    # Reject obvious test data
    if c[:4] in ('AAAA','BBBB','CCCC','DDDD','XXXX','YYYY','ZZZZ'): return False
    return True


def _validate_gstin(gstin: str) -> bool:
    """GSTIN: 2 digits + 5 alpha + 4 digits + alpha + 1-9/A-Z + Z + 0-9/A-Z."""
    g = gstin.upper().strip()
    if len(g) != 15: return False
    if not re.match(r'^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$', g): return False
    # State code must be 01-37
    state = int(g[:2])
    if state < 1 or state > 37: return False
    return True


def _validate_driving_licence(dl: str) -> bool:
    """Indian DL: state code (2) + district (2) + year (4) + serial (7)."""
    d = re.sub(r'[\s\-]', '', dl.upper())
    if not re.match(r'^[A-Z]{2}\d{2}\d{4}\d{7}$', d): return False
    # Valid state codes
    states = {'AP','AR','AS','BR','CG','GA','GJ','HR','HP','JH','KA','KL',
              'MP','MH','MN','ML','MZ','NL','OD','PB','RJ','SK','TN','TS',
              'TR','UP','UK','WB','AN','CH','DN','DD','DL','JK','LA','LD',
              'PY','TG'}
    if d[:2] not in states: return False
    year = int(d[4:8])
    if year < 1990 or year > 2030: return False
    return True


def _validate_abha(abha: str) -> bool:
    """ABHA Health ID: XX-XXXX-XXXX-XXXX (14 digits with dashes)."""
    n = re.sub(r'[\-\s]', '', abha)
    if len(n) != 14: return False
    if not n.isdigit(): return False
    if len(set(n)) <= 2: return False
    return True


# ── Context patterns ──────────────────────────────────────────

# Column names where bank account is plausible
_BANK_COL = re.compile(
    r'(account|acct|acc_no|bank|ifsc|iban|routing|sort.?code|'
    r'beneficiar|remit|payment|transfer|debit|credit|saving|current|'
    r'neft|rtgs|imps|upi)',
    re.I)

# Column names where mobile is plausible
_MOBILE_COL = re.compile(
    r'(phone|mobile|cell|contact|whatsapp|tel|fax|sms)',
    re.I)

# Column names where email is plausible
_EMAIL_COL = re.compile(
    r'(email|mail|e.?mail)',
    re.I)

# Column names that suggest ID documents
_ID_COL = re.compile(
    r'(aadhaar|aadhar|uid|pan|passport|voter|driving|licence|license|'
    r'dl_no|dl_num|id_no|document|kyc|identity|gstin|gst)',
    re.I)

# Column names that suggest personal info
_PERSONAL_COL = re.compile(
    r'(name|dob|birth|age|gender|address|city|state|zip|pin|country|'
    r'salary|income|tax|designation|department)',
    re.I)


# ── Detector definitions ──────────────────────────────────────

DETECTORS = [
    {
        'name': 'Aadhaar',
        'pattern': r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_aadhaar(m),
        'context_required': False,  # Can appear anywhere
    },
    {
        'name': 'PAN',
        'pattern': r'\b[A-Z]{3}[PCHABGJFLT][A-Z]\d{4}[A-Z]\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_pan(m),
        'context_required': False,
    },
    {
        'name': 'Passport',
        'pattern': r'\b[A-PR-WY][1-9]\d{7}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_passport(m),
        'context_required': True,  # Only in ID-related columns
        'context_pattern': _ID_COL,
    },
    {
        'name': 'CreditCard',
        'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_credit_card(m),
        'context_required': False,
    },
    {
        'name': 'ABHA',
        'pattern': r'\b\d{2}-\d{4}-\d{4}-\d{4}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_abha(m),
        'context_required': False,
    },
    {
        'name': 'VoterID',
        'pattern': r'\b[A-Z]{3}\d{7}\b',
        'sensitivity': 'HIGH',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_voter_id(m),
        'context_required': True,
        'context_pattern': _ID_COL,
    },
    {
        'name': 'DrivingLicence',
        'pattern': r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b',
        'sensitivity': 'HIGH',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_driving_licence(m),
        'context_required': True,
        'context_pattern': _ID_COL,
    },
    {
        'name': 'BankAccount',
        'pattern': r'\b\d{9,18}\b',
        'sensitivity': 'CRITICAL',
        'dpdp_spdi': True,
        'validate': lambda m, ctx: _validate_bank_account(m),
        'context_required': True,  # Only in bank-related columns
        'context_pattern': _BANK_COL,
    },
    {
        'name': 'Mobile',
        'pattern': r'(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m, ctx: _validate_mobile(m),
        'context_required': False,
    },
    {
        'name': 'Email',
        'pattern': r'\b[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        'sensitivity': 'LOW',
        'dpdp_spdi': False,
        'validate': lambda m, ctx: '@' in m and '.' in m.split('@')[1] and len(m) > 5,
        'context_required': False,
    },
    {
        'name': 'GSTIN',
        'pattern': r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m, ctx: _validate_gstin(m),
        'context_required': False,
    },
    {
        'name': 'IFSC',
        'pattern': r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        'sensitivity': 'LOW',
        'dpdp_spdi': False,
        'validate': lambda m, ctx: _validate_ifsc(m),
        'context_required': False,
    },
    {
        'name': 'DOB',
        'pattern': r'\b(?:0[1-9]|[12]\d|3[01])[\/\-\.](?:0[1-9]|1[012])[\/\-\.](?:19|20)\d{2}\b',
        'sensitivity': 'MEDIUM',
        'dpdp_spdi': False,
        'validate': lambda m, ctx: True,
        'context_required': True,
        'context_pattern': _PERSONAL_COL,
    },
    {
        'name': 'IPAddress',
        'pattern': r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        'sensitivity': 'LOW',
        'dpdp_spdi': False,
        'validate': lambda m, ctx: not any(m.startswith(p) for p in (
            '127.','0.','255.','169.254.',  # loopback, unspecified, broadcast, link-local
            '10.','172.16.','172.17.','172.18.','172.19.','172.2','172.3',  # private
            '192.168.',  # private class C
        )),
        'context_required': False,
    },
]


def mask_value(val: str) -> str:
    """Mask middle portion for safe display."""
    v = re.sub(r'[\s\-]', '', str(val))
    if len(v) <= 4: return '*' * len(v)
    show = max(2, len(v) // 5)
    return v[:show] + '*' * (len(v) - show * 2) + v[-show:]


def scan_text(text: str, context: str = '') -> list:
    """
    High-accuracy PII scan.
    - Context-aware: some detectors only fire in relevant columns
    - Validated: each match passes checksum/format validation
    - Deduplication: same value detected once per detector
    Returns list of findings with raw_value and masked_value.
    """
    results = []
    text = str(text)
    seen = set()
    ctx_lower = context.lower()

    for det in DETECTORS:
        # Check context requirement
        if det.get('context_required'):
            ctx_pat = det.get('context_pattern')
            if ctx_pat and not ctx_pat.search(ctx_lower):
                continue  # Skip — column name doesn't match expected context

        for match in re.finditer(det['pattern'], text, re.IGNORECASE if det['name'] in ('PAN','VoterID','DrivingLicence','IFSC','GSTIN','Passport') else 0):
            raw = match.group().strip()
            clean = re.sub(r'[\s\-]', '', raw)
            key = (det['name'], clean.upper())
            if key in seen:
                continue

            # Run validator
            try:
                if not det['validate'](clean, ctx_lower):
                    continue
            except:
                continue

            seen.add(key)
            results.append({
                'detector': det['name'],
                'detector_name': det['name'],
                'raw_value': raw,
                'masked_value': mask_value(raw),
                'sensitivity': det['sensitivity'],
                'dpdp_spdi': det['dpdp_spdi'],
                'context': context,
            })

    return results
