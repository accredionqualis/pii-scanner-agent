import re
import hashlib

def verhoeff_check(number):
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    inv = [0,4,3,2,1,5,6,7,8,9]
    c = 0
    for i,n in enumerate(reversed(number)):
        c = d[c][p[i%8][int(n)]]
    return c == 0

def luhn_check(number):
    digits = [int(d) for d in str(number) if d.isdigit()]
    odd = digits[-1::-2]
    even = [sum(divmod(d*2,10)) for d in digits[-2::-2]]
    return (sum(odd)+sum(even)) % 10 == 0

DETECTORS = [
    {'name':'Aadhaar','pattern':r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b','sensitivity':'CRITICAL','dpdp_spdi':True,
     'validate':lambda m: verhoeff_check(re.sub(r'\s','',m))},
    {'name':'PAN','pattern':r'\b[A-Z]{3}[ABCFGHLJPTF][A-Z]\d{4}[A-Z]\b','sensitivity':'HIGH','dpdp_spdi':True,
     'validate':lambda m: True},
    {'name':'Passport','pattern':r'\b[A-PR-WYa-pr-wy][1-9]\d{7}\b','sensitivity':'CRITICAL','dpdp_spdi':True,
     'validate':lambda m: True},
    {'name':'Mobile','pattern':r'\b[6-9]\d{9}\b','sensitivity':'MEDIUM','dpdp_spdi':False,
     'validate':lambda m: True},
    {'name':'Email','pattern':r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b','sensitivity':'LOW','dpdp_spdi':False,
     'validate':lambda m: True},
    {'name':'GSTIN','pattern':r'\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b','sensitivity':'MEDIUM','dpdp_spdi':False,
     'validate':lambda m: True},
    {'name':'VoterID','pattern':r'\b[A-Z]{3}\d{7}\b','sensitivity':'HIGH','dpdp_spdi':True,
     'validate':lambda m: True},
    {'name':'DrivingLicence','pattern':r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}\b','sensitivity':'HIGH','dpdp_spdi':True,
     'validate':lambda m: True},
    {'name':'ABHA','pattern':r'\b\d{2}-\d{4}-\d{4}-\d{4}\b','sensitivity':'CRITICAL','dpdp_spdi':True,
     'validate':lambda m: True},
    {'name':'CreditCard','pattern':r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b','sensitivity':'CRITICAL','dpdp_spdi':False,
     'validate':luhn_check},
    {'name':'IFSC','pattern':r'\b[A-Z]{4}0[A-Z0-9]{6}\b','sensitivity':'LOW','dpdp_spdi':False,
     'validate':lambda m: True},
    {'name':'IPAddress','pattern':r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b','sensitivity':'LOW','dpdp_spdi':False,
     'validate':lambda m: True},
]

def scan_text(text, max_samples=5):
    findings = []
    for det in DETECTORS:
        matches = re.findall(det['pattern'], text)
        valid = [m for m in matches if det['validate'](re.sub(r'\s','',m))]
        if valid:
            findings.append({
                'detector': det['name'],
                'sensitivity': det['sensitivity'],
                'dpdp_spdi': det['dpdp_spdi'],
                'sample_count': len(valid),
                'samples': [hashlib.sha256(v.encode()).hexdigest()[:8]+'***' for v in valid[:max_samples]]
            })
    return findings

if __name__ == '__main__':
    test = "Name: Rahul Kumar, Aadhaar: 2345 6789 0123, PAN: ABCDE1234F, Mobile: 9876543210, Email: rahul@test.com"
    results = scan_text(test)
    for r in results:
        print(f"{r['detector']}: {r['sample_count']} found ({r['sensitivity']})")
