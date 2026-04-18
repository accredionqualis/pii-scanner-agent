import os
import re
from detectors import scan_text

SUPPORTED_EXTENSIONS = {'.txt','.csv','.log','.json','.xml','.sql','.md','.html','.htm'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
SKIP_DIRS = {'node_modules','.git','__pycache__','.next','dist','build','venv','.venv'}

class FileScanner:
    def __init__(self, path, api_client=None):
        self.path = path
        self.api_client = api_client

    def scan(self, progress_cb=None):
        findings = []
        files_scanned = 0
        for root, dirs, files in os.walk(self.path):
            # Skip system directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SUPPORTED_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        text = f.read()
                    file_findings = scan_text(text)
                    for finding in file_findings:
                        findings.append({
                            'detector': finding['detector'],
                            'file_path': fpath,
                            'table_name': '',
                            'column_name': '',
                            'sample_count': finding['sample_count'],
                            'sensitivity': finding['sensitivity'],
                            'is_dpdp_spdi': finding['dpdp_spdi'],
                        })
                    files_scanned += 1
                    if progress_cb and files_scanned % 10 == 0:
                        progress_cb(f"Scanned {files_scanned} files...")
                except Exception:
                    pass
        return findings

if __name__ == '__main__':
    import tempfile, os
    d = tempfile.mkdtemp()
    with open(os.path.join(d,'test.csv'),'w') as f:
        f.write("name,email,phone,aadhaar\nRahul,rahul@test.com,9876543210,234567890126\n")
    scanner = FileScanner(d)
    results = scanner.scan(print)
    for r in results:
        print(f"  {r['file_path']}: {r['detector']} ({r['sensitivity']})")
    import shutil
    shutil.rmtree(d)
