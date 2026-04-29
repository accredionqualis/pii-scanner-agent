"""
KnightGuard GRC PII Scanner Agent — File Scanner
"""
import os
import time
from pathlib import Path
from typing import List, Dict
from detectors import detect_pii

SUPPORTED_EXTENSIONS = {
    '.txt', '.csv', '.json', '.xml', '.log', '.sql',
    '.pdf', '.docx', '.xlsx', '.xls', '.doc',
    '.py', '.js', '.ts', '.java', '.php', '.rb',
    '.yaml', '.yml', '.ini', '.conf', '.env',
    '.html', '.htm', '.md',
}

SKIP_DIRS = {
    '__pycache__', '.git', 'node_modules', '.next',
    'dist', 'build', 'venv', '.venv', 'env',
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


class FileScanner:
    def __init__(self, root_path: str, max_files: int = 1000):
        self.root_path = Path(root_path)
        self.max_files = max_files
        self.scanned = 0
        self.skipped = 0

    def scan(self) -> List[Dict]:
        findings = []
        start = time.time()

        for fpath in self._iter_files():
            if self.scanned >= self.max_files:
                print(f"  Reached max file limit ({self.max_files})")
                break
            file_findings = self._scan_file(fpath)
            findings.extend(file_findings)
            self.scanned += 1
            if self.scanned % 100 == 0:
                print(f"  Scanned {self.scanned} files, {len(findings)} findings...")

        elapsed = round(time.time() - start, 2)
        print(f"  Done: {self.scanned} files scanned, {self.skipped} skipped in {elapsed}s")
        return findings

    def _iter_files(self):
        for root, dirs, files in os.walk(self.root_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in SUPPORTED_EXTENSIONS:
                    yield fpath

    def _scan_file(self, fpath: Path) -> List[Dict]:
        try:
            if fpath.stat().st_size > MAX_FILE_SIZE:
                self.skipped += 1
                return []
            text = fpath.read_text(encoding='utf-8', errors='ignore')
            findings = detect_pii(text, context=str(fpath))
            for f in findings:
                f['file_path'] = str(fpath)
                f['file_name'] = fpath.name
            return findings
        except PermissionError:
            self.skipped += 1
            return []
        except Exception:
            self.skipped += 1
            return []
