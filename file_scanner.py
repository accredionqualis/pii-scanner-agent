"""
KnightGuard GRC — File Scanner v2.0
Scans text files, PDFs, Office docs, and images (OCR).
Sends full raw PII values (feature #7).
"""
import os
import re
from pathlib import Path
from detectors import scan_text
from logger import vprint

TEXT_EXTENSIONS = {
    '.txt', '.csv', '.json', '.xml', '.log', '.sql',
    '.py', '.js', '.ts', '.html', '.htm', '.md',
    '.yaml', '.yml', '.ini', '.conf', '.config', '.env',
    '.sh', '.bat', '.ps1', '.properties', '.toml',
    '.eml', '.msg',
}
OFFICE_EXTENSIONS = {'.docx', '.xlsx', '.pptx', '.odt', '.ods'}
PDF_EXTENSIONS = {'.pdf'}
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif', '.gif', '.webp'}

SKIP_DIRS = {
    '__pycache__', '.git', 'node_modules', '.next', 'dist',
    'build', 'venv', '.venv', 'env', 'Windows', 'Program Files',
    'Program Files (x86)', '$Recycle.Bin', 'AppData',
    'System32', 'SysWOW64',
}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB


def _make_finding(findings_list, file_path):
    """Group raw scan results into per-file findings."""
    from collections import defaultdict
    groups = defaultdict(list)
    for f in findings_list:
        groups[f['detector']].append(f)

    results = []
    for detector, items in groups.items():
        results.append({
            'detector': detector,
            'detector_name': detector,
            'file_path': str(file_path),
            'sensitivity': items[0]['sensitivity'],
            'dpdp_spdi': items[0]['dpdp_spdi'],
            'sample_count': len(items),
            'raw_values': [i['raw_value'] for i in items],       # Feature #7
            'masked_values': [i['masked_value'] for i in items],
            'sample_values': [i['masked_value'] for i in items],
        })
    return results


def scan_text_file(filepath):
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return []
        text = open(filepath, encoding='utf-8', errors='ignore').read()
        raw = scan_text(text, str(filepath))
        return _make_finding(raw, filepath)
    except Exception:
        return []


def scan_pdf(filepath):
    try:
        import pdfplumber
        text = ''
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages[:50]:  # max 50 pages
                t = page.extract_text()
                if t:
                    text += t + '\n'
        raw = scan_text(text, str(filepath))
        return _make_finding(raw, filepath)
    except ImportError:
        # Fallback: read raw bytes and look for text
        try:
            content = open(filepath, 'rb').read().decode('latin-1', errors='ignore')
            raw = scan_text(content, str(filepath))
            return _make_finding(raw, filepath)
        except Exception:
            return []
    except Exception:
        return []


def scan_office(filepath):
    ext = Path(filepath).suffix.lower()
    text = ''
    try:
        if ext == '.docx':
            import zipfile
            with zipfile.ZipFile(filepath) as z:
                if 'word/document.xml' in z.namelist():
                    xml = z.read('word/document.xml').decode('utf-8', errors='ignore')
                    text = re.sub(r'<[^>]+>', ' ', xml)
        elif ext == '.xlsx':
            import zipfile
            with zipfile.ZipFile(filepath) as z:
                for name in z.namelist():
                    if name.startswith('xl/worksheets/') and name.endswith('.xml'):
                        xml = z.read(name).decode('utf-8', errors='ignore')
                        text += re.sub(r'<[^>]+>', ' ', xml) + '\n'
        elif ext in ('.pptx', '.odt', '.ods'):
            import zipfile
            with zipfile.ZipFile(filepath) as z:
                for name in z.namelist():
                    if name.endswith('.xml'):
                        xml = z.read(name).decode('utf-8', errors='ignore')
                        text += re.sub(r'<[^>]+>', ' ', xml) + '\n'
    except Exception:
        pass

    if text:
        raw = scan_text(text, str(filepath))
        return _make_finding(raw, filepath)
    return []


def scan_image_ocr(filepath):
    """OCR scan — extracts text from images of Aadhaar, PAN, etc."""
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(filepath)
        # Try multiple PSM modes for different card layouts
        texts = []
        for psm in (6, 3, 11):
            try:
                t = pytesseract.image_to_string(img, config=f'--psm {psm}')
                if t.strip():
                    texts.append(t)
            except Exception:
                pass
        text = '\n'.join(texts)
        if not text.strip():
            return []
        raw = scan_text(text, str(filepath))
        findings = _make_finding(raw, filepath)
        for f in findings:
            f['source'] = 'ocr'
        return findings
    except ImportError:
        return []  # OCR not available — skip silently
    except Exception:
        return []


def scan_files(root_path, max_files=5000, ocr_images=True, send_raw=True):
    """
    Recursively scan all files under root_path.
    Returns list of findings with full raw values (feature #7).
    """
    root = Path(root_path)
    if not root.exists():
        print(f"  ✗ Path does not exist: {root_path}")
        return []

    findings = []
    count = 0
    skipped = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip system/hidden dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith('.')]

        for fname in filenames:
            if count >= max_files:
                break
            fp = Path(dirpath) / fname
            ext = fp.suffix.lower()

            try:
                if not fp.exists() or not fp.is_file():
                    continue
                size = fp.stat().st_size
                if size == 0 or size > MAX_FILE_SIZE:
                    skipped += 1
                    continue
            except Exception:
                continue

            result = []
            vprint(f'Scanning: {fp}')
            if ext in TEXT_EXTENSIONS:
                result = scan_text_file(fp)
            elif ext in PDF_EXTENSIONS:
                result = scan_pdf(fp)
            elif ext in OFFICE_EXTENSIONS:
                result = scan_office(fp)
            elif ext in IMAGE_EXTENSIONS and ocr_images:
                result = scan_image_ocr(fp)
            else:
                continue

            count += 1
            if result:
                findings.extend(result)
                print(f"  [{count}] {fp.name} — {len(result)} finding(s)")
                for r in result:
                    vprint(f"    ✓ {r['detector']} in {fp.name}: {r.get('masked_values',['?'])[0]}")

            if count % 200 == 0:
                print(f"  Scanned {count} files, {len(findings)} total findings...")

    print(f"  Complete: {count} files scanned, {skipped} skipped, {len(findings)} findings")
    return findings
