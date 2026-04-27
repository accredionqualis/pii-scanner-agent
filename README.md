# KnightGuard GRC — PII Scanner Agent v2.0
**ByteKnight Security Pvt. Ltd.** | https://knightguardgrc.com

## ⬇️ Download
**[→ Download latest Windows EXE from Releases](../../releases/latest)**

No Python or installation required. Download and run directly.

---

## Features
| Feature | Status |
|---------|--------|
| PostgreSQL, MySQL, Oracle, MSSQL, MongoDB, SQLite | ✅ |
| Full offline scan mode | ✅ |
| Upload offline results | ✅ |
| Network endpoint/laptop/desktop scanning | ✅ |
| Image OCR (Aadhaar/PAN card photos) | ✅ |
| Agent activate/deactivate by super admin | ✅ |
| Full raw PII values submitted | ✅ |

---

## Quick Start

### 1. Configure
```cmd
KnightGuard-PII-Scanner.exe configure --server https://api.knightguardgrc.com --api-key YOUR_KEY
```

### 2. Test connection
```cmd
KnightGuard-PII-Scanner.exe status
```

### 3. Discover databases on network
```cmd
KnightGuard-PII-Scanner.exe discover
KnightGuard-PII-Scanner.exe discover --subnet 192.168.1
```

### 4. Scan database
```cmd
KnightGuard-PII-Scanner.exe scan-db --db "postgresql://user:pass@192.168.1.10/mydb"
KnightGuard-PII-Scanner.exe scan-db --db "oracle://user:pass@192.168.1.20:1521/ORCL"
KnightGuard-PII-Scanner.exe scan-db --db "mysql://user:pass@192.168.1.30/hrdb"
KnightGuard-PII-Scanner.exe scan-db --db "mssql://user:pass@192.168.1.40/master"
KnightGuard-PII-Scanner.exe scan-db --db "mongodb://user:pass@192.168.1.50/mydb"
```

### 5. Scan files (with image OCR)
```cmd
KnightGuard-PII-Scanner.exe scan-files --path "C:\Users\Documents"
KnightGuard-PII-Scanner.exe scan-files --path "D:\Shared" --no-ocr
```

### 6. Scan endpoints/laptops on network
```cmd
KnightGuard-PII-Scanner.exe scan-endpoint --targets 192.168.1.50,192.168.1.51
KnightGuard-PII-Scanner.exe scan-endpoint --targets 192.168.1.50 --smb-user admin --smb-pass Password123
```

### 7. Offline mode (air-gapped networks)
```cmd
KnightGuard-PII-Scanner.exe scan-db --db "oracle://..." --offline
KnightGuard-PII-Scanner.exe scan-files --path "C:\Data" --offline
KnightGuard-PII-Scanner.exe upload --file pii_database_20260427_143022.json
```

### 8. Background daemon (sends heartbeat)
```cmd
KnightGuard-PII-Scanner.exe daemon
KnightGuard-PII-Scanner.exe daemon --interval 600
```

---

## PII Types Detected
| Type | Severity | DPDP SPDI |
|------|----------|-----------|
| Aadhaar | CRITICAL | ✅ |
| PAN | CRITICAL | ✅ |
| Passport | CRITICAL | ✅ |
| ABHA Health ID | CRITICAL | ✅ |
| Credit/Debit Card | CRITICAL | ✅ |
| Bank Account | CRITICAL | ✅ |
| Voter ID | HIGH | ✅ |
| Driving Licence | HIGH | ✅ |
| Mobile | MEDIUM | ❌ |
| GSTIN | MEDIUM | ❌ |
| Email | LOW | ❌ |
| IFSC | MEDIUM | ❌ |
| Date of Birth | MEDIUM | ❌ |
| IP Address | LOW | ❌ |

---

## Oracle Read-Only User (run as SYSDBA)
```sql
CREATE USER pii_scanner IDENTIFIED BY StrongPass123;
GRANT CREATE SESSION TO pii_scanner;
GRANT SELECT ANY TABLE TO pii_scanner;
GRANT SELECT ANY DICTIONARY TO pii_scanner;
```

## Oracle Common Service Names
- `ORCL` — Default
- `ORCLPDB` — Pluggable DB
- `XE` — Express Edition
- `XEPDB1` — XE Pluggable DB
