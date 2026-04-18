# SCE GRC PII Scanner Agent v1.0
## ScudoCyber Solutions Pvt. Ltd.

A lightweight PII detection agent that scans databases, files and networks
for personally identifiable information and reports findings to the SCE GRC platform.

## Supported Detectors (Indian PII Focus)
- Aadhaar (with Verhoeff checksum validation)
- PAN Card
- Passport
- Mobile Number
- Email Address
- GSTIN
- Voter ID
- Driving Licence
- ABHA Health ID
- Credit/Debit Cards (Luhn validated)
- IFSC Code
- IP Address

## Installation

### Prerequisites
- Python 3.8+
- pip

### Install dependencies
pip install -r requirements.txt

## Configuration
python3 main.py configure --server https://api.scegrc.com --api-key YOUR_API_KEY

## Usage

### Test connection
python3 main.py test

### Scan a MySQL database
python3 main.py db --type mysql --host 192.168.1.10 --database mydb --username root --password pass

### Scan a PostgreSQL database
python3 main.py db --type postgresql --host 192.168.1.10 --database mydb --username postgres --password pass

### Scan a MSSQL database
python3 main.py db --type mssql --host 192.168.1.10 --database mydb --username sa --password pass

### Scan an Oracle database
python3 main.py db --type oracle --host 192.168.1.10 --database ORCL --username system --password pass

### Scan files/folders
python3 main.py files --path /var/data

### Discover databases on network
python3 main.py network --cidr 192.168.1.0/24

## Windows .exe Build
pip install pyinstaller
pyinstaller --onefile --name PIIScanner main.py
# Output: dist/PIIScanner.exe

## DPDP Act 2023 — SPDI Categories
The following detectors flag data as Sensitive Personal Data (SPDI):
- Aadhaar Number
- PAN Card
- Passport Number
- Voter ID
- Driving Licence
- ABHA Health ID

## Support
support@scudocyber.com | https://scegrc.com
