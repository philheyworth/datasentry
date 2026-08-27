"""
Seed the DataSentry backend with realistic multi-customer demo data
so the dashboard shows a meaningful fleet.
"""
import json, requests, random, hashlib
from datetime import datetime, timedelta

API_URL = "http://127.0.0.1:8765"
API_KEY = "dsk_bDhpsJ67ycXPyH3VBwUEvz1zEviYj7uIPky_duCEJNE"

CUSTOMERS = [
    {"id": "acme-corp",      "name": "Acme Corporation"},
    {"id": "globex-ltd",     "name": "Globex Ltd"},
    {"id": "initech-uk",     "name": "Initech UK"},
    {"id": "umbrella-group", "name": "Umbrella Group"},
]

MACHINE_TEMPLATES = [
    # (hostname, username, os, os_version, loc_types_and_pii_scale)
    ("DESKTOP-ACCOUNTS",  "accounts",    "Windows", "10 Pro",       "network_heavy",  2.0),
    ("LAPTOP-HR-01",      "hr.admin",    "Windows", "11 Pro",       "cloud_heavy",    1.8),
    ("DESKTOP-PHIL01",    "p.heworth",   "Windows", "11 Pro",       "mixed",          1.5),
    ("LAPTOP-SARAH",      "s.jones",     "Windows", "11 Home",      "onedrive",       0.9),
    ("MACBOOK-TOM",       "t.price",     "macOS",   "15.2",         "mac_cloud",      0.7),
    ("MACBOOK-DESIGN",    "creative",    "macOS",   "14.6",         "icloud_heavy",   0.05),
    ("SERVER-DEV01",      "devuser",     "Linux",   "Ubuntu 22.04", "linux_local",    0.1),
    ("LAPTOP-CLEAN",      "newuser",     "Windows", "11 Home",      "clean",          0.0),
    ("DESKTOP-FINANCE",   "finance",     "Windows", "10 Pro",       "network_heavy",  2.2),
    ("LAPTOP-SALES-01",   "sales.mgr",  "Windows", "11 Pro",       "mixed",          0.8),
    ("MACBOOK-CEO",       "ceo",         "macOS",   "15.2",         "mac_cloud",      0.3),
    ("DESKTOP-RECEPTION", "reception",  "Windows", "10 Home",      "clean",          0.1),
]

def make_pii(scale):
    if scale == 0: return {}
    base = {
        "email":           int(random.randint(80,400)   * scale),
        "uk_phone":        int(random.randint(40,200)   * scale),
        "credit_card":     int(random.randint(0,30)     * scale),
        "uk_nino":         int(random.randint(0,50)     * scale),
        "date_of_birth":   int(random.randint(10,120)   * scale),
        "postcode":        int(random.randint(20,100)   * scale),
    }
    if scale > 1.0:
        base["iban"]            = int(random.randint(5,40) * scale)
        base["sort_code"]       = int(random.randint(20,80) * scale)
        base["uk_bank_account"] = int(random.randint(10,50) * scale)
    return {k:v for k,v in base.items() if v > 0}

def make_locations(loc_type, pii_scale):
    locs = []
    if loc_type == "network_heavy":
        locs = [
            {"label":"My Documents",  "type":"local",         "path":"C:\\Users\\~\\Documents",
             "total_files": random.randint(8000,22000),  "total_size_bytes": random.randint(2**30, 8*2**30),
             "pii_file_count": int(random.randint(200,800)*pii_scale), "pii_summary": make_pii(pii_scale)},
            {"label":f"Network Drive S: (\\\\fileserver\\shared)", "type":"network_drive", "path":"S:\\",
             "total_files": random.randint(40000,120000), "total_size_bytes": random.randint(20*2**30, 100*2**30),
             "pii_file_count": int(random.randint(800,2500)*pii_scale), "pii_summary": make_pii(pii_scale*1.5)},
            {"label":"Desktop",       "type":"local",         "path":"C:\\Users\\~\\Desktop",
             "total_files": random.randint(100,900),     "total_size_bytes": random.randint(50*2**20, 500*2**20),
             "pii_file_count": int(random.randint(10,80)*pii_scale),  "pii_summary": make_pii(pii_scale*0.3)},
        ]
    elif loc_type == "cloud_heavy":
        locs = [
            {"label":"My Documents", "type":"local",    "path":"C:\\Users\\~\\Documents",
             "total_files": random.randint(5000,15000), "total_size_bytes": random.randint(2**30, 6*2**30),
             "pii_file_count": int(random.randint(300,900)*pii_scale), "pii_summary": make_pii(pii_scale)},
            {"label":"OneDrive for Business (Tenant)", "type":"onedrive_business", "path":"C:\\Users\\~\\OneDrive - Tenant",
             "total_files": random.randint(5000,20000), "total_size_bytes": random.randint(3*2**30, 12*2**30),
             "pii_file_count": int(random.randint(200,600)*pii_scale), "pii_summary": make_pii(pii_scale)},
            {"label":"Downloads",    "type":"local",    "path":"C:\\Users\\~\\Downloads",
             "total_files": random.randint(500,3000),   "total_size_bytes": random.randint(500*2**20, 3*2**30),
             "pii_file_count": int(random.randint(20,100)*pii_scale),  "pii_summary": make_pii(pii_scale*0.4)},
        ]
    elif loc_type == "mixed":
        locs = [
            {"label":"My Documents",   "type":"local",    "path":"C:\\Users\\~\\Documents",
             "total_files": random.randint(8000,20000), "total_size_bytes": random.randint(2*2**30, 8*2**30),
             "pii_file_count": int(random.randint(150,600)*pii_scale), "pii_summary": make_pii(pii_scale)},
            {"label":"OneDrive Personal", "type":"onedrive", "path":"C:\\Users\\~\\OneDrive",
             "total_files": random.randint(1000,6000),  "total_size_bytes": random.randint(2**30, 4*2**30),
             "pii_file_count": int(random.randint(30,120)*pii_scale),  "pii_summary": make_pii(pii_scale*0.4)},
            {"label":"Dropbox (Personal)", "type":"dropbox", "path":"C:\\Users\\~\\Dropbox",
             "total_files": random.randint(3000,12000), "total_size_bytes": random.randint(2**30, 6*2**30),
             "pii_file_count": int(random.randint(80,280)*pii_scale),  "pii_summary": make_pii(pii_scale*0.7)},
        ]
    elif loc_type == "onedrive":
        locs = [
            {"label":"My Documents", "type":"local",    "path":"C:\\Users\\~\\Documents",
             "total_files": random.randint(3000,10000), "total_size_bytes": random.randint(500*2**20, 4*2**30),
             "pii_file_count": int(random.randint(50,250)*pii_scale),  "pii_summary": make_pii(pii_scale)},
            {"label":"OneDrive for Business (Tenant)", "type":"onedrive_business", "path":"C:\\Users\\~\\OneDrive - Tenant",
             "total_files": random.randint(5000,18000), "total_size_bytes": random.randint(3*2**30, 10*2**30),
             "pii_file_count": int(random.randint(100,400)*pii_scale), "pii_summary": make_pii(pii_scale)},
        ]
    elif loc_type == "mac_cloud":
        locs = [
            {"label":"Documents",    "type":"local",       "path":"/Users/~/Documents",
             "total_files": random.randint(5000,15000),   "total_size_bytes": random.randint(2**30, 8*2**30),
             "pii_file_count": int(random.randint(40,200)*pii_scale), "pii_summary": make_pii(pii_scale)},
            {"label":"iCloud Drive", "type":"icloud",      "path":"/Users/~/Library/Mobile Documents/com~apple~CloudDocs",
             "total_files": random.randint(2000,8000),    "total_size_bytes": random.randint(2*2**30, 10*2**30),
             "pii_file_count": int(random.randint(20,100)*pii_scale), "pii_summary": make_pii(pii_scale*0.5)},
            {"label":"Google Drive", "type":"google_drive","path":"/Users/~/Library/CloudStorage/GoogleDrive-user@example.com",
             "total_files": random.randint(4000,14000),   "total_size_bytes": random.randint(3*2**30, 12*2**30),
             "pii_file_count": int(random.randint(50,180)*pii_scale), "pii_summary": make_pii(pii_scale*0.6)},
            {"label":"Dropbox",      "type":"dropbox",     "path":"/Users/~/Dropbox",
             "total_files": random.randint(1000,5000),    "total_size_bytes": random.randint(500*2**20, 3*2**30),
             "pii_file_count": int(random.randint(10,60)*pii_scale),  "pii_summary": make_pii(pii_scale*0.3)},
        ]
    elif loc_type == "icloud_heavy":
        locs = [
            {"label":"Documents",    "type":"local",  "path":"/Users/~/Documents",
             "total_files": random.randint(1000,5000), "total_size_bytes": random.randint(10*2**30, 60*2**30),
             "pii_file_count": int(random.randint(2,20)*pii_scale),  "pii_summary": make_pii(pii_scale)},
            {"label":"iCloud Drive", "type":"icloud", "path":"/Users/~/Library/Mobile Documents/com~apple~CloudDocs",
             "total_files": random.randint(5000,30000),"total_size_bytes": random.randint(20*2**30, 80*2**30),
             "pii_file_count": int(random.randint(2,12)*pii_scale),  "pii_summary": make_pii(pii_scale)},
        ]
    elif loc_type == "linux_local":
        locs = [
            {"label":"Home", "type":"local", "path":"/home/devuser",
             "total_files": random.randint(20000,60000), "total_size_bytes": random.randint(5*2**30, 20*2**30),
             "pii_file_count": int(random.randint(5,40)*pii_scale), "pii_summary": make_pii(pii_scale)},
        ]
    else:  # clean
        locs = [
            {"label":"My Documents",    "type":"local",    "path":"C:\\Users\\~\\Documents",
             "total_files": random.randint(100,800),   "total_size_bytes": random.randint(50*2**20, 300*2**20),
             "pii_file_count": 0, "pii_summary": {}},
            {"label":"OneDrive Personal","type":"onedrive","path":"C:\\Users\\~\\OneDrive",
             "total_files": random.randint(200,1200),  "total_size_bytes": random.randint(100*2**20, 600*2**20),
             "pii_file_count": 0, "pii_summary": {}},
        ]

    for loc in locs:
        loc.setdefault("top_pii_files", [])
        loc.setdefault("top_extensions", [
            {"ext":".docx","count":random.randint(100,2000),"size_bytes":random.randint(10**7,10**9)},
            {"ext":".xlsx","count":random.randint(50,1000),"size_bytes":random.randint(5*10**6,5*10**8)},
            {"ext":".pdf","count":random.randint(50,500),"size_bytes":random.randint(10**7,10**9)},
            {"ext":".txt","count":random.randint(10,300),"size_bytes":random.randint(10**5,10**7)},
            {"ext":".csv","count":random.randint(10,200),"size_bytes":random.randint(10**5,10**8)},
        ])
        loc["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    return locs

def submit(report):
    r = requests.post(f"{API_URL}/api/scans", json=report,
                      headers={"X-API-Key": API_KEY}, timeout=30)
    r.raise_for_status()
    return r.json()

random.seed(42)
submitted = 0

for customer in CUSTOMERS:
    # Assign 2-4 machines per customer
    machines = random.sample(MACHINE_TEMPLATES, random.randint(2, 4))
    for hostname, username, os_name, os_ver, loc_type, pii_scale in machines:
        mid = hashlib.sha256(f"{customer['id']}:{hostname}".encode()).hexdigest()[:16]
        locs = make_locations(loc_type, pii_scale)
        total_files = sum(l["total_files"] for l in locs)
        total_size  = sum(l["total_size_bytes"] for l in locs)
        total_pii   = sum(l["pii_file_count"] for l in locs)
        days_ago = random.randint(0, 3)
        scan_time = (datetime.utcnow() - timedelta(days=days_ago, hours=random.randint(0,8))).isoformat() + "Z"

        report = {
            "machine": {
                "machine_id":  mid,
                "hostname":    hostname,
                "username":    username,
                "os":          os_name,
                "os_version":  os_ver,
                "architecture":"x86_64",
            },
            "customer": {"id": customer["id"], "name": customer["name"]},
            "scan_started_at": scan_time,
            "locations": locs,
            "summary": {
                "total_locations": len(locs),
                "total_files":     total_files,
                "total_size_bytes":total_size,
                "total_pii_files": total_pii,
                "capabilities":    {"docx":True,"xlsx":True,"pdf":True},
            }
        }
        result = submit(report)
        print(f"  ✓ {customer['name']:25s} → {hostname:25s} ({total_pii:4d} PII files)")
        submitted += 1

print(f"\nSeeded {submitted} machines across {len(CUSTOMERS)} customers.")
