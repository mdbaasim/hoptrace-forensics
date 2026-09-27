"""
HopTrace Forensics - FastAPI Server.
Exposes REST APIs for email analysis, sample triage, campaign graph data,
blockchain evidence verification, and serves the Cyber SOC web dashboard.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
import os
import io

from core.parser import parse_and_analyze_email
from core.samples import SAMPLE_EMAILS
from core.correlation import correlate_with_campaigns, generate_threat_graph
from core.custody import generate_blockchain_receipt

from collections import OrderedDict
from starlette.requests import Request

app = FastAPI(
    title="HopTrace Forensics Platform",
    description="AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence",
    version="1.0.0"
)

# AppSec Defense: HTTP Security Headers Middleware (Defends against Clickjacking, MIME-sniffing, XSS)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://*.tile.openstreetmap.org https://unpkg.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response

# AppSec Defense: Bounded LRU Memory Store (Defends against Memory Accumulation DoS)
MAX_CASES = 100
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB limit
CASE_STORE = OrderedDict()

def save_case_to_store(case_id: str, case_data: dict):
    if len(CASE_STORE) >= MAX_CASES:
        CASE_STORE.popitem(last=False)  # Evicts oldest case to cap memory
    CASE_STORE[case_id] = case_data


@app.get("/api/samples")
async def get_sample_list():
    """Returns available demonstration cases."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "description": s["description"]
        }
        for s in SAMPLE_EMAILS.values()
    ]


@app.get("/api/sample/{sample_id}")
async def analyze_sample(sample_id: str, pii_mask: bool = False):
    """Analyzes a pre-configured sample email."""
    if sample_id not in SAMPLE_EMAILS:
        raise HTTPException(status_code=404, detail="Sample case not found")
        
    sample = SAMPLE_EMAILS[sample_id]
    result = parse_and_analyze_email(sample["raw_eml"].encode("utf-8"), enable_pii_masking=pii_mask)
    
    # Enrich with campaign correlation
    origin_ip = result["origin_summary"]["origin_ip"]
    from_domain = result["authentication"]["from_domain"]
    asn = result["origin_summary"]["asn"]
    correlation = correlate_with_campaigns(origin_ip, from_domain, asn)
    result["campaign_correlation"] = correlation
    
    save_case_to_store(result["case_id"], result)
    return result


@app.post("/api/analyze")
async def analyze_uploaded_email(
    file: UploadFile = File(None),
    raw_text: str = Form(None),
    pii_mask: bool = Form(False)
):
    """Analyzes an uploaded .eml file or raw MIME text with payload size bounds."""
    if file:
        # AppSec Defense: Enforce 10 MB maximum upload ceiling to prevent RAM exhaustion DoS
        content = await file.read(MAX_PAYLOAD_SIZE + 1)
        if len(content) > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="File size exceeds maximum permitted limit (10 MB).")
    elif raw_text:
        raw_bytes = raw_text.encode("utf-8")
        if len(raw_bytes) > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="Text payload exceeds maximum permitted limit (10 MB).")
        content = raw_bytes
    else:
        raise HTTPException(status_code=400, detail="Provide an .eml file or raw email text.")
        
    result = parse_and_analyze_email(content, enable_pii_masking=pii_mask)
    
    # Enrich with campaign correlation
    origin_ip = result["origin_summary"]["origin_ip"]
    from_domain = result["authentication"]["from_domain"]
    asn = result["origin_summary"]["asn"]
    correlation = correlate_with_campaigns(origin_ip, from_domain, asn)
    result["campaign_correlation"] = correlation
    
    save_case_to_store(result["case_id"], result)
    return result


@app.get("/api/campaigns")
async def get_campaign_graph():
    """Returns relationship graph data of threat actors, IPs, and campaigns."""
    return generate_threat_graph()


@app.get("/api/verify/{sha256}")
async def verify_evidence_hash(sha256: str):
    """Verifies SHA-256 evidence integrity against the blockchain ledger."""
    clean_hash = sha256.strip().lower()
    # Find matching case
    matched = None
    for case in CASE_STORE.values():
        if case.get("evidence_hashes", {}).get("sha256", "").lower() == clean_hash:
            matched = case
            break
            
    receipt = generate_blockchain_receipt(clean_hash, matched["case_id"] if matched else "VERIFY-QUERY")
    return {
        "verified": matched is not None,
        "evidence_sha256": clean_hash,
        "is_case_on_record": matched is not None,
        "blockchain_receipt": receipt,
        "integrity_status": "AUTHENTIC / UNMODIFIED" if matched else "UNREGISTERED HASH"
    }


# Mount static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR)
    
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    """Serves the main SOC dashboard."""
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h1>HopTrace Forensics is running! static/index.html is being generated...</h1>")
