"""
MIME and Multi-Hop Header Forensic Parser.
Performs RFC 5322 parsing, extracts hop-by-hop 'Received:' headers in chronological order,
isolates originating IPs, calculates transit latency, and integrates forensic modules.
"""

import email
import email.policy
import email.utils
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from .auth_engine import evaluate_authentication
from .homoglyph import check_domain_spoofing
from .geo_threat import geolocate_ip, identify_origin_node, is_private_ip
from .ai_threat import analyze_email_content, compute_composite_threat_score
from .custody import (
    compute_evidence_hashes,
    generate_blockchain_receipt,
    generate_section_65b_certificate,
    mask_pii
)


def extract_ip_from_hop_text(hop_str: str) -> Optional[str]:
    """Finds IPv4 address from a Received header snippet."""
    # Common format: 'from mail.example.com ([1.2.3.4])' or 'from [1.2.3.4]'
    bracket_ip = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', hop_str)
    if bracket_ip:
        return bracket_ip.group(1)
        
    plain_ip = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', hop_str)
    if plain_ip:
        return plain_ip.group(1)
        
    return None


def parse_received_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Parses 'Received:' headers and orders them chronologically (Hop 1 = origin sender).
    Standard email received headers are prepended at the top, so the LAST header in the raw file
    is actually the EARLIEST transmission hop.
    """
    # Reverse to get chronological order (Earliest -> Latest)
    chronological = list(reversed(received_headers))
    hops = []
    
    prev_dt = None
    for idx, header_val in enumerate(chronological, start=1):
        clean_val = " ".join(header_val.split())
        ip = extract_ip_from_hop_text(clean_val)
        
        # Parse 'by' host
        by_match = re.search(r'\bby\s+([^\s;]+)', clean_val, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else "Unknown Relay"
        
        # Parse 'from' host
        from_match = re.search(r'\bfrom\s+([^\s;]+)', clean_val, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else "Client MTA"
        
        # Parse timestamp (usually after semicolon)
        hop_time = ""
        delay_sec = 0
        if ";" in clean_val:
            raw_time = clean_val.split(";")[-1].strip()
            try:
                parsed_tuple = email.utils.parsedate_to_datetime(raw_time)
                if parsed_tuple:
                    hop_time = parsed_tuple.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if prev_dt:
                        delay_sec = max(0, int((parsed_tuple - prev_dt).total_seconds()))
                    prev_dt = parsed_tuple
            except Exception:
                hop_time = raw_time

        geo_data = geolocate_ip(ip) if ip else {
            "ip": "N/A", "country": "Unknown", "city": "Unknown", "lat": 0.0, "lng": 0.0,
            "isp": "Unknown", "asn": "N/A", "is_tor": False, "is_vpn": False, "threat_score": 0
        }

        hops.append({
            "hop_number": idx,
            "ip": ip or "Not Disclosed",
            "from_host": from_host,
            "by_host": by_host,
            "timestamp": hop_time,
            "delay_seconds": delay_sec,
            "raw_snippet": clean_val[:120] + "..." if len(clean_val) > 120 else clean_val,
            "geo": geo_data
        })
        
    return hops


def parse_and_analyze_email(raw_bytes: bytes, enable_pii_masking: bool = False) -> Dict[str, Any]:
    """
    Master pipeline: Ingests raw email bytes, parses MIME & headers,
    runs authentication, NLP, GeoIP, homoglyph, and blockchain custody engines.
    """
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    
    # 1. Cryptographic Evidence Hashing (First step for legal integrity)
    evidence_hashes = compute_evidence_hashes(raw_bytes)
    
    # 2. MIME Structure Parsing
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    
    subject = msg.get("Subject", "(No Subject)")
    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    date_header = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    
    # Extract headers into a dictionary
    headers_dict = {k.lower(): str(v) for k, v in msg.items()}
    
    # 3. Extract Body Content (Plain text or sanitized HTML)
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition", ""))
            if ctype == "text/plain" and "attachment" not in cdispo:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text += payload.decode("utf-8", errors="replace") + "\n"
            elif ctype == "text/html" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    raw_html = payload.decode("utf-8", errors="replace")
                    body_text += re.sub(r'<[^>]+>', ' ', raw_html) + "\n"
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode("utf-8", errors="replace")
            
    # 4. Multi-Hop Received Headers Traversal
    received_headers = msg.get_all("Received", [])
    hops = parse_received_hops(received_headers)
    
    # Identify Earliest Reliable Origin Node
    origin_node = identify_origin_node(hops)
    origin_ip = origin_node.get("ip") if origin_node else "Unknown"
    origin_geo = origin_node.get("geo") if origin_node else {}
    
    # 5. Protocol Security & Authentication Check
    auth_eval = evaluate_authentication(headers_dict, origin_ip=origin_ip)
    
    # 6. Lookalike & Homoglyph Domain Detection
    from_domain = auth_eval.get("from_domain", "")
    homoglyph_eval = check_domain_spoofing(from_domain)
    
    # 7. AI Threat & NLP Analysis
    nlp_eval = analyze_email_content(subject, body_text)
    
    # 8. Composite Threat Scoring & Attribution
    composite_eval = compute_composite_threat_score(
        auth_eval=auth_eval,
        nlp_eval=nlp_eval,
        origin_geo=origin_geo,
        homoglyph_eval=homoglyph_eval
    )
    
    # 9. Blockchain Anchoring & Legal Section 65B Certificate
    blockchain_receipt = generate_blockchain_receipt(evidence_hashes["sha256"], case_id)
    sec_65b_cert = generate_section_65b_certificate(
        case_id=case_id,
        hashes=evidence_hashes,
        sender=from_header,
        recipient=to_header,
        origin_ip=origin_ip
    )
    
    # Apply PII masking if requested
    display_body = mask_pii(body_text) if enable_pii_masking else body_text
    display_from = mask_pii(from_header) if enable_pii_masking else from_header
    display_to = mask_pii(to_header) if enable_pii_masking else to_header

    return {
        "case_id": case_id,
        "metadata": {
            "subject": subject,
            "from": display_from,
            "to": display_to,
            "date": date_header,
            "message_id": message_id,
            "pii_masked": enable_pii_masking
        },
        "preview_body": display_body[:1500],
        "evidence_hashes": evidence_hashes,
        "origin_summary": {
            "origin_ip": origin_ip,
            "earliest_hop": origin_node.get("hop_number") if origin_node else 1,
            "country": origin_geo.get("country", "Unknown"),
            "city": origin_geo.get("city", "Unknown"),
            "isp": origin_geo.get("isp", "Unknown"),
            "asn": origin_geo.get("asn", "Unknown"),
            "is_tor": origin_geo.get("is_tor", False),
            "is_vpn": origin_geo.get("is_vpn", False),
            "threat_classification": origin_geo.get("classification", "Unclassified")
        },
        "hops": hops,
        "authentication": auth_eval,
        "homoglyph_analysis": homoglyph_eval,
        "nlp_analysis": nlp_eval,
        "threat_assessment": composite_eval,
        "blockchain_receipt": blockchain_receipt,
        "section_65b_certificate": sec_65b_cert
    }
