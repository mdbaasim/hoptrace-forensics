"""
AI Threat Detection and Natural Language Processing (NLP) Engine.
Analyzes email subject and body for urgency cues, BEC patterns, payment diversion,
credential harvesting, authority impersonation, and defangs malicious URLs.
"""

import re
import math
from typing import Dict, List, Any

# Urgency and Psychological Pressure Cues
URGENCY_KEYWORDS = [
    "immediately", "urgent", "critical", "act now", "within 24 hours", "within 2 hours",
    "deadline", "expire", "suspended", "termination", "legal action", "arrest warrant",
    "final notice", "strictly confidential", "do not disclose", "immediate attention"
]

# Business Email Compromise (BEC) & Financial Diversion Cues
BEC_KEYWORDS = [
    "wire transfer", "bank transfer", "updated bank details", "new account number",
    "invoice payment", "payment diversion", "remittance advice", "ach transfer",
    "vendor payment", "outstanding balance", "disburse funds", "gift card",
    "swift code", "iban", "crypto", "bitcoin", "direct deposit"
]

# Credential Harvesting Cues
CREDENTIAL_KEYWORDS = [
    "verify your account", "password expired", "confirm your identity", "login credentials",
    "update security information", "re-authenticate", "mailbox quota exceeded",
    "reset your password", "security alert", "unauthorized access detected"
]

# High-profile Authority Figures targeted in impersonation (Higher Ed & AICTE)
AUTHORITY_ROLES = [
    "aicte chairman", "member secretary", "vice chancellor", "registrar",
    "dean academic", "controller of examinations", "director", "principal",
    "chief financial officer", "cfo", "chief executive officer", "ceo"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".work", ".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq"]


def defang_url(url: str) -> str:
    """Defangs a URL so it cannot be accidentally clicked or detonated (e.g. hxxps[://]bad[.]com)."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace("://", "[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged


def extract_and_analyze_urls(text: str) -> List[Dict[str, Any]]:
    """Extracts URLs from email body, defangs them, and scores their risk."""
    url_pattern = r'https?://[^\s<>"\']+'
    found_urls = re.findall(url_pattern, text)
    
    analyzed_urls = []
    for raw_url in set(found_urls):
        is_suspicious = False
        reasons = []
        
        # Check IP as host
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', raw_url):
            is_suspicious = True
            reasons.append("Direct IP address used as URL host (bypasses domain reputation)")
            
        # Check suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if tld in raw_url.lower():
                is_suspicious = True
                reasons.append(f"Uses high-risk/frequently abused TLD: {tld}")
                break
                
        # Check login or auth keywords in URL
        if any(k in raw_url.lower() for k in ["login", "signin", "verify", "secure", "account", "update"]):
            reasons.append("Phishing lure keywords present in URL path")
            is_suspicious = True

        analyzed_urls.append({
            "original_url": raw_url,
            "defanged_url": defang_url(raw_url),
            "is_suspicious": is_suspicious,
            "reasons": reasons
        })
        
    return analyzed_urls


def analyze_email_content(subject: str, body: str) -> Dict[str, Any]:
    """
    Performs NLP and heuristic pattern recognition across email text:
    - Urgency scoring
    - BEC and financial fraud scoring
    - Credential theft scoring
    - Authority impersonation checks
    """
    full_text = f"{subject} {body}".lower()
    
    detected_urgency = [k for k in URGENCY_KEYWORDS if k in full_text]
    detected_bec = [k for k in BEC_KEYWORDS if k in full_text]
    detected_credential = [k for k in CREDENTIAL_KEYWORDS if k in full_text]
    detected_authorities = [k for k in AUTHORITY_ROLES if k in full_text]
    
    urls = extract_and_analyze_urls(body)
    suspicious_urls = [u for u in urls if u["is_suspicious"]]
    
    # Calculate sub-scores (0-100 scale)
    urgency_score = min(100, len(detected_urgency) * 25)
    bec_score = min(100, len(detected_bec) * 30 + (25 if detected_authorities else 0))
    credential_score = min(100, len(detected_credential) * 30 + (30 if suspicious_urls else 0))
    
    # Classify Primary Intent
    threat_category = "Legitimate"
    if bec_score >= 50:
        threat_category = "Business Email Compromise (BEC) / Financial Fraud"
    elif credential_score >= 50:
        threat_category = "Credential Harvesting / Phishing"
    elif urgency_score >= 50 and suspicious_urls:
        threat_category = "Malicious Link / Social Engineering"
    elif urgency_score >= 50 or detected_authorities:
        threat_category = "Suspicious Urgency / Impersonation"
        
    return {
        "threat_category": threat_category,
        "urgency_score": urgency_score,
        "bec_score": bec_score,
        "credential_score": credential_score,
        "detected_urgency_cues": detected_urgency,
        "detected_bec_cues": detected_bec,
        "detected_credential_cues": detected_credential,
        "detected_authorities": detected_authorities,
        "urls": urls,
        "has_suspicious_urls": len(suspicious_urls) > 0,
        "suspicious_url_count": len(suspicious_urls)
    }


def compute_composite_threat_score(
    auth_eval: dict,
    nlp_eval: dict,
    origin_geo: dict,
    homoglyph_eval: dict
) -> Dict[str, Any]:
    """
    Synthesizes signals from Protocol Auth, NLP Content, GeoIP/Tor, and Domain Homoglyph
    to compute an overarching Threat Risk Score (0-100).
    """
    score = 0
    factors = []
    
    # 1. Homoglyph / Lookalike Domain (Massive Flag)
    if homoglyph_eval.get("is_lookalike"):
        score += 40
        factors.append(f"Deceptive lookalike domain detected targeting '{homoglyph_eval.get('impersonated_target')}'.")
        
    # 2. Authentication Failures
    if auth_eval.get("spf", {}).get("status") == "fail":
        score += 25
        factors.append("SPF validation failed: sending server not authorized.")
    if auth_eval.get("dkim", {}).get("status") == "fail":
        score += 25
        factors.append("DKIM cryptographic signature failed or tampered.")
    if not auth_eval.get("is_aligned"):
        score += 15
        factors.append(auth_eval.get("alignment_anomaly", "Sender and Return-Path headers are misaligned."))
    if auth_eval.get("reply_to_diversion"):
        score += 20
        factors.append(auth_eval.get("reply_to_anomaly", "Reply-To diverts replies to an external domain."))
        
    # 3. Origin Infrastructure Risk (Tor / VPN / Bulletproof)
    if origin_geo.get("is_tor"):
        score += 35
        factors.append("Originating transmission routed through Tor Anonymity Network.")
    elif origin_geo.get("is_vpn"):
        score += 20
        factors.append("Originating transmission routed through Commercial VPN / Proxy Gateway.")
        
    # 4. NLP / Social Engineering Signals
    if nlp_eval.get("bec_score", 0) >= 50:
        score += 30
        factors.append("High-confidence BEC / Payment Diversion linguistic patterns.")
    if nlp_eval.get("credential_score", 0) >= 50:
        score += 25
        factors.append("Credential theft and fake account verification triggers.")
    if nlp_eval.get("urgency_score", 0) >= 50:
        score += 15
        factors.append("Psychological pressure / artificial urgency tactics detected.")
    if nlp_eval.get("has_suspicious_urls"):
        score += 20
        factors.append("Contains suspicious or defanged URLs with high-risk traits.")

    # Enterprise Risk Calibration:
    # Caps maximum composite threat score at 98% to reflect realistic probabilistic certainty
    # and distinguishes high-severity multi-vector threats (avoids flat/artificial 100% scores).
    if score <= 0:
        final_score = 0
    elif score < 70:
        final_score = score
    else:
        # Asymptotically compress high scores above 70 into the 75 - 98 range
        excess = score - 70
        boost = 28.0 * (1.0 - math.exp(-excess / 18.0))
        final_score = min(98, max(75 if score >= 75 else score, round(70 + boost)))
    
    # Determine Severity Level
    if final_score >= 75:
        severity = "CRITICAL"
        verdict = "MALICIOUS / HIGH-CONFIDENCE FRAUD"
    elif final_score >= 50:
        severity = "HIGH"
        verdict = "SUSPICIOUS / PROBABLE THREAT"
    elif final_score >= 25:
        severity = "MEDIUM"
        verdict = "ELEVATED RISK / REVIEW CAREFULLY"
    else:
        severity = "LOW"
        verdict = "LEGITIMATE / LOW RISK"

    # Attribution Assessment
    attribution = "Legitimate Sender"
    if homoglyph_eval.get("is_lookalike"):
        attribution = "Spoofed Domain Impersonator"
    elif origin_geo.get("is_tor") or origin_geo.get("is_vpn"):
        attribution = "Anonymized Threat Actor Infrastructure"
    elif auth_eval.get("spf", {}).get("status") == "pass" and final_score >= 60:
        attribution = "Likely Compromised Legitimate Account"
    elif final_score >= 50:
        attribution = "Unverified External Cyber Threat Actor"

    return {
        "composite_score": final_score,
        "severity": severity,
        "verdict": verdict,
        "attribution": attribution,
        "risk_factors": factors
    }
