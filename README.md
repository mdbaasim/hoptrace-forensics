# HopTrace Forensics

### AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
**Smart India Hackathon 2026 | Problem Statement ID: 26106**  
**Organization:** All India Council for Technical Education (AICTE) - Cyber Security Cell  
**Theme:** Blockchain & Cybersecurity | Category: Software / Institutional Cyber Defense  

---

## Executive Overview

HopTrace Forensics is a sovereign, institution-grade cyber forensic intelligence platform engineered to detect, deconstruct, and attribute advanced email-borne cyber threats targeting Indian higher education institutions, state universities, and regulatory authorities.

Unlike conventional spam filters that perform simple keyword heuristics and binary classification, HopTrace Forensics executes a multi-layer forensic pipeline:
1. **Multi-Hop Reverse Received Traversal:** Unwinds RFC 5322 `Received:` headers from the destination MTA back to the true origin node, discarding forged client headers.
2. **Zero-Day IDN Homoglyph Detection:** Identifies Punycode and internationalized domain name (IDN) spoofing (e.g., Cyrillic characters visually mimicking ASCII in regulatory domains).
3. **Cryptographic Protocol Validation:** Verifies SPF alignment, DKIM cryptographic signatures, and DMARC enforcement policies against live DNS records.
4. **Contextual AI Threat Intelligence:** Scans email payloads using behavioral NLP to extract psychological pressure tactics, extortion demands, fake authority roles, and automatically defangs malicious URLs (`hxxp://`).
5. **Bayesian Asymptotic Risk Calibration:** Computes a composite threat score (0 to 98%) reflecting true threat severity across multi-vector attacks without artificial saturation.
6. **Section 65B BSA 2023 Digital Custody:** Generates SHA-256 and SHA-512 cryptographic digests and anchors forensic evidence to an immutable blockchain ledger (Polygon PoS) for Indian court admissibility.

---

## Architecture and Data Pipeline

```
+-----------------------------------------------------------------------------------+
|                            RFC 5322 MIME Ingestion                                |
|           Raw .EML / .MSG Upload -> Header Extraction -> Safe Body Sanitize       |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        Multi-Hop Reverse Traversal Engine                         |
|     Received: Headers Unwinding -> RFC 1918 Private Filter -> Earliest External IP|
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                         Network & Geolocation Attribution                         |
|       MaxMind GeoIP Lookup -> City / Country -> ASN / ISP -> Tor/VPN Flagging     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                       Cryptographic Protocol Authentication                       |
|           SPF Verification -> DKIM RSA Signature -> DMARC Policy Alignment        |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        AI Threat & Behavioral NLP Engine                          |
|  Punycode Homoglyph Extraction -> Extortion Cues -> Role Impersonation -> URL Defang|
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                      Bayesian Asymptotic Risk Calibration                         |
|      Composite Threat Score (0 - 98%) -> Threat Classification & SOC Badging      |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     Legal Evidence & Chain of Custody (BSA 2023)                  |
|    SHA-256/512 Hashing -> Blockchain Anchoring Receipt -> Sec. 65B PDF Certificate|
+-----------------------------------------------------------------------------------+
```

---

## Demonstration Cases

HopTrace Forensics ships with 6 pre-configured forensic investigation scenarios:

| Case ID | Scenario | Origin Node | Threat Score | Forensic Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Case 1** | AICTE Official Impersonation (Cyrillic homoglyph, fake audit fee) | Frankfurt, DE (Tor Exit: 185.220.101.5) | 98 / 100 | CRITICAL: Homoglyph Extortion |
| **Case 2** | Campus Vendor BEC (Payment diversion requesting Rs. 14.5L to fake escrow) | Dallas, USA (VPN: 198.98.56.12) | 93 / 100 | CRITICAL: Business Email Compromise |
| **Case 3** | PMSSS Scholarship Phish (Fake portal harvesting student net banking) | Amsterdam, NL (Tor: 185.220.102.8) | 96 / 100 | CRITICAL: Credential Harvesting Scam |
| **Case 4** | Income Tax Notice Scam (Impersonated tax notice requesting verification) | Bucharest, RO (Bulletproof: 185.193.88.21) | 77 / 100 | CRITICAL: Fraudulent Financial Notice |
| **Case 5** | Campus Ransomware Dropper (Double extension payload Invoice-Audit.pdf.exe) | Hong Kong (Proxy DC: 118.193.41.102) | 77 / 100 | CRITICAL: Malicious Executable Dropper |
| **Case 6** | Legitimate AICTE Circular (Official technical guidelines circular) | New Delhi, IN (NIC Govt: 103.27.8.44) | 0 / 100 | LOW: Genuine AICTE Transmission |

---

## AppSec and Hardening Standards

The platform implements enterprise security standards aligned with OWASP Top 10:
- **Stored and DOM XSS Protection:** Centralized HTML entity escaping (`escapeHtml()`) across all dynamic email headers, hostnames, and defanged URLs.
- **Resource Exhaustion Defense:** Strict 10MB payload ceiling (`MAX_PAYLOAD_SIZE = 10 * 1024 * 1024`) returning HTTP 413 on oversized payloads.
- **Memory Leak Protection:** Bounded LRU cache for in-memory case storage (`MAX_CASES = 100`) preventing out-of-memory DoS.
- **HTTP Security Headers:** Active middleware enforcing `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy (CSP)`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **Fault-Tolerant Hash Verification:** Robust handling of arbitrary hash inputs with fallback seeding to avoid unhandled server exceptions.

---

## Installation and Quickstart

### Prerequisites
- Python 3.11 or higher
- Git

### Setup Instructions

1. **Clone the Repository:**
```bash
git clone https://github.com/<your-username>/HopTrace-Forensics.git
cd HopTrace-Forensics
```

2. **Create and Activate a Virtual Environment:**
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

3. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

4. **Launch the Platform:**
```bash
python run.py
```

5. **Access the SOC Dashboard:**
Open your browser and navigate to:
```
http://127.0.0.1:8050
```

---

## Repository Structure

```
HopTrace-Forensics/
|-- core/
|   |-- __init__.py
|   |-- ai_threat.py         # Behavioral NLP & asymptotic threat scoring
|   |-- auth_engine.py       # SPF, DKIM, DMARC protocol verification
|   |-- correlation.py       # Campaign graph correlation & syndicate mapping
|   |-- custody.py           # Section 65B BSA 2023 hashing & blockchain ledger
|   |-- geo_threat.py        # Hop traversal, IP extraction, and GeoIP lookup
|   |-- homoglyph.py         # IDN Punycode de-obfuscation & visual spoof detection
|   |-- parser.py            # RFC 5322 raw email MIME parser
|   `-- samples.py           # Pre-configured test scenario metadata
|-- samples/                 # Raw .EML benchmark evidence files (Cases 1-6)
|-- static/
|   |-- app.js               # Frontend application logic & AppSec sanitization
|   |-- index.html           # Official Indian Government portal layout
|   `-- style.css            # NIC/AICTE design system (Deep Navy & Saffron)
|-- HopTrace_Forensics_SIH_Pitch_Script.docx  # Video walkthrough script
|-- HopTrace_Forensics_SIH_PPT_Content.docx   # Full 8-slide presentation deck
|-- Procfile                 # Deployment process configuration
|-- requirements.txt         # Project dependencies
|-- run.py                   # Platform entrypoint
|-- server.py                # FastAPI backend & AppSec middleware
`-- README.md                # System documentation
```

---

## Legal and Regulatory Compliance

HopTrace Forensics is designed in accordance with:
- **Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023):** Section 65B electronic record admissibility compliance.
- **Information Technology Act, 2000 (Amended 2008):** Digital signatures and cyber forensic evidence integrity.
- **CERT-In Cyber Security Directions:** Incident reporting and institutional audit trail requirements.

---

## License

This project is developed for the Smart India Hackathon 2026 under Problem Statement 26106. Released under the Apache 2.0 License.
