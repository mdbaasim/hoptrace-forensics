"""
Homoglyph and Lookalike Domain Detection Engine.
Identifies Punycode (IDN) attacks, zero-width characters, Cyrillic/Greek substitutions,
and computes Levenshtein distance against sensitive institutional and financial domains.
"""

import unicodedata

# Common homoglyph mappings (Cyrillic, Greek, etc. to Latin equivalents)
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0410': 'A',  # Cyrillic a
    '\u0441': 'c', '\u0421': 'C',  # Cyrillic c
    '\u0435': 'e', '\u0415': 'E',  # Cyrillic e
    '\u0456': 'i', '\u0406': 'I',  # Cyrillic i
    '\u0458': 'j', '\u0408': 'J',  # Cyrillic j
    '\u043e': 'o', '\u041e': 'O',  # Cyrillic o
    '\u0440': 'p', '\u0420': 'P',  # Cyrillic p
    '\u0455': 's', '\u0405': 'S',  # Cyrillic s
    '\u0445': 'x', '\u0425': 'X',  # Cyrillic x
    '\u0443': 'y', '\u0423': 'Y',  # Cyrillic y
    '\u03bf': 'o', '\u039f': 'O',  # Greek omicron
    '\u03bd': 'v', '\u039d': 'N',  # Greek nu
    '\u0030': 'o',                 # Digit 0 mimicking o
    '\u0031': 'l',                 # Digit 1 mimicking l
}

# High-value domains targeted in institutional and financial attacks
MONITORED_DOMAINS = [
    "aicte-india.org",
    "education.gov.in",
    "ugc.ac.in",
    "cbse.gov.in",
    "nta.ac.in",
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
    "paypal.com",
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "github.com",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_domain(domain: str) -> str:
    """Transliterates homoglyph characters into their ASCII Latin equivalents."""
    normalized = []
    for char in domain:
        normalized.append(HOMOGLYPH_MAP.get(char, char))
    return "".join(normalized)


def check_domain_spoofing(domain: str) -> dict:
    """
    Analyzes a domain for lookalike indicators:
    - Punycode (IDN) presence
    - Non-ASCII/homoglyph character substitution
    - Levenshtein distance matches against high-value monitored targets
    """
    domain_lower = domain.lower().strip()
    is_punycode = domain_lower.startswith("xn--") or ".xn--" in domain_lower
    
    # Check for non-ASCII characters
    non_ascii_chars = [c for c in domain_lower if ord(c) > 127]
    has_homoglyphs = len(non_ascii_chars) > 0
    
    normalized = normalize_domain(domain_lower)
    
    spoof_target = None
    min_dist = 999
    
    # Extract domain base (e.g. 'aicte-india' from 'aicte-india.org')
    test_domain = normalized if has_homoglyphs else domain_lower
    
    for target in MONITORED_DOMAINS:
        # Exact match is legitimate (unless homoglyphs were used to mimic it)
        if domain_lower == target and not has_homoglyphs and not is_punycode:
            continue
            
        dist = levenshtein_distance(test_domain, target)
        if dist < min_dist:
            min_dist = dist
            spoof_target = target
            
    is_lookalike = False
    details = []
    
    if is_punycode:
        is_lookalike = True
        details.append(f"Punycode encoded domain detected: '{domain_lower}'. Often used to obscure Cyrillic/Greek spoofing.")
        
    if has_homoglyphs:
        is_lookalike = True
        details.append(f"Contains {len(non_ascii_chars)} disguised non-ASCII homoglyphs (e.g. Cyrillic) mimicking Latin characters.")
        
    if spoof_target and (min_dist <= 2 or (has_homoglyphs and min_dist == 0)):
        is_lookalike = True
        details.append(f"High-confidence lookalike attack targeting '{spoof_target}' (Edit distance: {min_dist}).")
    elif spoof_target and min_dist <= 3 and len(spoof_target) > 10:
        is_lookalike = True
        details.append(f"Possible typosquatting target: '{spoof_target}' (Edit distance: {min_dist}).")

    return {
        "domain": domain,
        "is_lookalike": is_lookalike,
        "is_punycode": is_punycode,
        "has_homoglyphs": has_homoglyphs,
        "impersonated_target": spoof_target if is_lookalike else None,
        "edit_distance": min_dist if is_lookalike else None,
        "normalized_domain": normalized,
        "details": details
    }
