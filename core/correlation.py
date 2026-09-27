"""
Identity Correlation and Campaign Graph Engine.
Uses NetworkX to build a relationship graph linking sender domains,
origin IPs, ASNs, threat signatures, and campaign clusters.
"""

from typing import Dict, List, Any
import networkx as nx

# Pre-indexed institutional cyber incident campaigns
ACTIVE_CAMPAIGNS = [
    {
        "id": "CAMP-2026-AICTE-01",
        "name": "Operation Shodh-Phish (Fake AICTE Approval Extortion)",
        "target_sector": "Technical Institutes & Engineering Colleges",
        "origin_asns": ["AS20473", "AS58271"],
        "origin_ips": ["185.220.101.5", "194.26.29.112"],
        "lookalike_domains": ["аicte-india.org", "aicte-approval-portal.in"],
        "threat_actor": "APT-DarkSlate (Suspected Extortion Syndicate)",
        "incidents_reported": 42
    },
    {
        "id": "CAMP-2026-FEE-02",
        "name": "Operation CampusWire (University Vendor Payment Diversion)",
        "target_sector": "State Universities & Finance Departments",
        "origin_asns": ["AS63949", "AS9009"],
        "origin_ips": ["45.33.32.156", "198.98.56.12"],
        "lookalike_domains": ["univ-finance-desk.net", "sbi-fees-collect.xyz"],
        "threat_actor": "SilverHound Financial BEC Group",
        "incidents_reported": 18
    },
    {
        "id": "CAMP-2026-SCHOLAR-03",
        "name": "PMSSS Fake Scholarship Credential Harvester",
        "target_sector": "Students & Scholarship Applicants",
        "origin_asns": ["AS20473"],
        "origin_ips": ["185.220.102.8"],
        "lookalike_domains": ["pmsss-scholarship-gov.top", "aicte-grant-apply.xyz"],
        "threat_actor": "PhishKite Phishing Crew",
        "incidents_reported": 95
    },
    {
        "id": "CAMP-2026-ITAX-04",
        "name": "Operation Kar-Chhal (Fake Income Tax Refund Phishing)",
        "target_sector": "Academic Faculty & Institutional Employees",
        "origin_asns": ["AS9009"],
        "origin_ips": ["185.193.88.21"],
        "lookalike_domains": ["incometax-efiling-gov.site", "tax-refund-portal.top"],
        "threat_actor": "ViperBait Financial Syndicate",
        "incidents_reported": 67
    },
    {
        "id": "CAMP-2026-RANSOM-05",
        "name": "Operation CampusLock (Invoice Dropper Ransomware)",
        "target_sector": "University IT Labs & Department Heads",
        "origin_asns": ["AS135377"],
        "origin_ips": ["118.193.41.102"],
        "lookalike_domains": ["procurement-orders-desk.cc", "vendor-audit-hub.com"],
        "threat_actor": "LockBit Affiliate Group 11",
        "incidents_reported": 29
    }
]


def correlate_with_campaigns(origin_ip: str, domain: str, asn: str = "") -> Dict[str, Any]:
    """Correlates an analyzed email with known active cyber campaigns."""
    matched_campaigns = []
    
    for camp in ACTIVE_CAMPAIGNS:
        match_reasons = []
        if origin_ip in camp["origin_ips"]:
            match_reasons.append(f"Origin IP {origin_ip} matches campaign infrastructure.")
        if asn and asn in camp["origin_asns"]:
            match_reasons.append(f"Origin ASN {asn} associated with threat syndicate.")
        if any(d in domain for d in camp["lookalike_domains"]):
            match_reasons.append(f"Domain pattern links to {camp['name']}.")
            
        if match_reasons:
            matched_campaigns.append({
                "campaign_id": camp["id"],
                "campaign_name": camp["name"],
                "threat_actor": camp["threat_actor"],
                "target_sector": camp["target_sector"],
                "incidents_linked": camp["incidents_reported"] + 1,
                "confidence": "HIGH" if len(match_reasons) > 1 else "MEDIUM",
                "match_reasons": match_reasons
            })

    return {
        "is_correlated": len(matched_campaigns) > 0,
        "matched_campaign_count": len(matched_campaigns),
        "campaigns": matched_campaigns
    }


def generate_threat_graph() -> Dict[str, Any]:
    """Generates an interconnected NetworkX graph for SOC correlation visualization."""
    G = nx.Graph()
    
    # Add Campaign nodes
    for camp in ACTIVE_CAMPAIGNS:
        c_node = f"Campaign: {camp['id']}"
        G.add_node(c_node, type="campaign", label=camp["name"], actor=camp["threat_actor"])
        
        # Link IPs
        for ip in camp["origin_ips"]:
            ip_node = f"IP: {ip}"
            G.add_node(ip_node, type="ip", label=ip)
            G.add_edge(c_node, ip_node, relationship="USED_INFRASTRUCTURE")
            
        # Link Domains
        for dom in camp["lookalike_domains"]:
            dom_node = f"Domain: {dom}"
            G.add_node(dom_node, type="domain", label=dom)
            G.add_edge(c_node, dom_node, relationship="USED_SPOOF_DOMAIN")

    nodes = [{"id": n, **G.nodes[n]} for n in G.nodes()]
    edges = [{"source": u, "target": v, "label": G[u][v]["relationship"]} for u, v in G.edges()]
    
    return {
        "nodes": nodes,
        "edges": edges,
        "active_campaign_count": len(ACTIVE_CAMPAIGNS)
    }
