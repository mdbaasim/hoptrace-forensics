/**
 * HopTrace Forensics - Tactical Multi-Page SOC Controller
 * Completely emoji-free, with investigator sign-in, persistent case status,
 * and reliable Leaflet map rendering.
 */

let map = null;
let fullMap = null;
let hopMarkers = [];
let fullHopMarkers = [];
let routePolyline = null;
let fullRoutePolyline = null;
let currentCaseData = null;

// ISO Country Code Badges (Replaced flag emojis)
const COUNTRY_CODES = {
    "Germany": "DE",
    "United States": "US",
    "Russia": "RU",
    "India": "IN",
    "Netherlands": "NL",
    "Switzerland": "CH",
    "United Kingdom": "GB",
    "Internal Network (RFC 1918)": "LAN",
    "Unknown": "EXT"
};

// AppSec Defense: HTML Entity Sanitizer (Defends against Stored & DOM-based XSS)
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initMaps();
    setupFileInput();
    setupDate();
    initInvestigatorSession();
    // Default load Case 1 (AICTE Homoglyph Extortion)
    loadSample("aicte_impersonation");
    switchPage("live-scanner");
});

// Theme Management (Original Tactical Dark Mode)
function initTheme() {
    localStorage.removeItem("hoptrace_theme");
    document.documentElement.removeAttribute("data-theme");
}

function setupDate() {
    const d = new Date();
    const options = { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' };
    const dateStr = d.toLocaleDateString('en-US', options);
    const dateEl = document.getElementById("liveDate");
    if (dateEl) dateEl.textContent = dateStr;
}

// Investigator Authentication Session Management
function initInvestigatorSession() {
    const rawOfficer = localStorage.getItem("hoptrace_officer_id") || "INV-AICTE-7821";
    const sanitizedOfficer = rawOfficer.replace(/[^a-zA-Z0-9_\-\s]/g, "").slice(0, 30);
    document.getElementById("officerBadgeLabel").textContent = `OFFICER: ${sanitizedOfficer}`;
}

function openLoginModal() {
    document.getElementById("loginModal").style.display = "flex";
}

function closeLoginModal() {
    document.getElementById("loginModal").style.display = "none";
}

function handleInvestigatorLogin(e) {
    e.preventDefault();
    const rawOfficer = document.getElementById("officerIdInput").value.trim();
    if (rawOfficer) {
        const sanitizedOfficer = rawOfficer.replace(/[^a-zA-Z0-9_\-\s]/g, "").slice(0, 30);
        localStorage.setItem("hoptrace_officer_id", sanitizedOfficer);
        document.getElementById("officerBadgeLabel").textContent = `OFFICER: ${sanitizedOfficer}`;
    }
    closeLoginModal();
}

function initMaps() {
    // Dedicated Full Screen Origin Map using Open Leaflet & OpenStreetMap
    fullMap = L.map("fullHopMap", {
        center: [25.0, 45.0],
        zoom: 3,
        minZoom: 2,
        maxZoom: 18,
        zoomControl: true,
        attributionControl: true
    });

    // Standard OpenStreetMap Tiles
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 19,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(fullMap);

    // Open Leaflet Scale Control
    L.control.scale({ metric: true, imperial: false }).addTo(fullMap);
}

// Page Navigation Switcher (Redirects cleanly between dedicated pages)
function switchPage(pageId, navElement) {
    // 1. Hide all pages
    document.querySelectorAll(".page-view").forEach(p => {
        p.classList.remove("active");
        p.style.display = "none";
    });
    
    // 2. Show requested target page
    const target = document.getElementById(`page-${pageId}`);
    if (target) {
        target.classList.add("active");
        target.style.display = "block";
    }

    // 3. Scroll main workspace back to top
    const wrapper = document.querySelector(".main-wrapper");
    if (wrapper) wrapper.scrollTop = 0;

    // 4. Update active nav link
    document.querySelectorAll(".nav-link").forEach(link => link.classList.remove("active"));
    if (navElement) {
        navElement.classList.add("active");
    } else {
        // Automatically find matching link for this page
        const match = document.querySelector(`.nav-link[onclick*="'${pageId}'"]`);
        if (match) match.classList.add("active");
    }

    // 5. Invalidate Open Leaflet map if switching to origin-map
    if (pageId === "origin-map" && fullMap) {
        setTimeout(() => {
            fullMap.invalidateSize();
            if (currentCaseData) {
                renderFullMap(currentCaseData.hops, currentCaseData.origin_summary);
            }
        }, 100);
    }
}

function syncPii(checked) {
    const piiEl = document.getElementById("piiToggle");
    if (piiEl) piiEl.checked = checked;
    const piiSetting = document.getElementById("piiSettingToggle");
    if (piiSetting && piiSetting.checked !== checked) piiSetting.checked = checked;

    const dropdown = document.getElementById("caseSelectorDropdown");
    const activeSampleId = (dropdown && dropdown.value) ? dropdown.value : "aicte_impersonation";
    loadSample(activeSampleId);
}

function setupFileInput() {
    const input = document.getElementById("fileInput");
    if (!input) return;
    input.addEventListener("change", async (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            const isPii = document.getElementById("piiToggle") ? document.getElementById("piiToggle").checked : false;
            const formData = new FormData();
            formData.append("file", file);
            formData.append("pii_mask", isPii);

            try {
                const res = await fetch("/api/analyze", {
                    method: "POST",
                    body: formData
                });
                const data = await res.json();
                currentCaseData = data;
                renderAllPages(data);
                switchPage("dashboard");
            } catch (err) {
                alert("Error analyzing file: " + err.message);
            } finally {
                e.target.value = ""; // Allows re-uploading the same file cleanly
            }
        }
    });
}

async function loadSample(sampleId) {
    const dropdown = document.getElementById("caseSelectorDropdown");
    if (dropdown && sampleId) dropdown.value = sampleId;

    document.querySelectorAll(".sample-pill-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.sampleId === sampleId);
    });

    const isPii = document.getElementById("piiToggle").checked;
    try {
        const response = await fetch(`/api/sample/${sampleId}?pii_mask=${isPii}`);
        const data = await response.json();
        currentCaseData = data;
        renderAllPages(data);
    } catch (err) {
        console.error("Failed to load sample:", err);
    }
}

// Master Render across all Pages
function renderAllPages(data) {
    // Update Persistent Case Header (Visible on Dashboard Page)
    const caseIdDisplay = document.getElementById("activeCaseIdDisplay");
    if (caseIdDisplay) caseIdDisplay.textContent = data.case_id;

    const caseTitleDisplay = document.getElementById("activeCaseTitleDisplay");
    if (caseTitleDisplay) caseTitleDisplay.textContent = data.metadata.subject;

    renderDashboardOverview(data);
    renderDashboardHopChain(data.hops, data.origin_summary);
    renderCountryHops(data.hops);
    renderForensicTable(data);
    renderFullMap(data.hops, data.origin_summary);
    renderHopsFullChain(data.hops, data.origin_summary);
    renderProtocolAuthPage(data.authentication, data.homoglyph_analysis);
    renderAiThreatsPage(data.nlp_analysis);
    renderEvidenceLedgerPage(data);
    renderCampaignsPage(data.campaign_correlation);
    renderScannerPage(data);
}

function renderDashboardOverview(data) {
    const score = data.threat_assessment.composite_score;
    const severity = data.threat_assessment.severity;
    
    // Top Metric Cards
    const scoreEl = document.getElementById("cardThreatScore");
    scoreEl.textContent = `${score} / 100`;
    scoreEl.style.color = score >= 75 ? "var(--coral-accent)" : score >= 50 ? "var(--amber-accent)" : "var(--green-accent)";
    
    const riskBadge = document.getElementById("riskBadge");
    riskBadge.textContent = severity;
    riskBadge.className = "trend-badge " + (score >= 75 ? "danger" : score >= 50 ? "purple" : "success");
    document.getElementById("cardThreatSub").textContent = data.threat_assessment.verdict;

    document.getElementById("cardHopCount").textContent = `${data.hops.length} Nodes`;
    document.getElementById("hopsBadge").textContent = `${data.hops.length} HOPS`;
    document.getElementById("cardHopSub").textContent = `Earliest Node: Hop #${data.origin_summary.earliest_hop}`;

    document.getElementById("cardOriginCountry").textContent = data.origin_summary.country;
    const origBadge = document.getElementById("originBadge");
    origBadge.textContent = data.origin_summary.is_tor ? "TOR EXIT" : data.origin_summary.is_vpn ? "VPN RELAY" : "PUBLIC IP";
    origBadge.className = "trend-badge " + (data.origin_summary.is_tor ? "danger" : "purple");
    document.getElementById("cardOriginIp").textContent = `${data.origin_summary.origin_ip} (${data.origin_summary.threat_classification})`;

    const authScore = data.authentication.auth_score;
    document.getElementById("cardAuthScore").textContent = `${authScore} % Pass`;
    const authBadge = document.getElementById("authScoreBadge");
    authBadge.textContent = authScore >= 80 ? "ALIGNED" : "FAILED";
    authBadge.className = "trend-badge " + (authScore >= 80 ? "success" : "danger");
    document.getElementById("cardAuthSub").textContent = `SPF: ${data.authentication.spf.status.toUpperCase()} | DKIM: ${data.authentication.dkim.status.toUpperCase()}`;

    // Middle Section Left: Email Payload & Metadata Inspector
    const dashThreat = document.getElementById("dashThreatBadge");
    if (dashThreat) {
        dashThreat.textContent = severity;
        dashThreat.className = "trend-badge " + (score >= 75 ? "danger" : score >= 50 ? "purple" : "success");
    }
    const fromEl = document.getElementById("dashFromDisplay");
    if (fromEl) fromEl.textContent = data.metadata.from || "Undisclosed";
    const replyEl = document.getElementById("dashReplyToDisplay");
    if (replyEl) replyEl.textContent = data.authentication.reply_to_email || "Same as Sender";
    const subjEl = document.getElementById("dashSubjectDisplay");
    if (subjEl) subjEl.textContent = data.metadata.subject || "(No Subject)";
    const bodyEl = document.getElementById("dashBodyDisplay");
    if (bodyEl) bodyEl.textContent = data.preview_body || "(No plain-text body content)";

    // Middle Section Right: Origin & Network Attribution
    const origIpEl = document.getElementById("dashOriginIp");
    if (origIpEl) origIpEl.textContent = data.origin_summary.origin_ip;
    const origGeoEl = document.getElementById("dashOriginGeo");
    if (origGeoEl) origGeoEl.textContent = `${data.origin_summary.city}, ${data.origin_summary.country}`;
    const origClassEl = document.getElementById("dashOriginClass");
    if (origClassEl) {
        origClassEl.textContent = data.origin_summary.threat_classification.toUpperCase();
        origClassEl.className = "trend-badge " + (data.origin_summary.is_tor ? "danger" : "purple");
    }
    const origIspEl = document.getElementById("dashOriginIsp");
    if (origIspEl) origIspEl.textContent = `${data.origin_summary.isp} (${data.origin_summary.asn})`;
}

// Hop-by-Hop Transmission Relay Audit on Dashboard
function renderDashboardHopChain(hops, originSummary) {
    const container = document.getElementById("dashboardHopChain");
    if (!container) return;
    container.innerHTML = "";

    hops.forEach(h => {
        const isOrigin = (h.ip === originSummary.origin_ip);
        const card = document.createElement("div");
        card.style.cssText = `
            background: var(--card-inner);
            border: 1px solid ${isOrigin ? 'var(--coral-accent)' : 'var(--border-color)'};
            border-radius: var(--radius-sm);
            padding: 10px 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        `;
        card.innerHTML = `
            <div style="display: flex; align-items: center; gap: 10px;">
                <span class="trend-badge ${isOrigin ? 'danger' : 'purple'}">HOP #${h.hop_number}</span>
                <div>
                    <div style="font-family: monospace; font-size: 0.85rem; font-weight: 700; color: var(--text-main);">${h.ip}</div>
                    <div style="font-size: 0.72rem; color: var(--text-dim);">${h.geo.city || 'LAN'}, ${h.geo.country || 'Internal'}</div>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.74rem; font-weight: 700; color: ${isOrigin ? 'var(--coral-accent)' : 'var(--text-main)'};">
                    ${isOrigin ? 'REAL SENDER (ORIGIN)' : 'TRANSIT SERVER'}
                </div>
                <div style="font-size: 0.68rem; color: var(--text-dim);">${h.timestamp || 'Verified'}</div>
            </div>
        `;
        container.appendChild(card);
    });
}

function renderCountryHops(hops) {
    const container = document.getElementById("countryHopsList");
    if (!container) return;
    container.innerHTML = "";

    hops.forEach(h => {
        const country = h.geo.country || "Internal";
        const code = COUNTRY_CODES[country] || "INT";
        const item = document.createElement("div");
        item.className = "country-hop-item";
        item.innerHTML = `
            <div class="country-code-pill">[${code}]</div>
            <div class="country-name">${country}</div>
            <div class="country-detail">Hop #${h.hop_number} (${h.ip})</div>
        `;
        container.appendChild(item);
    });
}

function renderForensicTable(data) {
    const tbody = document.getElementById("forensicTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const auth = data.authentication;
    const homo = data.homoglyph_analysis;
    const nlp = data.nlp_analysis;

    tbody.innerHTML += `
        <tr>
            <td><strong>SPF Email Check</strong></td>
            <td style="font-family: monospace;">${data.origin_summary.origin_ip}</td>
            <td><span class="table-badge ${auth.spf.status === 'pass' ? 'pass' : 'fail'}">${auth.spf.status.toUpperCase()}</span></td>
            <td>${auth.spf.status === 'pass' ? 'Legitimate' : '+25 Severity'}</td>
        </tr>
        <tr>
            <td><strong>DKIM Digital Signature</strong></td>
            <td style="font-family: monospace;">${auth.from_domain}</td>
            <td><span class="table-badge ${auth.dkim.status === 'pass' ? 'pass' : 'fail'}">${auth.dkim.status.toUpperCase()}</span></td>
            <td>${auth.dkim.status === 'pass' ? 'Verified' : '+25 Severity'}</td>
        </tr>
        <tr>
            <td><strong>Fake Lookalike Domain Check</strong></td>
            <td style="font-family: monospace;">${homo.domain}</td>
            <td><span class="table-badge ${homo.is_lookalike ? 'fail' : 'pass'}">${homo.is_lookalike ? 'FAKE DOMAIN DETECTED' : 'CLEAN'}</span></td>
            <td>${homo.is_lookalike ? '+40 Severity' : 'Verified'}</td>
        </tr>
        <tr>
            <td><strong>AI Scam & Urgency Intent</strong></td>
            <td>${nlp.threat_category}</td>
            <td><span class="table-badge ${nlp.bec_score >= 50 || nlp.urgency_score >= 50 ? 'fail' : 'pass'}">URGENCY: ${nlp.urgency_score}</span></td>
            <td>${nlp.bec_score >= 50 ? '+30 BEC' : 'Normal'}</td>
        </tr>
        <tr>
            <td><strong>Connection Type</strong></td>
            <td>${data.origin_summary.threat_classification}</td>
            <td><span class="table-badge ${data.origin_summary.is_tor ? 'fail' : 'pass'}">${data.origin_summary.is_tor ? 'TOR ANONYMIZER' : 'STANDARD'}</span></td>
            <td>${data.origin_summary.is_tor ? '+35 Severity' : 'Low'}</td>
        </tr>
    `;
}

// Page 3: Forensic Hops Full Chain
function renderHopsFullChain(hops, originSummary) {
    const container = document.getElementById("hopsFullChain");
    container.innerHTML = "";

    hops.forEach(h => {
        const isOrigin = (h.ip === originSummary.origin_ip);
        const card = document.createElement("div");
        card.style.cssText = `
            background: var(--card-inner);
            border: 1px solid ${isOrigin ? 'var(--coral-accent)' : 'var(--border-color)'};
            border-radius: var(--radius-md);
            padding: 14px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        `;
        card.innerHTML = `
            <div style="display: flex; align-items: center; gap: 14px;">
                <span class="trend-badge ${isOrigin ? 'danger' : 'purple'}">HOP #${escapeHtml(h.hop_number)}</span>
                <div>
                    <div style="font-family: monospace; font-size: 0.88rem; font-weight: 800; color: var(--text-main);">IP: ${escapeHtml(h.ip)}</div>
                    <div style="font-size: 0.74rem; color: var(--text-dim); margin-top: 2px;">
                        Received By: ${escapeHtml(h.by_host)} | Sent From: ${escapeHtml(h.from_host)}
                    </div>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.8rem; font-weight: 600; color: ${isOrigin ? 'var(--coral-accent)' : 'var(--text-main)'};">
                    ${escapeHtml(h.geo.city || 'LAN')}, ${escapeHtml(h.geo.country || 'Internal')}
                </div>
                <div style="font-size: 0.72rem; color: var(--text-dim);">${escapeHtml(h.timestamp || 'No timestamp')}</div>
            </div>
        `;
        container.appendChild(card);
    });
}

// Page 4: Protocol Auth
function renderProtocolAuthPage(auth, homo) {
    document.getElementById("pageSpfStatus").textContent = auth.spf.status.toUpperCase();
    document.getElementById("pageSpfDetail").textContent = auth.spf.reason;

    document.getElementById("pageDkimStatus").textContent = auth.dkim.status.toUpperCase();
    document.getElementById("pageDkimDetail").textContent = auth.dkim.reason;

    document.getElementById("pageDmarcStatus").textContent = auth.dmarc.status.toUpperCase();
    document.getElementById("pageDmarcDetail").textContent = auth.dmarc.reason;

    const homoBox = document.getElementById("pageHomoglyphDetails");
    if (homo.is_lookalike) {
        const sanitizedDetails = (homo.details || []).map(d => escapeHtml(d)).join("<br/>");
        homoBox.innerHTML = `
            <p><strong style="color: var(--coral-accent);">[ALERT] Fake Lookalike Domain Found:</strong> The domain <code style="background: #fee2e2; border: 1px solid #fca5a5; padding: 2px 6px; border-radius: 4px; color: #b91c1c; font-weight: 700;">${escapeHtml(homo.domain)}</code> uses disguised characters mimicking official <strong>${escapeHtml(homo.impersonated_target)}</strong>.</p>
            <p style="margin-top: 6px; color: var(--text-muted);">${sanitizedDetails}</p>
        `;
    } else {
        homoBox.innerHTML = `<p style="color: var(--green-accent); font-weight: 700;">[VERIFIED] Genuine Domain: '${escapeHtml(homo.domain)}' passed all fake lookalike checks with zero disguised characters.</p>`;
    }
}

// Page 5: AI Threat Intel
function renderAiThreatsPage(nlp) {
    document.getElementById("pageAiCategoryBadge").textContent = nlp.threat_category.toUpperCase();

    const cues = [...nlp.detected_urgency_cues, ...nlp.detected_bec_cues];
    const cuesBox = document.getElementById("pageDetectedCues");
    cuesBox.innerHTML = cues.length > 0 
        ? cues.map(c => `<span class="trend-badge danger">${escapeHtml(c)}</span>`).join("")
        : '<span style="color: var(--text-dim); font-size: 0.75rem;">None detected</span>';

    const rolesBox = document.getElementById("pageDetectedRoles");
    rolesBox.textContent = nlp.detected_authorities.length > 0 
        ? nlp.detected_authorities.map(escapeHtml).join(", ").toUpperCase()
        : "None identified";

    const urlBox = document.getElementById("pageDefangedUrls");
    if (nlp.urls && nlp.urls.length > 0) {
        urlBox.innerHTML = nlp.urls.map(u => `
            <div style="padding: 6px; border-radius: 4px; background: rgba(0,0,0,0.2);">
                <span style="color: ${u.is_suspicious ? 'var(--coral-accent)' : 'var(--green-accent)'};">[DEFANGED]</span> ${escapeHtml(u.defanged_url)}
            </div>
        `).join("");
    } else {
        urlBox.innerHTML = '<span style="color: var(--text-dim); font-size: 0.75rem;">No external hyperlinks present in body</span>';
    }
}

// Page 6: Evidence Ledger
function renderEvidenceLedgerPage(data) {
    const cert = data.section_65b_certificate;
    const block = data.blockchain_receipt;

    document.getElementById("ledgerCaseId").textContent = cert.case_id;
    document.getElementById("ledgerSha256").textContent = cert.sha256_digest;
    document.getElementById("ledgerSha512").textContent = data.evidence_hashes.sha512;
    document.getElementById("ledgerBlockNum").textContent = block.block_number;
    document.getElementById("ledgerTxHash").textContent = block.tx_hash;
    document.getElementById("ledgerDeclaration").textContent = cert.declaration;
}

// Page 7: Campaigns & Attribution
function renderCampaignsPage(campaign) {
    const box = document.getElementById("campaignListFull");
    box.innerHTML = "";

    if (campaign && campaign.is_correlated) {
        campaign.campaigns.forEach(c => {
            const card = document.createElement("div");
            card.style.cssText = `
                background: var(--card-inner);
                border: 1px solid var(--coral-accent);
                border-radius: var(--radius-md);
                padding: 16px;
                display: flex;
                flex-direction: column;
                gap: 6px;
            `;
            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: var(--text-main); font-size: 0.95rem; font-weight: 800;">${c.campaign_name}</strong>
                    <span class="trend-badge danger">${c.confidence} CONFIDENCE</span>
                </div>
                <div style="font-size: 0.78rem; color: var(--coral-accent);">Threat Actor: ${c.threat_actor}</div>
                <div style="font-size: 0.75rem; color: var(--text-dim);">Target Sector: ${c.target_sector} | Linked Incidents: ${c.incidents_linked}</div>
                <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 4px;">Indicators: ${c.match_reasons.join(" | ")}</div>
            `;
            box.appendChild(card);
        });
    } else {
        box.innerHTML = `
            <div style="background: var(--card-inner); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px; color: var(--text-muted); font-size: 0.8rem;">
                No active APT campaign matches found for this sender infrastructure.
            </div>
        `;
    }
}

// Dedicated Full Screen Origin Map (Open Leaflet with OpenStreetMap)

// Dedicated Full Screen Origin Map
function renderFullMap(hops, originSummary) {
    if (!fullMap) return;

    fullHopMarkers.forEach(m => fullMap.removeLayer(m));
    fullHopMarkers = [];
    if (fullRoutePolyline) {
        fullMap.removeLayer(fullRoutePolyline);
        fullRoutePolyline = null;
    }

    const latLngs = [];

    hops.forEach(hop => {
        const geo = hop.geo;
        if (geo && !geo.is_private && geo.lat !== 0.0) {
            const point = [geo.lat, geo.lng];
            latLngs.push(point);

            const isOrigin = (hop.ip === originSummary.origin_ip);
            const markerColor = isOrigin ? '#ff5b38' : '#7c6cf0';
            const markerHtml = `
                <div style="width: 20px; height: 20px; background: ${markerColor}; border: 2px solid #fff; border-radius: 50%; box-shadow: 0 0 15px ${markerColor};"></div>
            `;
            const icon = L.divIcon({ html: markerHtml, className: "", iconSize: [20, 20] });

            const marker = L.marker(point, { icon }).addTo(fullMap);
            marker.bindPopup(`
                <div style="font-family: monospace; font-size: 11px; color: #111;">
                    <strong>Hop #${hop.hop_number} ${isOrigin ? '(PROBABLE ORIGIN)' : ''}</strong><br/>
                    <strong>IP:</strong> ${hop.ip}<br/>
                    <strong>Location:</strong> ${geo.city}, ${geo.country}<br/>
                    <strong>ISP:</strong> ${geo.isp} (${geo.asn})<br/>
                    <strong>Classification:</strong> ${geo.classification || 'Standard Relay'}
                </div>
            `);
            fullHopMarkers.push(marker);
        }
    });

    if (latLngs.length > 1) {
        fullRoutePolyline = L.polyline(latLngs, { color: "#ff5b38", weight: 3, opacity: 0.9, dashArray: "6, 6" }).addTo(fullMap);
        fullMap.fitBounds(fullRoutePolyline.getBounds(), { padding: [50, 50] });
    } else if (latLngs.length === 1) {
        fullMap.setView(latLngs[0], 5);
    }
}

// Modal
function openBlockchainModal() {
    if (!currentCaseData) return;
    const cert = currentCaseData.section_65b_certificate;
    const block = currentCaseData.blockchain_receipt;

    document.getElementById("certCaseId").textContent = cert.case_id;
    document.getElementById("certSha256").textContent = cert.sha256_digest;
    document.getElementById("certBlockNum").textContent = block.block_number;
    document.getElementById("certTxHash").textContent = block.tx_hash;
    document.getElementById("certDeclaration").textContent = cert.declaration;

    document.getElementById("evidenceModal").style.display = "flex";
}

function closeBlockchainModal() {
    document.getElementById("evidenceModal").style.display = "none";
}

function exportForensicPdf() {
    window.print();
}

// ================= THREAT SIMULATOR STUDIO CONTROLLER =================
function openSimulatorModal() {
    loadCurrentIntoSimulator();
    document.getElementById("simulatorModal").style.display = "flex";
}

function closeSimulatorModal() {
    document.getElementById("simulatorModal").style.display = "none";
}

function onSimIpSelectChange(val) {
    const customInput = document.getElementById("simCustomIp");
    if (val === "custom") {
        customInput.style.display = "block";
        customInput.focus();
    } else {
        customInput.style.display = "none";
    }
}

function loadCurrentIntoSimulator() {
    if (!currentCaseData) return;
    const meta = currentCaseData.metadata || {};
    const origin = currentCaseData.origin_summary || {};

    document.getElementById("simFromName").value = meta.from ? meta.from.replace(/<.*?>/, "").trim() : "Investigator";
    const emailMatch = meta.from ? meta.from.match(/<([^>]+)>/) : null;
    document.getElementById("simFromEmail").value = emailMatch ? emailMatch[1] : (meta.from || "sender@domain.com");
    document.getElementById("simSubject").value = meta.subject || "";
    document.getElementById("simBody").value = currentCaseData.preview_body || "";
    
    // Set IP
    const sel = document.getElementById("simOriginIpSelect");
    const ip = origin.origin_ip || "185.220.101.5";
    let found = false;
    for (let i = 0; i < sel.options.length; i++) {
        if (sel.options[i].value === ip) {
            sel.selectedIndex = i;
            found = true;
            break;
        }
    }
    if (!found) {
        sel.value = "custom";
        document.getElementById("simCustomIp").style.display = "block";
        document.getElementById("simCustomIp").value = ip;
    } else {
        document.getElementById("simCustomIp").style.display = "none";
    }
}

function loadSimPreset(type) {
    if (type === "homoglyph") {
        document.getElementById("simFromName").value = "Member Secretary, AICTE";
        document.getElementById("simFromEmail").value = "membersecretary@\u0430icte-india.org";
        document.getElementById("simOriginIpSelect").value = "185.220.101.5";
        document.getElementById("simCustomIp").style.display = "none";
        document.getElementById("simReplyTo").value = "compliance-desk@secure-aicte-portal.top";
        document.getElementById("simSubject").value = "CRITICAL: Immediate Revocation of AICTE Approval (Action in 24 Hours)";
        document.getElementById("simBody").value = "CONFIDENTIAL NOTICE:\n\nIt has come to the attention of the AICTE Inspection Committee that your institution has failed mandatory compliance standards.\n\nPenalty regularization payment of INR 2,50,000 must be transferred immediately to the escrow account within 24 hours to prevent immediate police FIR and blacklisting.\n\nVerification portal: http://185.220.101.5/login-verify/portal-auth";
    } else if (type === "bec") {
        document.getElementById("simFromName").value = "National Lab Instruments Vendor";
        document.getElementById("simFromEmail").value = "billing@univ-finance-desk.net";
        document.getElementById("simOriginIpSelect").value = "198.98.56.12";
        document.getElementById("simCustomIp").style.display = "none";
        document.getElementById("simReplyTo").value = "settlements@vendor-pay-hub.xyz";
        document.getElementById("simSubject").value = "URGENT: Updated Bank Details for Invoice #INV-2026-8812";
        document.getElementById("simBody").value = "Dear Finance Officer,\n\nRegarding the outstanding invoice #INV-2026-8812 for the amount of INR 14,50,000:\n\nDo not disburse funds to our old account due to an audit. Please wire the payment to our updated corporate account immediately to avoid stoppage of lab equipment deliveries.";
    } else if (type === "clean") {
        document.getElementById("simFromName").value = "AICTE Academic Planning";
        document.getElementById("simFromEmail").value = "noreply@aicte-india.org";
        document.getElementById("simOriginIpSelect").value = "103.27.8.44";
        document.getElementById("simCustomIp").style.display = "none";
        document.getElementById("simReplyTo").value = "";
        document.getElementById("simSubject").value = "Official Announcement: National Faculty Development Program on Cybersecurity 2026";
        document.getElementById("simBody").value = "Greetings from All India Council for Technical Education (AICTE),\n\nWe are pleased to announce the two-week National Faculty Development Program on Cybersecurity and Cloud Forensics scheduled for next month. Registration is free of cost for all approved technical institutions.";
    }
}

function injectSnippet(type) {
    const bodyEl = document.getElementById("simBody");
    if (type === "extortion") {
        bodyEl.value += "\n\nA penalty fee of INR 50,000 must be remitted immediately to avoid punitive regulatory actions.";
    } else if (type === "fir") {
        bodyEl.value += "\n\nFailure to comply within the statutory 24-hour deadline will result in an immediate police FIR and institutional blacklisting.";
    } else if (type === "bank") {
        bodyEl.value += "\n\nBank Account: AICTE Regulatory Escrow\nAccount Number: 918273645102\nIFSC Code: SBIN0001824";
    } else if (type === "dropper") {
        bodyEl.value += "\n\nDownload and execute the secure verification statement immediately:\nhttp://118.193.41.102/invoices/Invoice-PO98104-AuditStatement.pdf.exe";
    }
    bodyEl.scrollTop = bodyEl.scrollHeight;
}

async function submitSimulatedEmail(e) {
    e.preventDefault();

    const fromName = document.getElementById("simFromName").value.trim();
    const fromEmail = document.getElementById("simFromEmail").value.trim();
    const sel = document.getElementById("simOriginIpSelect").value;
    const customIp = document.getElementById("simCustomIp").value.trim();
    const ip = (sel === "custom" && customIp) ? customIp : sel;
    const replyTo = document.getElementById("simReplyTo").value.trim();
    const subject = document.getElementById("simSubject").value.trim();
    const body = document.getElementById("simBody").value;
    const isPii = document.getElementById("piiToggle").checked;

    const dateStr = new Date().toUTCString();
    const rawMail = `Received: from mail-sim.relay-node.net ([${ip}]) by soc-gateway.in with ESMTP id 88A9F; ${dateStr}\r\nFrom: "${fromName}" <${fromEmail}>\r\nTo: "Simulated Recipient" <target@college.ac.in>\r\n${replyTo ? `Reply-To: <${replyTo}>\r\n` : ''}Subject: ${subject}\r\nDate: ${dateStr}\r\nMessage-ID: <sim-${Date.now()}@hoptrace.sim>\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\n${body}`;

    const formData = new FormData();
    formData.append("raw_text", rawMail);
    formData.append("pii_mask", isPii);

    // Deselect sample buttons
    document.querySelectorAll(".sample-pill-btn").forEach(btn => btn.classList.remove("active"));

    try {
        const res = await fetch("/api/analyze", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        currentCaseData = data;

        // Custom badge for simulation
        data.case_id = `SIM-${data.case_id.split('-').pop()}`;
        renderAllPages(data);
        switchPage("dashboard");
        closeSimulatorModal();

        // Brief flash feedback
        const badge = document.getElementById("activeCaseIdDisplay");
        if (badge) {
            badge.style.backgroundColor = "var(--primary)";
            badge.style.color = "#fff";
            badge.textContent = `${data.case_id} (LIVE SIMULATION)`;
        }
    } catch (err) {
        alert("Error running simulation: " + err.message);
    }
}

// ================= LIVE EMAIL THREAT SCANNER CONTROLLER =================
function renderScannerPage(data) {
    if (!data) return;
    const score = data.threat_assessment ? data.threat_assessment.composite_score : 0;
    const severity = data.threat_assessment ? data.threat_assessment.severity : "UNKNOWN";
    const verdict = data.threat_assessment ? data.threat_assessment.verdict : "ANALYSIS IN PROGRESS";

    // Score & Risk
    const scoreEl = document.getElementById("scannerThreatScore");
    if (scoreEl) {
        scoreEl.textContent = `${score} / 100`;
        scoreEl.style.color = score >= 75 ? "var(--danger)" : score >= 50 ? "var(--accent-saffron)" : "var(--accent-green)";
    }
    const badgeEl = document.getElementById("scannerRiskBadge");
    if (badgeEl) {
        badgeEl.textContent = severity;
        badgeEl.className = "trend-badge " + (score >= 75 ? "danger" : score >= 50 ? "purple" : "success");
    }
    const verdEl = document.getElementById("scannerVerdictVerdict");
    if (verdEl) verdEl.textContent = verdict;

    const meterEl = document.getElementById("scannerScoreMeter");
    if (meterEl) {
        meterEl.style.width = `${Math.min(100, Math.max(5, score))}%`;
        meterEl.style.backgroundColor = score >= 75 ? "var(--danger)" : score >= 50 ? "var(--accent-saffron)" : "var(--accent-green)";
    }

    // Origin
    const origVal = document.getElementById("scannerOriginVal");
    if (origVal && data.origin_summary) {
        origVal.textContent = `${data.origin_summary.origin_ip} - ${data.origin_summary.city}, ${data.origin_summary.country}`;
    }
    const origClass = document.getElementById("scannerOriginClassVal");
    if (origClass && data.origin_summary) {
        const infraType = data.origin_summary.is_tor ? "Tor Exit Node (Critical Risk)" : data.origin_summary.is_vpn ? "Commercial VPN Relay" : (data.origin_summary.threat_classification || "Direct Host");
        origClass.textContent = `${infraType} | ISP: ${data.origin_summary.isp || 'Unknown'}`;
    }

    // Homoglyph
    const homoVal = document.getElementById("scannerHomoglyphVal");
    const homoSub = document.getElementById("scannerHomoglyphSub");
    if (homoVal && data.homoglyph_analysis) {
        if (data.homoglyph_analysis.has_homoglyphs) {
            homoVal.textContent = `Cyrillic Spoofing Detected: ${data.homoglyph_analysis.detected_char || 'Confusable'}`;
            homoVal.style.color = "var(--danger)";
            if (homoSub) homoSub.textContent = `Punycode: ${data.homoglyph_analysis.punycode || 'Active'}`;
        } else {
            homoVal.textContent = "Clean ASCII Domain (No Homoglyphs Detected)";
            homoVal.style.color = "var(--accent-green)";
            if (homoSub) homoSub.textContent = "Legitimate character set";
        }
    }

    // Protocol Auth Pills
    const spfPill = document.getElementById("scannerSpfPill");
    const dkimPill = document.getElementById("scannerDkimPill");
    const dmarcPill = document.getElementById("scannerDmarcPill");
    if (data.authentication) {
        const spf = (data.authentication.spf && data.authentication.spf.status) ? data.authentication.spf.status.toUpperCase() : "NONE";
        const dkim = (data.authentication.dkim && data.authentication.dkim.status) ? data.authentication.dkim.status.toUpperCase() : "NONE";
        const dmarc = (data.authentication.dmarc && data.authentication.dmarc.status) ? data.authentication.dmarc.status.toUpperCase() : "NONE";
        if (spfPill) {
            spfPill.textContent = `SPF: ${spf}`;
            spfPill.className = "auth-mini-pill " + (spf === "PASS" ? "pass" : "fail");
        }
        if (dkimPill) {
            dkimPill.textContent = `DKIM: ${dkim}`;
            dkimPill.className = "auth-mini-pill " + (dkim === "PASS" ? "pass" : "fail");
        }
        if (dmarcPill) {
            dmarcPill.textContent = `DMARC: ${dmarc}`;
            dmarcPill.className = "auth-mini-pill " + (dmarc === "PASS" ? "pass" : "fail");
        }
    }

    // Detected NLP Cues
    const cuesContainer = document.getElementById("scannerCuesContainer");
    if (cuesContainer && data.nlp_analysis) {
        cuesContainer.innerHTML = "";
        const cues = (data.nlp_analysis.threat_cues && data.nlp_analysis.threat_cues.length > 0)
            ? data.nlp_analysis.threat_cues
            : ["No Fraudulent Language Patterns Detected"];
        cues.forEach(cue => {
            const span = document.createElement("span");
            span.className = "cue-pill";
            span.textContent = cue;
            cuesContainer.appendChild(span);
        });
    }

    // Also populate form fields with active case if inputs are empty
    const emailInp = document.getElementById("liveEmailInput");
    if (emailInp && !emailInp.value && data.metadata && data.metadata.from) {
        const match = data.metadata.from.match(/<([^>]+)>/);
        emailInp.value = match ? match[1] : data.metadata.from;
    }
    const nameInp = document.getElementById("liveFromNameInput");
    if (nameInp && !nameInp.value && data.metadata && data.metadata.from) {
        const match = data.metadata.from.match(/^"([^"]+)"/);
        if (match) nameInp.value = match[1];
    }
    const subjInp = document.getElementById("liveSubjectInput");
    if (subjInp && !subjInp.value && data.metadata) {
        subjInp.value = data.metadata.subject || "";
    }
    const bodyInp = document.getElementById("liveBodyInput");
    if (bodyInp && !bodyInp.value && data.preview_body) {
        bodyInp.value = data.preview_body;
    }
}

function injectCueToScanner(type) {
    const bodyEl = document.getElementById("liveBodyInput");
    if (!bodyEl) return;
    if (type === "extortion") {
        bodyEl.value += "\n\nA penalty fee of INR 50,000 must be remitted immediately to avoid punitive regulatory actions.";
    } else if (type === "fir") {
        bodyEl.value += "\n\nFailure to comply within the statutory 24-hour deadline will result in an immediate police FIR and institutional blacklisting.";
    } else if (type === "bank") {
        bodyEl.value += "\n\nBank Account: AICTE Regulatory Escrow\nAccount Number: 918273645102\nIFSC Code: SBIN0001824";
    } else if (type === "dropper") {
        bodyEl.value += "\n\nDownload and execute the secure verification statement immediately:\nhttp://118.193.41.102/invoices/Invoice-PO98104-AuditStatement.pdf.exe";
    }
    bodyEl.scrollTop = bodyEl.scrollHeight;
}

function resetScannerForm() {
    const emailInp = document.getElementById("liveEmailInput");
    if (emailInp) emailInp.value = "";
    const nameInp = document.getElementById("liveFromNameInput");
    if (nameInp) nameInp.value = "";
    const subjInp = document.getElementById("liveSubjectInput");
    if (subjInp) subjInp.value = "";
    const replyInp = document.getElementById("liveReplyToInput");
    if (replyInp) replyInp.value = "";
    const bodyInp = document.getElementById("liveBodyInput");
    if (bodyInp) bodyInp.value = "";
    const ipSel = document.getElementById("liveOriginIpSelect");
    if (ipSel) ipSel.value = "auto";
}

function quickFillAndScan(email, subject, ip, body, fromName) {
    const emailEl = document.getElementById("liveEmailInput");
    if (emailEl) emailEl.value = email;
    const subjEl = document.getElementById("liveSubjectInput");
    if (subjEl) subjEl.value = subject;
    const ipEl = document.getElementById("liveOriginIpSelect");
    if (ipEl) ipEl.value = ip;
    const bodyEl = document.getElementById("liveBodyInput");
    if (bodyEl) bodyEl.value = body;
    const nameEl = document.getElementById("liveFromNameInput");
    if (nameEl) nameEl.value = fromName || "";

    runScannerAudit(email, subject, ip, body, fromName);
}

async function handleLiveEmailScan(e) {
    if (e && e.preventDefault) e.preventDefault();
    const email = document.getElementById("liveEmailInput").value.trim();
    if (!email) return;

    const fromName = document.getElementById("liveFromNameInput") ? document.getElementById("liveFromNameInput").value.trim() : "";
    const subject = document.getElementById("liveSubjectInput").value.trim() || `Security Audit: Notice from ${email}`;
    const ipSel = document.getElementById("liveOriginIpSelect") ? document.getElementById("liveOriginIpSelect").value : "auto";
    const body = document.getElementById("liveBodyInput").value.trim() || `Official security transmission verification test for sender account ${email}.`;

    // Determine IP if 'auto'
    let ip = ipSel;
    if (ip === "auto" || !ip) {
        if (email.includes("aicte-india.org") || email.endsWith(".gov.in") || email.endsWith(".nic.in")) {
            ip = "103.27.8.44"; // New Delhi NIC
        } else if (email.includes("\u0430") || email.includes("top")) {
            ip = "185.220.101.5"; // Frankfurt Tor
        } else if (email.includes("net") || email.includes("univ")) {
            ip = "198.98.56.12"; // Dallas VPN
        } else if (email.includes("refund") || email.includes("tax") || email.includes("site")) {
            ip = "185.193.88.21"; // Bucharest
        } else {
            ip = "185.220.102.8"; // Default suspicious relay
        }
    }

    runScannerAudit(email, subject, ip, body, fromName);
}

async function runScannerAudit(email, subject, ip, body, fromName) {
    const btn = document.getElementById("scannerSubmitBtn");
    const label = document.getElementById("scannerBtnLabel");
    const originalText = label ? label.textContent : "Audit & Trace Email";

    if (label) label.textContent = "Auditing Headers & Tracing...";
    if (btn) btn.disabled = true;

    // Build realistic MIME string
    const dateStr = new Date().toUTCString();
    const domain = email.split("@")[1] || "unknown-relay.net";
    const displayName = fromName || email.split("@")[0].replace(/[\._]/g, " ").toUpperCase();
    const isPii = document.getElementById("piiToggle") ? document.getElementById("piiToggle").checked : false;
    const replyToInput = document.getElementById("liveReplyToInput");
    const replyToVal = replyToInput ? replyToInput.value.trim() : "";
    const replyToHeader = replyToVal ? `Reply-To: <${replyToVal}>\r\n` : "";

    const rawMail = `Received: from mail-scanner.gateway.in ([${ip}]) by cyber-soc-hub.in with ESMTP id SCAN_${Date.now()}; ${dateStr}\r\nFrom: "${displayName}" <${email}>\r\nTo: "Target Institution" <admin@college.ac.in>\r\n${replyToHeader}Subject: ${subject}\r\nDate: ${dateStr}\r\nMessage-ID: <scan-${Date.now()}@${domain}>\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\n${body}`;

    const formData = new FormData();
    formData.append("raw_text", rawMail);
    formData.append("pii_mask", isPii);

    // Deselect sample buttons
    document.querySelectorAll(".sample-pill-btn").forEach(b => b.classList.remove("active"));

    try {
        const res = await fetch("/api/analyze", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        currentCaseData = data;

        data.case_id = `LIVE-${data.case_id.split('-').pop()}`;
        renderAllPages(data);

        // Update badge
        const badge = document.getElementById("activeCaseIdDisplay");
        if (badge) {
            badge.style.backgroundColor = "var(--primary)";
            badge.style.color = "#ffffff";
            badge.textContent = `${data.case_id} (LIVE AUDIT)`;
        }
    } catch (err) {
        alert("Error auditing email: " + err.message);
    } finally {
        if (label) label.textContent = originalText;
        if (btn) btn.disabled = false;
    }
}


