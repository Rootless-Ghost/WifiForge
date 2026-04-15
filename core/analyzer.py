"""
WifiForge — Security Analyzer
Per-network severity assessment, findings, recommendations, and ATT&CK mapping.
"""

from __future__ import annotations

# ── ATT&CK mappings ───────────────────────────────────────────────────────────

_ATTCK: dict[str, dict] = {
    "T1040": {
        "technique_id":   "T1040",
        "technique_name": "Network Sniffing",
        "tactic":         "Discovery",
    },
    "T1110": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
    },
    "T1499": {
        "technique_id":   "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic":         "Impact",
    },
    "T1583": {
        "technique_id":   "T1583",
        "technique_name": "Acquire Infrastructure",
        "tactic":         "Resource Development",
    },
}


def _attck(tid: str) -> dict:
    return _ATTCK.get(tid, {"technique_id": tid, "technique_name": "Unknown", "tactic": "Unknown"})


# ── Per-network assessment ────────────────────────────────────────────────────

def assess(network: dict) -> dict:
    """
    Assess a single network dict produced by WifiScanner.
    Returns the network dict augmented with:
      severity    : CRITICAL | HIGH | MEDIUM | LOW | INFO
      findings    : list of finding strings
      recommendations : list of recommendation strings
      attck_techniques : list of ATT&CK dicts
    """
    enc = (network.get("encryption") or "UNKNOWN").upper()
    wps = bool(network.get("wps"))
    deauth = bool(network.get("deauth"))
    hidden = bool(network.get("hidden"))

    findings: list[str] = []
    recommendations: list[str] = []
    techniques: list[dict] = []
    severity_rank = 0  # higher = worse; map to label at the end

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    if enc == "OPEN":
        findings.append("Open network — no encryption, all traffic is visible in plaintext")
        recommendations.append("Enable WPA2 or WPA3 with a strong passphrase immediately")
        techniques.append(_attck("T1040"))
        severity_rank = max(severity_rank, 4)

    if enc == "WEP":
        findings.append("WEP encryption — deprecated and crackable in minutes")
        recommendations.append("Upgrade to WPA2-AES or WPA3 immediately; WEP offers no real protection")
        techniques.append(_attck("T1040"))
        severity_rank = max(severity_rank, 4)

    # ── HIGH ──────────────────────────────────────────────────────────────────

    if wps:
        findings.append("WPS enabled — vulnerable to Pixie Dust and brute-force PIN attacks")
        recommendations.append("Disable WPS in router settings; it adds significant attack surface")
        techniques.append(_attck("T1110"))
        severity_rank = max(severity_rank, 3)

    if deauth:
        findings.append("Deauthentication frames detected — possible deauth/disassociation attack in progress")
        recommendations.append("Enable 802.11w (Management Frame Protection) to prevent deauth attacks")
        techniques.append(_attck("T1499"))
        severity_rank = max(severity_rank, 3)

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    if enc == "WPA":
        findings.append("WPA/TKIP encryption — known vulnerabilities (TKIP MIC attacks, KRACK)")
        recommendations.append("Upgrade to WPA2-AES or WPA3")
        techniques.append(_attck("T1040"))
        severity_rank = max(severity_rank, 2)

    # ── LOW ───────────────────────────────────────────────────────────────────

    if hidden:
        findings.append("Hidden SSID — obscurity is not security; SSID is trivially discoverable via probe frames")
        recommendations.append("Relying on hidden SSID provides no real security; use strong encryption instead")
        techniques.append(_attck("T1583"))
        severity_rank = max(severity_rank, 1)

    # ── INFO (WPA2 / WPA3 with no other issues) ───────────────────────────────

    if enc in ("WPA2", "WPA3") and severity_rank == 0:
        findings.append(f"{enc} encryption — currently considered secure")
        recommendations.append("Ensure a strong passphrase (12+ chars, mixed) and keep firmware updated")

    if not findings:
        findings.append("No significant vulnerabilities detected")
        recommendations.append("Keep firmware updated and use a strong passphrase")

    # Deduplicate techniques by ID
    seen: set[str] = set()
    unique_techniques: list[dict] = []
    for t in techniques:
        if t["technique_id"] not in seen:
            seen.add(t["technique_id"])
            unique_techniques.append(t)

    severity_labels = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

    result = dict(network)
    result["severity"]         = severity_labels[severity_rank]
    result["findings"]         = findings
    result["recommendations"]  = recommendations
    result["attck_techniques"] = unique_techniques
    return result


def assess_all(networks: list[dict]) -> list[dict]:
    """Assess every network in the list and return augmented dicts sorted by severity."""
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    assessed = [assess(n) for n in networks]
    assessed.sort(key=lambda n: _order.get(n["severity"], 5))
    return assessed
