"""
WifiForge — Exporter
LogNorm-compatible ECS-lite NDJSON export.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("wififorge.exporter")


def _primary_technique(attck_techniques: list[dict]) -> tuple[str, str, str]:
    """Return (technique_id, technique_name, tactic) for the first technique, or UNKNOWN."""
    if attck_techniques:
        t = attck_techniques[0]
        return t.get("technique_id", "UNKNOWN"), t.get("technique_name", "Unknown"), t.get("tactic", "Unknown")
    return "UNKNOWN", "Unknown", "Unknown"


def to_lognorm(network: dict) -> dict:
    """Convert a single assessed network to an ECS-lite NDJSON record."""
    tid, tname, tactic = _primary_technique(network.get("attck_techniques", []))
    return {
        "event.kind":            "alert",
        "event.category":        "network",
        "network.ssid":          network.get("ssid") or "",
        "network.bssid":         network.get("bssid") or "",
        "network.channel":       network.get("channel"),
        "network.encryption":    network.get("encryption") or "",
        "network.wps_enabled":   bool(network.get("wps")),
        "network.rssi":          network.get("rssi"),
        "vulnerability.severity": network.get("severity", "INFO"),
        "threat.technique.id":   tid,
        "threat.technique.name": tname,
        "threat.tactic.name":    tactic,
        "source.tool":           "WifiForge",
        "@timestamp":            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def export_lognorm(networks: list[dict]) -> str:
    """Produce an NDJSON string for a list of assessed networks."""
    lines = []
    for network in networks:
        try:
            lines.append(json.dumps(to_lognorm(network)))
        except Exception as exc:
            logger.warning("Failed to serialize network %s: %s", network.get("bssid"), exc)
    return "\n".join(lines)
