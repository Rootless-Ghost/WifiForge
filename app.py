"""
WifiForge — Wireless Network Security Analyzer
Part of the Nebula Forge Detection Suite v2

Port: 5013
Usage: python app.py
"""

import io
import logging
import os
import sys
import uuid

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

load_dotenv()

from core.scanner import WifiScanner, list_interfaces
from core.analyzer import assess_all
from core.exporter import export_lognorm

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("wififorge")

# ── Jinja2 filters ─────────────────────────────────────────────────────────────

def _rssi_class(rssi) -> str:
    """Map RSSI dBm value to a CSS quality class."""
    try:
        r = int(rssi)
    except (TypeError, ValueError):
        return "unknown"
    if r >= -50:
        return "excellent"
    if r >= -65:
        return "good"
    if r >= -75:
        return "fair"
    return "poor"


def _tactic_class(tactic: str) -> str:
    return tactic.lower().replace(" ", "-").replace("_", "-") if tactic else "unknown"


# ── Flask app ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
app.config["MOCK_MODE"] = False
app.jinja_env.filters["rssi_class"]   = _rssi_class
app.jinja_env.filters["tactic_class"] = _tactic_class


@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


_scanner = WifiScanner()
_last_raw_snapshot: list = []
_last_assessed: list = []

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    interfaces = list_interfaces()
    return render_template("index.html", interfaces=interfaces,
                           mock_mode=app.config["MOCK_MODE"])


@app.post("/mock/toggle")
def mock_toggle():
    app.config["MOCK_MODE"] = not app.config["MOCK_MODE"]
    state = "enabled" if app.config["MOCK_MODE"] else "disabled"
    logger.info("Mock mode %s via UI toggle", state)
    return redirect(url_for("index"))


@app.get("/mock/status")
def mock_status():
    return jsonify({"mock_mode": app.config["MOCK_MODE"]})


@app.post("/scan/start")
def scan_start():
    if _scanner.scanning:
        return jsonify({"error": "Scan already running"}), 409

    scan_id = str(uuid.uuid4())[:8]

    if app.config["MOCK_MODE"]:
        _scanner.load_mock()
        return jsonify({
            "scan_id": scan_id,
            "interface": "mock",
            "duration": 0,
            "mock": True,
            "started": True,
        })

    data = request.get_json(force=True, silent=True) or {}
    interface = data.get("interface", "").strip()
    duration = int(data.get("duration", 60))

    if not interface:
        interfaces = list_interfaces()
        interface = interfaces[0] if interfaces else ""

    if not interface:
        return jsonify({"error": "No wireless interface available. Enable Mock Mode to test without hardware."}), 400

    started = _scanner.start(interface, duration)
    if not started:
        return jsonify({"error": "Failed to start scan. Scapy may be unavailable or scan already running."}), 500

    return jsonify({
        "scan_id": scan_id,
        "interface": interface,
        "duration": duration,
        "mock": False,
        "started": True,
    })


@app.post("/scan/stop")
def scan_stop():
    _scanner.stop()
    return jsonify({"status": "stopped"})


@app.get("/scan/results")
def scan_results():
    global _last_raw_snapshot, _last_assessed
    raw = _scanner.results()
    if raw == _last_raw_snapshot:
        assessed = _last_assessed
    else:
        assessed = assess_all(raw)
        _last_assessed = assessed
        _last_raw_snapshot = raw
    return jsonify({
        "scanning": _scanner.scanning,
        "mock": app.config["MOCK_MODE"],
        "count": len(assessed),
        "networks": assessed,
    })


@app.get("/results")
def results_page():
    raw = _scanner.results()
    assessed = assess_all(raw)

    open_count   = sum(1 for n in assessed if n.get("encryption") == "OPEN")
    wps_count    = sum(1 for n in assessed if n.get("wps"))
    deauth_count = sum(1 for n in assessed if n.get("deauth"))

    return render_template(
        "results.html",
        networks=assessed,
        total=len(assessed),
        open_count=open_count,
        wps_count=wps_count,
        deauth_count=deauth_count,
        mock=app.config["MOCK_MODE"],
    )


@app.post("/export/lognorm")
def export_lognorm_route():
    raw = _scanner.results()
    if not raw:
        return jsonify({"error": "No scan results to export"}), 400

    assessed = assess_all(raw)
    try:
        ndjson = export_lognorm(assessed)
    except Exception as exc:
        logger.exception("LogNorm export error: %s", exc)
        return jsonify({"error": str(exc)}), 500

    buf = io.BytesIO(ndjson.encode("utf-8"))
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/x-ndjson",
        as_attachment=True,
        download_name="wififorge_lognorm.ndjson",
    )


@app.get("/health")
@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "tool": "WifiForge", "port": 5013})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("WifiForge starting on 0.0.0.0:5013")
    app.run(host="0.0.0.0", port=5013, debug=False)
