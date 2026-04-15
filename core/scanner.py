"""
WifiForge — Passive WiFi Scanner
Scapy-based 802.11 beacon/probe/deauth capture, refactored from wifi_security_analyzer.py.

Requires:
  Linux  : root + wireless interface in monitor mode (airmon-ng start <iface>)
  Windows: Npcap installed (https://npcap.com) + admin privileges
  macOS  : root privileges
"""

import logging
import os
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger("wififorge.scanner")

# ── Scapy import (graceful fallback) ──────────────────────────────────────────

SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp,
        RadioTap, sniff,
    )
    SCAPY_AVAILABLE = True
except Exception as exc:
    logger.critical("Scapy import failed: %s — scan features disabled", exc)

# ── Mock dataset (UI testing / no hardware) ───────────────────────────────────

MOCK_NETWORKS = [
    {
        "ssid": "TestNet-Open", "bssid": "AA:BB:CC:11:22:33", "channel": 6,
        "rssi": -45, "encryption": "OPEN", "wps": False,
        "deauth": False, "hidden": False,
    },
    {
        "ssid": "TestNet-WEP", "bssid": "AA:BB:CC:44:55:66", "channel": 11,
        "rssi": -67, "encryption": "WEP", "wps": True,
        "deauth": False, "hidden": False,
    },
    {
        "ssid": "", "bssid": "AA:BB:CC:77:88:99", "channel": 1,
        "rssi": -78, "encryption": "WPA2", "wps": False,
        "deauth": True, "hidden": True,
    },
]


def _detect_encryption(packet) -> str:
    """
    Determine encryption type from a beacon/probe-response frame.
    Returns: OPEN | WEP | WPA | WPA2 | WPA3
    """
    cap = packet[Dot11Beacon].cap if packet.haslayer(Dot11Beacon) else 0

    privacy = bool(cap & 0x10)
    if not privacy:
        return "OPEN"

    # Walk information elements
    has_rsn = False
    has_wpa_ie = False
    has_wpa3 = False

    elt = packet.getlayer(Dot11Elt)
    while elt:
        # ID 48 = RSN (WPA2/WPA3)
        if elt.ID == 48 and elt.info:
            has_rsn = True
            # AKM suite list starts at offset 8 in RSN IE
            # Suite 00-0F-AC:8 = SAE → WPA3
            info = elt.info
            if len(info) >= 10:
                try:
                    akm_count = int.from_bytes(info[8:10], "little")
                    for i in range(akm_count):
                        offset = 10 + i * 4
                        if offset + 4 <= len(info):
                            akm = info[offset: offset + 4]
                            if akm == b"\x00\x0f\xac\x08":
                                has_wpa3 = True
                except Exception:
                    pass
        # ID 221 = Vendor Specific; WPA IE OUI = 00:50:F2:01
        elif elt.ID == 221 and elt.info and elt.info[:4] == b"\x00\x50\xf2\x01":
            has_wpa_ie = True
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            break

    if has_wpa3:
        return "WPA3"
    if has_rsn:
        return "WPA2"
    if has_wpa_ie:
        return "WPA"
    return "WEP"


def _detect_wps(packet) -> bool:
    """Return True if a WPS information element is present in the beacon."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        # ID 221, OUI 00:50:F2:04 = WPS
        if elt.ID == 221 and elt.info and elt.info[:4] == b"\x00\x50\xf2\x04":
            return True
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            break
    return False


# ── Scanner class ─────────────────────────────────────────────────────────────

class WifiScanner:
    def __init__(self):
        self._networks: dict[str, dict] = {}   # keyed by BSSID
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.scanning = False
        self.using_mock = False
        self.scan_start: str | None = None
        self.interface: str | None = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, interface: str, duration: int = 60) -> bool:
        """
        Start a background passive scan.
        Returns True if scan started, False if already running or no Scapy.
        """
        if self.scanning:
            logger.warning("Scan already running")
            return False

        self.interface = interface
        self._networks.clear()
        self._stop_event.clear()
        self.using_mock = False
        self.scan_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not SCAPY_AVAILABLE:
            logger.error("Scapy unavailable — cannot start scan")
            return False

        self._thread = threading.Thread(
            target=self._scan_worker,
            args=(interface, duration),
            daemon=True,
        )
        self._thread.start()
        self.scanning = True
        logger.info("Scan started on %s for %ds", interface, duration)
        return True

    def stop(self):
        """Signal the background scan to stop."""
        self._stop_event.set()
        self.scanning = False
        logger.info("Scan stop requested")

    def results(self) -> list[dict]:
        """Return a snapshot of discovered networks."""
        with self._lock:
            return list(self._networks.values())

    # ── Background worker ──────────────────────────────────────────────────────

    def _scan_worker(self, interface: str, duration: int):
        try:
            sniff(
                iface=interface,
                prn=self._packet_handler,
                store=False,
                timeout=duration,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
            logger.error("Scapy sniff error on %s: %s", interface, exc)
        finally:
            self.scanning = False
            logger.info("Scan finished — %d networks found", len(self._networks))

    def _packet_handler(self, packet):
        """Process a captured packet — beacon, probe response, or deauth."""
        try:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self._handle_beacon(packet)
            elif packet.haslayer(Dot11Deauth):
                self._handle_deauth(packet)
        except Exception as exc:
            logger.debug("Packet handler error: %s", exc)

    def _handle_beacon(self, packet):
        bssid = packet[Dot11].addr2
        if not bssid:
            return

        # Decode SSID
        try:
            raw_ssid = packet[Dot11Elt].info
            ssid = raw_ssid.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            ssid = ""

        hidden = ssid == ""

        # RSSI
        rssi = None
        if packet.haslayer(RadioTap):
            try:
                rssi = packet[RadioTap].dBm_AntSignal
            except Exception:
                pass

        # Channel
        channel = None
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3 and elt.info:
                try:
                    channel = elt.info[0]
                except Exception:
                    pass
                break
            try:
                elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                break

        encryption = _detect_encryption(packet)
        wps = _detect_wps(packet)

        with self._lock:
            if bssid not in self._networks:
                self._networks[bssid] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": channel,
                    "rssi": rssi,
                    "encryption": encryption,
                    "wps": wps,
                    "deauth": False,
                    "hidden": hidden,
                    "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            else:
                net = self._networks[bssid]
                net["last_seen"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                # Update RSSI and channel if we get fresh values
                if rssi is not None:
                    net["rssi"] = rssi
                if channel is not None:
                    net["channel"] = channel
                # Upgrade SSID if we now have it (hidden SSID may reveal itself)
                if not net["ssid"] and ssid:
                    net["ssid"] = ssid
                    net["hidden"] = False

    def _handle_deauth(self, packet):
        """Flag the destination BSSID as receiving deauth frames."""
        dst = packet[Dot11].addr1
        if not dst:
            return
        with self._lock:
            if dst in self._networks:
                self._networks[dst]["deauth"] = True
            else:
                # Record a stub entry so deauth data isn't lost
                self._networks[dst] = {
                    "ssid": "",
                    "bssid": dst,
                    "channel": None,
                    "rssi": None,
                    "encryption": "UNKNOWN",
                    "wps": False,
                    "deauth": True,
                    "hidden": False,
                    "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }

    # ── Mock fallback ──────────────────────────────────────────────────────────

    def load_mock(self):
        self.using_mock = True
        self.scanning = False
        with self._lock:
            for net in MOCK_NETWORKS:
                entry = dict(net)
                entry["first_seen"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                entry["last_seen"] = entry["first_seen"]
                self._networks[entry["bssid"]] = entry
        logger.info("Mock dataset loaded (%d networks)", len(MOCK_NETWORKS))


# ── Interface helpers ──────────────────────────────────────────────────────────

def list_interfaces() -> list[str]:
    """Return a list of available wireless interface names."""
    ifaces = []
    if os.name == "nt":
        # Windows — look for Wi-Fi adapters via ipconfig naming conventions
        try:
            import subprocess
            out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"],
                                          text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Name"):
                    ifaces.append(line.split(":", 1)[1].strip())
        except Exception:
            pass
    else:
        # Linux/macOS — scan /sys/class/net for wireless interfaces
        try:
            for name in os.listdir("/sys/class/net"):
                if os.path.exists(f"/sys/class/net/{name}/wireless"):
                    ifaces.append(name)
        except Exception:
            pass
        # Also check for mon* interfaces (already in monitor mode)
        try:
            for name in os.listdir("/sys/class/net"):
                if name.startswith("mon") and name not in ifaces:
                    ifaces.append(name)
        except Exception:
            pass

    if not ifaces:
        logger.warning("No wireless interfaces found")
    return ifaces
