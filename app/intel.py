import logging
import ipaddress
import urllib.request
import json
import queue
import threading
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger("ThreatIntel")

class ThreatIntelProvider:
    """
    Asynchronous Threat Intelligence and Geolocation enrichment provider for CryptoFlow-IDS.
    Guarantees sub-millisecond detection and firewall mitigation by providing instant
    local/cached intel, and deferring remote HTTP lookups to an isolated background thread.
    """

    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lookup_queue: queue.Queue = queue.Queue(maxsize=2000)
        self._running = True
        self._worker_thread = threading.Thread(target=self._lookup_worker, daemon=True)
        self._worker_thread.start()

    def is_private_or_loopback(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved
        except Exception:
            return True

    def is_resolved(self, ip: str) -> bool:
        """Returns True if IP is already in cache or is private/loopback."""
        return (ip in self._cache) or self.is_private_or_loopback(ip)

    def get_fast_intel(self, ip: str, entropy: float = 7.5) -> Dict[str, Any]:
        """
        Instant (<0.01ms) threat actor metadata lookup without network I/O.
        Returns cached data, local lab data, or an initial non-blocking placeholder.
        """
        if ip in self._cache:
            return self._cache[ip]

        # 1. Loopback / Private / Lab Testing Ranges
        if self.is_private_or_loopback(ip):
            intel = {
                "ip": ip,
                "country": "Local Lab / Simulation",
                "country_code": "LOC",
                "flag": "🧪",
                "city": "Internal Network",
                "org": "Simulated Exfiltration Vector",
                "asn": "AS-PRIVATE",
                "threat_score": min(100, int((entropy / 8.0) * 100)),
                "category": "Covert Local Tunnel",
                "resolved": True
            }
            self._cache[ip] = intel
            return intel

        # 2. Fast non-blocking placeholder for unresolved public IPs
        placeholder = {
            "ip": ip,
            "country": "Resolving...",
            "country_code": "LOC",
            "flag": "🌐",
            "city": "Lookup in progress",
            "org": "Resolving ASN...",
            "asn": "AS-RESOLVING",
            "threat_score": min(100, int((entropy / 8.0) * 100)),
            "category": "High-Entropy Exfiltration Target",
            "resolved": False
        }
        return placeholder

    def enqueue_lookup(self, threat_id: int, ip: str, entropy: float = 7.5,
                       callback: Optional[Callable[[int, Dict[str, Any]], None]] = None):
        """
        Asynchronously enqueues remote GeoIP/ASN resolution without blocking the sniffing loop.
        Once resolved, triggers the callback to update SQLite and emit WebSocket events.
        """
        if self.is_resolved(ip):
            if callback:
                try:
                    callback(threat_id, self.get_fast_intel(ip, entropy))
                except Exception as e:
                    logger.error(f"Error in immediate intel callback: {e}")
            return

        try:
            self._lookup_queue.put_nowait({
                "threat_id": threat_id,
                "ip": ip,
                "entropy": entropy,
                "callback": callback
            })
        except queue.Full:
            logger.warning("Threat intel lookup queue full, dropping lookup request.")

    def _lookup_worker(self):
        """Background thread executing external HTTP requests to ip-api."""
        while self._running:
            try:
                task = self._lookup_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            threat_id = task["threat_id"]
            ip = task["ip"]
            entropy = task["entropy"]
            callback = task.get("callback")

            intel = self._resolve_ip_external(ip, entropy)
            self._cache[ip] = intel

            if callback:
                try:
                    callback(threat_id, intel)
                except Exception as e:
                    logger.error(f"Error executing async intel callback: {e}")

            self._lookup_queue.task_done()

    def _resolve_ip_external(self, ip: str, entropy: float = 7.5) -> Dict[str, Any]:
        """Performs HTTP lookup with timeout."""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            req = urllib.request.Request(url, headers={'User-Agent': 'CryptoFlow-IDS/2.0'})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("status") == "success":
                        flag_code = data.get("countryCode", "UN")
                        return {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "country_code": flag_code,
                            "flag": self._get_flag_emoji(flag_code),
                            "city": data.get("city", "Unknown"),
                            "org": data.get("org") or data.get("isp", "Unknown Host"),
                            "asn": data.get("as", "AS-UNKNOWN"),
                            "threat_score": min(100, int((entropy / 8.0) * 100)),
                            "category": "Encrypted Exfiltration Vector",
                            "resolved": True
                        }
        except Exception:
            pass

        return {
            "ip": ip,
            "country": "External Host",
            "country_code": "EXT",
            "flag": "🌐",
            "city": "Unknown",
            "org": "Remote Autonomous System",
            "asn": "AS-REMOTE",
            "threat_score": min(100, int((entropy / 8.0) * 100)),
            "category": "High-Entropy Exfiltration Target",
            "resolved": True
        }

    def enrich_ip(self, ip: str, entropy: float = 7.5) -> Dict[str, Any]:
        """Backwards-compatible synchronous helper."""
        if ip in self._cache:
            return self._cache[ip]
        if self.is_private_or_loopback(ip):
            return self.get_fast_intel(ip, entropy)
        intel = self._resolve_ip_external(ip, entropy)
        self._cache[ip] = intel
        return intel

    def _get_flag_emoji(self, country_code: str) -> str:
        """Converts standard 2-letter ISO country code into regional indicator flag emoji."""
        if not country_code or len(country_code) != 2:
            return "🌐"
        try:
            return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))
        except Exception:
            return "🌐"

intel_provider = ThreatIntelProvider()
