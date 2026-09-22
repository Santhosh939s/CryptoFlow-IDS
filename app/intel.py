import logging
import ipaddress
import urllib.request
import json
from typing import Dict, Any

logger = logging.getLogger("ThreatIntel")

class ThreatIntelProvider:
    """
    Threat Intelligence and Geolocation enrichment provider for CryptoFlow-IDS.
    Enriches remote attacker IPs with Autonomous System (ASN), country, ISP,
    and calculated Threat Severity Scores.
    """

    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}

    def is_private_or_loopback(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved
        except Exception:
            return True

    def enrich_ip(self, ip: str, entropy: float = 7.5) -> Dict[str, Any]:
        """Resolves threat actor intelligence for an IP address."""
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
                "category": "Covert Local Tunnel"
            }
            self._cache[ip] = intel
            return intel

        # 2. Public IP resolution via lightweight GeoIP API
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            req = urllib.request.Request(url, headers={'User-Agent': 'CryptoFlow-IDS/2.0'})
            with urllib.request.urlopen(req, timeout=1.5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("status") == "success":
                        flag_code = data.get("countryCode", "UN")
                        intel = {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "country_code": flag_code,
                            "flag": self._get_flag_emoji(flag_code),
                            "city": data.get("city", "Unknown"),
                            "org": data.get("org") or data.get("isp", "Unknown Host"),
                            "asn": data.get("as", "AS-UNKNOWN"),
                            "threat_score": min(100, int((entropy / 8.0) * 100)),
                            "category": "Encrypted Exfiltration Vector"
                        }
                        self._cache[ip] = intel
                        return intel
        except Exception:
            pass

        # Fallback for offline or unreachable lookups
        fallback = {
            "ip": ip,
            "country": "External Host",
            "country_code": "EXT",
            "flag": "🌐",
            "city": "Unknown",
            "org": "Remote Autonomous System",
            "asn": "AS-REMOTE",
            "threat_score": min(100, int((entropy / 8.0) * 100)),
            "category": "High-Entropy Exfiltration Target"
        }
        self._cache[ip] = fallback
        return fallback

    def _get_flag_emoji(self, country_code: str) -> str:
        """Converts standard 2-letter ISO country code into regional indicator flag emoji."""
        if not country_code or len(country_code) != 2:
            return "🌐"
        try:
            return chr(127397 + ord(country_code[0].upper())) + chr(127397 + ord(country_code[1].upper()))
        except Exception:
            return "🌐"

intel_provider = ThreatIntelProvider()
