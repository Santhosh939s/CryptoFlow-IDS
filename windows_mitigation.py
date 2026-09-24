import sys
import time
import logging
import subprocess
import threading
from typing import Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WindowsMitigator")

import atexit
import socket

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

# Reserved and loopback IPs protected from accidental blocking
SAFE_WHITELIST: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "255.255.255.255",
}

# Auto-discover local adapter IPs to prevent blocking the host computer
try:
    _hostname = socket.gethostname()
    for _ip in socket.gethostbyname_ex(_hostname)[2]:
        SAFE_WHITELIST.add(_ip)
except Exception:
    pass

class WindowsFirewallMitigator:
    """
    High-throughput automated network intrusion mitigation engine for Windows.
    Uses an atomic in-memory cache and locking to prevent spawning duplicate
    'netsh advfirewall' sub-processes during high-volume packet floods.
    """

    def __init__(self, enable_loopback_block: bool = False):
        self.blocked_ips: Set[str] = set()
        self.pending_blocks: Set[str] = set()
        self.cooldown_ips: dict = {} # ip -> retry_after_timestamp
        self._lock = threading.Lock()
        self.enable_loopback_block = enable_loopback_block
        # Register automatic cleanup of firewall rules when app exits
        atexit.register(self.cleanup)

    def _rule_name(self, ip: str) -> str:
        """Standardized firewall rule display name for CryptoFlow blocks."""
        sanitized_ip = ip.replace(":", "_")
        return f"CryptoFlow-Block-{sanitized_ip}"

    def _is_rule_present(self, ip: str) -> bool:
        """Check if a firewall rule for this IP already exists in Windows Firewall."""
        with self._lock:
            if ip in self.blocked_ips:
                return True

        rule_name = self._rule_name(ip)
        try:
            cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
                creationflags=CREATE_NO_WINDOW
            )
            is_present = result.returncode == 0 and "No rules match" not in result.stdout
            if is_present:
                with self._lock:
                    self.blocked_ips.add(ip)
            return is_present
        except Exception as e:
            logger.debug(f"Error checking firewall rule: {e}")
            return False

    def block_ip(self, ip: str) -> bool:
        """
        Actively block a malicious source IP by inserting an inbound BLOCK rule.
        Guarantees strictly ONE 'netsh' invocation per IP regardless of packet flood volume.
        Includes failure backoff cooldown to prevent CPU spikes if unauthorized.
        """
        if ip in SAFE_WHITELIST and not self.enable_loopback_block:
            logger.warning(f"Skipping Windows Firewall block for whitelisted address: {ip}")
            return False

        now = time.time()
        # Fast-path atomic in-memory cache check
        with self._lock:
            if ip in self.blocked_ips or ip in self.pending_blocks:
                return True
            if ip in self.cooldown_ips and now < self.cooldown_ips[ip]:
                return False
            # Mark as pending immediately to absorb any concurrent packet triggers
            self.pending_blocks.add(ip)

        rule_name = self._rule_name(ip)
        try:
            # netsh advfirewall firewall add rule name="..." dir=in action=block remoteip=...
            cmd = (
                f'netsh advfirewall firewall add rule '
                f'name="{rule_name}" '
                f'dir=in '
                f'action=block '
                f'remoteip={ip} '
                f'description="Automated intrusion block by CryptoFlow-IDS"'
            )
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                creationflags=CREATE_NO_WINDOW
            )

            with self._lock:
                self.pending_blocks.discard(ip)
                if result.returncode == 0:
                    self.blocked_ips.add(ip)
                    logger.warning(f"🛡️ [WINDOWS FIREWALL MITIGATION] Blocked malicious IP: {ip}")
                    return True
                else:
                    self.cooldown_ips[ip] = time.time() + 15.0
                    stderr = result.stderr.strip() or result.stdout.strip()
                    if "Run as administrator" in stderr or "administrator" in stderr.lower():
                        logger.error("Administrator privileges required to modify Windows Firewall.")
                    else:
                        logger.error(f"Failed to add firewall rule for {ip}: {stderr}")
                    return False

        except Exception as e:
            with self._lock:
                self.pending_blocks.discard(ip)
                self.cooldown_ips[ip] = time.time() + 15.0
            logger.error(f"Error executing Windows Firewall command for {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove the Windows Defender Firewall block rule for an IP."""
        rule_name = self._rule_name(ip)
        with self._lock:
            self.blocked_ips.discard(ip)
            self.pending_blocks.discard(ip)

        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                creationflags=CREATE_NO_WINDOW
            )
            logger.info(f"Unblocked IP: {ip}")
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False

    def cleanup(self):
        """Remove all dynamically created firewall rules upon detector shutdown."""
        with self._lock:
            ips_to_clear = list(self.blocked_ips)

        if not ips_to_clear:
            return

        logger.info("Cleaning up dynamic CryptoFlow Windows Firewall rules...")
        for ip in ips_to_clear:
            self.unblock_ip(ip)
