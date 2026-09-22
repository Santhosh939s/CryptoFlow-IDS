import os
import sys
import logging
import subprocess
from typing import Set

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("MitigationEngine")

# Loopback and reserved IPs protected by default
SAFE_WHITELIST: Set[str] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

class FirewallMitigator:
    """
    Automated network intrusion mitigation engine using iptables.
    Actively drops malicious source IPs at the Linux kernel firewall boundary.
    """

    def __init__(self, enable_loopback_block: bool = False, dry_run: bool = False):
        self.blocked_ips: Set[str] = set()
        self.enable_loopback_block = enable_loopback_block
        self.dry_run = dry_run or (sys.platform != "linux")

        if self.dry_run and sys.platform != "linux":
            logger.info("Non-Linux platform detected; FirewallMitigator running in simulation mode.")

    def _is_rule_present(self, ip: str) -> bool:
        """Check if an iptables rule already exists for this IP."""
        if self.dry_run:
            return ip in self.blocked_ips

        try:
            cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception:
            return False

    def block_ip(self, ip: str) -> bool:
        """
        Actively block a malicious source IP using an iptables DROP rule.
        Returns True if the block is active, False otherwise.
        """
        if ip in SAFE_WHITELIST and not self.enable_loopback_block:
            logger.warning(f"Skipping iptables block for whitelisted IP: {ip}")
            return False

        if ip in self.blocked_ips or self._is_rule_present(ip):
            logger.info(f"IP {ip} is already blocked.")
            self.blocked_ips.add(ip)
            return True

        if self.dry_run:
            self.blocked_ips.add(ip)
            logger.warning(f"🛡️ [DRY RUN / SIMULATION] iptables -I INPUT 1 -s {ip} -j DROP")
            return True

        try:
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            self.blocked_ips.add(ip)
            logger.warning(f"🛡️ [MITIGATION TRIGGERED] Blocked malicious IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute iptables block for {ip}: {e}")
            return False
        except PermissionError:
            logger.error("Root privileges required to run iptables. Please execute with sudo.")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove iptables block rule for an IP."""
        if self.dry_run:
            self.blocked_ips.discard(ip)
            logger.info(f"[SIMULATION] Unblocked IP: {ip}")
            return True

        try:
            # Remove all duplicate rules if any exist
            while self._is_rule_present(ip):
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, check=True)
            self.blocked_ips.discard(ip)
            logger.info(f"Unblocked IP: {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to unblock {ip}: {e}")
            return False

    def cleanup(self):
        """Clean up all dynamically added iptables rules upon engine shutdown."""
        if not self.blocked_ips:
            return
        logger.info("Flushing dynamic IDS mitigation rules...")
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
