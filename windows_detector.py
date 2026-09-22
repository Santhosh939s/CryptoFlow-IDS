import sys
import os
import time
import math
import ctypes
import warnings
import joblib

# Windows administrator check
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# Scapy packet capture imports
try:
    from scapy.all import sniff, TCP, UDP, Raw, IP, conf, get_windows_if_list
except ImportError:
    print("[!] Scapy is not installed. Please install dependencies:")
    print("    pip install scapy scikit-learn pandas numpy joblib")
    sys.exit(1)

from windows_mitigation import WindowsFirewallMitigator

warnings.filterwarnings("ignore", category=UserWarning)

# ANSI Color Codes (Supported in Windows Terminal and PowerShell)
RED    = '\033[91m\033[1m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
YELLOW = '\033[93m'
RESET  = '\033[0m'

# ──────────────────────────────────────────────
#  TUNING KNOBS
# ──────────────────────────────────────────────
ENTROPY_SAFE_THRESHOLD   = 4.5   # Below this -> safe plain text
ENTROPY_ALERT_THRESHOLD  = 7.2   # Above this + AI=1 -> RED ALERT
LOOPBACK_ALERT_ENTROPY   = 7.5   # Loopback high entropy -> direct alert (victim.py)
MIN_PAYLOAD_BYTES        = 200   # Minimum payload length for inspection
SAFE_PRINT_INTERVAL      = 0.4   # Seconds between safe traffic prints
ALERT_COOLDOWN           = 5.0   # Seconds to stay in ALERT MODE after last threat
LOOPBACK_IPS             = {"127.0.0.1", "::1"}
# ──────────────────────────────────────────────

# Global State
last_safe_print = 0.0
last_alert_time = 0.0
alert_mode      = False
classifier      = None
mitigator       = None

def calculate_entropy(payload: bytes) -> float:
    """Calculates Shannon Entropy for a given byte sequence."""
    if not payload:
        return 0.0
    length = len(payload)
    byte_counts = [0] * 256
    for b in payload:
        byte_counts[b] += 1
    entropy = 0.0
    for count in byte_counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def is_known_tls_pattern(payload: bytes) -> bool:
    """Detects standard TLS/HTTPS record layer (0x14-0x17 followed by 0x03)."""
    if len(payload) < 3:
        return False
    return payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03

def is_quic_packet(payload: bytes, dst_port: int, src_port: int) -> bool:
    """
    Identifies RFC 9000 QUIC packets on UDP ports 443 / 8443.
    QUIC packets mandate fixed bit (0x40) set to 1 in both Long and Short Headers.
    """
    if dst_port in (443, 8443) or src_port in (443, 8443):
        if payload and (payload[0] & 0x40) != 0:
            return True
    return False

def fire_alert(src_ip, dst_ip, port, entropy, payload_len, protocol, is_quic, confidence=None):
    """Prints the RED ALERT banner and triggers automated Windows Defender Firewall mitigation."""
    global alert_mode, last_alert_time
    alert_mode      = True
    last_alert_time = time.time()

    proto_name = "QUIC (UDP)" if is_quic else ("TCP" if protocol == "TCP" else "UDP")
    conf_line = f"  Confidence : {confidence * 100:.1f}%" if confidence is not None else \
                f"  Confidence : Rule-Based (Loopback Random Payload)"

    print(f"\n{RED}{'=' * 58}{RESET}")
    print(f"{RED}  🚨  MALICIOUS EXFILTRATION DETECTED [WINDOWS IDS]  🚨{RESET}")
    print(f"{RED}{'=' * 58}{RESET}")
    print(f"{RED}  Protocol   : {proto_name}{RESET}")
    print(f"{RED}  From       : {src_ip}{RESET}")
    print(f"{RED}  To         : {dst_ip}  Port: {port}{RESET}")
    print(f"{RED}  Entropy    : {entropy:.4f} / 8.0{RESET}")
    print(f"{RED}  Payload    : {payload_len} bytes{RESET}")
    print(f"{RED}{conf_line}{RESET}")
    print(f"{RED}{'=' * 58}{RESET}")

    # Automated Windows Firewall Mitigation
    blocked = mitigator.block_ip(src_ip)
    if blocked:
        print(f"{YELLOW}  🛡️  WINDOWS FIREWALL: Inbound BLOCK rule added for {src_ip}{RESET}")
        print(f"{YELLOW}{'=' * 58}{RESET}\n")
    else:
        print()

def process_packet(packet):
    """Processes captured Windows packets, runs feature extraction and AI inference."""
    global last_safe_print, last_alert_time, alert_mode

    # Must contain Raw payload and be TCP or UDP
    if not packet.haslayer(Raw) or not (packet.haslayer(TCP) or packet.haslayer(UDP)):
        return

    payload = bytes(packet[Raw].load)
    if len(payload) < MIN_PAYLOAD_BYTES:
        return

    protocol = "TCP" if packet.haslayer(TCP) else "UDP"
    port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
    src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
    size = len(packet)
    entropy = calculate_entropy(payload)
    is_quic = is_quic_packet(payload, port, src_port)
    now = time.time()

    src_ip = packet[IP].src if packet.haslayer(IP) else "?"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "?"

    # Reset alert cooldown
    if alert_mode and (now - last_alert_time > ALERT_COOLDOWN):
        alert_mode = False
        print(f"\n{GREEN}[✔] Threat cleared. Resuming normal Windows monitoring...{RESET}\n")

    proto_label = "QUIC" if is_quic else protocol

    # ── RULE-BASED: Loopback Simulation (victim.py) ──────────────────
    if src_ip in LOOPBACK_IPS and dst_ip in LOOPBACK_IPS:
        if entropy > LOOPBACK_ALERT_ENTROPY:
            fire_alert(src_ip, dst_ip, port, entropy, len(payload), protocol, is_quic, confidence=None)
            return
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{GREEN}[SAFE] Loopback {proto_label} | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── FAST PATH: Safe plain-text traffic ───────────────────────────
    if entropy < ENTROPY_SAFE_THRESHOLD:
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{GREEN}[SAFE] Normal Traffic | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── FILTER: Legitimate TLS Web Traffic ───────────────────────────
    if is_known_tls_pattern(payload):
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{CYAN}[SAFE] Encrypted TLS Web | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── AI DETECTION PATH (Random Forest Model) ──────────────────────
    try:
        features = [[entropy, size, port]]
        prediction = classifier.predict(features)[0]
        confidence = classifier.predict_proba(features)[0][1]

        if prediction == 1 and entropy > ENTROPY_ALERT_THRESHOLD and confidence > 0.75:
            fire_alert(src_ip, dst_ip, port, entropy, len(payload), protocol, is_quic, confidence)
        else:
            if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
                tag = f"[SAFE] High-Entropy {proto_label}"
                print(f"{CYAN}{tag} | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
                last_safe_print = now
    except Exception:
        pass

def select_windows_interfaces():
    """Detect available network interfaces on Windows, prioritizing active adapters and Npcap Loopback."""
    ifaces_to_monitor = []
    try:
        win_if_list = get_windows_if_list()
        for iface in win_if_list:
            name = iface.get("name", "")
            description = iface.get("description", "")
            # Look for Npcap loopback adapter or active network adapters
            if "loopback" in description.lower() or "npcap loopback" in name.lower():
                ifaces_to_monitor.append(iface.get("name"))
            elif iface.get("ips") and any(not ip.startswith("169.254") for ip in iface.get("ips", [])):
                ifaces_to_monitor.append(iface.get("name"))
    except Exception:
        pass

    if not ifaces_to_monitor:
        # Fallback to Scapy default interface
        ifaces_to_monitor = [conf.iface]
    return ifaces_to_monitor

def main():
    global classifier, mitigator

    print("=" * 58)
    print("   CryptoFlow IDS — Windows Real-Time Exfiltration Detector")
    print("=" * 58)

    if not is_admin():
        print(f"\n{YELLOW}[WARNING] Not running as Administrator!{RESET}")
        print("  Windows Defender Firewall mitigation requires Administrator rights.")
        print("  Please run Command Prompt / PowerShell as Administrator for full mitigation.\n")

    # 1. Initialize Windows Firewall Mitigator
    mitigator = WindowsFirewallMitigator(enable_loopback_block=False)

    # 2. Load AI Model
    print("Loading AI model...")
    try:
        classifier = joblib.load("traffic_classifier.pkl")
        print("✅ Random Forest AI model loaded.\n")
    except FileNotFoundError:
        print("[!] 'traffic_classifier.pkl' not found. Run train_model.py first.")
        sys.exit(1)

    # 3. Detect Windows Interfaces
    interfaces = select_windows_interfaces()
    print("🔍 Active Windows Interfaces selected for monitoring:")
    for iface in interfaces:
        print(f"   • {iface}")

    print(f"\n⚡ Scanner ACTIVE — monitoring TCP and UDP/QUIC.")
    print("   Mitigation Engine : Windows Defender Firewall (netsh)")
    print("   Press Ctrl+C to stop.\n")
    print("-" * 58)

    try:
        sniff(
            iface=interfaces,
            filter="tcp or udp",
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{CYAN}[*] Stopping Windows CryptoFlow IDS...{RESET}")
        mitigator.cleanup()
        print(f"{GREEN}[✔] Clean exit. Goodbye!{RESET}")
    except Exception as e:
        print(f"\n[!] Sniffing error: {e}")
        print("    Ensure Npcap is installed on Windows with 'Support loopback traffic' enabled.")
        mitigator.cleanup()

if __name__ == "__main__":
    main()
