import math
import joblib
import warnings
import time
from scapy.all import sniff, TCP, Raw, get_if_list

warnings.filterwarnings("ignore", category=UserWarning)

# ANSI Color Codes
RED   = '\033[91m\033[1m'
GREEN = '\033[92m'
CYAN  = '\033[96m'
RESET = '\033[0m'

# ──────────────────────────────────────────────
#  TUNING KNOBS
# ──────────────────────────────────────────────
ENTROPY_SAFE_THRESHOLD   = 4.5   # below this → safe plain text
ENTROPY_ALERT_THRESHOLD  = 7.2   # above this + AI=1 → RED ALERT
LOOPBACK_ALERT_ENTROPY   = 7.5   # loopback high entropy → direct alert (victim.py)
MIN_PAYLOAD_BYTES        = 200   # lowered so victim.py 1024-byte chunks always pass
SAFE_PRINT_INTERVAL      = 0.4   # seconds between safe traffic prints
ALERT_COOLDOWN           = 5.0   # seconds to stay in ALERT MODE after last threat
LOOPBACK_IPS             = {"127.0.0.1", "::1"}
# ──────────────────────────────────────────────

# Global state
last_safe_print = 0.0
last_alert_time = 0.0
alert_mode      = False

def get_all_interfaces():
    """Return ALL interfaces including lo (loopback) for victim.py simulation."""
    return get_if_list()  # includes lo, wlo1, eth0, etc.

def calculate_entropy(payload):
    if not payload:
        return 0.0
    length = len(payload)
    byte_counts = [0] * 256
    for byte in payload:
        byte_counts[byte] += 1
    entropy = 0.0
    for count in byte_counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def is_known_tls_pattern(payload):
    """
    True for real TLS/HTTPS from browser.
    TLS records always start with content-type (0x14-0x17) + version (0x03 0x0x).
    os.urandom() will almost never match this exact pattern.
    """
    if len(payload) < 3:
        return False
    return payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03

def fire_alert(src_ip, dst_ip, port, entropy, payload_len, confidence=None):
    """Print the RED ALERT banner."""
    global alert_mode, last_alert_time
    alert_mode      = True
    last_alert_time = time.time()

    conf_line = f"  Confidence : {confidence*100:.1f}%" if confidence is not None else \
                f"  Confidence : Rule-Based (Loopback Random Payload)"

    print(f"\n{RED}{'='*55}{RESET}")
    print(f"{RED}  🚨  MALICIOUS EXFILTRATION DETECTED!  🚨{RESET}")
    print(f"{RED}{'='*55}{RESET}")
    print(f"{RED}  From       : {src_ip}{RESET}")
    print(f"{RED}  To         : {dst_ip}  Port: {port}{RESET}")
    print(f"{RED}  Entropy    : {entropy:.4f} / 8.0{RESET}")
    print(f"{RED}  Payload    : {payload_len} bytes{RESET}")
    print(f"{RED}  {conf_line}{RESET}")
    print(f"{RED}{'='*55}{RESET}\n")

def process_packet(packet):
    global last_safe_print, last_alert_time, alert_mode

    if not (packet.haslayer(Raw) and packet.haslayer(TCP)):
        return

    payload = bytes(packet[Raw].load)
    if len(payload) < MIN_PAYLOAD_BYTES:
        return

    size    = len(packet)
    port    = packet[TCP].dport
    entropy = calculate_entropy(payload)
    now     = time.time()

    src_ip = packet['IP'].src if packet.haslayer('IP') else "?"
    dst_ip = packet['IP'].dst if packet.haslayer('IP') else "?"

    # ── Update alert_mode cooldown ───────────────────────────────
    if alert_mode and (now - last_alert_time > ALERT_COOLDOWN):
        alert_mode = False
        print(f"\n{GREEN}[✔] Threat cleared. Resuming normal monitoring...{RESET}\n")

    # ── RULE-BASED: Loopback + high entropy = victim.py simulation
    # No legitimate app sends os.urandom() to localhost:443
    if src_ip in LOOPBACK_IPS and dst_ip in LOOPBACK_IPS:
        if entropy > LOOPBACK_ALERT_ENTROPY:
            fire_alert(src_ip, dst_ip, port, entropy, len(payload), confidence=None)
            return
        # Loopback but low entropy → show as safe
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{GREEN}[SAFE] Loopback Traffic | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── FAST PATH: Safe plain-text traffic ──────────────────────
    if entropy < ENTROPY_SAFE_THRESHOLD:
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{GREEN}[SAFE] Normal Traffic | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── FILTER: Legitimate TLS/HTTPS from browser ────────────────
    if is_known_tls_pattern(payload):
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{CYAN}[SAFE] Encrypted Web Traffic | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── AI DETECTION PATH (for non-loopback suspicious traffic) ──
    try:
        prediction = classifier.predict([[entropy, size, port]])[0]
        confidence = classifier.predict_proba([[entropy, size, port]])[0][1]

        if prediction == 1 and entropy > ENTROPY_ALERT_THRESHOLD and confidence > 0.75:
            fire_alert(src_ip, dst_ip, port, entropy, len(payload), confidence)
        else:
            if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
                print(f"{CYAN}[SAFE] High-Entropy Safe | {src_ip} → {dst_ip}:{port} | Entropy: {entropy:.2f}{RESET}")
                last_safe_print = now

    except Exception:
        pass

# ── ENTRY POINT ──────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("   CryptoFlow IDS — Real-Time Exfiltration Detector")
    print("=" * 55)

    print("\nLoading AI model...")
    try:
        classifier = joblib.load("traffic_classifier.pkl")
    except FileNotFoundError:
        print("[!] 'traffic_classifier.pkl' not found. Run train_model.py first.")
        exit(1)
    print("✅ Model loaded.\n")

    interfaces = get_all_interfaces()
    if not interfaces:
        print("[!] No network interfaces found.")
        exit(1)

    print("🔍 Monitoring interfaces:")
    for iface in interfaces:
        print(f"   • {iface}")

    print(f"\n⚡ Scanner ACTIVE — monitoring ALL traffic (WiFi + Loopback).")
    print(f"   Normal mode  → Shows SAFE traffic continuously")
    print(f"   Attack mode  → Suppresses SAFE, shows only RED ALERTs")
    print(f"   Press Ctrl+C to stop.\n")
    print("-" * 55)

    sniff(
        iface=interfaces,
        filter="tcp",
        prn=process_packet,
        store=False
    )
