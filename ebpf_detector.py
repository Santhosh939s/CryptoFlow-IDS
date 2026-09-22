import sys
import os
import time
import math
import struct
import socket
import joblib
import ctypes
import warnings
from mitigation import FirewallMitigator

warnings.filterwarnings("ignore", category=UserWarning)

# ANSI Color Codes
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

def calculate_entropy(payload_bytes: bytes) -> float:
    """Calculates Shannon Entropy for a given payload slice."""
    if not payload_bytes:
        return 0.0
    length = len(payload_bytes)
    byte_counts = [0] * 256
    for b in payload_bytes:
        byte_counts[b] += 1
    entropy = 0.0
    for count in byte_counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def is_known_tls_pattern(payload: bytes) -> bool:
    """
    True for standard TLS/HTTPS record layers from browsers.
    TLS records start with content-type (0x14-0x17) + version (0x03 0x0x).
    """
    if len(payload) < 3:
        return False
    return payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03

def fire_alert(src_ip, dst_ip, port, entropy, payload_len, protocol, is_quic, confidence=None):
    """Prints the RED ALERT banner and triggers automated iptables firewall mitigation."""
    global alert_mode, last_alert_time
    alert_mode      = True
    last_alert_time = time.time()

    proto_name = "QUIC (UDP)" if is_quic else ("TCP" if protocol == 6 else "UDP")
    conf_line = f"  Confidence : {confidence * 100:.1f}%" if confidence is not None else \
                f"  Confidence : Rule-Based (Loopback Random Payload)"

    print(f"\n{RED}{'=' * 58}{RESET}")
    print(f"{RED}  🚨  MALICIOUS EXFILTRATION DETECTED [eBPF KERNEL]  🚨{RESET}")
    print(f"{RED}{'=' * 58}{RESET}")
    print(f"{RED}  Protocol   : {proto_name}{RESET}")
    print(f"{RED}  From       : {src_ip}{RESET}")
    print(f"{RED}  To         : {dst_ip}  Port: {port}{RESET}")
    print(f"{RED}  Entropy    : {entropy:.4f} / 8.0{RESET}")
    print(f"{RED}  Payload    : {payload_len} bytes{RESET}")
    print(f"{RED}{conf_line}{RESET}")
    print(f"{RED}{'=' * 58}{RESET}")

    # Automated Mitigation Action
    blocked = mitigator.block_ip(src_ip)
    if blocked:
        print(f"{YELLOW}  🛡️  AUTOMATED MITIGATION: iptables DROP rule installed for {src_ip}{RESET}")
        print(f"{YELLOW}{'=' * 58}{RESET}\n")
    else:
        print()

def process_event(cpu, data, size):
    """
    Callback invoked whenever the kernel eBPF program pushes a packet event
    to the BPF_PERF_OUTPUT ring buffer.
    """
    global last_safe_print, last_alert_time, alert_mode

    # Unpack C struct:
    # u32 src_ip, dst_ip; u16 src_port, dst_port; u32 packet_size, payload_len;
    # u8 protocol, is_quic; u16 payload_captured_len; unsigned char payload[1024];
    header_format = "=IIHHIIBBH"
    header_size = struct.calcsize(header_format)

    (src_ip_raw, dst_ip_raw, src_port, dst_port,
     packet_size, payload_len, protocol, is_quic,
     captured_len) = struct.unpack_from(header_format, data)

    src_ip = socket.inet_ntoa(struct.pack("=I", src_ip_raw))
    dst_ip = socket.inet_ntoa(struct.pack("=I", dst_ip_raw))

    # Read captured payload slice directly from memory buffer
    payload_ptr = ctypes.cast(data + header_size, ctypes.POINTER(ctypes.c_char * captured_len))
    payload = bytes(payload_ptr.contents)

    entropy = calculate_entropy(payload)
    now = time.time()

    # Reset alert mode after cooldown
    if alert_mode and (now - last_alert_time > ALERT_COOLDOWN):
        alert_mode = False
        print(f"\n{GREEN}[✔] Threat cleared. Resuming real-time eBPF monitoring...{RESET}\n")

    proto_label = "QUIC" if is_quic else ("TCP" if protocol == 6 else "UDP")

    # ── RULE-BASED: Loopback Simulation (victim.py) ──────────────────
    if src_ip in LOOPBACK_IPS and dst_ip in LOOPBACK_IPS:
        if entropy > LOOPBACK_ALERT_ENTROPY:
            fire_alert(src_ip, dst_ip, dst_port, entropy, payload_len, protocol, is_quic, confidence=None)
            return
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{GREEN}[SAFE] Loopback {proto_label} | {src_ip} → {dst_ip}:{dst_port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── FAST PATH: Safe plain-text traffic ───────────────────────────
    if entropy < ENTROPY_SAFE_THRESHOLD:
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{GREEN}[SAFE] Normal Traffic | {src_ip} → {dst_ip}:{dst_port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── FILTER: Legitimate TLS Web Traffic ───────────────────────────
    if is_known_tls_pattern(payload):
        if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
            print(f"{CYAN}[SAFE] Encrypted TLS Web | {src_ip} → {dst_ip}:{dst_port} | Entropy: {entropy:.2f}{RESET}")
            last_safe_print = now
        return

    # ── AI DETECTION PATH (Random Forest Model) ──────────────────────
    try:
        # Feature Vector: [Entropy, PacketSize, DstPort]
        features = [[entropy, packet_size, dst_port]]
        prediction = classifier.predict(features)[0]
        confidence = classifier.predict_proba(features)[0][1]

        if prediction == 1 and entropy > ENTROPY_ALERT_THRESHOLD and confidence > 0.75:
            fire_alert(src_ip, dst_ip, dst_port, entropy, payload_len, protocol, is_quic, confidence)
        else:
            if not alert_mode and (now - last_safe_print > SAFE_PRINT_INTERVAL):
                tag = f"[SAFE] Encrypted {proto_label}"
                print(f"{CYAN}{tag} | {src_ip} → {dst_ip}:{dst_port} | Entropy: {entropy:.2f}{RESET}")
                last_safe_print = now
    except Exception:
        pass

def get_interfaces():
    """Detect loopback and available active network interfaces on Linux."""
    ifaces = ["lo"]
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == '00000000' and fields[0] not in ifaces:
                    ifaces.append(fields[0])
    except Exception:
        pass
    return ifaces

def main():
    global classifier, mitigator

    print("=" * 58)
    print("   CryptoFlow IDS — Next-Gen eBPF Real-Time Detector")
    print("=" * 58)

    # 1. Initialize Firewall Mitigation Engine
    # Set enable_loopback_block=True if you want to test dropping 127.0.0.1 in testing
    mitigator = FirewallMitigator(enable_loopback_block=False)

    # 2. Load AI Model
    print("\nLoading AI model...")
    try:
        classifier = joblib.load("traffic_classifier.pkl")
        print("✅ Model loaded successfully.\n")
    except FileNotFoundError:
        print("[!] 'traffic_classifier.pkl' not found. Run train_model.py first.")
        sys.exit(1)

    # 3. Compile and Load eBPF C Code via BCC
    try:
        from bcc import BPF
    except ImportError:
        print("[!] BCC (python3-bpfcc) is not installed.")
        print("    Install via: sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)")
        sys.exit(1)

    c_source_file = "ebpf_sniffer.c"
    if not os.path.exists(c_source_file):
        print(f"[!] eBPF source file '{c_source_file}' not found.")
        sys.exit(1)

    print("⚡ Compiling and loading in-kernel eBPF socket filter...")
    bpf = BPF(src_file=c_source_file)
    fn = bpf.load_func("packet_filter", BPF.SOCKET_FILTER)

    # 4. Attach eBPF filter to raw sockets on network interfaces
    interfaces = get_interfaces()
    print("🔍 Attaching eBPF probes to interfaces:")
    attached_count = 0
    for iface in interfaces:
        try:
            BPF.attach_raw_socket(fn, iface)
            print(f"   • {iface} (ACTIVE)")
            attached_count += 1
        except Exception as e:
            print(f"   • {iface} (FAILED: {e})")

    if attached_count == 0:
        print("[!] Failed to attach eBPF probe to any interface. Ensure root privileges.")
        sys.exit(1)

    # 5. Open Ring Buffer and Poll
    bpf["events"].open_perf_buffer(process_event)

    print(f"\n⚡ eBPF Kernel Probe ACTIVE — ultra-low latency monitoring enabled.")
    print(f"   Protocols    : TCP and UDP (QUIC)")
    print(f"   Mitigation   : Automated iptables DROP on detection")
    print(f"   Press Ctrl+C to stop.\n")
    print("-" * 58)

    try:
        while True:
            bpf.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print(f"\n{CYAN}[*] Shutting down CryptoFlow eBPF IDS...{RESET}")
        mitigator.cleanup()
        print(f"{GREEN}[✔] Clean exit. Goodbye!{RESET}")

if __name__ == "__main__":
    if sys.platform == "linux" and os.geteuid() != 0:
        print("[!] eBPF and iptables require root privileges. Run with:")
        print("    sudo python3 ebpf_detector.py")
        sys.exit(1)
    main()
