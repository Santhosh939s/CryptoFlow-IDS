import socket
import os
import time
import sys

TARGET_IP = "127.0.0.1"
TARGET_PORT = 443  # Standard HTTPS / QUIC port

def simulate_tcp_exfiltration():
    print(f"\n[*] Initiating simulated TCP exfiltration to {TARGET_IP}:{TARGET_PORT}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))

        for i in range(5):
            print(f"[-] Sending malicious high-entropy TCP chunk {i + 1}/5...")
            # High-entropy random payload mimicking encrypted exfiltration
            malicious_payload = os.urandom(1024)
            s.send(malicious_payload)
            time.sleep(1)

        s.close()
        print("[+] TCP exfiltration simulation complete.")
    except ConnectionRefusedError:
        print(f"[!] Connection failed! Is Terminal 1 running 'python target_server.py'?")

def simulate_quic_exfiltration():
    print(f"\n[*] Initiating simulated UDP/QUIC exfiltration to {TARGET_IP}:{TARGET_PORT}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for i in range(5):
            print(f"[-] Sending malicious high-entropy QUIC (UDP) packet {i + 1}/5...")
            # QUIC Long Header Initial packet simulation:
            # First byte: 0xC0 (Long Header + Fixed Bit), followed by QUIC v1 Version (0x00000001)
            quic_header = bytes([0xC0, 0x00, 0x00, 0x00, 0x01])
            malicious_payload = quic_header + os.urandom(1019)  # 1024 bytes total
            s.sendto(malicious_payload, (TARGET_IP, TARGET_PORT))
            time.sleep(1)

        s.close()
        print("[+] QUIC exfiltration simulation complete.")
    except Exception as e:
        print(f"[!] QUIC simulation error: {e}")

if __name__ == "__main__":
    print("=" * 55)
    print("   CryptoFlow IDS — Malicious Exfiltration Simulator")
    print("=" * 55)

    mode = "both"
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()

    if mode == "tcp":
        simulate_tcp_exfiltration()
    elif mode == "quic":
        simulate_quic_exfiltration()
    else:
        # Default: simulate both TCP and QUIC
        simulate_tcp_exfiltration()
        time.sleep(1)
        simulate_quic_exfiltration()
