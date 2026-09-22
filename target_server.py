import sys
import socket
import threading

HOST = "127.0.0.1"
PORT = 443  # Default HTTPS port used by CryptoFlow simulation

def start_tcp_listener():
    """Listens for TCP connections and discards received data."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] TCP Target Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[+] TCP Connection established from {addr[0]}:{addr[1]}")
            while True:
                data = conn.recv(4096)
                if not data:
                    break
            conn.close()
    except PermissionError:
        print(f"[!] Permission denied binding to port {PORT}. Run as Administrator or use a port > 1024.")
    except Exception as e:
        print(f"[!] TCP server error: {e}")

def start_udp_listener():
    """Listens for UDP / QUIC packets and discards received data."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((HOST, PORT))
        print(f"[*] UDP/QUIC Target Server listening on {HOST}:{PORT}")

        while True:
            data, addr = s.recvfrom(4096)
    except PermissionError:
        print(f"[!] Permission denied binding UDP to port {PORT}. Run as Administrator.")
    except Exception as e:
        print(f"[!] UDP server error: {e}")

if __name__ == "__main__":
    print("=" * 55)
    print("   CryptoFlow IDS — Target Server (Terminal 1)")
    print("=" * 55)
    print(f"Listening on {HOST}:{PORT} for incoming simulated exfiltration.\n")

    # Run UDP in a background thread and TCP in foreground
    udp_thread = threading.Thread(target=start_udp_listener, daemon=True)
    udp_thread.start()

    try:
        start_tcp_listener()
    except KeyboardInterrupt:
        print("\nTarget server stopped.")
