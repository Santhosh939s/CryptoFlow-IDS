import socket
import os
import time
import threading
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("Simulator")

class AttackSimulator:
    """
    In-App simulation controller for demonstrating CryptoFlow-IDS.
    Manages the background target listener and sends simulated
    malicious encrypted chunks (TCP & QUIC) with 1 click from the UI.
    """

    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 443):
        self.target_ip = target_ip
        self.target_port = target_port

        self.server_running = False
        self.tcp_server_sock: Optional[socket.socket] = None
        self.udp_server_sock: Optional[socket.socket] = None
        self.server_thread: Optional[threading.Thread] = None

        self.simulating = False
        self.last_sim_result: Dict[str, Any] = {}

    def ensure_target_server(self):
        """Starts the local dummy target server if not already running."""
        if self.server_running:
            return True

        try:
            self.tcp_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_server_sock.bind((self.target_ip, self.target_port))
            self.tcp_server_sock.listen(5)

            self.udp_server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_server_sock.bind((self.target_ip, self.target_port))

            self.server_running = True

            def _listener():
                while self.server_running:
                    try:
                        self.tcp_server_sock.settimeout(1.0)
                        conn, _ = self.tcp_server_sock.accept()
                        threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
                    except socket.timeout:
                        continue
                    except Exception:
                        break

            self.server_thread = threading.Thread(target=_listener, daemon=True)
            self.server_thread.start()
            logger.info(f"Simulator target server running on {self.target_ip}:{self.target_port}")
            return True
        except Exception as e:
            logger.warning(f"Could not bind simulator to port {self.target_port}: {e}")
            self.server_running = False
            return False

    def _handle_client(self, conn: socket.socket):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
        except Exception:
            pass
        finally:
            conn.close()

    def run_simulation_async(self, mode: str = "both", chunks: int = 5, callback=None):
        """Runs the attack simulation asynchronously in a background thread."""
        if self.simulating:
            return False

        def _worker():
            self.simulating = True
            self.ensure_target_server()
            time.sleep(0.3)

            results = {
                "mode": mode,
                "chunks_sent": 0,
                "status": "in_progress",
                "error": None
            }

            try:
                if mode in ("tcp", "both"):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((self.target_ip, self.target_port))
                    for i in range(chunks):
                        payload = os.urandom(1024)
                        s.send(payload)
                        results["chunks_sent"] += 1
                        time.sleep(0.6)
                    s.close()

                if mode in ("quic", "both"):
                    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    for i in range(chunks):
                        # QUIC Initial packet simulation with RFC 9000 fixed bit
                        quic_header = bytes([0xC0, 0x00, 0x00, 0x00, 0x01])
                        payload = quic_header + os.urandom(1019)
                        u.sendto(payload, (self.target_ip, self.target_port))
                        results["chunks_sent"] += 1
                        time.sleep(0.6)
                    u.close()

                results["status"] = "completed"
            except Exception as e:
                logger.error(f"Simulation error: {e}")
                results["status"] = "failed"
                results["error"] = str(e)
            finally:
                self.simulating = False
                self.last_sim_result = results
                if callback:
                    callback(results)

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def get_status(self) -> Dict[str, Any]:
        return {
            "server_running": self.server_running,
            "target": f"{self.target_ip}:{self.target_port}",
            "simulating": self.simulating,
            "last_result": self.last_sim_result
        }

simulator = AttackSimulator()
