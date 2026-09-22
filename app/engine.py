import sys
import os
import time
import math
import multiprocessing
import threading
import logging
from typing import List, Dict, Any, Optional, Callable

# Load root directory into sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.database import db
from app.forensics import forensics
from app.intel import intel_provider

if sys.platform == "win32":
    from windows_mitigation import WindowsFirewallMitigator as Mitigator
else:
    from mitigation import FirewallMitigator as Mitigator

logger = logging.getLogger("IDSEngine")

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

def is_known_tls(payload: bytes) -> bool:
    if len(payload) < 3:
        return False
    return payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03

def is_quic(payload: bytes, dport: int, sport: int) -> bool:
    if dport in (443, 8443) or sport in (443, 8443):
        if payload and (payload[0] & 0x40) != 0:
            return True
    return False

def _sniffer_process_worker(iface_target, event_queue: multiprocessing.Queue, stop_event: multiprocessing.Event):
    """
    Dedicated OS process for packet sniffing and CPU-intensive Shannon Entropy math.
    Bypasses Python GIL completely so FastAPI/WebSockets maintain 60 FPS.
    """
    # Load model inside the child process
    classifier = None
    model_path = os.path.join(ROOT_DIR, "traffic_classifier.pkl")
    if os.path.exists(model_path):
        try:
            import joblib
            classifier = joblib.load(model_path)
        except Exception:
            classifier = None

    try:
        from scapy.all import sniff, conf, TCP, UDP, Raw, IP

        if not iface_target or iface_target == "default":
            iface_target = conf.iface

        def _pkt_callback(packet):
            if stop_event.is_set():
                return

            try:
                if not packet.haslayer(Raw) or not (packet.haslayer(TCP) or packet.haslayer(UDP)):
                    return

                payload = bytes(packet[Raw].load)
                if len(payload) < 200:
                    return

                is_tcp = packet.haslayer(TCP)
                protocol = "TCP" if is_tcp else "UDP"
                port = packet[TCP].dport if is_tcp else packet[UDP].dport
                sport = packet[TCP].sport if is_tcp else packet[UDP].sport
                size = len(packet)

                # CPU-intensive math runs on dedicated core
                entropy = calculate_entropy(payload)
                quic_flag = is_quic(payload, port, sport)
                tls_flag = is_known_tls(payload)

                src_ip = packet[IP].src if packet.haslayer(IP) else "127.0.0.1"
                dst_ip = packet[IP].dst if packet.haslayer(IP) else "127.0.0.1"

                is_threat = False
                confidence = 0.0

                # Threat Classification
                if src_ip in ("127.0.0.1", "::1") and dst_ip in ("127.0.0.1", "::1"):
                    if entropy > 7.5:
                        is_threat = True
                        confidence = 0.99
                elif entropy < 4.5 or tls_flag:
                    is_threat = False
                elif classifier:
                    pred = classifier.predict([[entropy, size, port]])[0]
                    conf = classifier.predict_proba([[entropy, size, port]])[0][1]
                    if pred == 1 and entropy > 7.2 and conf > 0.75:
                        is_threat = True
                        confidence = float(conf)
                elif entropy > 7.6:
                    is_threat = True
                    confidence = 0.85

                # Dispatch event back to main FastAPI process
                event_queue.put_nowait({
                    "type": "flow",
                    "timestamp": time.time(),
                    "data": {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": port,
                        "protocol": "QUIC" if quic_flag else ("TLS" if tls_flag else protocol),
                        "entropy": round(entropy, 2),
                        "size": size,
                        "payload_len": len(payload),
                        "is_quic": quic_flag,
                        "is_threat": is_threat,
                        "confidence": round(confidence * 100, 1),
                        "payload_sample": payload[:1500] if is_threat else b""
                    }
                })

            except Exception:
                pass

        sniff(
            iface=iface_target,
            filter="tcp or udp",
            prn=_pkt_callback,
            stop_filter=lambda p: stop_event.is_set(),
            store=False
        )

    except Exception as e:
        event_queue.put_nowait({
            "type": "engine_error",
            "timestamp": time.time(),
            "data": {"error": str(e)}
        })
    finally:
        event_queue.put_nowait({
            "type": "engine_status",
            "timestamp": time.time(),
            "data": {"status": "stopped"}
        })

class IDSEngine:
    """
    Multiprocessing IDS Engine controller.
    Runs sniffer in an isolated OS process via multiprocessing.Process
    and streams events to FastAPI via multiprocessing.Queue.
    """

    def __init__(self):
        self.running = False
        self.process: Optional[multiprocessing.Process] = None
        self.stop_event: Optional[multiprocessing.Event] = None
        self.event_queue: Optional[multiprocessing.Queue] = None
        self.queue_reader_thread: Optional[threading.Thread] = None

        self.selected_interface: Optional[str] = None
        self.mitigator = Mitigator(enable_loopback_block=False)
        self.event_subscribers: List[Callable[[Dict[str, Any]], None]] = []

        self.stats = {
            "packets_inspected": 0,
            "threats_detected": 0,
            "quic_packets": 0,
            "tcp_packets": 0,
            "tls_packets": 0,
            "blocked_count": 0,
            "pps": 0,
            "current_threat_level": "NORMAL",
            "last_threat_time": 0.0
        }
        self.packet_rate_counter = 0
        self.rate_timer = time.time()
        self.recent_entropies = []

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]):
        self.event_subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]):
        if callback in self.event_subscribers:
            self.event_subscribers.remove(callback)

    def _broadcast(self, event: Dict[str, Any]):
        for sub in list(self.event_subscribers):
            try:
                sub(event)
            except Exception:
                pass

    def get_available_interfaces(self) -> List[Dict[str, str]]:
        results = []
        if sys.platform == "win32":
            try:
                from scapy.all import get_windows_if_list
                for iface in get_windows_if_list():
                    name = iface.get("name", "")
                    desc = iface.get("description", "")
                    ips = iface.get("ips", [])
                    ip_str = ", ".join(ips) if ips else "No IP"
                    results.append({
                        "id": name,
                        "name": f"{desc} ({ip_str})",
                        "is_loopback": "loopback" in desc.lower() or "npcap loopback" in name.lower()
                    })
            except Exception:
                pass
        else:
            try:
                from scapy.all import get_if_list
                for iface in get_if_list():
                    results.append({
                        "id": iface,
                        "name": iface,
                        "is_loopback": iface == "lo"
                    })
            except Exception:
                pass

        if not results:
            results.append({"id": "default", "name": "Default Interface", "is_loopback": False})
        return results

    def start(self, interface: Optional[str] = None):
        """Spawns the packet sniffer in a completely separate OS process."""
        if self.running:
            return

        self.selected_interface = interface
        self.stop_event = multiprocessing.Event()
        self.event_queue = multiprocessing.Queue()
        self.running = True
        self.stats["current_threat_level"] = "NORMAL"

        iface_target = self.selected_interface
        if not iface_target or iface_target == "default":
            avail = self.get_available_interfaces()
            loopback_or_active = [a["id"] for a in avail if a.get("is_loopback")]
            iface_target = loopback_or_active[0] if loopback_or_active else "default"

        # Spawn separate OS process to bypass GIL
        self.process = multiprocessing.Process(
            target=_sniffer_process_worker,
            args=(iface_target, self.event_queue, self.stop_event),
            daemon=True
        )
        self.process.start()

        # Start thread in main process to drain the multiprocessing Queue
        self.queue_reader_thread = threading.Thread(target=self._queue_drainer, daemon=True)
        self.queue_reader_thread.start()

        logger.info(f"IDS Sniffer Process started (PID: {self.process.pid}) on interface: {iface_target}")
        self._broadcast({"type": "engine_status", "data": {"status": "running", "interface": iface_target}})

    def stop(self):
        """Signals the child sniffer process to stop and waits for it."""
        if not self.running:
            return

        self.running = False
        if self.stop_event:
            self.stop_event.set()

        if self.process and self.process.is_alive():
            self.process.join(timeout=2.0)
            if self.process.is_alive():
                self.process.terminate()

        logger.info("IDS Sniffer Process stopped.")
        self._broadcast({"type": "engine_status", "data": {"status": "stopped"}})

    def _queue_drainer(self):
        """Drains IPC queue from sniffer process and updates stats / database."""
        while self.running and self.event_queue:
            try:
                event = self.event_queue.get(timeout=0.2)
                self._handle_ipc_event(event)
            except Exception:
                continue

    def _handle_ipc_event(self, event: Dict[str, Any]):
        event_type = event.get("type")
        data = event.get("data", {})

        if event_type == "flow":
            self.packet_rate_counter += 1
            self.stats["packets_inspected"] += 1

            proto = data.get("protocol")
            if proto == "QUIC":
                self.stats["quic_packets"] += 1
            elif proto == "TLS":
                self.stats["tls_packets"] += 1
            else:
                self.stats["tcp_packets"] += 1

            entropy = data.get("entropy", 0.0)
            self.recent_entropies.append(entropy)
            if len(self.recent_entropies) > 50:
                self.recent_entropies.pop(0)

            # Check if this flow is a threat
            if data.get("is_threat"):
                self._handle_threat(data)

            self._broadcast(event)

        elif event_type in ("engine_status", "engine_error"):
            if event_type == "engine_status" and data.get("status") == "stopped":
                self.running = False
            self._broadcast(event)

    def _handle_threat(self, data: Dict[str, Any]):
        self.stats["threats_detected"] += 1
        self.stats["current_threat_level"] = "CRITICAL"
        self.stats["last_threat_time"] = time.time()

        src_ip = data.get("src_ip", "127.0.0.1")
        dst_ip = data.get("dst_ip", "127.0.0.1")
        port = data.get("port", 443)
        entropy = data.get("entropy", 7.5)
        size = data.get("size", 1024)
        payload_len = data.get("payload_len", 1024)
        protocol = data.get("protocol", "TCP")
        is_quic_flag = data.get("is_quic", False)
        confidence = data.get("confidence", 95.0) / 100.0

        payload_sample = data.get("payload_sample", b"")

        # 1. Threat Intelligence & IP Enrichment
        intel = intel_provider.enrich_ip(src_ip, entropy)
        country = intel.get("country", "Local Lab / Simulation")
        country_code = intel.get("country_code", "LOC")
        flag = intel.get("flag", "🧪")
        asn = intel.get("asn", "AS-PRIVATE")
        threat_score = intel.get("threat_score", 85)

        # 2. Execute firewall mitigation with atomic caching
        mitigated = self.mitigator.block_ip(src_ip)
        if mitigated:
            self.stats["blocked_count"] += 1
            db.log_blocked_ip(src_ip, reason=f"High-entropy exfiltration ({entropy:.2f})")

        # 3. Automated Forensic Incident PCAP Capture
        now_ts = int(time.time())
        pcap_file = forensics.record_incident_packet(
            threat_id=now_ts,
            packet_bytes=payload_sample,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=port,
            protocol=protocol
        )

        # 4. Persist to SQLite
        threat_id = db.log_threat(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=port,
            entropy=entropy,
            packet_size=size,
            payload_len=payload_len,
            protocol=protocol,
            is_quic=is_quic_flag,
            confidence=confidence,
            mitigated=mitigated,
            country=country,
            country_code=country_code,
            flag=flag,
            asn=asn,
            threat_score=threat_score,
            pcap_file=pcap_file
        )

        threat_alert = {
            "type": "threat_alert",
            "timestamp": time.time(),
            "data": {
                "id": threat_id,
                "datetime_str": time.strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": port,
                "entropy": entropy,
                "packet_size": size,
                "payload_len": payload_len,
                "protocol": protocol,
                "is_quic": is_quic_flag,
                "confidence": round(confidence * 100, 1),
                "mitigated": mitigated,
                "country": country,
                "country_code": country_code,
                "flag": flag,
                "asn": asn,
                "threat_score": threat_score,
                "pcap_file": pcap_file
            }
        }
        self._broadcast(threat_alert)

    def get_status(self) -> Dict[str, Any]:
        now = time.time()
        elapsed = now - self.rate_timer
        if elapsed >= 1.0:
            self.stats["pps"] = int(self.packet_rate_counter / elapsed)
            self.packet_rate_counter = 0
            self.rate_timer = now

        if self.stats["current_threat_level"] == "CRITICAL" and (now - self.stats["last_threat_time"] > 5.0):
            self.stats["current_threat_level"] = "NORMAL"

        return {
            "running": self.running,
            "interface": self.selected_interface,
            "stats": self.stats,
            "recent_entropies": self.recent_entropies[-20:]
        }

engine = IDSEngine()
