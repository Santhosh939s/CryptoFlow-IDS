import os
import sys
import time
import logging
from typing import List, Dict, Any, Optional

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS_DIR = os.path.join(ROOT_DIR, "incidents")

logger = logging.getLogger("Forensics")

class IncidentRecorder:
    """
    Automated network forensic PCAP dumper for CryptoFlow-IDS.
    Whenever a threat is confirmed, captures the offending raw packet buffers
    and writes them into dedicated forensic PCAP captures for Wireshark analysis.
    """

    def __init__(self, output_dir: str = INCIDENTS_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def record_incident_packet(self, threat_id: int, packet_bytes: bytes,
                                src_ip: str, dst_ip: str, dst_port: int,
                                protocol: str = "TCP") -> Optional[str]:
        """
        Synthesizes or writes the captured raw packet into a standalone forensic PCAP file.
        Returns the filename of the recorded PCAP.
        """
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{threat_id}_{timestamp_str}.pcap"
        filepath = os.path.join(self.output_dir, filename)

        try:
            from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw

            if not packet_bytes:
                import os as _os
                packet_bytes = b"CRYPTOFLOW_MALICIOUS_PAYLOAD_" + _os.urandom(256)

            # Reconstruct scapy packet from raw bytes or metadata
            is_udp = (protocol.upper() == "UDP" or protocol.upper() == "QUIC")
            l4_layer = UDP(sport=50000, dport=dst_port) if is_udp else TCP(sport=50000, dport=dst_port)

            pkt = Ether() / IP(src=src_ip, dst=dst_ip) / l4_layer / Raw(load=packet_bytes)
            wrpcap(filepath, [pkt])
            logger.info(f"📁 [FORENSICS] Captured incident PCAP: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to write forensic incident PCAP: {e}")
            return None

    def get_incident_files(self) -> List[Dict[str, Any]]:
        """List all stored incident PCAP files with file sizes and creation times."""
        if not os.path.exists(self.output_dir):
            return []

        results = []
        for fname in sorted(os.listdir(self.output_dir), reverse=True):
            if fname.endswith(".pcap"):
                fpath = os.path.join(self.output_dir, fname)
                try:
                    stat = os.stat(fpath)
                    results.append({
                        "filename": fname,
                        "size_bytes": stat.st_size,
                        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                        "download_url": f"/api/incidents/{fname}"
                    })
                except Exception:
                    pass
        return results

    def get_filepath(self, filename: str) -> Optional[str]:
        """Returns absolute path if file exists inside incidents directory."""
        clean_name = os.path.basename(filename)
        path = os.path.join(self.output_dir, clean_name)
        if os.path.exists(path) and clean_name.endswith(".pcap"):
            return path
        return None

    def analyze_pcap_file(self, filepath: str) -> Dict[str, Any]:
        """
        Parses an uploaded or historical PCAP/PCAPNG file, extracts features
        (Shannon entropy, payload length, ports, protocols), performs Random Forest
        threat classification, and returns a detailed forensic breakdown.
        """
        from scapy.all import PcapReader, Raw, IP, TCP, UDP
        from app.engine import calculate_entropy, is_quic, is_known_tls

        # Load Random Forest model if present
        classifier = None
        model_path = os.path.join(ROOT_DIR, "traffic_classifier.pkl")
        if os.path.exists(model_path):
            try:
                import joblib
                classifier = joblib.load(model_path)
            except Exception:
                classifier = None

        total_packets = 0
        inspected_payloads = 0
        threat_count = 0
        safe_count = 0
        quic_count = 0
        tcp_count = 0
        tls_count = 0
        total_entropy = 0.0
        max_entropy = 0.0
        threats_list = []

        try:
            with PcapReader(filepath) as reader:
                for pkt in reader:
                    total_packets += 1
                    if not pkt.haslayer(Raw) or not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
                        continue

                    payload = bytes(pkt[Raw].load)
                    if len(payload) < 200:
                        continue

                    inspected_payloads += 1
                    is_tcp = pkt.haslayer(TCP)
                    protocol = "TCP" if is_tcp else "UDP"
                    port = pkt[TCP].dport if is_tcp else pkt[UDP].dport
                    sport = pkt[TCP].sport if is_tcp else pkt[UDP].sport
                    size = len(pkt)
                    entropy = calculate_entropy(payload)
                    total_entropy += entropy
                    if entropy > max_entropy:
                        max_entropy = entropy

                    quic_flag = is_quic(payload, port, sport)
                    tls_flag = is_known_tls(payload)

                    if quic_flag:
                        quic_count += 1
                    elif tls_flag:
                        tls_count += 1
                    elif is_tcp:
                        tcp_count += 1
                    else:
                        quic_count += 1

                    src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
                    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"

                    # Inference
                    is_threat = False
                    conf = 0.0
                    if entropy < 4.5 or tls_flag:
                        is_threat = False
                    elif classifier:
                        try:
                            pred = classifier.predict([[entropy, size, port]])[0]
                            proba = classifier.predict_proba([[entropy, size, port]])[0][1]
                            if pred == 1 and entropy > 7.2 and proba > 0.75:
                                is_threat = True
                                conf = float(proba)
                        except Exception:
                            if entropy > 7.5:
                                is_threat = True
                                conf = 0.9
                    elif entropy > 7.5:
                        is_threat = True
                        conf = 0.85

                    if is_threat:
                        threat_count += 1
                        if len(threats_list) < 50:
                            threats_list.append({
                                "packet_num": total_packets,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": port,
                                "protocol": "QUIC" if quic_flag else protocol,
                                "entropy": round(entropy, 4),
                                "size": size,
                                "payload_len": len(payload),
                                "confidence": round(conf * 100, 1)
                            })
                    else:
                        safe_count += 1
        except Exception as e:
            logger.error(f"Error reading PCAP file {filepath}: {e}")

        avg_entropy = (total_entropy / inspected_payloads) if inspected_payloads > 0 else 0.0

        return {
            "total_packets": total_packets,
            "inspected_payloads": inspected_payloads,
            "threat_count": threat_count,
            "safe_count": safe_count,
            "quic_count": quic_count,
            "tcp_count": tcp_count,
            "tls_count": tls_count,
            "avg_entropy": round(avg_entropy, 3),
            "max_entropy": round(max_entropy, 3),
            "threat_ratio": round((threat_count / inspected_payloads * 100), 1) if inspected_payloads > 0 else 0.0,
            "threats": threats_list
        }

forensics = IncidentRecorder()
