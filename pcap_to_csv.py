import csv
import math
from scapy.all import PcapReader, TCP, UDP, Raw

def calculate_entropy(payload: bytes) -> float:
    """Calculates Shannon Entropy for a given payload."""
    if not payload:
        return 0.0
    entropy = 0.0
    length = len(payload)
    byte_counts = {byte: 0 for byte in range(256)}

    for byte in payload:
        byte_counts[byte] += 1

    for count in byte_counts.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy

def is_quic_packet(payload: bytes, dst_port: int, src_port: int) -> bool:
    """Detects RFC 9000 QUIC packets on UDP ports 443 / 8443."""
    if dst_port in (443, 8443) or src_port in (443, 8443):
        if payload and (payload[0] & 0x40) != 0:  # Fixed bit set
            return True
    return False

def process_pcap(pcap_file, label, csv_writer, max_packets=None):
    print(f"Processing {pcap_file}...")
    count = 0

    try:
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                # Filter for packets containing an actual payload (TCP or UDP/QUIC)
                if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                    payload = bytes(packet[Raw].load)
                    size = len(packet)

                    if packet.haslayer(TCP):
                        dst_port = packet[TCP].dport
                    else:
                        dst_port = packet[UDP].dport

                    entropy = calculate_entropy(payload)

                    # Write the extracted features to the CSV
                    # Format: [Entropy, PacketSize, DstPort, Label]
                    csv_writer.writerow([entropy, size, dst_port, label])
                    count += 1

                    if count % 5000 == 0:
                        print(f"  ...extracted {count} packets")

                    if max_packets and count >= max_packets:
                        break

        print(f"Finished {pcap_file}. Total usable packets extracted: {count}")
    except FileNotFoundError:
        print(f"[!] Error: Could not find {pcap_file}. Make sure it is in the same folder.")

if __name__ == "__main__":
    output_file = "dataset.csv"
    target_limit = 15000

    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Entropy", "PacketSize", "DstPort", "Label"])

        # 1. Process Benign Traffic (Label: 0)
        process_pcap("my_benign_traffic.pcap", label=0, csv_writer=writer, max_packets=target_limit)

        # 2. Process Malicious Traffic (Label: 1)
        process_pcap("botnet-capture-20110810-neris.pcap", label=1, csv_writer=writer, max_packets=target_limit)

    print(f"\nSuccess! Dataset saved to {output_file}.")
