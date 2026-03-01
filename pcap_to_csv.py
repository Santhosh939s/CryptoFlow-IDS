import csv
import math
from scapy.all import PcapReader, TCP, UDP, Raw

def calculate_entropy(payload):
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

def process_pcap(pcap_file, label, csv_writer, max_packets=None):
    print(f"Processing {pcap_file}...")
    count = 0
    
    # We use PcapReader instead of rdpcap to prevent RAM overload with large files
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                # Filter for packets containing an actual payload
                if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                    payload = bytes(packet[Raw].load)
                    size = len(packet)
                    
                    if packet.haslayer(TCP):
                        dst_port = packet[TCP].dport
                    else:
                        dst_port = packet[UDP].dport
                        
                    entropy = calculate_entropy(payload)
                    
                    # Write the extracted features to the CSV
                    csv_writer.writerow([entropy, size, dst_port, label])
                    count += 1
                    
                    # Print progress so you know it hasn't frozen
                    if count % 5000 == 0:
                        print(f"  ...extracted {count} packets")
                        
                    # Stop if we reach our target balance limit
                    if max_packets and count >= max_packets:
                        break
                        
        print(f"Finished {pcap_file}. Total usable packets extracted: {count}")
    except FileNotFoundError:
        print(f"[!] Error: Could not find {pcap_file}. Make sure it is in the same folder.")

if __name__ == "__main__":
    output_file = "dataset.csv"
    
    # We will limit extraction to 15,000 packets per class for a balanced 30,000 row dataset
    target_limit = 15000 
    
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Create the header row
        writer.writerow(["Entropy", "PacketSize", "DstPort", "Label"])
        
        # 1. Process Benign Traffic (Label: 0)
        process_pcap("my_benign_traffic.pcap", label=0, csv_writer=writer, max_packets=target_limit)
        
        # 2. Process Malicious Traffic (Label: 1)
        # Ensure the filename matches the Neris pcap you downloaded
        process_pcap("botnet-capture-20110810-neris.pcap", label=1, csv_writer=writer, max_packets=target_limit)
        
    print(f"\nSuccess! Dataset saved to {output_file}.")
import math
from scapy.all import PcapReader, TCP, UDP, Raw

def calculate_entropy(payload):
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

def process_pcap(pcap_file, label, csv_writer, max_packets=None):
    print(f"Processing {pcap_file}...")
    count = 0
    
    # We use PcapReader instead of rdpcap to prevent RAM overload with large files
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                # Filter for packets containing an actual payload
                if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                    payload = bytes(packet[Raw].load)
                    size = len(packet)
                    
                    if packet.haslayer(TCP):
                        dst_port = packet[TCP].dport
                    else:
                        dst_port = packet[UDP].dport
                        
                    entropy = calculate_entropy(payload)
                    
                    # Write the extracted features to the CSV
                    csv_writer.writerow([entropy, size, dst_port, label])
                    count += 1
                    
                    # Print progress so you know it hasn't frozen
                    if count % 5000 == 0:
                        print(f"  ...extracted {count} packets")
                        
                    # Stop if we reach our target balance limit
                    if max_packets and count >= max_packets:
                        break
                        
        print(f"Finished {pcap_file}. Total usable packets extracted: {count}")
    except FileNotFoundError:
        print(f"[!] Error: Could not find {pcap_file}. Make sure it is in the same folder.")

if __name__ == "__main__":
    output_file = "dataset.csv"
    
    # We will limit extraction to 15,000 packets per class for a balanced 30,000 row dataset
    target_limit = 15000 
    
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Create the header row
        writer.writerow(["Entropy", "PacketSize", "DstPort", "Label"])
        
        # 1. Process Benign Traffic (Label: 0)
        process_pcap("my_benign_traffic.pcap", label=0, csv_writer=writer, max_packets=target_limit)
        
        # 2. Process Malicious Traffic (Label: 1)
        # Ensure the filename matches the Neris pcap you downloaded
        process_pcap("botnet-capture-20110810-neris.pcap", label=1, csv_writer=writer, max_packets=target_limit)
        
    print(f"\nSuccess! Dataset saved to {output_file}.")
