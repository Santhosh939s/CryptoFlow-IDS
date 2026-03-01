import math
import joblib
import warnings
from scapy.all import sniff, TCP, UDP, Raw

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Global variables
global classifier
global malicious_detected

# Start with the assumption that the network is safe
malicious_detected = False

# ANSI Color Codes for terminal output
RED = '\033[91m'
RESET = '\033[0m'

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

def process_packet(packet):
    """Extracts features and feeds them to the AI."""
    global malicious_detected
    
    if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        payload = bytes(packet[Raw].load)
        size = len(packet)
        port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        entropy = calculate_entropy(payload)
        
        if entropy > 4.5:
            feature_vector = [[entropy, size, port]]
            prediction = classifier.predict(feature_vector)[0]
            
            if prediction == 1:
                # Threat found! Flip the switch so it never prints [SAFE] again
                malicious_detected = True
                # Print the alert in Bright Red, then reset the color
                print(f"{RED}[RED ALERT] Malicious Exfiltration! | Port: {port} | Entropy: {entropy:.2f} | Size: {size} bytes{RESET}")
            else:
                # It is safe, but we ONLY print it if we haven't found malware yet
                if not malicious_detected:
                    print(f"[SAFE] Normal Traffic Inspected | Port: {port} | Entropy: {entropy:.2f}")

if __name__ == "__main__":
    print("Loading AI Model 'traffic_classifier.pkl'...")
    try:
        classifier = joblib.load("traffic_classifier.pkl")
    except FileNotFoundError:
        print("[!] Error: 'traffic_classifier.pkl' not found. Please run train_model.py first.")
        exit(1)
        
    print("Starting Hybrid AI Detector...")
    print("Monitoring Local Lab ('lo') AND Live Wi-Fi ('wlo1') simultaneously.")
    print("Waiting for traffic. Press Ctrl+C to stop.")
    
    sniff(iface=["lo", "wlo1"], filter="tcp or udp", prn=process_packet, store=False)
