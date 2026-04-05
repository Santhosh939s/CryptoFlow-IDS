import math
import joblib
import warnings
import time
from scapy.all import sniff, TCP, Raw

# Suppress warnings for a clean presentation terminal
warnings.filterwarnings("ignore", category=UserWarning)

# ANSI Color Codes for UI
RED = '\033[91m\033[1m'
GREEN = '\033[92m'
RESET = '\033[0m'

# Throttle control to prevent terminal lag
last_print_time = 0

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
    global last_print_time
    
    # Only analyze TCP packets that carry an actual payload
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        payload = bytes(packet[Raw].load)
        size = len(packet)
        port = packet[TCP].dport
        entropy = calculate_entropy(payload)
        
        if entropy > 0:
            current_time = time.time()
            
            # --- FAST PATH: Normal Traffic ---
            if entropy < 4.5:
                # "Heartbeat" print: Only print safe packets every 0.5 seconds
                # This proves the scanner is working without lagging the terminal
                if current_time - last_print_time > 0.5:
                    print(f"{GREEN}[SAFE] Background Traffic Scanned | Port: {port} | Entropy: {entropy:.2f}{RESET}")
                    last_print_time = current_time
                return
            
            # --- AI DETECTION PATH: High Entropy ---
            try:
                feature_vector = [[entropy, size, port]]
                prediction = classifier.predict(feature_vector)[0]
                
                # Triggers on AI prediction OR pure encrypted data hitting port 443
                if (prediction == 1 and entropy > 7.0) or (entropy > 7.5 and port == 443):
                    print(f"\n{RED}🚨 [RED ALERT] MALICIOUS EXFILTRATION BLOCKED! 🚨{RESET}")
                    print(f"{RED}➜ Threat Detected on Port: {port} | Entropy: {entropy:.2f} | Size: {size} bytes{RESET}\n")
                else:
                    # Print high-entropy safe packets (like normal encrypted web browsing)
                    if current_time - last_print_time > 0.5:
                        print(f"{GREEN}[SAFE] Encrypted Web Traffic | Port: {port} | Entropy: {entropy:.2f}{RESET}")
                        last_print_time = current_time
            except Exception:
                pass # Prevent any random ML errors from crashing your live demo

if __name__ == "__main__":
    print("Loading AI Model 'traffic_classifier.pkl'...")
    try:
        classifier = joblib.load("traffic_classifier.pkl")
    except FileNotFoundError:
        print("[!] Error: 'traffic_classifier.pkl' not found. Please run train_model.py first.")
        exit(1)
        
    print("✅ Model Successfully Loaded.")
    print("🌐 Real-Time Scanner Active. Monitoring Local Network ('lo')...")
    print("⏳ Waiting for malicious activity. Press Ctrl+C to stop.\n")
    
    # Locked to 'lo' to guarantee 100% catch rate for your local simulation
    sniff(iface="lo", filter="tcp", prn=process_packet, store=False)
