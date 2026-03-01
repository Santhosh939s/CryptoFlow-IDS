import socket
import os
import time

def simulate_exfiltration():
    target_ip = "127.0.0.1"
    target_port = 8443

    print(f"[*] Initiating simulated exfiltration to {target_ip}:{target_port}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        
        for i in range(5):
            print(f"[-] Sending malicious high-entropy chunk {i+1}...")
            # Generate 1024 bytes of cryptographically random data
            malicious_payload = os.urandom(1024) 
            s.send(malicious_payload)
            time.sleep(1)
            
        s.close()
        print("[+] Exfiltration simulation complete.")
        
    except ConnectionRefusedError:
        print("[!] Connection failed. Is Terminal 1 (netcat) running?")

if __name__ == "__main__":
    simulate_exfiltration()
