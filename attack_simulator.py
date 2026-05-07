import socket
import time
import random
import threading

TARGET_IP = "127.0.0.1"
ATTACKER_IP = "127.0.0.2" 

# =====================================================================
# DUMMY SERVERS (Creates the "Backward" traffic the AI requires)
# =====================================================================
def start_dummy_targets():
    def listen_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((TARGET_IP, port))
            s.listen(100) 
            while True:
                conn, addr = s.accept()
                try:
                    conn.recv(1024)
                    conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n") 
                except: pass
                conn.close()
        except: pass
            
    threading.Thread(target=listen_port, args=(80,), daemon=True).start()
    threading.Thread(target=listen_port, args=(21,), daemon=True).start()

print("⚙️ Booting background target servers...")
start_dummy_targets()
time.sleep(1)

# =====================================================================
# THE ATTACKS
# =====================================================================

def simulate_ddos():
    print("🚨 [ATTACK] Intense UDP Flood (DDoS) - 15 SECONDS")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    t_end = time.time() + 15  
    count = 0
    while time.time() < t_end:
        sock.sendto(payload, (TARGET_IP, 80))
        count += 1
    print(f"🛑 DDoS Complete. Sent {count} packets.")


def simulate_web_attack():
    print("🚨 [ATTACK] Web Attack (Targeted TCP) - 15 SECONDS")
    t_end = time.time() + 15
    
    def attack_thread():
        while time.time() < t_end:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((ATTACKER_IP, 0)) # Spoof IP so Agent sees Attacker vs Server
                sock.connect((TARGET_IP, 80))
                
                # Moderate variance, exactly what the AI looks for in Web Attacks
                junk = random.randint(100, 800) 
                sock.sendall(f"GET /?data={'A'*junk} HTTP/1.1\r\n\r\n".encode())
                try: sock.recv(512)
                except: pass
                sock.close()
                time.sleep(0.05) # Rate limit to NOT look like a DDoS
            except: pass

    # 5 controlled threads. Fast enough to trigger, slow enough to stay a Web Attack.
    threads = [threading.Thread(target=attack_thread) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    print("🛑 Web Attack Complete.")


def simulate_brute_force():
    print("🚨 [ATTACK] Brute Force (Targeted TCP) - 15 SECONDS")
    t_end = time.time() + 15

    def attack_thread():
        while time.time() < t_end:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((ATTACKER_IP, 0)) 
                sock.settimeout(0.5)
                sock.connect((TARGET_IP, 21)) # Hits Port 21
                
                sock.sendall(b"USER admin\r\nPASS 12345\r\n")
                try: sock.recv(512)
                except: pass
                
                # Violent close to spike RST Flags
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
                sock.close()
                time.sleep(0.05) 
            except: pass

    threads = [threading.Thread(target=attack_thread) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    print("🛑 Brute Force Complete.")

if __name__ == "__main__":
    print("\n=== M.Tech NIDS Attack Simulator (DATASET-ALIGNED) ===")
    print("1. DDoS Flood (UDP - Fast)")
    print("2. Web Attack (TCP - Controlled Variance)")
    print("3. Brute Force (TCP - Controlled RST)")
    
    choice = input("\nEnter choice (1/2/3): ")
    if choice == '1': simulate_ddos()
    elif choice == '2': simulate_web_attack()
    elif choice == '3': simulate_brute_force()