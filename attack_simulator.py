import socket
import time
import random
import threading
import customtkinter as ctk

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

start_dummy_targets()

# =====================================================================
# THE ATTACKS (Now with UI Status Updates)
# =====================================================================
def update_status(text, color):
    status_label.configure(text=text, text_color=color)

def simulate_ddos():
    update_status("🚨 INITIATING UDP FLOOD...", "#ff4c4c")
    def run_attack():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        t_end = time.time() + 15  
        while time.time() < t_end:
            sock.sendto(payload, (TARGET_IP, 80))
        update_status("✅ SYSTEM READY", "#00ffcc")
    threading.Thread(target=run_attack).start()

def simulate_web_attack():
    update_status("🚨 INITIATING WEB ATTACK...", "#ff4c4c")
    def run_attack():
        t_end = time.time() + 15
        def attack_thread():
            while time.time() < t_end:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.bind((ATTACKER_IP, 0)) 
                    sock.connect((TARGET_IP, 80))
                    junk = random.randint(100, 800) 
                    sock.sendall(f"GET /?data={'A'*junk} HTTP/1.1\r\n\r\n".encode())
                    try: sock.recv(512)
                    except: pass
                    sock.close()
                    time.sleep(0.05) 
                except: pass
        threads = [threading.Thread(target=attack_thread) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        update_status("✅ SYSTEM READY", "#00ffcc")
    threading.Thread(target=run_attack).start()

def simulate_brute_force():
    update_status("🚨 INITIATING BRUTE FORCE...", "#ff4c4c")
    def run_attack():
        t_end = time.time() + 15
        def attack_thread():
            while time.time() < t_end:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.bind((ATTACKER_IP, 0)) 
                    sock.settimeout(0.5)
                    sock.connect((TARGET_IP, 21)) 
                    sock.sendall(b"USER admin\r\nPASS 12345\r\n")
                    try: sock.recv(512)
                    except: pass
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
                    sock.close()
                    time.sleep(0.05) 
                except: pass
        threads = [threading.Thread(target=attack_thread) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        update_status("✅ SYSTEM READY", "#00ffcc")
    threading.Thread(target=run_attack).start()

# =====================================================================
# THE GUI (Modern & Minimalist)
# =====================================================================
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("blue")  

app = ctk.CTk()
app.geometry("400x380")
app.title("SOC Attack Simulator")
app.resizable(False, False)

title = ctk.CTkLabel(app, text="COMMAND CENTER", font=("Roboto", 24, "bold"))
title.pack(pady=(20, 5))

subtitle = ctk.CTkLabel(app, text="M.Tech NIDS Attack Generator", font=("Roboto", 12), text_color="gray")
subtitle.pack(pady=(0, 20))

btn_ddos = ctk.CTkButton(app, text="1. DDoS Flood (UDP)", height=40, command=simulate_ddos)
btn_ddos.pack(pady=10, padx=40, fill="x")

btn_web = ctk.CTkButton(app, text="2. Web Attack (TCP)", height=40, command=simulate_web_attack)
btn_web.pack(pady=10, padx=40, fill="x")

btn_brute = ctk.CTkButton(app, text="3. Brute Force (TCP)", height=40, command=simulate_brute_force)
btn_brute.pack(pady=10, padx=40, fill="x")

status_label = ctk.CTkLabel(app, text="✅ SYSTEM READY", font=("Roboto", 14, "bold"), text_color="#00ffcc")
status_label.pack(pady=(20, 0))

app.mainloop()