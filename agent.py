# python agent.py  -> to run this script

import time
import logging
import socket
import threading
import numpy as np 
import customtkinter as ctk
from scapy.all import sniff, IP, TCP, UDP, conf
from supabase import create_client
from dotenv import load_dotenv
import os
load_dotenv()

# Suppress runtime warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

# DYNAMIC DEVICE ID FIX
DEVICE_ID = socket.gethostname() 

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
is_agent_running = False

def extract_features(raw_packets):
    # --- YOUR ORIGINAL FEATURE EXTRACTION LOGIC INTACT ---
    packets = []
    for p in raw_packets:
        if IP in p and TCP in p and (p[TCP].sport in [8501, 443] or p[TCP].dport in [8501, 443]):
            continue
        if IP in p: packets.append(p)

    if len(packets) < 5: return None

    attacker_ip = packets[0][IP].src
    for pkt in packets:
        if TCP in pkt and pkt[TCP].dport in [80, 21]:
            attacker_ip = pkt[IP].src
            break
        elif UDP in pkt and pkt[UDP].dport in [80, 21]:
            attacker_ip = pkt[IP].src
            break

    fwd_pkts, bwd_pkts, fwd_byts, bwd_byts = 0, 0, 0, 0
    rst_flag_cnt, ece_flag_cnt = 0, 0
    dst_ports, pkt_lengths = [], []
    
    init_win_bytes = 8192 
    fwd_seg_size = 20
    
    duration = max(packets[-1].time - packets[0].time, 0.01) 
    
    for pkt in packets:
        length = len(pkt)
        pkt_lengths.append(length)
        is_fwd = (pkt[IP].src == attacker_ip)
        
        if is_fwd:
            fwd_pkts += 1; fwd_byts += length
        else:
            bwd_pkts += 1; bwd_byts += length
            
        if TCP in pkt:
            dst_ports.append(pkt[TCP].dport)
            if 'R' in pkt[TCP].flags: rst_flag_cnt += 1
            if 'E' in pkt[TCP].flags: ece_flag_cnt += 1
        elif UDP in pkt:
            dst_ports.append(pkt[UDP].dport)

    target_port = max(set(dst_ports), key=dst_ports.count) if dst_ports else 0
    
    features = {
        'Init Fwd Win Byts': int(init_win_bytes), 
        'Fwd Seg Size Min': int(fwd_seg_size),
        'Dst Port': int(target_port), 
        'RST Flag Cnt': int(rst_flag_cnt),
        'Fwd Header Len': int(fwd_pkts * 20), 
        'ECE Flag Cnt': int(ece_flag_cnt),
        'Bwd Header Len': int(bwd_pkts * 20), 
        'Bwd Pkts/s': float(bwd_pkts / duration),
        'Flow Byts/s': float((fwd_byts + bwd_byts) / duration), 
        'Fwd IAT Tot': float(duration * 1000),
        'Pkt Len Var': float(np.var(pkt_lengths)) if pkt_lengths else 0.0,
        'Bwd Pkt Len Std': float(np.std(pkt_lengths)) if bwd_pkts > 0 else 0.0,
        'Subflow Bwd Pkts': int(bwd_pkts), 
        'Subflow Bwd Byts': int(bwd_byts),
        'Fwd IAT Mean': float((duration * 1000) / fwd_pkts) if fwd_pkts > 0 else 0.0
    }

    for key, value in features.items():
        if hasattr(value, "item"): features[key] = value.item()
    return features

def agent_monitoring_loop():
    global is_agent_running
    while is_agent_running:
        try:
            # Captures packets dynamically from system loopback
            packets = sniff(timeout=2, iface=conf.loopback_name) 
            
            # Double-check execution status right after sniff finishes 
            if not is_agent_running: 
                break
                
            features = extract_features(packets)
            if features:
                data = {"device_id": DEVICE_ID, "features": features}
                supabase.table("network_logs").insert(data).execute()
        except Exception as e: 
            pass
        
        # Micro-sleep checks so thread exits fast when stopped
        for _ in range(5):
            if not is_agent_running: break
            time.sleep(0.1)

def start_agent():
    global is_agent_running
    if not is_agent_running:
        is_agent_running = True
        update_status(f"🟢 ACTIVE [{DEVICE_ID}]", "#00ffcc")
        threading.Thread(target=agent_monitoring_loop, daemon=True).start()

def stop_agent():
    global is_agent_running
    is_agent_running = False
    update_status("🔴 SENSOR OFFLINE", "#ff4c4c")

def update_status(text, color):
    status_label.configure(text=text, text_color=color)

# ==========================================
# THE GUI SETUP
# ==========================================
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("blue")  

app = ctk.CTk()
app.geometry("400x260")
app.title("Network Sensor Agent")
app.resizable(False, False)

title = ctk.CTkLabel(app, text="NIDS SENSOR CONTROL", font=("Roboto", 20, "bold"))
title.pack(pady=(20, 5))

subtitle = ctk.CTkLabel(app, text=f"Local Machine: {DEVICE_ID}", font=("Roboto", 12), text_color="gray")
subtitle.pack(pady=(0, 20))

btn_start = ctk.CTkButton(app, text="▶ START SENSOR", fg_color="#28a745", hover_color="#218838", height=40, command=start_agent)
btn_start.pack(pady=10, padx=40, fill="x")

btn_stop = ctk.CTkButton(app, text="⏹ STOP SENSOR", fg_color="#dc3545", hover_color="#c82333", height=40, command=stop_agent)
btn_stop.pack(pady=10, padx=40, fill="x")

status_label = ctk.CTkLabel(app, text="🔴 SENSOR OFFLINE", font=("Roboto", 14, "bold"), text_color="#ff4c4c")
status_label.pack(pady=(15, 0))

app.mainloop()