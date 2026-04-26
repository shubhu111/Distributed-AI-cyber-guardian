import time
import logging
from scapy.all import sniff, IP, TCP, UDP, conf
from supabase import create_client
import pandas as pd
import numpy as np

# --- CONFIGURATION ---
# Replace these with the keys you copied from Supabase Settings > API
SUPABASE_URL = "https://ebewuyjlcgrwaldxolpn.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImViZXd1eWpsY2dyd2FsZHhvbHBuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcyMDM2NTgsImV4cCI6MjA5Mjc3OTY1OH0.2ER8kbkt9URPAbJeTnzdbWZtR9AY4-lXrSDN3XmFifk"

# Give this laptop a name so you can identify it in the dashboard
DEVICE_ID = "Laptop_Pune_01" 

# Connect to the cloud database
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Mute Scapy's technical warnings for a cleaner terminal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def extract_features(packets):
    """
    This is the "Brain" of the sensor. It takes raw network packets 
    and turns them into the 15 math features your AI understands.
    """
    if len(packets) == 0: return None
    
    fwd_pkts, bwd_pkts, fwd_byts, bwd_byts = 0, 0, 0, 0
    rst_flag_cnt, ece_flag_cnt = 0, 0
    dst_ports, pkt_lengths = [], []
    init_win_bytes, fwd_seg_size = 8192, 20
    
    if not packets[0].haslayer(IP): return None
    my_ip = packets[0][IP].src
    duration = max(packets[-1].time - packets[0].time, 0.01) 
    
    for pkt in packets:
        if IP in pkt:
            length = len(pkt)
            pkt_lengths.append(length)
            is_fwd = pkt[IP].src == my_ip
            
            if is_fwd:
                fwd_pkts += 1; fwd_byts += length
                fwd_seg_size = max(fwd_seg_size, pkt[IP].ihl * 4 if IP in pkt else 20)
            else:
                bwd_pkts += 1; bwd_byts += length
                
            if TCP in pkt:
                dst_ports.append(pkt[TCP].dport)
                if 'R' in pkt[TCP].flags: rst_flag_cnt += 1
                if 'E' in pkt[TCP].flags: ece_flag_cnt += 1
                # Grab real OS window size if possible
                if is_fwd and init_win_bytes == 8192: init_win_bytes = pkt[TCP].window
            elif UDP in pkt:
                dst_ports.append(pkt[UDP].dport)

    target_port = max(set(dst_ports), key=dst_ports.count) if dst_ports else 0
    
    # Return as a dictionary that Supabase can store in the 'features' JSONB column
    return {
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
        'Pkt Len Var': float(np.var(pkt_lengths)) if pkt_lengths else 0,
        'Bwd Pkt Len Std': float(np.std(pkt_lengths)) if bwd_pkts > 0 else 0,
        'Subflow Bwd Pkts': int(bwd_pkts), 
        'Subflow Bwd Byts': int(bwd_byts),
        'Fwd IAT Mean': float((duration * 1000) / fwd_pkts) if fwd_pkts > 0 else 0
    }

# --- THE AGENT LOOP ---
print(f"🚀 Agent Active on {DEVICE_ID}...")
print("Listening for network traffic to push to Supabase...")

while True:
    try:
        # Sniff for a 3-second window
        # We use 'iface=conf.loopback_name' for testing attacks on the same laptop
        packets = sniff(timeout=3, iface=conf.loopback_name) 
        
        if len(packets) > 5:
            features = extract_features(packets)
            if features:
                # Prepare the row for the 'network_logs' table
                data = {
                    "device_id": DEVICE_ID, 
                    "features": features
                }
                # PUSH the data to the cloud
                supabase.table("network_logs").insert(data).execute()
                print(f"📡 {time.strftime('%H:%M:%S')} - Batch pushed to Supabase.")
    
    except Exception as e:
        print(f"⚠️ Connection Error: {e}")
    
    # Wait 1 second before the next scan to save CPU
    time.sleep(1)