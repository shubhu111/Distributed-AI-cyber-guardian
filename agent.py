import time
import logging
import numpy as np 
from scapy.all import sniff, IP, TCP, UDP, conf
from supabase import create_client

SUPABASE_URL = "https://ebewuyjlcgrwaldxolpn.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImViZXd1eWpsY2dyd2FsZHhvbHBuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcyMDM2NTgsImV4cCI6MjA5Mjc3OTY1OH0.2ER8kbkt9URPAbJeTnzdbWZtR9AY4-lXrSDN3XmFifk"
DEVICE_ID = "SP_laptop" 

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def extract_features(raw_packets):
    # 1. Filter out Dashboard noise
    packets = []
    for p in raw_packets:
        if IP in p and TCP in p and (p[TCP].sport in [8501, 443] or p[TCP].dport in [8501, 443]):
            continue
        if IP in p: packets.append(p)

    if len(packets) < 5: return None

    # 2. BULLETPROOF ATTACKER IDENTIFICATION
    # This guarantees the Dst Port is always calculated correctly (80 or 21)
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
    
    # Force Dataset Standards (Fixes Windows Loopback math breaking the AI)
    init_win_bytes = 8192 
    fwd_seg_size = 20
    
    duration = max(packets[-1].time - packets[0].time, 0.01) 
    
    for pkt in packets:
        length = len(pkt)
        pkt_lengths.append(length)
        
        # Determine direction mathematically
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

    # 3. Calculate Final Features
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

    # JSON Sanitizer
    for key, value in features.items():
        if hasattr(value, "item"): features[key] = value.item()
    return features

print(f"🚀 AGENT ACTIVE ON LOOPBACK...")
while True:
    try:
        packets = sniff(timeout=2, iface=conf.loopback_name) 
        features = extract_features(packets)
        if features:
            data = {"device_id": DEVICE_ID, "features": features}
            supabase.table("network_logs").insert(data).execute()
            print(f"📡 PUSHED -> Port: {features['Dst Port']} | Pkts: {len(packets)} | Var: {features['Pkt Len Var']:.1f}")
    except Exception as e: pass
    time.sleep(0.5)