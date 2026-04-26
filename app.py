import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
from scapy.all import sniff, IP, TCP, UDP

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(page_title="NIDS | Live AI Radar", page_icon="📡", layout="wide")

# --- 2. LOAD AI ARTIFACTS ---
@st.cache_resource
def load_nids_assets():
    try:
        model = joblib.load('nids_random_forest.pkl')
        scaler = joblib.load('nids_scaler.pkl')
        features = joblib.load('nids_features.pkl')        
        class_names = joblib.load('attack_classes.pkl') 
        return model, scaler, features, class_names
    except Exception as e:
        st.error(f"🔍 System Error: {e}")
        return None, None, None, None

model, scaler, feature_names, class_names = load_nids_assets()

if model is None:
    st.stop()

# --- 3. LIVE PACKET EXTRACTOR (Scapy Engine) ---
def process_live_packets(packets):
    """ Converts raw live packets into the 15 features the model needs """
    if len(packets) == 0:
        return None
        
    # Variables to track
    fwd_pkts, bwd_pkts = 0, 0
    fwd_byts, bwd_byts = 0, 0
    fwd_header_len, bwd_header_len = 0, 0
    rst_flag_cnt, ece_flag_cnt = 0, 0
    dst_ports = []
    pkt_lengths = []
    
    # Assume the first packet's Source IP is 'us' (Forward direction)
    if not packets[0].haslayer(IP):
        return None
    my_ip = packets[0][IP].src
    
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = max(end_time - start_time, 0.001) # Avoid division by zero
    
    for pkt in packets:
        if IP in pkt:
            length = len(pkt)
            pkt_lengths.append(length)
            
            # Check Direction
            is_fwd = pkt[IP].src == my_ip
            
            if is_fwd:
                fwd_pkts += 1
                fwd_byts += length
                fwd_header_len += pkt[IP].ihl * 4 if IP in pkt else 20
            else:
                bwd_pkts += 1
                bwd_byts += length
                bwd_header_len += pkt[IP].ihl * 4 if IP in pkt else 20
            
            # Extract TCP specific features
            if TCP in pkt:
                dst_ports.append(pkt[TCP].dport)
                flags = pkt[TCP].flags
                if 'R' in flags: rst_flag_cnt += 1
                if 'E' in flags: ece_flag_cnt += 1
            elif UDP in pkt:
                dst_ports.append(pkt[UDP].dport)

    # Calculate final 15 features safely
    try:
        live_features = {
            'Init Fwd Win Byts': 8192, # Default OS window size approx
            'Fwd Seg Size Min': 20 if fwd_pkts > 0 else 0,
            'Dst Port': max(set(dst_ports), key=dst_ports.count) if dst_ports else 0,
            'RST Flag Cnt': rst_flag_cnt,
            'Fwd Header Len': fwd_header_len,
            'ECE Flag Cnt': ece_flag_cnt,
            'Bwd Header Len': bwd_header_len,
            'Bwd Pkts/s': bwd_pkts / duration,
            'Flow Byts/s': (fwd_byts + bwd_byts) / duration,
            'Fwd IAT Tot': duration * 1000, # Approx in ms
            'Pkt Len Var': np.var(pkt_lengths) if pkt_lengths else 0,
            'Bwd Pkt Len Std': np.std(pkt_lengths) if bwd_pkts > 0 else 0,
            'Subflow Bwd Pkts': bwd_pkts,
            'Subflow Bwd Byts': bwd_byts,
            'Fwd IAT Mean': (duration * 1000) / fwd_pkts if fwd_pkts > 0 else 0
        }
        
        # Format exactly as the model expects
        df = pd.DataFrame([live_features])[feature_names]
        return df
    except Exception as e:
        return None

# --- 4. MAIN UI ---
st.title("📡 Live Network Defense Engine")
st.markdown("Monitoring your local network interface for malicious traffic.")

# Initialize session state for toggle
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False

def toggle_monitoring():
    st.session_state.monitoring = not st.session_state.monitoring

# UI Controls
col1, col2 = st.columns([1, 5])
with col1:
    btn_text = "🛑 STOP MONITORING" if st.session_state.monitoring else "🟢 START LIVE RADAR"
    st.button(btn_text, on_click=toggle_monitoring, use_container_width=True)
with col2:
    st.write(f"**Status:** {'Listening to network card...' if st.session_state.monitoring else 'System Idle.'}")

st.divider()

# Placeholder for live updates
dashboard_placeholder = st.empty()

# --- 5. THE LIVE LOOP ---
if st.session_state.monitoring:
    with dashboard_placeholder.container():
        st.info("Sniffing network traffic... Please wait 3 seconds for initial batch.")
        
    while st.session_state.monitoring:
        # 1. Capture traffic for 3 seconds
        # (This listens to your actual computer's Wi-Fi/Ethernet)
        live_packets = sniff(timeout=3) 
        
        if len(live_packets) > 5: # If we actually caught some internet traffic
            # 2. Extract features
            live_df = process_live_packets(live_packets)
            
            if live_df is not None:
                # 3. AI Prediction
                scaled_data = scaler.transform(live_df)
                prediction = model.predict(scaled_data)[0]
                probabilities = model.predict_proba(scaled_data)[0]
                
                result_text = class_names[prediction]
                confidence = np.max(probabilities) * 100
                
                # 4. Update the UI
                with dashboard_placeholder.container():
                    res_col1, res_col2 = st.columns([2, 1])
                    with res_col1:
                        if result_text == "Benign":
                            st.success(f"### ✅ TRAFFIC SECURE (Benign)\nCaptured **{len(live_packets)}** packets in last 3s.")
                        else:
                            st.error(f"### 🚨 {result_text.upper()} DETECTED!\nCaptured **{len(live_packets)}** packets. Immediate action required.")
                    
                    with res_col2:
                        st.metric("AI Confidence", f"{confidence:.1f}%")
                        st.metric("Live Flow Rate", f"{live_df['Flow Byts/s'].iloc[0] / 1024:.1f} KB/s")
                    
                    st.write("---")
                    st.write("**Live Extracted Header Data:**")
                    st.dataframe(live_df, use_container_width=True)
        else:
            with dashboard_placeholder.container():
                st.warning("No significant network traffic detected in the last 3 seconds. Try opening a website.")
        
        # Small sleep to prevent CPU overload
        time.sleep(0.1)