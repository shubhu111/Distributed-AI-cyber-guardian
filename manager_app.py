import os
import time
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request
from supabase import create_client, Client
import smtplib
from email.message import EmailMessage

# --- 1. CONFIGURATION (KEYS HIDDEN FOR DEPLOYMENT) ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)

# --- GLOBAL APP STATE ---
SOC_CONFIG = {
    "alerts_enabled": False,
    "admin_email": "",
    "admin_name": "Rutuja",
    "org_name": "Security Node",
    "retention_days": "30",
    "slack_webhook": ""
}

# --- 2. LOAD AI ARTIFACTS ---
def load_assets():
    try:
        model = joblib.load('nids_random_forest.pkl')
        scaler = joblib.load('nids_scaler.pkl')
        feature_names = list(joblib.load('nids_features.pkl'))
        class_names = list(joblib.load('attack_classes.pkl'))
        return model, scaler, feature_names, class_names
    except Exception as e:
        print(f"Error loading AI models: {e}")
        return None, None, None, None

model, scaler, feature_names, class_names = load_assets()

def get_recent_data(limit=60):
    try:
        res = supabase.table("network_logs").select("*").order("created_at", desc=True).limit(limit).execute()
        return pd.DataFrame(res.data) if not pd.DataFrame(res.data).empty else None
    except Exception as e:
        print(f"Database Error: {e}")
        return None

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alert_settings', methods=['GET', 'POST'])
def alert_settings():
    global SOC_CONFIG
    if request.method == 'POST':
        data = request.json
        SOC_CONFIG["alerts_enabled"] = data.get("enabled", False)
        SOC_CONFIG["admin_email"] = data.get("email", "")
        return jsonify({"status": "success"})
    return jsonify({"alerts_enabled": SOC_CONFIG["alerts_enabled"], "admin_email": SOC_CONFIG["admin_email"]})

@app.route('/api/system_settings', methods=['GET', 'POST'])
def system_settings():
    global SOC_CONFIG
    if request.method == 'POST':
        data = request.json
        SOC_CONFIG["admin_name"] = data.get("admin_name", "Rutuja")
        SOC_CONFIG["org_name"] = data.get("org_name", "Security Node")
        SOC_CONFIG["retention_days"] = data.get("retention_days", "30")
        SOC_CONFIG["slack_webhook"] = data.get("slack_webhook", "")
        return jsonify({"status": "success"})
    return jsonify(SOC_CONFIG)

@app.route('/api/trigger_test_alert', methods=['POST'])
def trigger_test_alert():
    global SOC_CONFIG
    if not SOC_CONFIG["alerts_enabled"] or not SOC_CONFIG["admin_email"]:
        return jsonify({"status": "error", "message": "Alerts disabled or email missing."})
    
    target_email = SOC_CONFIG["admin_email"]
    # HIDDEN EMAIL CREDENTIALS
    SENDER_EMAIL = os.getenv("SENDER_EMAIL")
    APP_PASSWORD = os.getenv("APP_PASSWORD") 
    
    try:
        msg = EmailMessage()
        msg.set_content(f"CRITICAL WARNING: The Enterprise SOC has detected anomalous network activity.\n\nTarget Admin: {target_email}\nDashboard is actively monitoring.")
        msg['Subject'] = '🚨 SOC THREAT ALERT 🚨'
        msg['From'] = SENDER_EMAIL
        msg['To'] = target_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return jsonify({"status": "success", "message": f"Test alert sent to {target_email}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"SMTP Error. Check Python Terminal."})

@app.route('/api/data')
def api_data():
    df = get_recent_data(60) 
    api_response = {
        "global": { "devices_online": 0, "threat_level": "🟢 SECURE", "attacks_deflected": 0, "health": "📡 Active Uplink" },
        "charts": { "times": [], "volume_traces": [], "confidence_traces": [] },
        "devices": [], "ledger": []
    }
    
    if df is not None:
        active_threats = 0
        
        times = pd.to_datetime(df['created_at']).dt.strftime('%H:%M:%S').unique().tolist()[:30]
        api_response["charts"]["times"] = times[::-1]
        
        for device_id, device_df in df.groupby('device_id'):
            features_list = device_df['features'].tolist()
            input_df = pd.DataFrame(features_list, columns=feature_names).fillna(0)
            scaled_data = scaler.transform(input_df)
            predictions = model.predict(scaled_data)
            probabilities = model.predict_proba(scaled_data)
            
            latest_time_raw = pd.to_datetime(device_df.iloc[0]['created_at'], utc=timezone.utc)
            seconds_since_last_sync = (datetime.now(timezone.utc) - latest_time_raw).total_seconds()
            latest_flow = features_list[0].get('Flow Byts/s', 0)
            
            is_under_attack = False
            final_status = "Benign"
            final_conf = 0.0
            
            if seconds_since_last_sync > 15:
                is_under_attack, final_status, final_conf = False, "Benign", 100.0
            else:
                for i in range(len(device_df)):
                    packet_time = pd.to_datetime(device_df.iloc[i]['created_at'], utc=timezone.utc)
                    seconds_ago = (datetime.now(timezone.utc) - packet_time).total_seconds()
                    
                    if seconds_ago > 40:
                        continue 
                        
                    feat = features_list[i]
                    port = feat.get('Dst Port', 0)
                    variance = feat.get('Pkt Len Var', 0)
                    rst_flags = feat.get('RST Flag Cnt', 0)
                    
                    pkt_attack = False
                    status = "Benign"
                    conf = 0.0
                    
                    if port == 21 and rst_flags > 10:
                        pkt_attack, status, conf = True, "Brute Force", 99.8
                    elif port == 80 and variance > 5000:
                        pkt_attack, status, conf = True, "Web Attack", 98.5
                    else:
                        ml_status = class_names[predictions[i]]
                        if ml_status not in ["Benign", "Normal"]:
                            pkt_attack, status, conf = True, ml_status, np.max(probabilities[i]) * 100
                            
                    if pkt_attack:
                        is_under_attack = True
                        final_status = status
                        final_conf = conf
                        break 
                        
                if not is_under_attack:
                    final_conf = np.max(probabilities[0]) * 100
                    
            if is_under_attack: active_threats += 1
            
            api_response["devices"].append({
                "id": device_id, 
                "is_attack": is_under_attack, 
                "status": final_status, 
                "confidence": f"{final_conf:.1f}%", 
                "flow": int(latest_flow),
                "features": features_list[0] 
            })
            
            human_event = "Threat Neutralized" if is_under_attack else "Routine Telemetry Sync"
            api_response["ledger"].append({"Timestamp": latest_time_raw.strftime('%Y-%m-%d %H:%M:%S'), "Event Type": human_event, "Affected Devices": device_id})

            limit = min(30, len(device_df))
            vol_data = []
            conf_data = []
            for i in range(limit):
                vol_data.insert(0, features_list[i].get('Flow Byts/s', 0))
                conf_data.insert(0, float(np.max(probabilities[i])))
                
            api_response["charts"]["volume_traces"].append({"name": device_id, "data": vol_data})
            api_response["charts"]["confidence_traces"].append({"name": f"{device_id} Conf", "data": conf_data})
            
        api_response["global"] = {"devices_online": df['device_id'].nunique(), "threat_level": "🟢 SECURE" if active_threats == 0 else "🔴 ELEVATED", "attacks_deflected": active_threats, "health": "📡 Active Uplink"}
        
    return jsonify(api_response)

@app.route('/api/history')
def api_history():
    try:
        res = supabase.table("network_logs").select("*").order("created_at", desc=True).limit(500).execute()
        df = pd.DataFrame(res.data)
        history_data = []
        if not df.empty:
            for _, row in df.iterrows():
                raw_features = row['features']
                port, variance, flow_bytes = raw_features.get('Dst Port', 0), raw_features.get('Pkt Len Var', 0), raw_features.get('Flow Byts/s', 0)
                status = "Benign"
                if port == 21 and raw_features.get('RST Flag Cnt', 0) > 10: status = "Brute Force"
                elif port == 80 and variance > 5000: status = "Web Attack"
                elif port == 80 and flow_bytes > 100000: status = "DDoS"
                
                human_status = "Safe" if status == "Benign" else f"Exploit ({status})"
                history_data.append({"Timestamp": pd.to_datetime(row['created_at']).strftime('%Y-%m-%d %H:%M:%S'), "Device": row['device_id'], "Port": int(port), "Variance": f"{variance:.1f}", "Bytes_per_sec": int(flow_bytes), "Status": human_status})
        return jsonify(history_data)
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    # For local testing, Flask uses 5000. Deployment platforms often set 'PORT' automatically.
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)