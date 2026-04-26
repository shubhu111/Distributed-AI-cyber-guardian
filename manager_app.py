import streamlit as st
import pandas as pd
import joblib
import numpy as np
import time
import os
from supabase import create_client

# --- 1. SECURE CONFIGURATION ---
# This logic checks Streamlit Cloud Secrets first, then falls back to local .env
try:
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
except Exception:
    # If not in the cloud, try loading from local .env file
    try:
        from dotenv import load_dotenv
        load_dotenv()
        SUPABASE_URL = os.getenv("SUPABASE_URL")
        SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    except ImportError:
        SUPABASE_URL = None
        SUPABASE_KEY = None

# Safety Check: Stop the app if keys are missing
if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("🔑 **API Keys Missing!**")
    st.info("Local: Add them to a `.env` file. \n\nCloud: Add them to Streamlit Secrets.")
    st.stop()

# Initialize Supabase
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(page_title="Global Security Dashboard", layout="wide")

# --- 2. LOAD AI ARTIFACTS ---
@st.cache_resource
def load_assets():
    try:
        model = joblib.load('nids_random_forest.pkl')
        scaler = joblib.load('nids_scaler.pkl')
        feature_names = joblib.load('nids_features.pkl')
        class_names = joblib.load('attack_classes.pkl')
        return model, scaler, feature_names, class_names
    except Exception as e:
        st.error(f"Error loading AI models: {e}")
        return None, None, None, None

model, scaler, feature_names, class_names = load_assets()

# --- 3. UI HEADER ---
st.title("🛡️ Enterprise Security Operations Center (SOC)")
st.markdown("Watching distributed sensors via Supabase Cloud.")

# --- 4. FETCH DATA FROM CLOUD ---
def get_latest_device_status():
    """Gets the single latest log for every laptop connected to the system"""
    try:
        response = supabase.table("network_logs").select("*").order("created_at", desc=True).execute()
        df = pd.DataFrame(response.data)
        
        if df.empty:
            return None
        
        # Keep only the newest row for each unique device_id
        latest_per_device = df.sort_values('created_at').groupby('device_id').tail(1)
        return latest_per_device
    except Exception as e:
        st.error(f"Database Error: {e}")
        return None

# --- 5. THE LIVE PROCESSING LOOP ---
placeholder = st.empty()

while True:
    latest_data = get_latest_device_status()
    
    with placeholder.container():
        if latest_data is None:
            st.warning("📡 No devices are currently reporting data. Start `agent.py` on your laptop.")
        else:
            # Create a grid for multiple laptops
            cols = st.columns(3) 
            
            for idx, (i, row) in enumerate(latest_data.iterrows()):
                device_name = row['device_id']
                features_dict = row['features'] 
                
                # Convert JSON features back to a DataFrame for the AI
                input_df = pd.DataFrame([features_dict])[feature_names]
                
                # AI PREDICTION
                scaled_data = scaler.transform(input_df)
                prediction = model.predict(scaled_data)[0]
                probabilities = model.predict_proba(scaled_data)[0]
                
                result_text = class_names[prediction]
                confidence = np.max(probabilities) * 100
                
                # DRAW DEVICE CARD
                with cols[idx % 3]:
                    with st.container(border=True):
                        st.subheader(f"💻 {device_name}")
                        
                        if result_text == "Benign":
                            st.success("✅ STATUS: SECURE")
                        else:
                            st.error(f"🚨 ATTACK: {result_text.upper()}")
                        
                        st.metric("AI Confidence", f"{confidence:.1f}%")
                        st.caption(f"Last Log: {row['created_at']}")
                        
                        with st.expander("View Raw Cloud Features"):
                            st.json(features_dict)

    # Wait 5 seconds before pulling data again
    time.sleep(5)
    st.rerun()