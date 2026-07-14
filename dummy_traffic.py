# python dummy_traffic.py -> to run this script

import urllib.request
import time
import threading
import customtkinter as ctk

is_running = False

def traffic_loop():
    global is_running
    while is_running:
        try:
            # Constantly "knock" on the local port 4 times a second
            urllib.request.urlopen("http://127.0.0.1:5000", timeout=0.5)
        except Exception:
            pass
        
        # Fulfills original rate limiting constraint
        time.sleep(0.25)

def start_traffic():
    global is_running
    if not is_running:
        is_running = True
        update_status("🟢 TRAFFIC ACTIVE", "#00ffcc")
        threading.Thread(target=traffic_loop, daemon=True).start()

def stop_traffic():
    global is_running
    is_running = False
    update_status("🔴 TRAFFIC STOPPED", "#ff4c4c")

def update_status(text, color):
    status_label.configure(text=text, text_color=color)

# ==========================================
# THE GUI SETUP
# ==========================================
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("blue")  

app = ctk.CTk()
app.geometry("400x260")
app.title("Normal Traffic Generator")
app.resizable(False, False)

title = ctk.CTkLabel(app, text="BACKGROUND NOISE", font=("Roboto", 20, "bold"))
title.pack(pady=(20, 5))

subtitle = ctk.CTkLabel(app, text="Generates safe baseline network data", font=("Roboto", 12), text_color="gray")
subtitle.pack(pady=(0, 20))

btn_start = ctk.CTkButton(app, text="▶ START TRAFFIC", fg_color="#28a745", hover_color="#218838", height=40, command=start_traffic)
btn_start.pack(pady=10, padx=40, fill="x")

btn_stop = ctk.CTkButton(app, text="⏹ STOP TRAFFIC", fg_color="#dc3545", hover_color="#c82333", height=40, command=stop_traffic)
btn_stop.pack(pady=10, padx=40, fill="x")

status_label = ctk.CTkLabel(app, text="🔴 TRAFFIC STOPPED", font=("Roboto", 14, "bold"), text_color="#ff4c4c")
status_label.pack(pady=(15, 0))

app.mainloop()