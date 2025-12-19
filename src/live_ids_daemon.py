import os
import time
import threading
import logging
from collections import deque
import pandas as pd
import joblib
from scapy.all import sniff, TCP, Raw

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
INTERFACE = None          # None -> sniff on all interfaces
FTP_PORT = 21
WINDOW_SIZE_SEC = 1       
MODEL_PATH = os.path.join(os.path.dirname(__file__), "window_model.pkl")
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "live_ids.log")

# ----------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LiveIDS")

# ----------------------------------------------------------------------
# Load model
# ----------------------------------------------------------------------
if not os.path.exists(MODEL_PATH):
    logger.error(f"Model file not found at {MODEL_PATH}. Train it first.")
    exit(1)

clf = joblib.load(MODEL_PATH)
logger.info("Loaded trained model from %s", MODEL_PATH)

# buffer for packets
packet_buffer = deque()

def packet_handler(pkt):
    if TCP not in pkt:
        return
    if pkt[TCP].sport != FTP_PORT and pkt[TCP].dport != FTP_PORT:
        return

    row = {
        "frame.time_epoch": pkt.time,
        "frame.len": len(pkt),
        "ftp.response.code": None,
        "ftp.request.command": None,
    }

    if Raw in pkt:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
        parts = payload.split(" ", 1)
        if parts:
            cmd = parts[0].upper()
            if cmd.isdigit() and len(cmd) == 3:
                row["ftp.response.code"] = int(cmd)
            else:
                row["ftp.request.command"] = cmd

    packet_buffer.append(row)

def start_sniffing():
    logger.info("Starting packet capture on port %s", FTP_PORT)
    sniff(prn=packet_handler, filter=f"tcp port {FTP_PORT}", iface=INTERFACE, store=False)

def process_windows():
    while True:
        time.sleep(WINDOW_SIZE_SEC)
        if not packet_buffer:
            continue
        
        packets = list(packet_buffer)
        packet_buffer.clear()
        
        df = pd.DataFrame(packets)
        df["timestamp"] = pd.to_datetime(df["frame.time_epoch"], unit="s")
        df = df.sort_values("timestamp")
        df.set_index("timestamp", inplace=True)
        
        # Aggregate same as training
        resampled = df.resample(f"{WINDOW_SIZE_SEC}s").agg({
            "frame.len": ["count", "sum", "mean"],
            "ftp.response.code": lambda x: (x == 530).sum(),
        })
        resampled.columns = ["packet_count", "byte_sum", "byte_mean", "failed_login_count"]
        resampled = resampled[resampled["packet_count"] > 0].fillna(0)
        
        if resampled.empty:
            continue
            
        preds = clf.predict(resampled)
        label_map = {0: "Benign", 1: "Attack", 2: "PostExploit"}
        
        for i, pred in enumerate(preds):
            if pred != 0:
                logger.warning(f"[ALERT] {label_map[pred]} detected in window starting {resampled.index[i]}")

def main():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    process_thread = threading.Thread(target=process_windows, daemon=True)
    
    sniff_thread.start()
    process_thread.start()
    
    logger.info("Live IDS daemon started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested.")

if __name__ == "__main__":
    main()
