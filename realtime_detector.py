import can
import time
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

def train_baseline_model():
    print("[*] Training baseline anomaly detection model...")
    df = pd.read_csv('can_dataset.csv')
    df = df.dropna().copy()
    
    cols = {c: c.strip().lower() for c in df.columns}
    df = df.rename(columns=cols)
    
    time_col = [c for c in df.columns if 'time' in c][0]
    id_col = [c for c in df.columns if 'id' in c][0]
    data_col = [c for c in df.columns if 'data' in c][0]
    
    df['time_delta'] = df[time_col].diff().fillna(0)
    
    def parse_id(val):
        try:
            return int(str(val), 16) if '0x' in str(val).lower() else int(val)
        except:
            return int(str(val), 16)
            
    df['id_int'] = df[id_col].apply(parse_id)
    
    def parse_payload(data_str):
        try:
            bytes_list = [int(b, 16) for b in str(data_str).strip().split()]
            if len(bytes_list) >= 2:
                return (bytes_list[0] << 8) | bytes_list[1]
            return 0
        except:
            return 0
            
    df['payload_val'] = df[data_col].apply(parse_payload)
    
    features = ['time_delta', 'id_int', 'payload_val']
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(df[features])
    return model

def monitor_live_bus(model):
    bus = can.interface.Bus(channel='vcan0', interface='socketcan')
    print("[+] Real-time CAN-Sentinel IDS running on vcan0. Listening for frames...")
    
    last_timestamp = time.time()
    
    try:
        while True:
            msg = bus.recv(1.0)
            if msg:
                current_time = time.time()
                time_delta = current_time - last_timestamp
                last_timestamp = current_time
                
                arbitration_id = msg.arbitration_id
                
                payload_val = 0
                if len(msg.data) >= 2:
                    payload_val = (msg.data[0] << 8) | msg.data[1]
                
                sample = pd.DataFrame([{
                    'time_delta': time_delta,
                    'id_int': arbitration_id,
                    'payload_val': payload_val
                }])
                
                pred = model.predict(sample)[0]
                
                if pred == -1 or arbitration_id == 0x000 or payload_val > 9000:
                    print(f"[ALERT - ANOMALY DETECTED] ID: {hex(arbitration_id)} | Delta: {time_delta:.4f}s | Payload Value: {payload_val}")
                else:
                    print(f"[OK] ID: {hex(arbitration_id)} | Payload Value: {payload_val}")
                    
    except KeyboardInterrupt:
        print("\n[+] Real-time monitoring stopped.")

if __name__ == "__main__":
    detector_model = train_baseline_model()
    monitor_live_bus(detector_model)
