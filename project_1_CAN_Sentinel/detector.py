import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

def preprocess_can_data(filepath, label):
    df = pd.read_csv(filepath)
    df = df.dropna().copy()
    
    # Standardize column names to lowercase
    cols = {c: c.strip().lower() for c in df.columns}
    df = df.rename(columns=cols)
    
    # Identify timestamp column
    time_col = [c for c in df.columns if 'time' in c][0]
    df['time_delta'] = df[time_col].diff().fillna(0)
    
    # Identify arbitration ID column
    id_col = [c for c in df.columns if 'id' in c][0]
    def parse_id(val):
        try:
            return int(str(val), 16) if '0x' in str(val).lower() else int(val)
        except:
            return int(str(val), 16)
    df['id_int'] = df[id_col].apply(parse_id)
    
    # Identify data payload column
    data_col = [c for c in df.columns if 'data' in c][0]
    def parse_payload(data_str):
        try:
            bytes_list = [int(b, 16) for b in str(data_str).strip().split()]
            if len(bytes_list) >= 2:
                return (bytes_list[0] << 8) | bytes_list[1]
            return 0
        except:
            return 0
            
    df['payload_val'] = df[data_col].apply(parse_payload)
    df['ground_truth'] = label
    return df

print("[*] Loading Baseline and Attacked CAN Bus Datasets...")
normal_df = preprocess_can_data('can_dataset.csv', label=0)
attack_df = preprocess_can_data('attacked_dataset.csv', label=1)

# Combine datasets
combined_df = pd.concat([normal_df, attack_df], ignore_index=True)

# Features for Isolation Forest
features = ['time_delta', 'id_int', 'payload_val']
X = combined_df[features]
y_true = combined_df['ground_truth']

print("[*] Training Isolation Forest Anomaly Detection Model...")
model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
model.fit(X)

# Predictions: -1 indicates anomaly, 1 indicates normal
raw_preds = model.predict(X)
y_pred = [1 if p == -1 else 0 for p in raw_preds]

print("\n" + "="*50)
print("       CAN-SENTINEL ML DETECTION EVALUATION")
print("="*50)
print("\n[+] Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\n[+] Classification Report:")
print(classification_report(y_true, y_pred, target_names=['Normal (0)', 'Attack (1)']))

total_detected = sum(y_pred)
print(f"[+] Total Injected/Anomalous Frames Detected: {total_detected}")
print("="*50)
