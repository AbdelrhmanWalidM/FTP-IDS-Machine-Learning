import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import os

import glob

# ==========================================
# CONFIGURATION
# ==========================================
DATASET_FILE = 'ftp_combined_dataset.csv'

def load_and_label_data():
    if not os.path.exists(DATASET_FILE):
        print(f"ERROR: {DATASET_FILE} not found. Please run combine_csvs.py first.")
        return None
        
    print(f"Loading {DATASET_FILE}...")
    df = pd.read_csv(DATASET_FILE)
    
    # Auto-labeling Logic
    # The file already has 'label' (0 or 1) from the merge script.
    # We just need to refine the attack labels:
    
    # Label = 1 (Brute Force) - Default for attack files
    
    # Refine Label = 2 (Post Exploit) if command is suspicious
    # We only apply this to rows that are ALREADY marked as attack (label=1)
    # to avoid false positives if a normal user does a LIST (though unlikely in this lab setup)
    post_exploit_cmds = ['RETR', 'STOR', 'DELE', 'MKD', 'RMD', 'SITE']
    df.loc[(df['label'] == 1) & (df['ftp.request.command'].isin(post_exploit_cmds)), 'label'] = 2
    
    print(f"Data Distribution:\n{df['label'].value_counts()}")
    
    return df

def preprocess_data(df):
    print("Preprocessing data...")
    
    # Fill NaNs
    df.fillna({'ftp.request.command': 'NONE', 'ftp.response.code': 0, 'ftp.response.arg': 'NONE'}, inplace=True)
    
    # Feature Engineering
    # Encode categorical columns
    le_cmd = LabelEncoder()
    df['ftp.command_enc'] = le_cmd.fit_transform(df['ftp.request.command'].astype(str))
    
    # FIX: Encode TCP flags if they are strings (e.g. 'PA', 'A')
    le_flags = LabelEncoder()
    df['tcp.flags_enc'] = le_flags.fit_transform(df['tcp.flags'].astype(str))
    
    # We can also use packet length and flags
    # We drop IPs for the model to generalize (avoid learning specific IP addresses)
    # UPDATED: Use the encoded flags instead of the raw string flags
    features = ['frame.len', 'tcp.srcport', 'tcp.dstport', 'tcp.flags_enc', 'ftp.command_enc', 'ftp.response.code']
    
    X = df[features]
    y = df['label']
    
    return X, y

def train_model(X, y):
    print("Training Random Forest Model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42,stratify=y)
    
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    print("Model Training Complete.")
    
    # Evaluation
    y_pred = clf.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'BruteForce', 'PostExploit'] if 2 in y.values else ['Benign', 'Attack']))
    
    return clf

if __name__ == "__main__":
    df = load_and_label_data()
    if df is not None and len(df) > 0:
        X, y = preprocess_data(df)
        model = train_model(X, y)
        print("\nDone! The model is trained and ready.")
        
        # Example prediction
        print("\nTest Prediction (Simulated 'RETR' command):")
        # Construct a fake input matching our features: len=100, ports=random, flags=24(PA), cmd='RETR', code=226
        # Note: You would need to handle the LabelEncoder transformation properly in production
        pass
