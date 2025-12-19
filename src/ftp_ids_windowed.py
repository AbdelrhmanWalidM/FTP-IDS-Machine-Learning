import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix,ConfusionMatrixDisplay

DATASET_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'ftp_combined_dataset.csv')

def load_and_window_data(window_size='10s'):
    if not os.path.exists(DATASET_FILE):
        print(f"ERROR: {DATASET_FILE} not found.")
        return None

    print(f"Loading {DATASET_FILE} for Windowing...")
    df = pd.read_csv(DATASET_FILE)
    print(f"Loaded {len(df)} rows.")

    # 1. Convert Time
    df['timestamp'] = pd.to_datetime(df['frame.time_epoch'], unit='s')
    df = df.sort_values('timestamp')
    df.set_index('timestamp', inplace=True)

    # 2. Refine Labels (Same logic as before to ensure accuracy)
    df['label'] = 0 # Default Benign
    # If original label in CSV was 1, mark as 1
    df.loc[df['label'] == 1, 'label'] = 1 
    # Refine 530s
    df.loc[df['ftp.response.code'] == 530, 'label'] = 1
    # Refine PostExploit
    post_exploit_cmds = ['RETR', 'STOR', 'DELETE', 'MKDIR', 'RMD', 'SITE']
    df.loc[(df['label'] == 1) & (df['ftp.request.command'].isin(post_exploit_cmds)), 'label'] = 2

    print("Grouping data into Time Windows...")
    
    # 3. Aggregation Logic
    # We group by 1 second (or whatever window_size is)
    # Features to extract per window:
    resampled = df.resample(window_size).agg({
        'frame.len': ['count', 'sum', 'mean'],     # Volume features
        'ftp.response.code': lambda x: (x == 530).sum(), # Count of failed logins
        'label': 'max'                             # If ANY packet is attack, window is attack
    })
    
    # Flatten columns
    resampled.columns = ['packet_count', 'byte_sum', 'byte_mean', 'failed_login_count', 'label']
    
    # Drop empty windows (where no packets occurred)
    resampled = resampled[resampled['packet_count'] > 0]
    
    # 4. Add "Unique Commands" feature using a custom loop or apply
    # (Resample apply is slow, doing it separate)
    # Faster way: Just check if any post-exploit command existed
    # For simplicity, we stick to the aggregated features above, which are very strong for Brute Force
    
    # Cleaning
    resampled.fillna(0, inplace=True)
    
    print(f"Created {len(resampled)} time windows.")
    print(f"Window Distribution:\n{resampled['label'].value_counts()}")
    
    return resampled

def train_window_model(df):
    features = ['packet_count', 'byte_sum', 'byte_mean', 'failed_login_count']
    X = df[features]
    y = df['label']
    
    print("\nTraining Window-Based Random Forest...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    # clf = LogisticRegression(random_state=42)
    clf.fit(X_train, y_train)
    
    # Save the trained model for later inference
    model_path = os.path.join(os.path.dirname(__file__), "window_model.pkl")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")
    
    y_pred = clf.predict(X_test)
    print("\nClassification Report (Window-Based):")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'BruteForce', 'PostExploit'] if 2 in y.values else ['Benign', 'Attack']))
    
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'BruteForce', 'PostExploit'] if 2 in y.values else ['Benign', 'Attack'])
    disp.plot()
    plt.show()
    
    return clf

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_path = sys.argv[1]
        df_windowed = load_and_window_data(window_size='1s')
        if df_windowed is not None:
            model = train_window_model(df_windowed)
        inference_df = predict_on_file(test_path, window_size='1s')
        print("Inference completed. Summary of predictions:")
        print(inference_df['predicted_name'].value_counts())
    else:
        df_windowed = load_and_window_data(window_size='1s')
        if df_windowed is not None:
            model = train_window_model(df_windowed)
            print("Done.")