import os
import sys
import pandas as pd
import joblib


def preprocess(csv_path: str, window_size: str = "1s"):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"{csv_path} not found")

    df = pd.read_csv(csv_path)
    # Convert epoch to datetime and set as index
    df["timestamp"] = pd.to_datetime(df["frame.time_epoch"], unit="s")
    df = df.sort_values("timestamp")
    df.set_index("timestamp", inplace=True)

    # Re‑apply the same label‑refinement logic
    df["label"] = 0
    df.loc[df["ftp.response.code"] == 530, "label"] = 1
    post_exploit_cmds = ["RETR", "STOR", "DELE", "MKD", "RMD", "SITE"]
    df.loc[(df["label"] == 1) & (df["ftp.request.command"].isin(post_exploit_cmds)), "label"] = 2

    # Resample / aggregate into windows
    resampled = df.resample(window_size).agg({
        "frame.len": ["count", "sum", "mean"],
        "ftp.response.code": lambda x: (x == 530).sum(),
        "label": "max",
    })
    # Flatten multi‑index columns
    resampled.columns = [
        "packet_count",
        "byte_sum",
        "byte_mean",
        "failed_login_count",
        "label",
    ]
    # Remove empty windows
    resampled = resampled[resampled["packet_count"] > 0]
    resampled.fillna(0, inplace=True)
    return resampled

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_window_model.py <test_csv> [window_size]")
        sys.exit(1)

    test_csv = sys.argv[1]
    window_size = sys.argv[2] if len(sys.argv) > 2 else "1s"

    # Load the trained model (must exist in the same folder)
    model_path = os.path.join(os.path.dirname(__file__), "window_model.pkl")
    if not os.path.exists(model_path):
        print(f"ERROR: Trained model not found at {model_path}. Train it first using ftp_ids_windowed.py.")
        sys.exit(1)
    clf = joblib.load(model_path)

    try:
        df_windows = preprocess(test_csv, window_size)
    except Exception as e:
        print(f"Error during preprocessing: {e}")
        sys.exit(1)

    # Predict
    feature_cols = ["packet_count", "byte_sum", "byte_mean", "failed_login_count"]
    X = df_windows[feature_cols]
    preds = clf.predict(X)
    label_map = {0: "Benign", 1: "Attack", 2: "PostExploit"}
    df_windows["predicted_label"] = preds
    df_windows["predicted_name"] = df_windows["predicted_label"].map(label_map)

    # Summary output
    print("\nPrediction summary (per time window):")
    # print(df_windows.tail(50))                               
    print(df_windows["predicted_name"].value_counts())

    out_path = os.path.splitext(test_csv)[0] + "_predictions.csv"
    df_windows.to_csv(out_path, index_label="window_start")
    print(f"Detailed predictions saved to {out_path}")

if __name__ == "__main__":
    main()