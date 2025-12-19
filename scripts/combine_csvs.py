import glob
import pandas as pd
import os

def combine_csvs():
    data_frames = []
    
    # 1. Process Normal Files
    normal_files = glob.glob('ftp_normal_*.csv')
    print(f"Found {len(normal_files)} normal files.")
    for f in normal_files:
        try:
            df = pd.read_csv(f)
            df['label'] = 0 # Mark as Benign
            data_frames.append(df)
        except Exception as e:
            print(f"Error reading {f}: {e}")

    # 2. Process Attack Files
    attack_files = glob.glob('ftp_attack_*.csv')
    print(f"Found {len(attack_files)} attack files.")
    for f in attack_files:
        try:
            df = pd.read_csv(f)
            df['label'] = 1 # Mark as Attack (Initial)
            data_frames.append(df)
        except Exception as e:
            print(f"Error reading {f}: {e}")

    if not data_frames:
        print("No CSV files found to combine!")
        return

    # Combine
    combined_df = pd.concat(data_frames, ignore_index=True)
    
    # Save
    output_file = 'ftp_combined_dataset.csv'
    combined_df.to_csv(output_file, index=False)
    print(f"Successfully created {output_file} with {len(combined_df)} rows.")

if __name__ == "__main__":
    combine_csvs()
