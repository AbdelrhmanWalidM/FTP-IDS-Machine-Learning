import glob
import pandas as pd
from scapy.all import rdpcap, IP, TCP, Raw

# Patterns
NORMAL_PATTERN = '*nor*.pcapng' # Matches normal and noraml
ATTACK_PATTERN = '*attack*.pcapng'

def parse_pcap(file_path):
    print(f"Reading {file_path} (this might take a moment)...")
    packets = rdpcap(file_path)
    
    data = []
    
    for pkt in packets:
        try:
            # Basic info
            row = {
                'frame.time_epoch': float(pkt.time),
                'frame.len': len(pkt),
                'ip.src': '',
                'ip.dst': '',
                'tcp.srcport': 0,
                'tcp.dstport': 0,
                'tcp.flags': '',
                'ftp.request.command': '',
                'ftp.request.arg': '',
                'ftp.response.code': 0,
                'ftp.response.arg': ''
            }
            
            if IP in pkt:
                row['ip.src'] = pkt[IP].src
                row['ip.dst'] = pkt[IP].dst
            
            if TCP in pkt:
                row['tcp.srcport'] = pkt[TCP].sport
                row['tcp.dstport'] = pkt[TCP].dport
                row['tcp.flags'] = str(pkt[TCP].flags)
                
                # Manual FTP Parsing from Raw Payload
                if Raw in pkt:
                    load = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                    # FTP Request (Command + Arg)
                    # Typical commands: USER, PASS, LIST, RETR, STOR, etc.
                    # Simple heuristic: Uppercase word at start usually
                    parts = load.split(' ', 1)
                    if len(parts) > 0:
                        cmd_candidate = parts[0].upper()
                        # List of common FTP commands for validation
                        ftp_cmds = ['USER', 'PASS', 'LIST', 'PORT', 'QUIT', 'TYPE', 'MODE', 'STRU', 
                                    'RETR', 'STOR', 'STOU', 'APPE', 'ALLO', 'REST', 'RNFR', 'RNTO', 
                                    'ABOR', 'DELE', 'CWD', 'RMD', 'MKD', 'PWD', 'SYST', 'STAT', 'HELP', 'SITE']
                        
                        if cmd_candidate in ftp_cmds:
                            row['ftp.request.command'] = cmd_candidate
                            if len(parts) > 1:
                                row['ftp.request.arg'] = parts[1].strip()
                        
                        # FTP Response (Code + Msg)
                        # Starts with 3 digits
                        elif cmd_candidate.isdigit() and len(cmd_candidate) == 3:
                             row['ftp.response.code'] = int(cmd_candidate)
                             if len(parts) > 1:
                                 row['ftp.response.arg'] = parts[1].strip()

            data.append(row)
        except Exception as e:
            continue
            
    return pd.DataFrame(data)

def convert_files(pattern, prefix):
    files = glob.glob(pattern)
    for f in files:
        if f.endswith('.csv'): continue # skip existing csvs
        
        output_csv = f"{prefix}_{f}.csv".replace('.pcapng', '')
        # sanitize name
        output_csv = output_csv.replace('..', '.') 
        
        print(f"Converting {f} -> {output_csv}")
        df = parse_pcap(f)
        df.to_csv(output_csv, index=False)
        print(f"Saved {len(df)} packets.")

if __name__ == "__main__":
    print("Starting Scapy Conversion...")
    convert_files(NORMAL_PATTERN, 'ftp_normal')
    convert_files(ATTACK_PATTERN, 'ftp_attack')
    print("Done! Now run 'python ftp_ids_model.py'")
