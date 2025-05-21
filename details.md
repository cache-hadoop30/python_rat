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


