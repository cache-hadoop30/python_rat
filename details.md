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
