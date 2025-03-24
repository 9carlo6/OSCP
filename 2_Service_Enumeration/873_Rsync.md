# Nmap

```bash
sudo nmap -sV -p $IP
```

# Probing for Accessible Shares

```bash
nc -nv $IP 873
```

# Enumerating an Open Share

```bash
rsync -av --list-only rsync://$IP/SHARENAME
```
