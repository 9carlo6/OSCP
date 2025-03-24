# SSH Audit

```bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py $IP
```

# Service Interaction

```bash
ssh $IP
ssh user@$IP
ssh -i id_rsa user@$IP
ssh -v user@$IP -o PreferredAuthentications=password
ssh $IP -oKexAlgorithms=+ALGORITHM_NAME
ssh $IP -oKexAlgorithms=+ALGORITHM_NAME -c CIPHER_NAME
```

# Brute Forcing
## crackmapexec

```bash
sudo crackmapexec ssh $IP -u users.txt -p passwords.txt --continue-on-success
```

# Generating an ssh password with openssl

```bash
openssl passwd 123
```