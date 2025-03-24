# Nmap

```bash
sudo nmap -p1521 -sV $IP --open
sudo nmap -p1521 -sV $IP --open --script oracle-sid-brute
```

# ODAT

```bash
odat all -s $IP
```

# Service Interaction
## SQLplus

```bash
sqlplus user/password@$IP/XE

# IN CASO DI ERRORE:
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```

## Oracle RDBMS

```bash
>select table_name from all_tables;
>select * from user_role_privs;
>sqlplus scott/tiger@10.129.204.235/XE as sysdba
```
