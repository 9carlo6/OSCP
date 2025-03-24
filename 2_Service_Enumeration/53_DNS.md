
| **Server Type**              | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DNS Root Server              | The root servers of the DNS are responsible for the top-level domains (TLD). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe. |
| Authoritative Nameserver     | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point.                                                                                                                                                                            |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying.                                                                                                                                                                                                                                               |
| Caching DNS Server           | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.                                                                                                                                                                                                                                                                                             |
| Forwarding Server            | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                                                                                                                                                                                                                                                            |
| Resolver                     | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                                                                                                                                                                                                                                                               |

| **DNS Record** | **Description**                                                                                                                                                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A              | Returns an IPv4 address of the requested domain as a result.                                                                                                                                                                                      |
| AAAA           | Returns an IPv6 address of the requested domain.                                                                                                                                                                                                  |
| MX             | Returns the responsible mail servers as a result.                                                                                                                                                                                                 |
| NS             | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                                              |
| TXT            | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| CNAME          | This record serves as an alias. If the domain www.prova.com should point to the same IP, and we create an A record for one and a CNAME record for the other.                                                                                      |
| PTR            | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                                                                                     |
| SOA            | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                                                            |

| **Command**                        | **Description**                                      |
| ---------------------------------- | ---------------------------------------------------- |
| `nslookup $TARGET`                 | Identify the `A` record for the target domain.       |
| `nslookup -query=A $TARGET`        | Identify the `A` record for the target domain.       |
| `dig $TARGET @<nameserver/IP>`     | Identify the `A` record for the target domain.       |
| `dig a $TARGET @<nameserver/IP>`   | Identify the `A` record for the target domain.       |
| `nslookup -query=PTR <IP>`         | Identify the `PTR` record for the target IP address. |
| `dig -x <IP> @<nameserver/IP>`     | Identify the `PTR` record for the target IP address. |
| `nslookup -query=ANY $TARGET`      | Identify `ANY` records for the target domain.        |
| `dig any $TARGET @<nameserver/IP>` | Identify `ANY` records for the target domain.        |
| `nslookup -query=TXT $TARGET`      | Identify the `TXT` records for the target domain.    |
| `dig txt $TARGET @<nameserver/IP>` | Identify the `TXT` records for the target domain.    |
| `nslookup -query=MX $TARGET`       | Identify the `MX` records for the target domain.     |
| `dig mx $TARGET @<nameserver/IP>`  | Identify the `MX` records for the target domain.     |

---

# Service Interaction via DIG

## DIG - NS Query

```bash
dig ns prova.com @$IP
```

## DIG - Version Query

```bash
dig CH TXT version.bind $IP
```

## DIG - ANY Query

```bash
dig any prova.com @$IP
```

## DIG - AXFR Zone Transfer

```bash
dig axfr prova.com @$IP
```

## DIG - AXFR Zone Transfer - Subnet

```bash
dig axfr subnet.prova.com @$IP
```

# Service Enumeration via dnsrecon

```bash
dnsrecon -d $TARGET -t std
```

# Brute Forcing

## Bash Commands

```bash
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.prova.com @$IP | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

```bash
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.prova.com @$IP | grep -v ';\|MX' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

## dnsrecon

```bash
dnsenum --dnsserver $IP --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt prova.com
```

# Search for domain names associated with the host

```bash
whois $IP
```

```bash
nslookup
> server $IP
Default server: ...
Address: ...
> $IP
```

# Resolve DNS

```bash
host website.com
nslookup website.com
```

# Search name servers

```bash
host -t ns domain.com
```

# Search mail servers

```bash
host -t mx domain.com
```

# Zone Transfer

## nmap

```bash
nmap --script dns-zone-transfer -p 53 domain.com
```

## host

```bash
host -l domain.name dns.server
````

## dnsrecon 

```bash
dnsrecon -d domain.com -t axfr
dnsrecon -d $IP -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
````
