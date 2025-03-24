# Host Scan

## Initial Scan

```bash
sudo nmap -sC -sV -O -oA /usr/share/nmap/initial $IP
```

## Full Scan

```bash
sudo nmap -sC -sV -O -p- -oA /usr/share/nmap/full $IP
```

## Fast TCP Port Scan:

```bash
nmap -F -T4 -oN nmap/fastTCPScan $IP
```

## Simple TCP Port Scan

```bash
nmap -p- -T4 -oN nmap/ezTCPScan $IP
```

## Simple UDP Port Scan

```bash
nmap -sU -n -p- -T4 -oN nmap/ezUDPScan $IP
```

## Aggressive Scan

```bash
nmap -A -T4 -px,y,z -v -oN nmap/aggressiveScan $IP
```

## TCP Version Detection

```bash
nmap -sV --reason -O -p- $IP
```

## UDP Version Detection

```bash
nmap -sU -sV -n $IP
```

## Heartbleed Scan

```bash
nmap --script ssl-heartbleed $IP
```


## Version/OS Detection

```bash
nmap -v --dns-server \<DNS\> -sV --reason -O --open -Pn $IP
```

## Unknown Services

```bash
amap -d $IP \<PORT\>
```

## Full nmapAutomator scanning

```bash
sudo nmapAutomator.sh --host $IP --type All
```

# Subnet Scans

## List Scan

```bash
nmap -sL -oN nmap/listScan 10.x.x.x/xx
```

## Ping Scan

```bash
nmap -sn -oN nmap/pingScan 10.x.x.x/xx
```

## nbtscan

```bash
nbtscan -r 10.x.x.x.x
```

## netdiscover

```bash
netdiscover -r 10.x.x.x/24
```

