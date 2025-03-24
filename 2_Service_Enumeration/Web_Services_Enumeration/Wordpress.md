# WPScan

## Api Token

- https://wpscan.com/profile/

## Vulnerability Database Update

```bash
wpscan --update
```

## Scanning a Single URL

```bash
wpscan --url <target_url>

wpscan --url <target_url> --random-user-agent
```

## Enumerating Plugins and Themes

```bash
wpscan --url <target_url> --enumerate p --enumerate t
```

## Performing a Full Scan

```bash
wpscan --url <target_url> --enumerate p --enumerate t --enumerate u u
```

## wpscan + cewl

```bash
cewl <target_url> | tee cewl_passwords.txt

wpscan --url <target_url> -U user.txt -P cewl_passwords.txt
```

## Others Scan

```bash
wpscan --url http://<RHOST> --enumerate p --plugins-detection aggressive

wpscan --url http://<RHOST>
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```