# MultiDDNSv6

Program that gets the IPv6 prefix from the machine and checks if it has changed, then updates DNS records via service providers with FQDNs and IPv6 suffixes from the config.

## Use as Service

### Linux: Systemd
```
[Unit]
Description=Multi DDNS V6
After=network.target

[Service]
Type=simple
WorkingDirectory=/etc/mddns6
ExecStart=/usr/bin/mddns6/mddns6

[Install]
WantedBy=multi-user.target
```

## Build
Adjust the environment variables to you needs
```
GOARCH=amd64
GOOS=linux
```

### Examples

#### Build on Windows(PowerShell) to be executed on Linux
```powershell
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o mddns6
```

## Future & Support & Contribution
We are planning to use (and support) these scripts as long as needed. We will gladly read (and most likely accept) PRs for patches, improvements and updates.

## License
Shall be used under [GPLv3](https://github.com/GamingLounge-me/MultiDDNSv6/blob/main/LICENSE).