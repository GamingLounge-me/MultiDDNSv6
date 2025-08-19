# Disable IPv6 deprecated ips

in go you cant directly check which ip is deprecated without going an os spezific implementation for every platform.

here is an exmaple for Debian based systems.

## Debian

/etc/sysctl.conf
```
net.ipv6.conf.*.use_tempaddr = 0
```