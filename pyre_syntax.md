Important info
---------------

General rules:

 - If protocols aren't specified, assume tcp only
 - If filter type isn't specified, assume `INPUT`
 - For catch-all, use the parameter `all` e.g. `allow all` or `drop forward all`



Allow (ACCEPT) rules
-----------

Allow all ICMP only for v4:

```
allow icmpv4
```

Allow specific ICMPv6 types:

```
allow icmpv6-type 1-4,133-137,141,142,148,149
allow icmpv6-type 130-132,143,151-153 from fe80::/10
```

Open port 22 for IPv4 and IPv6:

```
allow port 22
```

Allow port 21 only from selected IP's (mix and match IPv4 and v6)

```
allow port 21 from 2a07:e01::1,192.168.8.1
```

Allow port 80 and 443 from the subnet 10.0.0.0/8 on interface eth0

```
allow port 80,443 from 10.0.0.0/8 if-in eth0
```

Allow forwarding from interface wg0 to eth0

```
allow forward if-in wg0 if-out eth0
```

Allow forwarding from interface eth0 to wg0 only if related or established

```
allow forward if-in eth0 if-out wg0 state related,established
```


Deny (REJECT) / Drop (DROP) rules
-----------

Drop any packets with the state `INVALID`

```
drop state invalid
```

