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

Syntax Reference
------------------

Starting words:

```
allow    # Set the action to ACCEPT
accept   # Alias for allow
drop     # Set the action to DROP
reject   # Set the action to REJECT
```

Chain keywords:

```
forward  # Set the chain to FORWARD (INPUT is assumed default)
output   # Set the chain to OUTPUT (INPUT is assumed default)

# The `chain` keyword can be used to specify one or more chains for a rule
# Example:
#   
#     allow chain input,forward port 443
#
# The above rule would result in the below iptables rules:
#
#     -A INPUT -p tcp --dport 443 -j ACCEPT
#     -A FORWARD -p tcp --dport 443 -j ACCEPT
#
chain   [chain,chain,...]

# The `all` keyword duplicates a rule in all known chains for a table
# Example:
#     allow all from 192.168.0.0/16
# The above rule would result in the ACCEPT rule being duplicated for chains INPUT, FORWARD, and OUTPUT 
#
all     # Duplicate the rule in all known chains for this table

```

State:

```
state [state1,state2,...]    # Equivalent to `-m state --state state1,state2` 
```

Source / destination IPs and interfaces:

```
# The `from` keyword creates `-s` (source IP) rules for one or more IPs
# Unlike normal iptables, you can mix and match IPv4 and IPv6 in the same rule:
#
#     allow port 443 from 1.2.3.4,192.168.0.0/16,2a07:e00::1
#
# This results in the following iptables rules:
#
#   (IPv4 Rules)
#   -A INPUT -p tcp --dport 443 -s 1.2.3.4/32 -j ACCEPT
#   -A INPUT -p tcp --dport 443 -s 192.168.0.0/16 -j ACCEPT
#   (IPv6 Rules)
#   -A INPUT -p tcp --dport 443 -s 2a07:e00::1/128 -j ACCEPT
# 
from [ip,ip,...]

to [ip,ip,...]             # Same as `from` but for destination IPs

# `if-in` and `if-out` work the same as `from` and `to` - but for physical interfaces
# e.g.   allow port 22 if-in eth1,eth2

if-in  [iface,iface,...]    # Match one or more source interfaces
if-out [iface,iface,...]    # Match one or more destination interfaces
```

Source / destination ports:

```
# Ports can be specified either individually, comma separated, and/or as a range (using `-` or `:`).
# You can optionally specify the protocol after the port(s), which can be `tcp`, `udp`, or `both`
# (protocol defaults to `tcp` if not specified)

port  [1,2-3,4,...] (proto)    # Match these destination port(s)
sport [1,2-3,4,...] (proto)    # Match these source port(s)

```




