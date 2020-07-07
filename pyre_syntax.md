# Pyrewall Syntax Documentation

- [Important Info](#important-info)

- [Using raw IPTables rules when needed](#using-raw-iptables-rules-when-needed)

  - [Inline `ipt` rules](#inline-ipt-rules)
  - [Importing a standard Persistent IPTables rules.v4 / v6 file](#importing-a-standard-persistent-iptables-rules-v4-v6-file)

- [Allow (ACCEPT) rules](#allow-accept-rules)

- [Deny (REJECT) / Drop (DROP) rules](#deny-reject--drop-drop-rules)

- [Syntax Reference](#syntax-reference)

## Important info

General rules:

- If protocols aren't specified, assume tcp only
  - Specify `both` to match TCP and UDP, e.g. `allow port 80 both`
- If filter type isn't specified, assume `INPUT`
- For catch-all, use the parameter `all` e.g. `allow all` or `drop forward all`
  - `allow all` is equivalent to `-A INPUT -j ACCEPT`, `-A FORWARD -j ACCEPT` and `-A OUTPUT -j ACCEPT`
  - `allow all from 1.2.3.4` works the same as `allow all` but adds the source address `-s 1.2.3.4/32`

## Using raw IPTables rules when needed

In some cases, Pyrewall might not yet have syntax to support certain IPTables rules.

Knowing this is likely to be an issue, there are two ways that you can add raw IPTables rules within
a Pyrewall file when you need them.

### Inline `ipt` rules

The easiest way to add arbitrary IPTables rules to a `.pyre` file is to use `ipt` / `ipt4` / `ipt6`.

- The `ipt` (short for `iptables`) directive adds a raw IPTables rule to both the IPv4 and IPv6 iptables
- The `ipt4` (iptables v4) directive adds a raw IPTables rule to just the IPv4 iptables
- The `ipt6` (iptables v6) directive adds a raw IPTables rule to just the IPv6 iptables

**Example:**

```pyre
@chain INPUT DROP
@chain FORWARD DROP

accept from 1.2.3.0/24

ipt -A FORWARD -i eth2 -o eth1 --special arguments -j ACCEPT
ipt4 -A INPUT -p tcp -m set --match-set v4_blocklist -j DROP
ipt6 -A INPUT -s 2a07:e01::/48 -j LOG
```

**Resulting IPTables Output:**

```iptables
# --- IPv4 Rules --- #
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 1.2.3.0/24 -j ACCEPT
-A FORWARD -i eth2 -o eth1 --special arguments -j ACCEPT
-A INPUT -p tcp -m set --match-set v4_blocklist -j DROP
COMMIT
### End of table filter ###
# --- End IPv4 Rules --- #

# --- IPv6 Rules --- #
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -i eth2 -o eth1 --special arguments -j ACCEPT
-A INPUT -s 2a07:e01::/48 -j LOG
COMMIT
### End of table filter ###
# --- End IPv6 Rules --- #
```

### Importing a standard Persistent IPTables rules.v4 / v6 file

If you have many raw IPTables rules that you want to use, you can import a `rules.v4` / `rules.v6` file from within a `.pyre` file,
and the rules will be injected below the lines you place the `@import` statement under.

For example: you're migrating from `netfilter-persistent` / `iptables-persistent` and there are many rules that can't be converted into Pyrewall format yet.

The IPTables rules file ideally should contain **only rule lines** e.g. `-A INPUT -s 10.8.0.0/24 -j ACCEPT`

The rules filename must also end in either `.v4` if the rules are for IPv4 IPTables, or `.v6` for IPv6 IPTables rules.

#### Example `rules.v4`

```iptables
-A INPUT -s 10.8.0.0/24 -j ACCEPT
-A INPUT -p udp -m udp --dport 51515 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 51515 -j ACCEPT
-A INPUT -s 10.65.0.0/16 -i infra -j ACCEPT
```

#### Example Pyre File

```pyre
@chain INPUT DROP

rem Allow traffic from internal IPs
allow from 2a07:e00::/32,192.168.0.0/16

rem4 === Imported IPv4 iptables rules from /etc/pyrewall/rules.v4 ===
@import rules.v4
rem4 === END of IPv4 iptables rules ===

rem Open port 9000 for TCP and UDP
allow port 9000 both

```

#### Generated IPTables from above Pyre file

```iptables
# --- IPv4 Rules --- #
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
# Allow traffic from internal IPs
-A INPUT -s 192.168.0.0/16 -j ACCEPT
# === Imported IPv4 iptables rules from /etc/pyrewall/rules.v4 ===
-A INPUT -s 10.8.0.0/24 -j ACCEPT
-A INPUT -p udp -m udp --dport 51515 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 51515 -j ACCEPT
-A INPUT -s 10.65.0.0/16 -i infra -j ACCEPT
# === END of IPv4 iptables rules ===
# Open port 9000 for TCP and UDP
-A INPUT -p tcp --dport 9000 -j ACCEPT
-A INPUT -p udp --dport 9000 -j ACCEPT
COMMIT
### End of table filter ###
# --- End IPv4 Rules --- #

# --- IPv6 Rules --- #
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
# Allow traffic from internal IPs
-A INPUT -s 2a07:e00::/32 -j ACCEPT
# Open port 9000 for TCP and UDP
-A INPUT -p tcp --dport 9000 -j ACCEPT
-A INPUT -p udp --dport 9000 -j ACCEPT
COMMIT
### End of table filter ###
# --- End IPv6 Rules --- #
```

## Allow (ACCEPT) rules

### ICMP for IPv4 and IPv6

**Aliases:** `icmp4` and `icmp6` are aliased to `icmpv4` and `icmpv6` respectively.

#### Allow ALL ICMP traffic for both IPv4 and IPv6

```
# Warning: allowing all ICMP traffic can be dangerous for IPv6!
allow icmp
```

**NOTE:** The protocol keyword `icmp` by default covers both IPv4 and IPv6. **HOWEVER**, if ICMP types are specified in an `icmp` rule,
the rule will become an IPv4-only rule to avoid IP version compatibility errors. 

Despite this, you can still specify both IPv4 + IPv6 source/destination addresses, as long as you don't specify any ICMP types.

#### Example 1 (Allow all ICMP from specific IPv4 / v6 addresses)

```
Pyre >> allow icmp from 10.0.0.0/8,fe80::/10                                                                                                             

### IPv4 Rules ###
-A INPUT -p icmp -s 10.0.0.0/8 -j ACCEPT
### End IPv4 Rules ###

### IPv6 Rules ###
-A INPUT -p ipv6-icmp -s fe80::/10 -j ACCEPT
### End IPv6 Rules ###
                                                                                              
```

#### Example 2 (Allow only specific ICMP types using the `icmp` protocl, which will force IPv4):

```
Pyre >> allow icmp types echo-request,destination-unreachable

### IPv4 Rules ###
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
### End IPv4 Rules ###
```

#### Allow all ICMP only for v4

```
Pyre >> allow icmp4

### IPv4 Rules ###
-A INPUT -p icmp -j ACCEPT
### End IPv4 Rules ###
```

#### Allow specific IPv6 ICMP (`icmpv6`) types

```
 Pyre >> allow icmp6 type 1-4,133-137,141,142,148,149
         allow icmp6 type 130-132,143,151-153 from fe80::/10


### IPv6 Rules ###
-A INPUT -p ipv6-icmp --icmpv6-type 1 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 2 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 3 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 4 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 133 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 134 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 135 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 136 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 137 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 141 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 142 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 148 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 149 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 130 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 131 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 132 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 143 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 151 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 152 -s fe80::/10 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 153 -s fe80::/10 -j ACCEPT
### End IPv6 Rules ###
```

#### Open port 22 for IPv4 and IPv6

```
allow port 22
```

#### Allow port 21 only from selected IP's (mix and match IPv4 and v6)

```
Pyre >> allow port 21 from 2a07:e01::1,192.168.8.1                         

### IPv4 Rules ###
-A INPUT -p tcp --dport 21 -s 192.168.8.1/32 -j ACCEPT
### End IPv4 Rules ###

### IPv6 Rules ###
-A INPUT -p tcp --dport 21 -s 2a07:e01::1/128 -j ACCEPT
### End IPv6 Rules ###
```

Allow port 80 and 443 from the subnet 10.0.0.0/8 on interface eth0

```
allow port 80,443 from 10.0.0.0/8 if-in eth0
```

#### Allow forwarding from interface `wg0` to `eth0`

```
Pyre >> allow forward if-in wg0 if-out eth0

### IPv4 Rules ###
-A FORWARD -i wg0 -o eth0 -j ACCEPT
### End IPv4 Rules ###

### IPv6 Rules ###
-A FORWARD -i wg0 -o eth0 -j ACCEPT
### End IPv6 Rules ###
```

#### Allow forwarding from interface `eth0` to `wg0` only if related or established

```
Pyre >> allow forward if-in eth0 if-out wg0 state related,established

### IPv4 Rules ###
-A FORWARD -m state --state RELATED,ESTABLISHED -i eth0 -o wg0 -j ACCEPT
### End IPv4 Rules ###

### IPv6 Rules ###
-A FORWARD -m state --state RELATED,ESTABLISHED -i eth0 -o wg0 -j ACCEPT
### End IPv6 Rules ###
```


## Deny (REJECT) / Drop (DROP) rules

### Drop any packets with the state `INVALID`

```
Pyre >> drop state invalid

### IPv4 Rules ###
-A INPUT -m state --state INVALID -j DROP
### End IPv4 Rules ###

### IPv6 Rules ###
-A INPUT -m state --state INVALID -j DROP
### End IPv6 Rules ###
```

## Syntax Reference

Starting words:

```pyre
allow    # Set the action to ACCEPT
accept   # Alias for allow
drop     # Set the action to DROP
reject   # Set the action to REJECT
```

Chain keywords:

```pyre
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

```pyre
state [state1,state2,...]    # Equivalent to `-m state --state state1,state2` 
```

Source / destination IPs and interfaces:

```pyre
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

```pyre
# Ports can be specified either individually, comma separated, and/or as a range (using `-` or `:`).
# You can optionally specify the protocol after the port(s), which can be `tcp`, `udp`, or `both`
# (protocol defaults to `tcp` if not specified)

port  [1,2-3,4,...] (proto)    # Match these destination port(s)
sport [1,2-3,4,...] (proto)    # Match these source port(s)

```
