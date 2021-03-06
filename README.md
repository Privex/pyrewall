# Privex Pyrewall

[![Build Status](https://travis-ci.com/Privex/pyrewall.svg?branch=master)](https://travis-ci.com/Privex/pyrewall) 
[![Codecov](https://img.shields.io/codecov/c/github/Privex/pyrewall)](https://codecov.io/gh/Privex/pyrewall)  
[![PyPi Version](https://img.shields.io/pypi/v/pyrewall.svg)](https://pypi.org/project/pyrewall/)
![License Button](https://img.shields.io/pypi/l/pyrewall) 
![PyPI - Downloads](https://img.shields.io/pypi/dm/pyrewall)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyrewall) 
![GitHub last commit](https://img.shields.io/github/last-commit/Privex/pyrewall)

An iptables firewall management system in Python.

![Screenshot of REPL](https://cdn.privex.io/github/pyrewall/pyrewall_repl.png)

![Screenshot of Syntax Highlighting for Nano and Vim](https://cdn.discordapp.com/attachments/612057164038799362/721434730267934792/unknown.png)

WARNING: Still under construction

```
+===================================================+
|                 © 2019 Privex Inc.                |
|               https://www.privex.io               |
+===================================================+
|                                                   |
|        PyreWall - Python iptables firewall tool   |
|        License: X11/MIT                           |
|                                                   |
|        Core Developer(s):                         |
|                                                   |
|          (+)  Chris (@someguy123) [Privex]        |
|                                                   |
+===================================================+

PyreWall - A Python tool / service for managing iptables firewalls with ease
Copyright (c) 2021    Privex Inc. ( https://www.privex.io )

```

## Quickstart Install

To make installation of both Pyrewall, and [Pyrewall Syntax Highlighters](https://github.com/Privex/pyrewall-syntax-highlighters)
extremely easy, we have a shellscript that will do the following:

- Ensures you have Python 3.7 or newer. If you don't have any Python versions installed which are >= 3.7, then the script will attempt to automatically install the latest available version from your package manager (supported: `apt` / `apt-get`, `yum` / `dnf`, `apk` (alpine), and `brew` (macOS))
- Installs Pyrewall using `pip` from the latest version of Python that you have installed (after the script has ensure you have at least 3.7). If you aren't running the script as root, it will attempt to use `sudo -H` to install the package as root, so that the `pyre` binary can be installed globally into /usr/local/bin
- Installs the Vim and Nano [Pyrewall Syntax Highlighters](https://github.com/Privex/pyrewall-syntax-highlighters) for `.pyre` files within your current user's configurations in ~/.vim and ~/.nano
- Installs the Vim and Nano [Pyrewall Syntax Highlighters](https://github.com/Privex/pyrewall-syntax-highlighters) for `.pyre` files globally within /etc/vim and /usr/share/nano

The quick install shellscript is served by [Privex CDN](https://cdn.privex.io) to allow for a relatively short URL,
but the original code is kept in this repo at [extras/install-pyre.sh](https://github.com/Privex/pyrewall/blob/master/extras/install-pyre.sh)

### Fully automated install

If you just want to install Pyrewall, instead of reading - just run this one-liner to install Pyrewall, along with
[Pyrewall Syntax Highlighters](https://github.com/Privex/pyrewall-syntax-highlighters) (locally and globally).

```sh
FULL_AUTO=1 curl -fsS https://cdn.privex.io/github/pyrewall/install.sh | bash
```

### Command line arguments for quick installer

If you download the quick installer script before executing it, you can specify various command line arguments,
allowing you to enable and disable different install stages, automate the install, as well as quiet mode / verbose mode.

This can also be done via environment variables if you want one-liners. Env vars are covered in the next section.

```sh
wget -O pyre.sh https://cdn.privex.io/github/pyrewall/install.sh
chmod +x pyre.sh
# Without CLI args, it will auto-install newer python versions if needed, but will prompt you
# with yes/no before installing local syntax highlighters and before global highlighters.
./pyre.sh

# Install Pyrewall in fully automated mode. It will assume yes to the local/global syntax
# highlighter prompts.
# Equivalent to: ./pyre.sh -g -l
./pyre.sh -a
./pyre.sh --auto   # short version - same as previous command

# Install Pyrewall - assume YES to installing syntax highlighters locally, but NO
# to global installation
./pyre.sh --local --no-global
./pyre.sh -l -ng   # short version - does the same as previous command

# Install Pyrewall, but don't try to auto-install any Python interpreters
./pyre.sh --no-python
./pyre.sh -np      # short version - does the same as previous command

# Quiet mode - only important messages are printed (and generally to stderr)
./pyre.sh --quiet
./pyre.sh -q

# Verbose mode - sets DEBUG=1 to enable verbose debugging output
./pyre.sh --verbose
./pyre.sh -v
```

### One-liners using ENV vars

If you don't want to have to save the file, make it executable, etc. - you can also pipe the script into bash,
however, due to the use of prompts, it's important to set either `FULL_AUTO=1` or the separate `INSTALL_LOCAL`/`INSTALL_GLOBAL` env vars, to disable the prompts, since the prompts may cause issues when piping.

```sh
# Standard auto-install. Assume YES to local and global syntax highlighters
INSTALL_LOCAL=1 INSTALL_GLOBAL=1 curl -fsS https://cdn.privex.io/github/pyrewall/install.sh | bash
# Same as previous command, just shorter
FULL_AUTO=1 curl -fsS https://cdn.privex.io/github/pyrewall/install.sh | bash

# Only install syntax highlighters locally, and DO NOT auto-install any Python interpreters
INSTALL_PYTHON=0 INSTALL_GLOBAL=0 INSTALL_LOCAL=1 curl -fsS https://cdn.privex.io/github/pyrewall/install.sh | bash

# Quiet mode + install global and local syntax highlighters
FULL_AUTO=1 QUIET=1 curl -fsS https://cdn.privex.io/github/pyrewall/install.sh | bash

# If something seems to be broken, you can set DEBUG=1 to enable debugging output,
# which will show more verbose messages to help you see what it's doing at each step.
FULL_AUTO=1 DEBUG=1 curl -fsS https://cdn.privex.io/github/pyrewall/install.sh | bash
```

## Install

Pyrewall can easily be installed from PyPi, using the standard `pip3` package manager.

```sh
# Install/Upgrade Pyrewall using pip3 as root
sudo -H pip3 install -U pyrewall
```

It's recommended that you create `/etc/pyrewall` along with a "master rules file" `rules.pyre`.

```sh
sudo mkdir /etc/pyrewall
sudo touch /etc/pyrewall/rules.pyre
```

NOTE: If you don't like the name `rules.pyre`, your master rules file can be named any of the following 
(these names are tried in order):

- rules.pyre
- main.pyre
- master.pyre
- base.pyre
- firewall.pyre

Be warned: if you have both `rules.pyre` and `firewall.pyre` for example, `rules.pyre` will take precedence,
and `firewall.pyre` will not be used unless you manually specify it when calling `pyre`.

If you want Pyrewall to automatically load your firewall rules on boot, there's a systemd service file included,
with an automated install command built into `pyre`

```sh
sudo pyre install_service
```

## Usage

Once you've installed Pyrewall, including the service, you can begin adding Pyre rules to `/etc/pyrewall/rules.pyre`
(or an alternative master filename you decided on).

To load the rules from the master file, you can simply run `pyre load`. Unless you specify `-n`, it uses a "dead mans switch"
confirmation prompt after the rules are loaded, asking you to confirm that you can still access the server and haven't
locked yourself out.

```sh
pyre load
```

If you don't respond within 15 seconds (can be adjusted with `--timeout`), Pyrewall will restore the
IPv4 + IPv6 rules you had before running `pyre load` 

You can also load rules from individual files (they will replace your existing rules):

```sh
pyre load somefile.pyre
```

If you don't want Pyrewall to apply the rules for you, you can use the `parse` command to parse a Pyre file and output
IPv4 / IPv6 iptables rules for you to apply manually with `iptables-restore` / `ip6tables-restore`, or with an auto-load
system such as `netfilter-persistent`:

```sh
pyre parse --output4 /etc/iptables/rules.v4 --output6 /etc/iptables/rules.v6 my_rules.pyre
# Alternatively, you can use UNIX stdin and stdout for reading in Pyre files, and outputting the generated iptables
# rules through pipes and redirects.
pyre parse -i 4 my_rules.pyre > rules.v4
pyre parse -i 6 my_rules.pyre > rules.v6

cat my_rules.pyre | pyre parse -i 4 | sudo tee /etc/iptables/rules.v4
```

## Syntax Highlighting

![Screenshot of Syntax Highlighting for Nano and Vim](https://cdn.discordapp.com/attachments/612057164038799362/721434730267934792/unknown.png)

Above is a screenshot of Pyre syntax sighlighting for Nano and Vim using our official highlighters from [Privex/pyrewall-syntax-highlighters](https://github.com/Privex/pyrewall-syntax-highlighters) - which were originally designed by @toasterrepairman

Syntax highlighting for `.pyre` files is currently available for the following editors:

- Vim
- Nano
- Visual Studio Code (VSCode)

The highlighters are available in a separate repo: [Privex/pyrewall-syntax-highlighters](https://github.com/Privex/pyrewall-syntax-highlighters)

## Basic Pyre File

Below is an example **Pyre rules file**, showing both common rules syntax, as well as special interpreter
features such as `@chain`, `@table` and `@import`

```pyre
# This line isn't needed, it's just here to show the syntax. The default table is 'filter' anyway.
@table filter
# By default, INPUT, FORWARD, and OUTPUT are set to ACCEPT, just like standard iptables.
# Using @chain we can change them to DROP or REJECT.
@chain INPUT DROP
@chain FORWARD DROP

# We recommend using the included 'sane.pyre' template, which handles things you'd usually copy/paste, such as
# allowing related/established connections, accepting ICMPv4 and certain ICMPv6 types, allowing loopback 
# (localhost) traffic etc.
@import templates/sane.pyre

# You can specify multiple chains on one line, and also mix/match IPv4 and IPv6 addresses + subnets.
allow chain input,forward state new from 1.2.3.4,2a07:e02:123::/64

# This is equivalent to 3 ACCEPT rules (INPUT,FORWARD,OUTPUT) for each of the below subnets.
# You can put the IPs on the same line, comma separated, or put them on a separate line if you prefer.
allow all from 185.130.44.0/27
allow all from 2a07:e00::/32

# This allows port 80, 443, and 8000 to 9000 incoming - for both TCP and UDP.
allow port 80,443,8000-9000

# You can import additional .pyre files, along with standard iptables .v4 and .v6 files
# They'll be searched for within (in order):
# (current_work_dir)    /etc/pyrewall         /usr/local/etc/pyrewall     ~/.pyrewall
# (root_of_project)     (root_of_package)
@import example/other.pyre

# Reject INPUT, FORWARD and OUTPUT from this IPv4 address
reject from 12.34.56.78

rem By using 'rem', we can also write comments that will be converted into standard '#' comments
rem when the Pyre file is exported to ip(6)tables-save format.
drop forward from 3.4.5.6,2001:def::/64

# Allow port 9090 + 1010 via TCP and UDP from the specified IPv4 and IPv6 address
allow port 9090,1010 both from 10.0.0.1,2a07:e01::/32

# This is equivalent to:
# -A INPUT -p tcp -m multiport --dports 99,88 -m multiport --sports 10,20 -j ACCEPT
allow port 99,88 sport 10,20

# Allow UDP traffic where the source port is between 1000 and 2000
allow sport 1000-2000 udp
```

## Using the REPL

![Animated GIF showing REPL demo](https://cdn.privex.io/github/pyrewall/pyrewall_repl_demo.gif)

(NOTE: The animated GIF demo above is ~110MB and may take a while to load depending on your internet.
You can alternatively view the original speed, full quality 
demo [on our YouTube video](https://www.youtube.com/watch?v=qDOpfNTV6d4&feature=youtu.be))

**Pyrewall** comes with a REPL (Read Eval Print Loop), which is an interactive prompt for experimenting
with the **Pyre language**. It features arrow key support (you can press up/down to access history, and the
tab completions), tab completion with syntax suggestion, and live syntax highlighting as you type.

This is similar to the interactive interpreters of programming languages such as Python (`python3 -i`) and PHP (`php -i`).

Once you've got Pyrewall installed, just type `pyre repl` and you'll be dropped into the REPL.

```sh
pyre repl
```

You can type `\?` or `help` to display help for both using the REPL's features, and some example lines of Pyre that you can try.

You can also load the REPL with a `.pyre` file, allowing you to print the file with syntax highlighting, append new lines to it,
and compile it into IPv4 / IPv6 iptables rules:

```sh
# Load the REPL with the included templates/sane.pyre pre-loaded into the REPL history
pyre repl templates/sane.pyre
```

To print the rules entered during current session (including ones loaded if you specified files on the CLI):

```pyre
# Show the Pyre rules entered during this session, with syntax highlighting
\show
# Compile the IPv4 Pyre rules into IPv4 iptables format and print them
\show ip4
# Compile the IPv6 Pyre rules into IPv6 iptables format and print them
\show ip6
# Print both IPv4 + IPv6 iptables rules
\show both
# Print Pyre rules, as well as IPv4 + IPv6 rules
\show all
```

To output the rules from your REPL session into a file:

```pyre
# Output the Pyre rules into a Pyre file
\output pyre my_rules.pyre

# Convert the Pyre rules into IPv4 iptables format and output them into a file for use with iptables-restore
\output ip4 ipt_rules.v4

# Convert the Pyre rules into IPv6 iptables format and output them into a file for use with ip6tables-restore
\output ip6 ipt_rules.v6
```
