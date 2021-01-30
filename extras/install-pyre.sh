#!/usr/bin/env bash

# Error handling function for ShellCore
_sc_fail() { >&2 echo "Failed to load or install Privex ShellCore..." && exit 1; }
# If `load.sh` isn't found in the user install / global install, then download and run the auto-installer
# from Privex's CDN.
[[ -f "${HOME}/.pv-shcore/load.sh" ]] || [[ -f "/usr/local/share/pv-shcore/load.sh" ]] || \
    { curl -fsS https://cdn.privex.io/github/shell-core/install.sh | bash >/dev/null; } || _sc_fail

# Attempt to load the local install of ShellCore first, then fallback to global install if it's not found.
[[ -d "${HOME}/.pv-shcore" ]] && source "${HOME}/.pv-shcore/load.sh" || \
    source "/usr/local/share/pv-shcore/load.sh" || _sc_fail


: ${FULL_AUTO="0"}
# 0 = don't touch global vimrc / nano  ||  1 = auto adjust vimrc/nano  ||  2 = ask before touching
: ${INSTALL_GLOBAL="2"}
# 0 = don't touch local vimrc / nano  ||  1 = auto adjust vimrc/nano  ||  2 = ask before touching
: ${INSTALL_LOCAL="2"}
(( FULL_AUTO )) && (( INSTALL_GLOBAL == 2 )) && INSTALL_GLOBAL=1
(( FULL_AUTO )) && (( INSTALL_LOCAL == 2 )) && INSTALL_LOCAL=1

# If MIN_VER isn't met - then this var controls whether or not we'll auto-install Python
# using apt(-get) / yum/dnf
: ${INSTALL_PYTHON="1"}
# This is similar to INSTALL_PYTHON, but controls the fallback installer, for partially supported
# systems (macOS (OSX), Alpine, etc.) - if set to 0 and ran on a system that's only partially supported,
# then we will NOT attempt to install Python (partially supported systems basically requires bruteforcing
#    the python package names from 'python3' to 'python39' / 'python3.9')
: ${INSTALL_PYTHON_FB="1"}
: ${DEBUG=0}
: ${QUIET=0}


export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:${PATH}"
export PATH="${HOME}/.local/bin:${PATH}"
if [ -z ${DEPS+x} ]; then
  DEPS=('privex-helpers' 'python-dotenv' 'prompt_toolkit' 'pygments' 'colorama' 'rich')
fi

: ${USE_DATACLASSES=1}
: ${MIN_VER=3070}
: ${PREF_VER=3080}

export DEBIAN_FRONTEND="noninteractive"

OS_TYPE="" _YUM_CMD="yum" _APT_CMD="apt-get" INDEX_UPDATED=0
PKG_MGR="" PKG_MGR_UPDATE="" PKG_MGR_AVAIL=""
_YUM_CONFD=0 _APT_CONFD=0

HIGHEST_VER=0

qmsg() {
    (( QUIET )) || msg "$@"
}

qerr() {
    (( QUIET )) || msgerr "$@"
}

dbg() {
    (( DEBUG )) && msgerr "$@"
}

# Configure PKG_MGR vars for a redhat based system
_pkg-rhel() {
    if (( _YUM_CONFD )); then
        return 0
    fi
    command -v dnf &>/dev/null && _YUM_CMD="dnf"
    if (( EUID != 0 )); then
        if command -v sudo &>/dev/null; then
            _APT_CMD="sudo $_YUM_CMD"
        else
            _APT_CMD="su -c '$_YUM_CMD'"
        fi
    fi
    PKG_MGR_AVAIL="$_YUM_CMD info"
    PKG_MGR="$_YUM_CMD install -y" OS_TYPE="redhat"
    _YUM_CONFD=1
}

# Configure PKG_MGR vars for a debian based system
_pkg-deb() {
    if (( _APT_CONFD )); then
        return 0
    fi
    command -v apt &>/dev/null && _APT_CMD="apt"
    if (( EUID != 0 )); then
        if command -v sudo &>/dev/null; then
            _APT_CMD="sudo $_APT_CMD"
        else
            _APT_CMD="su -c '$_APT_CMD'"
        fi
    fi
    PKG_MGR_UPDATE="$_APT_CMD update -qy" PKG_MGR_AVAIL="$_APT_CMD show"
    PKG_MGR="$_APT_CMD install --no-install-recommends -qy" OS_TYPE="debian"
    _APT_CONFD=1
}

# return 0 if a package is available (or if we don't support checking and we just have to hope it installs)
_pkg-avail() {
    if [[ -n "$PKG_MGR_AVAIL" ]]; then
        eval "$PKG_MGR_AVAIL $1" &> /dev/null
        return $?
    fi
    return 0
}

# install 1 or more packages. handles running package mgr update cmd if available
# plus checks if packages are available using _pkg-avail to avoid wasteful failures
_pkg-inst() {
    if ! (( INDEX_UPDATED )) && [[ -n "$PKG_MGR_UPDATE" ]]; then
        eval "$PKG_MGR_UPDATE"
        export INDEX_UPDATED=1
    fi
    avail_pkgs=()
    for p in "$@"; do
        if _pkg-avail "$p"; then
            avail_pkgs+=("$p")
        fi
    done
    if (( ${#avail_pkgs[@]} > 0 )); then
        eval "$PKG_MGR ${avail_pkgs[*]}"
        _ret=$?
        if (( _ret )); then
            for p in "${avail_pkgs[@]}"; do
                eval "$PKG_MGR $p"
            done
        fi
    fi
}
_pyver() {
    local _xver=0
    grep -Eqi "^python 3.4" <<< "$1" && _xver=3040
    grep -Eqi "^python 3.5" <<< "$1" && _xver=3050
    grep -Eqi "^python 3.6" <<< "$1" && _xver=3060
    grep -Eqi "^python 3.7" <<< "$1" && _xver=3070
    grep -Eqi "^python 3.8" <<< "$1" && _xver=3080
    grep -Eqi "^python 3.9" <<< "$1" && _xver=3090
    grep -Eqi "^python 3.10" <<< "$1" && _xver=3100
    echo "$_xver"
}

export -f qerr qmsg msg msgerr dbg

while (( $# > 0 )); do
    case "$1" in
        "-a"|"--auto"|"--full-auto"|auto)
            FULL_AUTO=1
            (( INSTALL_GLOBAL == 2 )) && INSTALL_GLOBAL=1
            (( INSTALL_LOCAL == 2 )) && INSTALL_LOCAL=1
            ;;
        "-g"|"--global"|global)
            INSTALL_GLOBAL=1
            ;;
        "-ng"|"--no-global"|noglobal)
            INSTALL_GLOBAL=0
            ;;
        "-l"|"--local"|local)
            INSTALL_LOCAL=1
            ;;
        "-nl"|"--no-local"|nolocal)
            INSTALL_LOCAL=0
            ;;
        "-q"|"--quiet"|quiet|"--silent"|silent)
            QUIET=1
            ;;
        "-v"|"--verbose"|"--debug"|verbose)
            DEBUG=1
            ;;
        "-np"|"--no-python"|nopython)
            INSTALL_PYTHON=0
            ;;
    esac
    shift
done

# scan python 3.10 to 3.6 plus system python3 to discover which is the highest version installed
for cmd in python3.10 python3.9 python3.8 python3.7 python3.6 python3 ; do
    if command -v "$cmd" &>/dev/null; then
        dbg " [DBG] Found interpreter $cmd - checking version"
        PVER="$("$cmd" -V)"
        IVER="$(_pyver "$PVER")"
        if (( IVER > HIGHEST_VER )); then 
            dbg " [DBG] New highest version: $IVER"
            HIGHEST_VER=$IVER
        fi
    fi
done


if [[ -f "/etc/debian_version" ]]; then
    dbg " [...] Found /etc/debian_version - must be debian based."; _pkg-deb
elif [[ -f "/etc/redhat-release" ]]; then
    dbg " [...] Found /etc/redhat-release - must be RedHat based."; _pkg-rhel
elif grep -qi "darwin" <<< "$(uname -a)"; then
    dbg " [...] Kernel is darwin! Must be macOS. Installing fontforge via brew"; PKG_MGR="brew install"
else
    if command -v apt-get &>/dev/null || command -v apt &>/dev/null; then
        dbg " [...] Found apt-get / apt package manager. Probably debian based."; _pkg-deb
    elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
        dbg " [...] Found yum or dnf package manager. Probably redhat based."; _pkg-rhel
    elif command -v apk &>/dev/null; then
        dbg " [...] Found apk package manager. Probably Alpine based."; PKG_MGR="apk add"
    elif command -v brew &>/dev/null; then
        dbg " [...] Found brew package manager. Probably macOS based."; PKG_MGR="brew install"
    else
        dbg " [!!!] COULD NOT IDENTIFY DISTRO. Cannot ensure python + dependencies installed"
    fi
fi

if (( HIGHEST_VER < MIN_VER )) && (( INSTALL_PYTHON )); then
    if [[ "$OS_TYPE" == "debian" ]]; then
        {
            qerr yellow " [...] Attempting to install highest possible Python version via APT (${PKG_MGR}) package manager"

            _pkg-inst python3 python3-dev python3-pip python3-venv 
            _pkg-inst python3.6 python3.6-dev python3.6-pip \
                      python3.7 python3.7-dev python3.7-pip \
                      python3.8 python3.8-dev python3.8-pip \
                      python3.9 python3.9-dev python3.9-pip
        } >&2 
    elif [[ "$OS_TYPE" == "redhat" ]]; then
        {
            qerr yellow " [...] Attempting to install highest possible Python version via yum '${PKG_MGR}' package manager"
            _pkg-inst epel-release
            _pkg-inst gcc
            _pkg-inst python3 python3-devel python3-pip
            _pkg-inst python36 python36-devel python36-pip \
                      python37 python37-devel python37-pip \
                      python38 python38-devel python38-pip \
                      python39 python39-devel python39-pip

        } >&2 
    else
        if [[ -z "$PKG_MGR" ]]; then
             qerr red " [!!!] COULD NOT DETECT PACKAGE MANAGER. Cannot install/update python"
        elif (( INSTALL_PYTHON_FB == 0 )); then
            qerr yellow " [!!!] INSTALL_PYTHON_FB is false. Not attempting to install python with fallback pkg mgr: $PKG_MGR \n\n"
        else
            {
                qerr yellow " [...] Package manager '${PKG_MGR}' is not properly supported by this script"
                qerr yellow " [...] However, we will try our best to install the latest Python version possible...\n"
                if [[ -n "$PKG_MGR_UPDATE" ]]; then
                    eval "$PKG_MGR_UPDATE"
                fi
                py_pkgs=(
                    python3 python3-pip python3-dev python3-devel python3-venv 
                    python3.7 python3.8 python3.9 python37 python38 python39
                )
                for p in py_pkgs; do
                    eval "$PKG_MGR $p"
                done
            } >&2
        fi
    fi
else
    qerr green " [+++] System already meets minimum python ver: MIN_VER=${MIN_VER} HIGHEST_VER=${HIGHEST_VER}\n"
fi

PYTHON_INTP="python3"

for cmd in python3.10 python3.9 python3.8 python3.7 python3.6 python3 ; do
    qerr yellow " [DBG] Checking if we have $cmd"
    if command -v "$cmd" &>/dev/null; then
        qerr green " [DBG] Found interpreter $cmd - checking python dependencies"
        INSTALLED_DEPS="$(env "$cmd" -m pip freeze)" MISSING_DEPS=0
        for d in "${DEPS[@]}"; do
            if ! grep -q "$d" <<< "$INSTALLED_DEPS"; then
                qerr red " [DBG] Missing dependency: $d"
                MISSING_DEPS=1
            fi
        done
        if (( MISSING_DEPS )); then
            qerr cyan " [DBG] Installing all dependencies: ${DEPS[*]}"
            if (( EUID != 0 )); then
                env sudo -H -- "$cmd" -m pip install -U "${DEPS[@]}" > /dev/null
            else
                env "$cmd" -m pip install -U "${DEPS[@]}" > /dev/null
            fi
        fi
        # if the python ver is < 3.7, and USE_DATACLASSES is true, then install the backported dataclasses package
        PY_VER="$($cmd -V)"
        IVER="$(_pyver "$PY_VER")"
        if (( IVER < 3070 )) && (( USE_DATACLASSES )); then
            if ! grep -q "dataclasses" <<< "$INSTALLED_DEPS"; then
                qerr red " [DBG] Missing dependency: dataclasses (< py3.7)"
                qerr cyan " [DBG] Installing dependency: dataclasses"
                if (( EUID != 0 )); then
                    env sudo -H -- "$cmd" -m pip install -U dataclasses > /dev/null
                else
                    env "$cmd" -m pip install -U dataclasses > /dev/null
                fi
            fi
        fi
        qerr bold magenta "\n\n >>> Installing Python package 'pyrewall' using interpreter: $cmd \n\n"

        if (( EUID != 0 )); then
            env sudo -H -- "$cmd" -m pip install -U pyrewall > /dev/null
        else
            env "$cmd" -m pip install -U pyrewall > /dev/null
        fi
        PYTHON_INTP="$cmd"
        break
    fi
done


: ${VIM_SYNTAX_SRC="https://raw.githubusercontent.com/Privex/pyrewall-syntax-highlighters/master/Vim/pyrewall.vim"}
: ${VIMRC_LINE="autocmd BufNewFile,BufRead *.pyre set syntax=pyrewall"}
: ${VIMRC_SCAN="set syntax=pyrewall"}
: ${NANO_SYNTAX_SRC="https://raw.githubusercontent.com/Privex/pyrewall-syntax-highlighters/master/Nano/pyre.nanorc"}

setup-vimrc() {
    local vim_file="$1" vim_syntax="$2"
    local vim_folder="$(dirname "$vim_file")"


    qerr magenta "     [...] Auto-creating '$vim_syntax' and '$vim_folder' if they don't already exist..."
    [[ ! -d "$vim_syntax" ]] && ! can_write "$(dirname "$vim_syntax")" && sudo mkdir -p "$vim_syntax"
    [[ ! -d "$vim_syntax" ]] && mkdir -p "$vim_syntax"
    [[ ! -d "$vim_folder" ]] && ! can_write "$(dirname "$vim_folder")" && sudo mkdir -p "$vim_folder"
    [[ ! -d "$vim_folder" ]] && mkdir -p "$vim_folder"
    
    cd "$vim_syntax"
    qerr magenta "     [...] Downloading syntax file into ${vim_syntax}/pyrewall.vim from $VIM_SYNTAX_SRC"
    if can_write "$vim_syntax"; then
        wget -q -O pyrewall.vim "$VIM_SYNTAX_SRC"
    else
        sudo wget -q -O pyrewall.vim "$VIM_SYNTAX_SRC"
    fi

    qerr magenta "     [...] Ensuring file $vim_file exists..."
    local has_line=0
    if ! [[ -f "$vim_file" ]]; then
        can_write "$vim_folder" && touch "$vim_file" || sudo touch "$vim_file"
    fi

    qerr magenta "     [...] Checking if '$VIMRC_SCAN' is present in $vim_file"
    if can_read "$vim_file"; then
        grep -q "$VIMRC_SCAN" "$vim_file" && has_line=1
    else
        sudo grep -q "$VIMRC_SCAN" "$vim_file" && has_line=1
    fi

    if (( has_line )); then
        qerr green "     [+++] File $vim_file already contains the syntax line. Not updating.\n"
    else
        qerr cyan "     [!!!] File $vim_file DOES NOT contain the syntax line. Adding syntax line to file: ${VIMRC_LINE}\n"
        if can_write "$vim_file"; then
            echo "$VIMRC_LINE" | tee -a "$vim_file"
        else
            echo "$VIMRC_LINE" | sudo tee -a "$vim_file"
        fi
    fi
    qerr green "     [+++] Finished downloading syntax file + adjusting vimrc file.\n"
    cd - &>/dev/null
}

qerr bold magenta "\n\n >>> Setting up Pyrewall Syntax Highlighters for VIM and Nano \n\n"

if (( INSTALL_LOCAL == 2 )); then
    echo
    yesno "${BOLD}${YELLOW}Do you want to update the local VIM / NANO folders for your user?${RESET} (Y/n) > " defyes && INSTALL_LOCAL=1 || INSTALL_LOCAL=0
fi

if (( INSTALL_LOCAL )); then
    qerr green " >>> Installing Pyrewall Syntax for local vim in ~/.vim and ~/.vimrc"
    setup-vimrc "${HOME}/.vimrc" "${HOME}/.vim/syntax"
    qerr green " >>> Installing Pyrewall Syntax for local nano in ~/.nano"
    [[ ! -d "${HOME}/.nano" ]] && mkdir -p "${HOME}/.nano"
    cd "${HOME}/.nano"
    wget -q -O pyre.nanorc "$NANO_SYNTAX_SRC"
else
    qerr yellow " !!! INSTALL_LOCAL is false. Not installing local vim / nano syntax highlighter.\n"
fi


if (( INSTALL_GLOBAL == 2 )); then
    echo
    yesno "${BOLD}${YELLOW}Do you want to update the global VIM / NANO folders?${RESET} (Y/n) > " defyes && INSTALL_GLOBAL=1 || INSTALL_GLOBAL=0
fi

if (( INSTALL_GLOBAL )); then
    qerr green " >>> Installing Pyrewall Syntax for global vim in /etc/vim"
    setup-vimrc "/etc/vim/vimrc.local" "/etc/vim/syntax"

    qerr green " >>> Installing Pyrewall Syntax for global nano in /usr/share/nano"
    [[ ! -d "/usr/share/nano" ]] && sudo mkdir -p "/usr/share/nano"
    cd /usr/share/nano
    sudo wget -q -O pyre.nanorc "$NANO_SYNTAX_SRC"
else
    qerr yellow " !!! INSTALL_GLOBAL is false. Not installing global vim / nano syntax highlighter.\n"
fi


qmsg bold green "\n\n [+++] Finished installing Pyrewall and/or Pyrewall Syntax Highlighters! :)\n\n"

