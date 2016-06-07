#! /bin/sh
# Please have a TMP or TMPDIR environment variable if you don't trust /tmp,
# or don't run this as root.
#
# -- partly taken from PureFTPd
#

VERSION=1.6.4


# exits with a custom error message
bail_error () {
    echo
    echo $1
    echo
    exit 1
}

get_config() {
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --$z"
    done
}

get_error() {
    ge_rval=0
    if  cat $tmp 2>&1 | grep Error > /dev/null ; then
	ge_rval=1
    fi
    return ${ge_rval}
}

 

#------------------------------------------------------------
#
#  Find a 'dialog' program
#
#------------------------------------------------------------
PATH=/usr/local/bin:/usr/local/sbin:$PATH; export PATH

WELCOME=`cat <<EOF
Welcome to the SAMHAIN configuration tool

This script is meant to make installing SAMHAIN as easy as
possible.  Just read the text below, hit ENTER, and you are
on your way. 

SAMHAIN ships with NO WARRANTY whatsoever, without
even the implied warranty of merchantability or fitness 
for a particular purpose. The author takes no responsibility
for the consequences of running this script.

Please send any questions to support@la-samhna.com.
EOF`

if [ -z "$dialog" ] ; then
  if [ -n "$DISPLAY" ] ; then
    Xdialog --msgbox "$WELCOME" 20 75 2> /dev/null && dialog='Xdialog'
        gauge='--gauge'
  fi
fi
if [ -z "$dialog" ] ; then
  dialog --msgbox "$WELCOME" 20 75 2> /dev/null && dialog='dialog'

# Workaround for old versions of 'dialog' (Slackware)

  if "$dialog" 2>&1 | grep gauge > /dev/null ; then
    gauge='--gauge'
  elif "$dialog" 2>&1 | grep guage > /dev/null ; then
    gauge='--guage'
  else
    gauge=''
  fi
fi
if [ -z "$dialog" ] ; then
  lxdialog --msgbox "$WELCOME" 20 75 2> /dev/null && dialog='lxdialog'
fi
if [ -z "$dialog" ] ; then
  /usr/src/linux/scripts/lxdialog/lxdialog --msgbox "$WELCOME" 20 75 2> /dev/null && dialog='/usr/src/linux/scripts/lxdialog/lxdialog'
fi

if [ -z "$dialog" ] ; then
  bail_error "No \"dialog\" found, GUI installation impossible"
fi

#------------------------------------------------------------
#
#  Find a writable temporary directory
#
#------------------------------------------------------------
tempdir=''
for tmpdir in "$TMP" "$TMPDIR" /tmp /var/tmp; do
  if [ -z "$tempdir" ] && [ -d "$tmpdir" ] && [ -w "$tmpdir" ]; then
    tempdir="$tmpdir"
  fi
done
if [ -z "$tempdir" ]; then
  bail_error "Unable to find a suitable temporary directory"
fi

# Create a temporary file
tmp=`mktemp $tempdir/build.gui.XXXXXX`
if [ $? -ne 0 ]; then
  bail_error "Cannot create temp file, exiting..."
fi

trap "rm -f $tmp; exit 1" EXIT SIGHUP SIGINT SIGQUIT SIGSEGV SIGTERM

#------------------------------------------------------------
#
#  Build config line
#
#------------------------------------------------------------
cfgline='';

$dialog \
--title "Compile-time options" \
--backtitle "Samhain $VERSION" \
--radiolist "Samhain can run as standalone application on a single dektop machine, or as a client/server application for centralized monitoring of many hosts" \
10 75 3 \
"disable-network"          "Single desktop machine" on \
"enable-network=client"    "Network (client)" off \
"enable-network=server"    "Network (server)" off \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    get_config
else
    get_error || bail_error "Your \"dialog\" does not support --radiolist, GUI installation impossible"
    cfgline="--disable-network"
fi

cfgtest=`echo $cfgline | grep disable`


#------------------------------------------------------------
#
#  Server options
#
#------------------------------------------------------------
if [ -z $cfgtest ]; then

INET=yes
HTML="\n /usr/local/var/samhain/samhain.html"

$dialog \
--backtitle "Samhain $VERSION" \
--msgbox "You have chosen to build SAMHAIN as a client/server application.\n\nThis requires some additional configuration.\nPlease read the manual if you are not sure\nwhich options are useful or neccessary for you." 10 75 

if [ $? = -1 ]; then
    exit 1
fi


$dialog \
--title 'Network options' \
--separate-output \
--backtitle "Samhain $VERSION" \
--checklist 'Use SPACE to set/unset. If in doubt, read the manual.' \
20 75 10 \
'enable-udp' "Server listens also on 514/udp" off \
'disable-encrypt' "Disable client/server encryption" off \
'disable-srp' "Disable SRP client/server authentication" off \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    get_config
fi

$dialog \
--title 'Network options' \
--backtitle "Samhain $VERSION" \
--inputbox "Server port" 10 75 "49777" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi

if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-port=$z"
    done
fi


$dialog \
--title 'Network options' \
--backtitle "Samhain $VERSION" \
--inputbox "Server address" 10 75 "127.0.0.1" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-logserver=$z"
    done
fi

$dialog \
--title "Network options" \
--backtitle 'Samhain $VERSION' \
--inputbox "Backup server address" 10 75 "none" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	if [ "x$z" != "xnone" ]; then 
	    cfgline="$cfgline --with-altlogserver=$z"
	fi
    done
fi

# if [ -z $cfgtest ]; then
fi

os=`uname -s`
if [ x"$os" = xLinux ]
then
    PROC=`uname -m`
    if [ x"$PROC" = xi686 ] ; then
       I386_LINUX=yes
    fi
    if [ x"$PROC" = xi586 ] ; then 
       I386_LINUX=yes
    fi
    if [ x"$PROC" = xi486 ] ; then
       I386_LINUX=yes
    fi
    if [ x"$PROC" = xi386 ] ; then
       I386_LINUX=yes
    fi
fi

$dialog \
--title 'General options' \
--separate-output \
--backtitle "Samhain $VERSION" \
--checklist 'Use SPACE to set/unset. If in doubt, read the MANUAL.' \
20 75 10 \
'enable-static' "Don't link with shared libraries" on \
'enable-suidcheck' "Check for suid/sgid files" on \
'enable-login-watch' "Watch for login/logout events" off \
'enable-ptrace' "Enable anti-debugger code" off \
'enable-db-reload' "Reload database on SIGHUP" off \
'enable-xml-log' "Write log in XML format" off \
'disable-mail' "Compile without built-in mailer" off \
'disable-external-scripts' "Disable use of external scripts" off \
'enable-debug' "Compile in debugging code" off \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    get_config
fi


#------------------------------------------------------------
#
#  Signature options
#
#------------------------------------------------------------
$dialog \
--title "Signed database and configuration" \
--backtitle "Samhain $VERSION" \
--yesno "Samhain can be configured to support PGP signed database\nand configuration files. This requires a working installation\nof GnuPG.\n\nDo you want to use this option ?" \
10 75 \
2> $tmp

mtest=$?

if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
  

$dialog \
--title "Signed database and configuration" \
--backtitle "Samhain $VERSION" \
--inputbox "Please enter the full path to gpg (i.e. the GnuPG binary)" \
10 75 "/usr/bin/gpg" \
2> $tmp

mtest=$?

if [ $mtest = -1 ] 
then
    exit 1
fi
if [ $mtest = 0 ]
then

mfile=`cat $tmp`
for z in $mfile ; do
	cfgline="$cfgline --with-gpg=$z"
done

$dialog \
--title "Signed database and configuration" \
--backtitle "Samhain $VERSION" \
--inputbox "Please enter the fingerprint of the key to use (one string, no spaces)" \
10 75 "6BD9050FD8FC941B43412DCC68B7AB8957548DCD" \
2> $tmp

mtest=$?

if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    z=`cat $tmp`
    cfgline="$cfgline --with-fp=$z"
fi
  

fi  
# want signed
fi

#------------------------------------------------------------
#
#  Stealth options
#
#------------------------------------------------------------
$dialog \
--title "Stealth options" \
--backtitle "Samhain $VERSION" \
--yesno "Samhain has some stealth options to hide its presence.\nDo you want to take advantage of these ?" \
10 75 \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then

$dialog \
--title "Stealth options" \
--backtitle "Samhain $VERSION" \
--radiolist "Full stealth mode will hide ascii strings within the binary, and use a config file that is hidden by steganography within an image file. Micro stealth is just strings hiding, without the stego config file." \
20 75 4 \
'full' "Enable full stealth mode" off \
'micro' "Enable micro stealth mode" on \
'none'  "None of both" off \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	mtest=$z
    done
else
    mtest="none"
fi

if [ "x$mtest" != "xnone" ]; then

if [ "x$mtest" = "xfull" ]; then
    FULL_STEALTH="yes"
fi

$dialog \
--title 'Stealth options' \
--backtitle "Samhain $VERSION" \
--inputbox "Please select a number between 128 and 255. This number will be used to obfuscate strings within the binary by xoring them." 10 75 "137" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	mnum=$z
    done
else
    mnum="137"
fi

if [ "x$FULL_STEALTH" = "xyes" ]; then
    cfgline="$cfgline --enable-stealth=$mnum"
else
    cfgline="$cfgline --enable-micro-stealth=$mnum"
fi

# if [ "x$mtest" != "xnone" ]; then
fi


$dialog \
--title 'Stealth options' \
--backtitle "Samhain $VERSION" \
--inputbox "Please choose a new name to replace \"samhain\" upon installation" \
10 75 "samhain" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --enable-install-name=$z"
    done
fi

$dialog \
--title "Stealth options" \
--backtitle "Samhain $VERSION" \
--inputbox "You can set a magic string such that command line arguments will be ignored unless the first argument is this magic string, and read from stdin otherwise. If you do not want this, select CANCEL, otherwise choose a string and select OK." \
10 75 "foo" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --enable-nocl=$z"
    done
fi

if [ "x$I386_LINUX" = "xyes" ]; then
$dialog \
--title "Stealth options" \
--backtitle "Samhain $VERSION" \
--yesno "SAMHAIN can compile and install a kernel module to hide the SAMHAIN daemon process. Do you want that ?"\
2> $tmp

mtest=$?

if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    cfgline="$cfgline --enable-khide"
fi

# f [ "x$I386_LINUX" = "xyes" ]; then
fi

# want stealth
fi

#------------------------------------------------------------
#
#  Paths to configure
#
#------------------------------------------------------------
$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--radiolist "Do you wish to change the default paths ?\n\nThe default paths are:\n\n /usr/local/sbin all binaries\n /etc/samhainrc configuration file\n /var/lib/samhain/samhain_file data file\n /var/log/samhain_log log file\n /var/run/samhain.pid pid file $HTML" 20 76 5 \
'usr'    "Install binaries in /usr/sbin" off \
'opt'    "Use /opt/samhain, /etc/opt, /var/opt" off \
'all'    "Set paths individually" off \
'cancel' "Don't change the paths" on \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
#
# edit paths
#
mfile=`cat $tmp`
for z in $mfile ; do
    if [ "x$z" = "xopt" ]; then
	    cfgline="$cfgline --prefix=OPT"
    fi
    if [ "x$z" = "xusr" ]; then
	    cfgline="$cfgline --prefix=USR"
    fi
    if [ "x$z" = "xall" ]; then
$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Exec prefix" 10 75 "/usr/local" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --exec-prefix=$z"
    done
fi


$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Configuration" 10 75 "/etc/samhainrc" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-config-file=$z"
    done
fi

$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Man pages" 10 75 "/usr/local/share/man" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-mandir=$z"
    done
fi

$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Database" 10 75 "/var/lib/samhain/samhain_data" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-data-file=$z"
    done
fi

$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Log file" 10 75 "/var/log/samhain_log" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-log-file=$z"
    done
fi

$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Lock file" 10 75 "/var/run/samhain.pid" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-pid-file=$z"
    done
fi

if [ "x$INET" = "xyes" ]; then
$dialog \
--title 'Paths' \
--backtitle "Samhain $VERSION" \
--inputbox "Server status" 10 75 "/var/lib/samhain/samhain.html" \
2> $tmp

mtest=$?
if [ $mtest = -1 ]; then
    exit 1
fi
if [ $mtest = 0 ]; then
    mfile=`cat $tmp`
    for z in $mfile ; do
	cfgline="$cfgline --with-html-file=$z"
    done
fi
# if [ "x$INET" = "xyes" ]; then
fi

   fi

done
# edit paths
fi


if [ ! -f "configure" ] ; then
    bail_error "Setup problem... try to install manually"
fi

echo "./configure $cfgline" > Install.log 2>/dev/null

if [ $? != 0 ]; then
    $dialog --infobox "ERROR writing to \"Install.log\".\n\nAborting." 10 55
    exit 1
fi



if [ "x$KCHECK" = "xyes" ]; then
    if [ `id -u` != 0 ]; then
$dialog --msgbox "Compiling with --with-kcheck option (kernel rootkit detection). This\nrequires root privileges for at least one command during compilation,\nbut you are not running this as root. Please expect compilation to fail.\n\nYou need to follow the instructions shown in the \nerror message after failure." 20 75
    fi
fi


if [ -n "$gauge" ] ; then
(
  sfail=0
  echo 20
  rm -f config.cache 2> /dev/null
  echo 30
  if [ -z "$cfgline2" ]; then
    ./configure $cfgline >> Install.log 2>&1
  else
    ./configure $cfgline --with-checksum="$cfgline2" >> Install.log 2>&1
  fi
  cfail=$?
  echo 50
  if [ $cfail = 0 ]; then
    make clean >> Install.log 2>&1
    cfail=$?
  else
    sfail=1
  fi
  echo 60
  if [ $cfail = 0 ]; then
    make >> Install.log 2>&1
    cfail=$?
  else
    sfail=1
  fi
  echo 80
  if [ $cfail = 0 ]; then
    make install >> Install.log 2>&1
    cfail=$?
  else
    sfail=1
  fi
  echo 100
  echo cfail=$cfail > $tmp
  echo sfail=$sfail >> $tmp
) | $dialog \
--title 'Compilation and installation' \
--backtitle "Samhain $VERSION" \
"$gauge" 'Please wait...' 10 75 10
else
  sfail=0
  rm -f config.cache 2> /dev/null
  $dialog --infobox "Running configure ..." 4 44
  if [ -z "$cfgline2" ]; then
    ./configure $cfgline >> Install.log 2>&1
  else
    ./configure $cfgline --with-checksum="$cfgline2" >> Install.log 2>&1
  fi
  cfail=$?
  if [ $cfail = 0 ]; then
    $dialog --infobox "Running make clean ..." 4 44
    make clean >> Install.log 2>&1
    cfail=$?
  else
    sfail=1
  fi
  if [ $cfail = 0 ]; then
    $dialog --infobox "Running make ..." 4 44
    make >> Install.log 2>&1
    cfail=$?
  else
    sfail=1
  fi
  if [ $cfail = 0 ]; then
    $dialog --infobox "Running make install ..." 4 44
    make install >> Install.log 2>&1
    cfail=$?
  else
    sfail=1
  fi
  echo cfail=$cfail > $tmp
  echo sfail=$sfail >> $tmp
fi

. $tmp


echo "SAMHAIN is now installed on your system." > $tmp
echo "Please read the documentation to know how to run it." >> $tmp 


if [ "x$sfail" = "x0" ] ; then

    if [ "x$cfail" = "x0" ] ; then
        if [ "x${FULL_STEALTH}" = "xyes" ]; then
	    tail -21 Install.log >> $tmp
	else
	    tail -11 Install.log >> $tmp
	fi
	$dialog --title "Build report (use arrow keys to scroll the text box)" \
--backtitle "Samhain $VERSION installed. PLEASE READ THE MANUAL." \
--textbox \
$tmp \
20 75
    else
	$dialog --title "Problem report" \
--backtitle "Samhain $VERSION: Build failed (see Install.log):" \
--msgbox \
"Compilation was successful, but you need to be root in\norder to install the files to the selected prefix.\nPlease run 'make install' as root." \
10 75
    fi

else

    MSG=`tail -10 Install.log`
    $dialog --title "Problem report" \
--backtitle "Samhain $VERSION: Build failed (see Install.log):" \
--msgbox "$MSG" 20 75

fi

rm -f $tmp

exit 0






