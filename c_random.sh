#! /bin/sh 

# this program collects some entropy from the system
# into the file "my_random_file" and outputs the 16-bit
# Unix 'sum' checksum (seems to be the only portable way
# to get true entropy with a shell script).

# Apparently, on FreeBSD /dev/random does not block (???), must make sure
# we really got something rather than nothing.

rnd_tst=no

/bin/rm -f ./my_random_file  2>/dev/null

if test -r "/dev/urandom"; then
  if test -c "/dev/urandom"; then
    dd if=/dev/urandom ibs=1 count=4 > my_random_file 2>/dev/null
    nsum=`sum ./my_random_file | awk '{print $1 }' | sed 's%^0*%%g' 2>/dev/null`
    if test x$nsum != x; then
      rnd_tst=yes
    fi
  fi
fi

if test x$rnd_tst = xno; then
    if test -r "/dev/srandom"; then
      if test -c "/dev/srandom"; then
        dd if=/dev/srandom ibs=1 count=4 > my_random_file 2>/dev/null
        nsum=`sum ./my_random_file | awk '{print $1 }' | sed 's%^0*%%g' 2>/dev/null`
       if test x$nsum != x; then
          rnd_tst=yes
       fi
      fi
    fi
fi

if test x$rnd_tst = xno; then
#
    touch ./my_random_file
#
    if test -r "/usr/ucb/vmstat"; then
	/usr/ucb/vmstat >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/vmstat"; then
	/bin/vmstat >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/vmstat"; then
	/sbin/vmstat >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/vmstat"; then
	/usr/bin/vmstat >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/vmstat"; then
	/usr/sbin/vmstat >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/vmstat"; then
	/usr/local/bin/vmstat >> my_random_file 2>/dev/null
    fi
#
    if test -r "/usr/ucb/netstat"; then
	/usr/ucb/netstat -n >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/netstat"; then
	/bin/netstat  -n >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/netstat"; then
	/sbin/netstat  -n >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/netstat"; then
	/usr/bin/netstat  -n >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/netstat"; then
	/usr/sbin/netstat  -n >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/netstat"; then
	/usr/local/bin/netstat  -n >> my_random_file 2>/dev/null
    fi
#
#
    if test -r "/usr/ucb/ps"; then
	/usr/ucb/ps -ef >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/ps"; then
	/bin/ps  -ef >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/ps"; then
	/sbin/ps  -ef >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/ps"; then
	/usr/bin/ps  -ef >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/ps"; then
	/usr/sbin/ps  -ef >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/ps"; then
	/usr/local/bin/ps  -ef >> my_random_file 2>/dev/null
    fi
#
#
    if test -r "/usr/ucb/arp"; then
	/usr/ucb/arp -a >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/arp"; then
	/bin/arp  -a >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/arp"; then
	/sbin/arp  -a >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/arp"; then
	/usr/bin/arp  -a >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/arp"; then
	/usr/sbin/arp  -a >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/arp"; then
	/usr/local/bin/arp  -a >> my_random_file 2>/dev/null
    fi
#
#
    if test -r "/usr/ucb/w"; then
	/usr/ucb/w  >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/w"; then
	/bin/w   >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/w"; then
	/sbin/w   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/w"; then
	/usr/bin/w   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/w"; then
	/usr/sbin/w   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/w"; then
	/usr/local/bin/w   >> my_random_file 2>/dev/null
    fi
#
#   Don't use (NFS problems ahead)
#
#    if test -r "/usr/ucb/df"; then
#	/usr/ucb/df  >> my_random_file 2>/dev/null
#    fi
#    if test -r "/bin/df"; then
#	/bin/df  >> my_random_file 2>/dev/null
#    fi
#    if test -r "/sbin/df"; then
#	/sbin/df  >> my_random_file 2>/dev/null
#    fi
#    if test -r "/usr/bin/df"; then
#	/usr/bin/df  >> my_random_file 2>/dev/null
#    fi
#    if test -r "/usr/sbin/df"; then
#	/usr/sbin/df  >> my_random_file 2>/dev/null
#    fi
#    if test -r "/usr/local/bin/df"; then
#	/usr/local/bin/df  >> my_random_file 2>/dev/null
#    fi
#
#
    if test -r "/usr/ucb/free"; then
	/usr/ucb/free  >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/free"; then
	/bin/free   >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/free"; then
	/sbin/free   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/free"; then
	/usr/bin/free   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/free"; then
	/usr/sbin/free   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/free"; then
	/usr/local/bin/free   >> my_random_file 2>/dev/null
    fi
#
#
    if test -r "/usr/ucb/uptime"; then
	/usr/ucb/uptime  >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/uptime"; then
	/bin/uptime   >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/uptime"; then
	/sbin/uptime   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/uptime"; then
	/usr/bin/uptime   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/uptime"; then
	/usr/sbin/uptime   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/uptime"; then
	/usr/local/bin/uptime   >> my_random_file 2>/dev/null
    fi
#
#
    if test -r "/usr/ucb/procinfo"; then
	/usr/ucb/procinfo -a >> my_random_file 2>/dev/null
    fi
    if test -r "/bin/procinfo"; then
	/bin/procinfo  -a  >> my_random_file 2>/dev/null
    fi
    if test -r "/sbin/procinfo"; then
	/sbin/procinfo  -a  >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/bin/procinfo"; then
	/usr/bin/procinfo -a   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/sbin/procinfo"; then
	/usr/sbin/procinfo -a   >> my_random_file 2>/dev/null
    fi
    if test -r "/usr/local/bin/procinfo"; then
	/usr/local/bin/procinfo  -a  >> my_random_file 2>/dev/null
    fi
#
    nsum=`sum ./my_random_file | awk '{print $1 }' | sed 's%^0*%%g' 2>/dev/null`
#
fi

#
# 'sum' is portable, but only 16 bit
#

/bin/rm -f ./my_random_file 2>/dev/null

echo $nsum


