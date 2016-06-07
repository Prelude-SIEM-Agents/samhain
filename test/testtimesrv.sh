#! /bin/sh

#
# Copyright Rainer Wichmann (2006)
#
# License Information:
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

RCFILE="$PW_DIR/testrc_1.dyn";  export RCFILE
LOGFILE="$PW_DIR/.samhain_log"; export LOGFILE
PIDFILE="$PW_DIR/.samhain_lock"; export PIDFILE

BASE="${PW_DIR}/testrun_testdata"; export BASE
TDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c"; export TDIRS
TFILES="x y z"; export TFILES

prep_testdata ()
{
    if test -d "$BASE"; then
	chmod -f -R 0700 "${BASE}" || {
	    [ -z "$quiet" ] &&   log_msg_fail "chmod -f -R 0700 ${BASE}"; 
	    return 1;
	}
    fi

    rm -rf "${BASE}" || {
	[ -z "$quiet" ] &&   log_msg_fail "rm -rf ${BASE}"; 
	return 1;
    }

    mkdir "${BASE}" || {
	[ -z "$quiet" ] &&   log_msg_fail "mkdir ${BASE}"; 
	return 1;
    }

    for ff in $TDIRS; do
	mkdir "${BASE}/${ff}" || { 
	    [ -z "$quiet" ] &&   log_msg_fail "mkdir ${BASE}/${ff}"; 
	    return 1;
	}
	chmod 0755 "${BASE}/${ff}"
	for gg in $TFILES; do
	    echo "This is a test file" > "${BASE}/${ff}/${gg}"
	    chmod 0644 "${BASE}/${ff}/${gg}"
	done
    done
}

mkconfig_misc ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    cat >> "${RCFILE}" <<End-of-data
[Misc]
Daemon=no
SetFilecheckTime=60
TrustedUser=uucp,fax,fnet
SetRecursionLevel=10
SetLoopTime=30
ReportFullDetail = no
ChecksumTest=check

End-of-data
}

mkconfig_log ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    cat >> "${RCFILE}" <<End-of-data
[Log]
MailSeverity=none
LogSeverity=warn
SyslogSeverity=none
PrintSeverity=info
MailSeverity=none
#Restrict to certain classes of messages
#LogClass=RUN
#PreludeSeverity=err
#ExportSeverity=none

End-of-data
}

mkconfig_sev ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    cat >> "${RCFILE}" <<End-of-data
[EventSeverity]
SeverityUser0=crit
SeverityUser1=crit
SeverityReadOnly=crit
SeverityLogFiles=crit
SeverityGrowingLogs=crit
SeverityIgnoreNone=crit
SeverityAttributes=crit
SeverityIgnoreAll=crit
SeverityFiles=err
SeverityDirs=err
SeverityNames=warn

End-of-data
}

prep_init ()
{
    rm -f ./.samhain_file
    rm -f "${LOGFILE}"
    rm -f ./.samhain_lock

    rm -f "${RCFILE}"
    mkconfig_sev
    mkconfig_log
    mkconfig_misc
}

TESTPOLICY="
[ReadOnly]
dir=${BASE}/c
[Attributes]
dir=${BASE}/a
#dir=${BASE}/b
"


testtime0_int ()
{
	[ -z "$verbose" ] || echo Working directory: $PW_DIR
	[ -z "$verbose" ] || { echo MAKE is $MAKE; echo; }
	#
	# standalone compilation
	#
	[ -z "$verbose" ] || { echo; echo "${S}Building standalone agent${E}"; echo; }
	#
	if test -r "Makefile"; then
		$MAKE distclean >/dev/null
	fi
	#
	${TOP_SRCDIR}/configure --quiet --enable-debug --enable-xml-log --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PIDFILE --with-data-file=$PW_DIR/.samhain_file
	#
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
		$MAKE  > /dev/null 2>>test_log
		if test x$? = x0; then
		    [ -z "$verbose" ] || log_msg_ok "make..."; 
		else
		    [ -z "$quiet" ] &&   log_msg_fail "make..."; 
		    return 1
		fi
	else
		[ -z "$quiet" ] &&       log_msg_fail "configure...";
		return 1
	fi

	prep_init && prep_testdata && echo "$TESTPOLICY" >>$RCFILE
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "prepare...";
	    return 1
	fi

	./samhain -t init -p none
	
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "init...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "init...";
	    return 1
	fi

	chmod 0555 "${BASE}/a/x"
	chmod 0555 "${BASE}/b/x"

	./samhain -t check -p none -l info -D

	count=0
	until [ -f $PIDFILE ]; do
	    one_sec_sleep
	    let "count = count + 1" >/dev/null
	    if [ $count -gt 12 ]; then
		break;
	    fi
	done

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "start daemon...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "start daemon...";
	    return 1
	fi

	return 0
}

MAXTEST=14; export MAXTEST

die () {
    test -z "$stoponerr" && return 0;
    PID=`cat $PIDFILE`
    kill -9 $PID
}

killdaemon () {
    if [ -f $PIDFILE ]; then
	PID=`cat $PIDFILE`
	kill -9 $PID
    fi
}

check_err () {
    if [ ${2} -ne 0 ]; then
	die;
	[ -z "$quiet" ] && log_fail ${1} ${MAXTEST} "${3}";
	return 1
    else
	[ -z "$quiet" ] && log_ok   ${1} ${MAXTEST} "${3}";
    fi
}

daemontest_started () {
    PID=`cat $PIDFILE`

    kill -0 $PID
    check_err ${1} $? "started"
}

daemontest_sigterm () {
    PID=`cat $PIDFILE`

    kill -15 $PID
    count=0
    while [ `kill -0 $PID` ]; do
	one_sec_sleep
	let "count = count + 1" >/dev/null
	if [ $count -gt 12 ]; then
	    check_err ${1} 1 "sigterm"
	    return 1
	fi
    done
    check_err ${1} 0 "sigterm"
}

daemontest_sigusr2 () {
    PID=`cat $PIDFILE`

    tmp=`grep 'File check completed' $LOGFILE | wc -l`
    kill -USR2 $PID
    kill -TTOU $PID
    
    count=0
    tmp2=`grep 'SUSPEND' $LOGFILE | wc -l`
    while [ $tmp2 -ne $2 ]; do
	one_sec_sleep
	let "count = count + 1" >/dev/null
	if [ $count -gt 12 ]; then
	    check_err ${1} 1 "sigusr2: suspend"
	    return 1
	fi
	tmp2=`grep 'SUSPEND' $LOGFILE | wc -l`
    done

    kill -USR2 $PID

    count=0
    tmp2=$tmp
    while [ $tmp2 -eq $tmp ]; do
	one_sec_sleep
	let "count = count + 1" >/dev/null
	if [ $count -gt 12 ]; then
	    check_err ${1} 1 "sigusr2: wakeup"
	    return 1
	fi
	tmp2=`grep 'File check completed' $LOGFILE | wc -l`
    done
    check_err ${1} 0 "sigusr2"
}

daemontest_sigttou () {
    PID=`cat $PIDFILE`

    tmp=`grep 'File check completed' $LOGFILE | wc -l`
    kill -TTOU $PID
    count=0
    tmp2=$tmp
    while [ $tmp2 -eq $tmp ]; do
	one_sec_sleep
	let "count = count + 1" >/dev/null
	if [ $count -gt 12 ]; then
	    check_err ${1} 1 "sigttou"
	    return 1
	fi
	tmp2=`grep 'File check completed' $LOGFILE | wc -l`
    done
    check_err ${1} 0 "sigttou"
}

daemontest_sighup () {

    if [ $2 -eq 1 ]; then
	echo "dir=${BASE}/b" >>$RCFILE
	tmp=`grep CRIT $LOGFILE | grep -v Runtime | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "policy count (before)";
	    return 1
	fi
    fi
    
    PID=`cat $PIDFILE`
    kill -HUP $PID

    if [ $2 -eq 1 ]; then
	kill -TTOU $PID
	count=0
	tmp=`grep CRIT $LOGFILE | grep -v Runtime | wc -l`
	while [ $tmp -lt 2 ]; do
	    one_sec_sleep
	    let "count = count + 1" >/dev/null
	    if [ $count -gt 12 ]; then
		[ -z "$verbose" ] || log_msg_fail "policy count (after)";
		return 1
	    fi
	    tmp=`grep CRIT $LOGFILE | grep -v Runtime | wc -l`
	done
    fi    

    count=0
    tmp2=0
    while [ $tmp2 -ne $2 ]; do
	one_sec_sleep
	let "count = count + 1" >/dev/null
	if [ $count -gt 12 ]; then
	    check_err ${1} 1 "sighup"
	    return 1
	fi
	tmp2=`grep 'Runtime configuration reloaded' $LOGFILE | wc -l`
    done
    check_err ${1} 0 "sighup"
}

daemontest_sigabrt () {
    PID=`cat $PIDFILE`
    kill -${3} $PID

    count=0
    while [ -f $LOGFILE.lock ]; do
	one_sec_sleep
	let "count = count + 1" >/dev/null
	if [ $count -gt 12 ]; then
	    check_err ${1} 1 "sigabrt"
	    return 1
	fi
    done

    kill -TTOU $PID

    five_sec_sleep

    if [ -f $LOGFILE.lock ]; then
	tmp=`grep '<trail>' $LOGFILE | wc -l`
	tst=$2; let "tst = tst + 2" >/dev/null;
	if [ $tmp -eq $tst ]; then
	    check_err ${1} 0 "sigabrt"
	    return 0
	fi
    fi
    check_err ${1} 1 "sigabrt"
}

testtime0 () {
    log_start "DAEMON CONTROL"

    testtime0_int;

    tcount=1

    trap 'killdaemon' 1 3 15

    daemontest_started $tcount;

    let "tcount = tcount + 1" >/dev/null
    daemontest_sigttou $tcount;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sigttou $tcount;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sigttou $tcount;

    let "tcount = tcount + 1" >/dev/null
    daemontest_sigusr2 $tcount 1;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sigusr2 $tcount 2;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sigusr2 $tcount 3;

    let "tcount = tcount + 1" >/dev/null
    daemontest_sigabrt $tcount 1 ABRT;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sigabrt $tcount 2 TTIN;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sigabrt $tcount 3 ABRT;

    let "tcount = tcount + 1" >/dev/null
    daemontest_sighup  $tcount 1;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sighup  $tcount 2;
    let "tcount = tcount + 1" >/dev/null
    daemontest_sighup  $tcount 3;

    let "tcount = tcount + 1" >/dev/null
    daemontest_sigterm $tcount;

    log_end "DAEMON CONTROL"
}


