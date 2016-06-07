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

LOGFILE="$PW_DIR/.samhain_log"; export LOGFILE
RCFILE="$PW_DIR/testrc_2";  export RCFILE

SERVER_BUILDOPTS="--quiet  $TRUST --enable-network=server --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-logserver=${SH_LOCALHOST}  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --enable-debug=gdb"; export SERVER_BUILDOPTS

CLIENT_BUILDOPTS="--quiet  $TRUST --enable-network=client --enable-srp --prefix=$PW_DIR --with-tmp-dir=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$RCFILE --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file  --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --enable-debug"; export CLIENT_BUILDOPTS

do_test_2_f () {

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}
	rm -f test_log_valgrind

 	# SetSocketAllowUid=$(id -u)
	#
	if test -f /usr/xpg4/bin/id; then
	    MY_ID=$(/usr/xpg4/bin/id -u)
	else
	    MY_ID=$(id -u)
	fi
	#
	sed -i -e "s/SetSocketAllowUid=0/SetSocketAllowUid=${MY_ID}/g" $RCFILE

	# Start server
	#
	${VALGRIND} ./yule -l info -p none >/dev/null 2>>test_log_valgrind &
	PROC_Y=$!
	five_sec_sleep


	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Client${E}: ./samhain.new -t check --foreground --forever .. &"; 
	    echo; 
	}
	${VALGRIND} ./samhain.new -t check -D -p none -l none -e info --bind-address=127.0.0.1 --server-host=localhost >/dev/null 2>>test_log_valgrind 
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "starting samhain.new";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "starting samhain.new";
	    kill $PROC_Y
	    return 1
	fi
	five_sec_sleep
	PROC_S=$(  ps aux | grep samhain.new | grep -v grep | awk '{ print $2; }' )

	for ff in 1 2; do
	    five_sec_sleep
	done
	egrep "File check completed" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	NR=$( egrep "File check completed" $LOGFILE | wc -l )
	if [ $NR -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (1)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	#
	# >>> (1) Send SIGTTOU to force a second scan, 
	# >>>      and verify that it was done
	#
	kill -TTOU $PROC_S
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Kill -TTOU";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	for ff in 1 2; do
	    five_sec_sleep
	done
	NR=$( egrep "File check completed" $LOGFILE | wc -l )
	if [ $NR -ne 2 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (2)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "sigttou";

	NR=$( egrep "POLICY" $LOGFILE | wc -l )
	if [ $NR -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (3)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	#
	# >>> (2) Modify the file system
	#

	UUID=$(uuidgen)
	mkdir /tmp/testrun_samhain/$UUID
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "mkdir";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	kill -TTOU $PROC_S
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Kill -TTOU (2)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	for ff in 1 2; do
	    five_sec_sleep
	done
	NR=$( egrep "POLICY" $LOGFILE | wc -l )
	if [ $NR -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (4)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "/tmp/testrun_samhain modified";

	kill $PROC_S; 
	five_sec_sleep

	rm -f ./.samhain_file
	rm -f ./file.${SH_LOCALHOST} 
	rm -f "./file.${ALTHOST}"

	rm ./.samhain_log 
	rm -f ./.samhain_lock

	#
	# >>> (3) Re-init the database 
	#
	./samhain.new -t init -p none
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "init (2) ..";
	    kill $PROC_Y;
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "init (2) ..";

	#
	# >>> (4) Re-start Samhain with delay
	#

	sed --in-place -e 's/SetUdpActive=no/StartupLoadDelay=10/g' ./rc.${SH_LOCALHOST}
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "sed (1) ..";
	    kill $PROC_Y;
	    return 1
	fi
	sed --in-place -e 's/SetUdpActive=no/StartupLoadDelay=10/g' "./rc.${ALTHOST}"
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "sed (2) ..";
	    kill $PROC_Y;
	    return 1
	fi

	${VALGRIND} ./samhain.new -t check -D -p none -l none -e info --bind-address=127.0.0.1 --server-host=localhost >/dev/null 2>>test_log_valgrind 
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "starting samhain.new (2)";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "starting samhain.new (2)";
	    kill $PROC_Y
	    return 1
	fi
	five_sec_sleep
	PROC_S=$(  ps aux | grep samhain.new | grep -v grep | awk '{ print $2; }' )

	#
	# >>> (5) Copy database to server after Samhain startup
	# >>>     verifies that StartupLoadDelay works
	#

	if test -f ./.samhain_file; then
	    mv ./.samhain_file ./file.${SH_LOCALHOST}
	    chmod 644 ./file.${SH_LOCALHOST}

	    ALTHOST=`find_hostname`
	    cp    ./file.${SH_LOCALHOST} "./file.${ALTHOST}" 2>/dev/null
	    chmod 644 ./file.${ALTHOST}
	else
	    [ -z "$verbose" ] || log_msg_fail "baseline file ..";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	for ff in 1 2 3; do
	    five_sec_sleep
	done
	NR=$( egrep "File check completed" $LOGFILE | wc -l )
	if [ $NR -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (5)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "file check after delay";

	NR=$( egrep "POLICY" $LOGFILE | wc -l )
	if [ $NR -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (6)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	kill $PROC_S; 
	kill $PROC_Y
	return 0
}

testrun2f_internal ()
{
        [ -z "$verbose" ] || { 
	    echo; 
	    echo Working directory: $PW_DIR; echo MAKE is $MAKE; 
	    echo; 
	}
	#
	#
	[ -z "$verbose" ] || { echo; echo "${S}Building client and server${E}"; echo; }
	#
	if test -r "Makefile"; then
		$MAKE distclean
	fi
	#
	${TOP_SRCDIR}/configure ${CLIENT_BUILDOPTS}
	#
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
		$MAKE > /dev/null 2>>test_log
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

	# save binary and build server
	#
	cp samhain samhain.build || return 1
	$MAKE clean >/dev/null || return 1

	${TOP_SRCDIR}/configure ${SERVER_BUILDOPTS}
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


	#####################################################################
	#
	#
	rm -f ./.samhain_file
	rm -f ./.samhain_log
	rm -f ./.samhain_lock
	rm -f ./rc.${SH_LOCALHOST}
	rm -f ./file.${SH_LOCALHOST}
	rm -f  "./rc.${ALTHOST}"
	rm -f  "./file.${ALTHOST}"

	cp ${SCRIPTDIR}/testrc_2.in testrc_2

	sed --in-place -e 's,file = /tmp,file = /tmp/testrun_samhain,g'  testrc_2
	mkdir /tmp/testrun_samhain 2>/dev/null

	./samhain.build -t init -p none

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "init...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "init...";
	    return 1
	fi

	# Create a password

	SHPW=`./yule -G`
	if test x"$SHPW" = x; then
	    [ -z "$quiet" ]   && log_msg_fail  "password not generated -- aborting"
	    return 1
	fi

	# Set in client

	./samhain_setpwd samhain.build new $SHPW >/dev/null

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "./samhain_setpwd samhain.build new $SHPW";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "./samhain_setpwd samhain.build new $SHPW";
	    return 1
	fi

	mv samhain.build.new  samhain.new || return 1

	rm -f ./.samhain_log*
	rm -f ./.samhain_lock

	SHCLT=`./yule -P $SHPW`

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "yule -P $SHPW";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "yule -P $SHPW";
	    return 1
	fi

	SHCLT1=`echo "${SHCLT}"  | sed s%HOSTNAME%${SH_LOCALHOST}%`
	AHOST=`find_hostname`
	SHCLT2=`echo "${SHCLT}"  | sed s%HOSTNAME%${AHOST}%`
	
 	echo $SHCLT1 >> testrc_2
 	echo $SHCLT2 >> testrc_2

	cp    ./testrc_2       ./rc.${SH_LOCALHOST}
	mv    ./.samhain_file  ./file.${SH_LOCALHOST}
	chmod 644 ./rc.${SH_LOCALHOST}
	chmod 644 ./file.${SH_LOCALHOST}

	ALTHOST=`find_hostname`
	cp    ./testrc_2       "./rc.${ALTHOST}"
	cp    ./file.${SH_LOCALHOST} "./file.${ALTHOST}" 2>/dev/null
	chmod 644 ./rc.${ALTHOST}
	chmod 644 ./file.${ALTHOST}

	echo $SHPW > ./testpw
}

MAXTEST=1; export MAXTEST

testrun2f ()
{
    log_start "RUN CLIENT/SERVER CASE ONE";
    #
    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    #
    SH_LOCALHOST=$1; export SH_LOCALHOST
    #
    testrun2f_internal
    do_test_2_f
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Case One Change Management Integration";
    else
	[ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Case One Change Management Integration";
    fi
    #
    log_end "RUN CLIENT/SERVER CASE ONE"
}
