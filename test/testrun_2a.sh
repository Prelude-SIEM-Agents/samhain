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

CLIENT_BUILDOPTS="--quiet  $TRUST --enable-network=client --enable-srp --prefix=$PW_DIR --with-tmp-dir=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$RCFILE --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file  --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --enable-suidcheck --enable-debug"; export CLIENT_BUILDOPTS

do_test_1_a () {

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}
	rm -f test_log_valgrind

	${VALGRIND} ./yule -l info -p none >/dev/null 2>>test_log_valgrind &
	PROC_Y=$!
	five_sec_sleep

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Client${E}: ./samhain.new -l none -p none -e info -t check --bind-address=127.0.0.1 --server-host=localhost"; 
	    echo; 
	}

	${VALGRIND} ./samhain.new -t check -p none -l none -e info --bind-address=127.0.0.1 --server-host=localhost >/dev/null 2>>test_log_valgrind
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "samhain.new -t check";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "samhain.new -t check";
	    kill $PROC_Y
	    return 1
	fi

	kill $PROC_Y
	five_sec_sleep

	egrep "START(>|\").*Yule(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Server start";
	    return 1
	fi
	egrep "NEW CLIENT" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client connect";
	    return 1
	fi
	egrep "Checking.*/etc" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check";
	    return 1
	fi
	egrep "EXIT.*Samhain" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client exit";
	    return 1
	fi
	egrep "EXIT.*Yule.*SIGTERM" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Server exit";
	    return 1
	fi
	
	[ -z "$VALGRIND" ] || {
	    tmp=`cat test_log_valgrind 2>/dev/null | wc -l`;
	    if [ $tmp -ne 0 ]; then
		[ -z "$verbose" ] || log_msg_fail "valgrind reports errors";
		cat test_log_valgrind
		return 1;
	    fi;
	}

	return 0
}

testrun2a_internal ()
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
	# Limit suid check
	#
	BASE="${PW_DIR}"; export BASE
	#
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
		$MAKE  'DBGDEF=-DSH_SUIDTESTDIR=\"${BASE}\"' > /dev/null 2>>test_log
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

MAXTEST=4; export MAXTEST

testrun2a ()
{
    log_start "RUN FULL CLIENT/SERVER";
    #
    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    #
    SH_LOCALHOST=$1; export SH_LOCALHOST
    #
    testrun2a_internal
    do_test_1_a
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Client download+logging";
    else
	[ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client download+logging";
    fi
    ####### EXIT HERE FOR TESTING ######
    #
    #
    SERVER_BUILDOPTS_ORIG="${SERVER_BUILDOPTS}"
    CLIENT_BUILDOPTS_ORIG="${CLIENT_BUILDOPTS}"
    #
    SERVER_BUILDOPTS="${SERVER_BUILDOPTS_ORIG} --disable-srp"; export SERVER_BUILDOPTS
    CLIENT_BUILDOPTS="${CLIENT_BUILDOPTS_ORIG} --disable-srp"; export CLIENT_BUILDOPTS
    #
    testrun2a_internal
    do_test_1_a
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   2 ${MAXTEST} "SRP disabled";
    else
	[ -z "$quiet" ] && log_fail 2 ${MAXTEST} "SRP disabled";
    fi
    #
    SERVER_BUILDOPTS="${SERVER_BUILDOPTS_ORIG} --disable-encrypt"; export SERVER_BUILDOPTS
    CLIENT_BUILDOPTS="${CLIENT_BUILDOPTS_ORIG} --disable-encrypt"; export CLIENT_BUILDOPTS
    #
    testrun2a_internal
    do_test_1_a
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   3 ${MAXTEST} "Encryption disabled";
    else
	[ -z "$quiet" ] && log_fail 3 ${MAXTEST} "Encryption disabled";
    fi
    #
    SERVER_BUILDOPTS="${SERVER_BUILDOPTS_ORIG} --disable-ipv6"; export SERVER_BUILDOPTS
    CLIENT_BUILDOPTS="${CLIENT_BUILDOPTS_ORIG} --disable-ipv6"; export CLIENT_BUILDOPTS
    #
    testrun2a_internal
    do_test_1_a
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   4 ${MAXTEST} "IPv6 disabled";
    else
	[ -z "$quiet" ] && log_fail 4 ${MAXTEST} "IPv6 disabled";
    fi
    #
    if [ -n "$cleanup" ]; then
	rm -f ./rc.${SH_LOCALHOST}
	rm -f ./file.${SH_LOCALHOST}
	ALTHOST=`find_hostname`
	rm -f "./file.${ALTHOST}"
	rm -f "./rc.${ALTHOST}"
    fi
    #
    log_end "RUN FULL CLIENT/SERVER"
}
