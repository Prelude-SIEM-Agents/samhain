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
HTML="$PW_DIR/yule.html";  export HTML

SERVER_BUILDOPTS="--quiet  $TRUST --enable-xml-log --enable-debug --enable-network=server --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-logserver=${SH_LOCALHOST}  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-database=mysql"; export SERVER_BUILDOPTS

CLIENT_BUILDOPTS="--quiet  $TRUST --prefix=$PW_DIR --with-tmp-dir=$PW_DIR --localstatedir=$PW_DIR --enable-network=client --disable-mail --disable-external-scripts --enable-login-watch --enable-xml-log --enable-db-reload --with-logserver=localhost --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock"; export CLIENT_BUILDOPTS

MAXTEST=4; export MAXTEST

do_test_1_c () {

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}

	rm -f test_log_valgrind

	${VALGRIND} ./yule.2 -q -l info -p none >/dev/null 2>>test_log_valgrind &
	PROC_Y2=$!
	five_sec_sleep

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server #2${E}: ./yule.2 -l info -p none &"; 
	    echo; 
	}

	${VALGRIND} ./yule -l info -p none -e info --bind-address=127.0.0.1 \
	    --server-port=49778 >/dev/null 2>>test_log_valgrind &
	PROC_Y=$!
	five_sec_sleep

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Client${E}: ./samhain.new -l none -p none -e info -t check"; 
	    echo; 
	}

	${VALGRIND} ./samhain.new -t check -p none -l none -e info --bind-address=127.0.0.1 >/dev/null 2>>test_log_valgrind
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "samhain.new -t check";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "samhain.new -t check";
	    kill $PROC_Y
	    kill $PROC_Y2
	    return 1
	fi

	kill $PROC_Y
	kill $PROC_Y2
	five_sec_sleep

	# cp ${LOGFILE}  triple_test
	# cp ${LOGFILE}2 triple_test_2

	egrep "START(>|\").*Yule(>|\")" ${LOGFILE}2 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Server #2 start";
	    return 1
	fi
	egrep "remote_host.*Checking.*/bin" ${LOGFILE}2 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (relayed)";
	    return 1
	fi
	egrep "remote_host.*EXIT.*Samhain" ${LOGFILE}2 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client exit (relayed)";
	    return 1
	fi
	egrep "EXIT.*Yule.*SIGTERM" ${LOGFILE}2 >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Server #2 exit";
	    return 1
	fi


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
	egrep "remote_host.*Checking.*/bin" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check";
	    return 1
	fi
	egrep "remote_host.*EXIT.*Samhain" $LOGFILE >/dev/null 2>&1
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

testrun_threesockets () {

    GPG="$1"

    [ -z "$verbose" ] || { 
        echo; 
        echo Working directory: $PW_DIR; echo MAKE is $MAKE; echo GPG is $GPG;
        echo; 
    }

    [ -z "$verbose" ] || { echo; echo "${S}Building client and server${E}"; echo; }

    if test -r "Makefile"; then
        $MAKE distclean
    fi

    ${TOP_SRCDIR}/configure --with-gpg=${GPG} --with-fp=EF6CEF54701A0AFDB86AF4C31AAD26C80F571F6C --with-checksum=no ${SERVER_BUILDOPTS} >/dev/null 2>&1

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

    rm -f ./.samhain_file
    rm -f ./.samhain_log
    rm -f ./.samhain_lock
    rm -f ./rc.${SH_LOCALHOST}
    rm -f ./file.${SH_LOCALHOST}
    
    cp ${SCRIPTDIR}/testrc_2.in testrc_2
    
    ORIGINAL="DatabaseSeverity=none"
    REPLACEMENT="DatabaseSeverity=warn"
    ex -s $RCFILE <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF

    ORIGINAL="MailSeverity=none"
    REPLACEMENT="MailSeverity=crit"
    ex -s $RCFILE <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF
    return 0
 }

check_mysql_log () {
    DATE="$1"

    rm -f test_log_db
    #
    echo "SELECT * FROM log WHERE entry_status = 'NEW' and log_time > '"${DATE}"';" | mysql --password=samhain -u samhain samhain >test_log_db
    #
    egrep "START.*Yule" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Server start";
	return 1
    fi
    egrep "NEW CLIENT" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Client connect";
	return 1
    fi
    egrep "Checking.*/bin" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Client file check";
	return 1
    fi
    egrep "EXIT.*Samhain" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Client exit";
	return 1
    fi
    egrep "EXIT.*Yule.*SIGTERM" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Server exit";
	return 1
    fi
    return 0
}

testrun2c ()
{
    log_start "RUN FULL CLIENT/SERVER W/MYSQL"
    #
    if [ -z "$doall" ]; then
	log_skip 1 $MAXTEST 'Client/server w/mysql (or use --really-all)'
	log_skip 2 $MAXTEST 'Client/server w/mysql (or use --really-all)'
	log_skip 3 $MAXTEST 'Client/server w/mysql (or use --really-all)'
	log_skip 4 $MAXTEST 'Client/server w/mysql (or use --really-all)'
	return 0
    fi
    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    MYSQL=`find_path mysql`
    if [ -z "$MYSQL" ]; then
	log_skip 1 $MAXTEST "mysql not found";
	log_skip 2 $MAXTEST "mysql not found";
	log_skip 3 $MAXTEST "mysql not found";
	log_skip 4 $MAXTEST "mysql not found";
	return 1
    else
	TEST=`echo "DESCRIBE log;" | mysql --password=samhain -u samhain samhain 2>/dev/null`
	if [ $? -ne 0 -o -z "$TEST" ]; then
	    log_skip 1 $MAXTEST "mysql not default setup"
	    log_skip 2 $MAXTEST "mysql not default setup"
	    log_skip 3 $MAXTEST "mysql not default setup"
	    log_skip 4 $MAXTEST "mysql not default setup"
	    return 1
	fi
    fi
    #
    SH_LOCALHOST=$1; export SH_LOCALHOST
    #
    DATE=`date '+%Y-%m-%d %T'`
    #
    testrun2a_internal
    #
    # BUILD Server 2
    #
    cp ./yule ./yule.orig

    ${TOP_SRCDIR}/configure --quiet  $TRUST --enable-debug --enable-network=server  --enable-xml-log --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=${RCFILE}2  --with-log-file=${LOGFILE}2 --with-pid-file=$PW_DIR/.samhain_lock2 --with-html-file=${HTML}2 --with-state-dir=$PW_DIR --with-port=49778 --with-database=mysql
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
    
    cp yule yule.2 || return 1
    #
    cp ./yule.orig ./yule
    #
    SHPW=`cat ./testpw`
    
    if test x"$SHPW" = x; then
	[ -z "$quiet" ]   && log_msg_fail  "password not generated -- aborting"
	return 1
    fi
    
    rm -f ./testpw
    
    ./samhain_setpwd yule new $SHPW >/dev/null
    
    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "./samhain_setpwd yule new $SHPW";
    else
	[ -z "$quiet" ]   && log_msg_fail  "./samhain_setpwd yule new $SHPW";
	return 1
    fi


    $MAKE clean >/dev/null || return 1
    mv yule.new yule || return 1
    #
    ORIGINAL="DatabaseSeverity=none"
    REPLACEMENT="DatabaseSeverity=info"
    ex -s $RCFILE <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF
    #
    do_test_1_a
    #
    if [ $? -ne 0 ]; then
	[ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client/server w/mysql";
    else
    #
	check_mysql_log "${DATE}"
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client/server w/mysql";
	else
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Client/server w/mysql";
	fi
    fi
    #
    cp testrc_2 testrc_22
    ORIGINAL="DatabaseSeverity=none"
    REPLACEMENT="DatabaseSeverity=info"
    ex -s $RCFILE <<EOF
%s/$REPLACEMENT/$ORIGINAL/g
wq
EOF
    #
    do_test_1_c
    #
    if [ $? -ne 0 ]; then
	[ -z "$quiet" ] && log_fail 2 ${MAXTEST} "Client/server (relay) w/mysql";
    else
    #
	check_mysql_log "${DATE}"
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ] && log_fail 2 ${MAXTEST} "Client/server (relay) w/mysql";
	else
	    [ -z "$quiet" ] && log_ok   2 ${MAXTEST} "Client/server (relay) w/mysql";
	fi
    fi
    #
    #
    if [ -f ./yule ]; then
	./yule -p info -l info --set-database-severity=info -D >/dev/null 2>>test_log 
	five_sec_sleep
	netstat -pant 2>/dev/null | grep 49777 | grep yule >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ] && log_fail 3 ${MAXTEST} "Client/server w/mysql";
	else
	    NSOCK=`netstat -pand 2>/dev/null | grep STREAM | grep yule | wc -l`
	    if [ $NSOCK -ne 2 ]; then
		[ -z "$quiet" ] && log_fail 3 ${MAXTEST} "Three sockets open";
		netstat -pand 2>/dev/null | grep yule 
	    else
		[ -z "$quiet" ] && log_ok   3 ${MAXTEST} "Three sockets open";
	    fi
	fi
	PID=`cat .samhain_lock`
	kill $PID
    else
	log_fail 3 ${MAXTEST} "Three sockets open";
    fi
    #
    cp ${SCRIPTDIR}/testrc_2.in testrc_2
    #
    GPG=`find_path gpg`
    if [ -z "$GPG" ]; then
        log_skip 4 $MAXTEST 'gpg not found in $PATH'
    else
        eval "$GPG" --list-keys 0F571F6C >/dev/null 2>/dev/null
        if [ $? -ne 0 ]; then
            log_skip 4 $MAXTEST 'public PGP key 0x0F571F6C not present'
        else
	    testrun_threesockets "$GPG"
	    #
	    cp ${SCRIPTDIR}/testrc_2.in testrc_2
	    #
	    if [ -f ./yule ]; then
		./yule -D --set-database-severity=warn >/dev/null 2>>test_log 
		five_sec_sleep
		netstat -pant 2>/dev/null | grep 49777 | grep yule >/dev/null 2>&1
		if [ $? -ne 0 ]; then
		    [ -z "$quiet" ] && log_fail 4 ${MAXTEST} "Three sockets open (gpg) - 1";
		else
		    NSOCK=`netstat -pand 2>/dev/null | grep STREAM | grep yule | wc -l`
		    if [ $NSOCK -ne 2 ]; then
			[ -z "$quiet" ] && log_fail 4 ${MAXTEST} "Three sockets open (gpg) - 2";
			netstat -pand 2>/dev/null | grep yule 
		    else
			[ -z "$quiet" ] && log_ok   4 ${MAXTEST} "Three sockets open (gpg)";
		    fi
		fi
		PID=`cat .samhain_lock`
		kill $PID
	    else
		log_fail 4 ${MAXTEST} "Three sockets open (gpg) - 3";
	    fi
	fi
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
    log_end "RUN FULL CLIENT/SERVER W/MYSQL"
}

