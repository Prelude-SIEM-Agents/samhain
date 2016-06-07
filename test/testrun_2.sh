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


do_test_1 () {

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}

	rm -f test_log_valgrind

	${VALGRIND} ./yule.2 -l info -p none >/dev/null 2>>test_log_valgrind &
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

do_test_2 () {

        ORIGINAL="UseSeparateLogs=no"
	REPLACEMENT="UseSeparateLogs=yes"
        ex -s $RCFILE <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF
# :%s is the "ex" substitution command.
# :wq is write-and-quit.
	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}

	rm -f $LOGFILE
	rm -f test_log_valgrind

	${VALGRIND} ./yule -l info -p none >/dev/null 2>>test_log_valgrind &
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
	    return 1
	fi

	kill $PROC_Y
	five_sec_sleep

	if [ -f ${LOGFILE}.${SH_LOCALHOST} ]; then
	    remhost=${SH_LOCALHOST}
	else
	    remhost=`echo $SH_LOCALHOST | sed 's,\..*,,'`
	fi
	if [ -f ${LOGFILE}.${remhost} ]; then
	    CLIENTLOG="${LOGFILE}.${remhost}"
	else
	    tail -n 1 ${SCRIPTDIR}/test.sh >/dev/null 2>&1
	    if [ $? -eq 0 ]; then
		CLIENTLOG=`ls -1 ${LOGFILE}.* 2>/dev/null | tail -n 1`
	    else
		CLIENTLOG=`ls -1 ${LOGFILE}.* 2>/dev/null | tail -1`
	    fi
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
	egrep "remote_host.*Checking.*/bin" ${CLIENTLOG} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check";
	    return 1
	fi
	egrep "remote_host.*EXIT.*Samhain" ${CLIENTLOG} >/dev/null 2>&1
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
	
	rm -f ${LOGFILE}.${remhost}
	return 0
}

do_test_3 () {

        ORIGINAL_1="ExportSeverity=none"
        REPLACEMENT_1="ExportSeverity=mark"
	ORIGINAL_2="UseSeparateLogs=yes"
	REPLACEMENT_2="UseSeparateLogs=no"
	ORIGINAL_3="LogSeverity=none"
	REPLACEMENT_3="LogSeverity=debug"
	ORIGINAL_4="# SetClientTimeLimit=1800"
	REPLACEMENT_4="SetClientTimeLimit=20"
	# takes too much time if we leave that in
	ORIGINAL_5="dir=1"
	REPLACEMENT_5="#dir=1"
        ex -s $RCFILE <<EOF
%s/${ORIGINAL_1}/${REPLACEMENT_1}/g
%s/${ORIGINAL_2}/${REPLACEMENT_2}/g
%s/${ORIGINAL_3}/${REPLACEMENT_3}/g
%s/${ORIGINAL_4}/${REPLACEMENT_4}/g
%s/${ORIGINAL_5}/${REPLACEMENT_5}/g
wq
EOF
# :%s is the "ex" substitution command.
# :wq is write-and-quit.
	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -p none -e none &"; 
	    echo; 
	}

	rm -f $LOGFILE
	rm -f test_log_valgrind

	${VALGRIND} ./yule -p none -e none >/dev/null 2>>test_log_valgrind &
	PROC_Y=$!
	five_sec_sleep

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Client${E}: ./samhain.new -t check -p none -l none --forever --bind-address=127.0.0.1 &"; 
	    echo; 
	}

	${VALGRIND} ./samhain.new -t check -p none -l none --forever --bind-address=127.0.0.1 >/dev/null 2>>test_log_valgrind &
	if test x$? = x0; then
	    PROC_S=$!
	    # echo "PID is ${PROC_S}"
	    [ -z "$verbose" ] || log_msg_ok    "samhain.new -t check";
	    five_sec_sleep
	    # Redirect the shells (un-)helpful job monitoring messages.
	    # The 'disown' buildin is not portable. 
	    { kill -9 ${PROC_S}; sleep 40; } >/dev/null 2>&1
	else
	    [ -z "$quiet" ]   && log_msg_fail  "samhain.new -t check";
	    kill $PROC_Y
	    return 1
	fi

	if [ -t 0 ]; then
	    # enable monitor mode again if interactive
	    set -m
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
	egrep "remote_host.*File check completed.*" ${LOGFILE} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check";
	    return 1
	fi
	egrep "Time limit exceeded" ${LOGFILE} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client dead detection";
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
	
	rm -f ${LOGFILE}
	return 0
}

do_test_4 () {

        # don't know what is supported on the test platform, so
        # prepare for both (password and socket credential)

        # 'id -u' is posix
        if test -f /usr/xpg4/bin/id
	then
	    me=`/usr/xpg4/bin/id -u`
	else
	    me=`id -u`
	fi

	ORIGINAL_1="SetSocketAllowUid=0"
	REPLACEMENT_1="SetSocketAllowUid=$me"
        ex -s $RCFILE <<EOF
%s/${ORIGINAL_1}/${REPLACEMENT_1}/g
wq
EOF

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}

	rm -f $LOGFILE
	rm -f test_log_valgrind

	${VALGRIND} ./yule -l info -p none -e none \
	    >/dev/null 2>>test_log_valgrind &
	PROC_Y=$!
	five_sec_sleep

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Client${E}: ./samhain.new -l none -p none -e info -t check"; 
	    echo; 
	}

	$MAKE yulectl >/dev/null 
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "make yulectl";
	    kill $PROC_Y
	    return 1
	fi


	./yulectl -v -c RELOAD foobar1 >test_log_yulectl 2>/dev/null

	if [ $? -ne 0 ]; then 
	    YULECTL_PASSWORD=samhain; export YULECTL_PASSWORD
	    ./yulectl -v -c RELOAD foobar1 >test_log_yulectl
	    if [ $? -ne 0 ]; then
		kill ${PROC_Y}
		[ -z "$verbose" ] || log_msg_fail "yulectl";
		return 1
	    fi
	fi

	./yulectl -v -c RELOAD foobar2 >test_yulectl_log

	if [ $? -ne 0 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "yulectl";
	    return 1
	fi

	./yulectl -v -c RELOAD foobar3 >test_log_yulectl

	if [ $? -ne 0 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "yulectl";
	    return 1
	fi

	./yulectl -v -c LISTALL dummy >test_log_yulectl

	if [ $? -ne 0 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "yulectl";
	    return 1
	fi

	tmp=`cat test_log_yulectl | grep RELOAD | wc -l`
	if [ $tmp -ne 3 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "command confirmation";
	    return 1
	fi

	./yulectl -v -c CANCEL foobar3 >test_log_yulectl

	if [ $? -ne 0 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "yulectl";
	    return 1
	fi

	./yulectl -v -c LISTALL dummy >test_log_yulectl

	if [ $? -ne 0 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "yulectl";
	    return 1
	fi

	tmp=`cat test_log_yulectl | grep RELOAD | wc -l`
	if [ $tmp -ne 2 ]; then
	    kill ${PROC_Y}
	    [ -z "$verbose" ] || log_msg_fail "command confirmation";
	    return 1
	fi

	kill ${PROC_Y}
	one_sec_sleep
	one_sec_sleep
	kill -9 ${PROC_Y} >/dev/null 2>&1

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

do_test_5 () {

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Server${E}: ./yule -l info -p none &"; 
	    echo; 
	}

( cat <<EOF
<!-- head -->
<html><head><title>test</title></head>
<body>
Current time: %T <br>
<table>
<!-- ehead -->
EOF
) >head.html

( cat <<EOF
<!-- foot -->
</table>
</body>
<!-- efoot -->
EOF
) >foot.html

( cat <<EOF
<!-- entry -->
<tr>
  <td>%H</td>
  <td>%S</td>
  <td>%T</td>
</tr>
<!-- eentry -->
EOF
) >entry.html

	${VALGRIND} ./yule -l info -p none -e none \
	    >/dev/null 2>>test_log_valgrind &
	PROC_Y=$!
	five_sec_sleep

	egrep '<!-- head -->' $HTML >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    # rm -f head.html; rm -f foot.html; rm -f entry.html;
	    kill $PROC_Y
	    [ -z "$verbose" ] || log_msg_fail "head.html (1)";
	    return 1
	fi

	egrep '<!-- foot -->' $HTML >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    rm -f head.html; rm -f foot.html; rm -f entry.html;
	    kill $PROC_Y
	    [ -z "$verbose" ] || log_msg_fail "foot.html (1)";
	    return 1
	fi

	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Start Client${E}: ./samhain.new -l none -p none -e info -t check"; 
	    echo; 
	}

	${VALGRIND} ./samhain.new -t check -p none -l none -e info --bind-address=127.0.0.1 >/dev/null 2>>test_log_valgrind
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "samhain.new -t check";
	else
	    kill $PROC_Y
	    [ -z "$quiet" ]   && log_msg_fail  "samhain.new -t check";
	    return 1
	fi

	cp $HTML  ${HTML}.tmp

	kill $PROC_Y
	five_sec_sleep

	# rm -f head.html; rm -f foot.html; rm -f entry.html;

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

	egrep '<!-- head -->' ${HTML}.tmp >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "head.html";
	    return 1
	fi
	egrep '<!-- ehead -->' ${HTML}.tmp >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "end head.html";
	    return 1
	fi

	egrep '<!-- entry -->' ${HTML}.tmp >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "entry.html";
	    return 1
	fi
	egrep '<!-- eentry -->' ${HTML}.tmp >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "end entry.html";
	    return 1
	fi

	egrep '<!-- foot -->' ${HTML}.tmp >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "foot.html";
	    return 1
	fi
	egrep '<!-- efoot -->' ${HTML}.tmp >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "end foot.html";
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

	rm ${HTML}.tmp

	return 0
}


testrun2_internal ()
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
	${TOP_SRCDIR}/configure --quiet  $TRUST --enable-debug --enable-network=client  --enable-xml-log --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file --enable-encrypt=2 --enable-static
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

	# save binary and build server2
	#
	cp samhain samhain.build || return 1
	$MAKE clean >/dev/null || return 1

	${TOP_SRCDIR}/configure --quiet  $TRUST --enable-debug --enable-network=server  --enable-xml-log --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=${RCFILE}2  --with-log-file=${LOGFILE}2 --with-pid-file=$PW_DIR/.samhain_lock2 --with-html-file=${HTML}2 --with-state-dir=$PW_DIR --enable-encrypt=2 --with-port=49778
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

	# save binary and build server
	#
	cp yule yule.2 || return 1
	$MAKE clean >/dev/null || return 1

	${TOP_SRCDIR}/configure --quiet  $TRUST --enable-debug --enable-network=server  --enable-xml-log --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-html-file=$HTML --with-state-dir=$PW_DIR --enable-encrypt=2
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

	# Set in server

	./samhain_setpwd yule new $SHPW >/dev/null

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "./samhain_setpwd yule new $SHPW";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "./samhain_setpwd yule new $SHPW";
	    return 1
	fi

	mv yule.new yule || return 1

	#

	rm -f ./.samhain_log*
	rm -f ./.samhain_lock*

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
	cp testrc_2 testrc_22

	do_test_1
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Client logging";
	else
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client logging";
	fi

	do_test_2
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   2 ${MAXTEST} "Client logging, separate logfiles";
	else
	    [ -z "$quiet" ] && log_fail 2 ${MAXTEST} "Client logging, separate logfiles";
	fi

	do_test_3
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   3 ${MAXTEST} "Dead client detection";
	else
	    [ -z "$quiet" ] && log_fail 3 ${MAXTEST} "Dead client detection";
	fi

	do_test_4
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   4 ${MAXTEST} "Server command socket";
	else
	    [ -z "$quiet" ] && log_fail 4 ${MAXTEST} "Server command socket";
	fi

	do_test_5
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   5 ${MAXTEST} "Server status file";
	else
	    [ -z "$quiet" ] && log_fail 5 ${MAXTEST} "Server status file";
	fi

	return $?
}

MAXTEST=5; export MAXTEST

testrun2 ()
{
    log_start "RUN CLIENT/SERVER"

    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    #
    SH_LOCALHOST=$1; export SH_LOCALHOST
    #
    testrun2_internal
    #
    log_end "RUN CLIENT/SERVER"

    return 0
}

