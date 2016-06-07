#! /bin/sh

#
# Copyright Rainer Wichmann (2015)
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

SERVER_BUILDOPTS="--quiet  $TRUST --enable-network=server --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-logserver=${SH_LOCALHOST}  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --enable-debug=gdb --enable-static"; export SERVER_BUILDOPTS

CLIENT_BUILDOPTS="--quiet  $TRUST --enable-network=client --enable-srp --prefix=$PW_DIR --with-tmp-dir=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$RCFILE --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file  --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --enable-static"; export CLIENT_BUILDOPTS

TEST_DIRS="one two three four"
TEST_FILES="change leave rmthis"
BASE="/tmp/testrun_samhain"

TEST_LIST="./tmp_list_file"

ALTHOST=`find_hostname`

PROC_S=0; export PROC_S
PROC_Y=0; export PROC_Y

mod_files ()
{
    rm -f "${TEST_LIST}"
    touch "${TEST_LIST}"
    #
    for dd in ${TEST_DIRS}; do
	echo "changed" > "${BASE}/$dd/change"
	rm -f "${BASE}/$dd/rmthis"
	echo "added" > "${BASE}/$dd/addedthis"
	echo "${BASE}/$dd"           >> "${TEST_LIST}"
	echo "${BASE}/$dd/change"    >> "${TEST_LIST}"
	echo "${BASE}/$dd/rmthis"    >> "${TEST_LIST}"
	echo "${BASE}/$dd/addedthis" >> "${TEST_LIST}"
    done
}

do_test_2_g_yule_start () {

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
	    echo "${S}Start Client${E}: ./samhain.new -t check -D .. &"; 
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

	return 0
}

do_test_2_g_two () {

	#
	# >>> Modify files
	#
	mod_files
	#
	if ! test -f ${TEST_LIST}; then
	    [ -z "$verbose" ] || log_msg_fail "No file list created";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	#
	#
	# >>> Trigger a scan
	#
	kill -TTOU $PROC_S
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Kill -TTOU";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	for ff in 1 2 3; do
	    five_sec_sleep
	done
	NR=$( egrep "File check completed" $LOGFILE | wc -l )
	if [ $NR -ne 2 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (2)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "sigttou";

	NR=$( egrep "POLICY" $LOGFILE | grep ReadOnly | wc -l )
	if [ $NR -ne 8 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (ReadOnly)";  
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	NR=$( egrep "POLICY" $LOGFILE | grep ADDED | wc -l )
	if [ $NR -ne 4 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (added)";  
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	NR=$( egrep "POLICY" $LOGFILE | grep MISSING | wc -l )
	if [ $NR -ne 4 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Client file check (removed)";  
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	kill $PROC_S; 
	kill $PROC_Y;
	return 0
}

do_test_2_g_one () {

	#
	# >>> (1) Modify files, create DeltaDB from file list in ${TEST_LIST}
	#
	mod_files
	#
	if ! test -f ${TEST_LIST}; then
	    [ -z "$verbose" ] || log_msg_fail "No file list created";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	#
	./samhain.new --outfile ./file.delta --create-database "${TEST_LIST}"
	#
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Create DeltaDB";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	if ! test -f ./file.delta; then
	    [ -z "$verbose" ] || log_msg_fail "No DeltaDB created";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	#
	# >>> (2) Copy to server and tag with a UUID
	#
	UUID=$(uuidgen)
	mv ./file.delta file.${SH_LOCALHOST}.${UUID}
	cp file.${SH_LOCALHOST}.${UUID} "./file.${ALTHOST}.${UUID}"
	
	#
	# >>> (3) Tell client to load delta database.
	# >>>     testrc_2: timestamps every 10 sec
	#
	grep '^SetLoopTime=10$' rc.${SH_LOCALHOST} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "SetLoopTime != 10 in rc.${SH_LOCALHOST}";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	grep '^SetLoopTime=10$' rc.${ALTHOST} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "SetLoopTime != 10 in rc.${ALTHOST}";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	./yulectl -c "DELTA:${UUID}" ${SH_LOCALHOST}
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (1)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	./yulectl -c "DELTA:${UUID}" ${ALTHOST}
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (2)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	NR=$( ./yulectl -c LIST | grep ${UUID} | grep -v grep | wc -l )
	if [ $NR -ne 2 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (3)";
	    [ -z "$verbose" ] || ./yulectl -c LIST
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	# Wait and verify that command has been sent
	#
	for tt in 1 2 3 4; do
	    five_sec_sleep
	done
	#
	NR=$( ./yulectl -c LIST | grep ${UUID} | grep -v grep | wc -l )
	if [ $NR -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (4)";
	    [ -z "$verbose" ] || ./yulectl -c LISTALL
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	#
	# >>> (4) Trigger a scan
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

	# --- The End ---

	kill $PROC_S; 
	kill $PROC_Y
	return 0
}

do_test_2_g_three () {

	#
	# >>> (1) Modify files, create DeltaDB from file list in ${TEST_LIST}
	#
	mod_files
	#
	if ! test -f ${TEST_LIST}; then
	    [ -z "$verbose" ] || log_msg_fail "No file list created";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	#
	./samhain.new --outfile ./file.delta --create-database "${TEST_LIST}"
	#
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "Create DeltaDB";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	if ! test -f ./file.delta; then
	    [ -z "$verbose" ] || log_msg_fail "No DeltaDB created";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	#
	# >>> (2) Copy to server and tag with a UUID
	#
	UUID=$(uuidgen)
	if [ x"$1" != "xnosig" ]; then
	    scripts/samhainadmin.pl -s ./test/gnupg/ -k 8A0B337A -m E ./file.delta >/dev/null
	fi
	if [ x"$1" == "xnodelta" ]; then
	    rm -f ./file.*
	else
	    mv ./file.delta file.${SH_LOCALHOST}.${UUID}
	    cp file.${SH_LOCALHOST}.${UUID} "./file.${ALTHOST}.${UUID}"
	fi
	
	#
	# >>> (3) Tell client to load delta database.
	# >>>     testrc_2: timestamps every 10 sec
	#
	grep '^SetLoopTime=10$' rc.${SH_LOCALHOST} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "SetLoopTime != 10 in rc.${SH_LOCALHOST}";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	grep '^SetLoopTime=10$' rc.${ALTHOST} >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "SetLoopTime != 10 in rc.${ALTHOST}";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	./yulectl -c "DELTA:${UUID}" ${SH_LOCALHOST}
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (1)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	./yulectl -c "DELTA:${UUID}" ${ALTHOST}
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (2)";
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi
	NR=$( ./yulectl -c LIST | grep ${UUID} | grep -v grep | wc -l )
	if [ $NR -ne 2 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (3)";
	    [ -z "$verbose" ] || ./yulectl -c LIST
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	# Wait and verify that command has been sent
	#
	for tt in 1 2 3 4; do
	    five_sec_sleep
	done
	#
	NR=$( ./yulectl -c LIST | grep ${UUID} | grep -v grep | wc -l )
	if [ $NR -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "yulectl (4)";
	    [ -z "$verbose" ] || ./yulectl -c LISTALL
	    kill $PROC_S; kill $PROC_Y;
	    return 1
	fi

	#
	# >>> (4) Trigger a scan
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
	if [ x"$1" != x ]; then
	    if [ x"$1" = xnodelta ]; then
		NR=$( egrep "File download failed" $LOGFILE | wc -l )
	    else
		NR=$( egrep "No good signature" $LOGFILE | wc -l )
	    fi
	    if [ $NR -ne 1 ]; then
		[ -z "$verbose" ] || log_msg_fail "Client file check (expected fail)";
		kill $PROC_S; kill $PROC_Y;
		return 1
	    else
		[ -z "$verbose" ] || log_msg_ok "Client file check (expected fail)";
		kill $PROC_S; kill $PROC_Y;
		return 0
	    fi
	fi

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

	# --- The End ---

	kill $PROC_S; 
	kill $PROC_Y
	return 0
}

testrun2g_prepare ()
{
	#####################################################################
	#
	# Create test area and initialize database
	#
	rm -f ./.samhain_file
	rm -f ./.samhain_log
	rm -f ./.samhain_lock
	rm -f ./rc.${SH_LOCALHOST}
	rm -f ./rc.${ALTHOST}
	rm -f ./file.*
	#
	rm -rf ${BASE}
	#
	mkdir ${BASE} 2>/dev/null
	for dd in ${TEST_DIRS}; do
	    mkdir ${BASE}/$dd
	    for ff in ${TEST_FILES}; do
		echo "foobar" > ${BASE}/$dd/$ff
	    done
	done
	#
	./samhain.build -t init -p none

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "init...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "init...";
	    return 1
	fi
}

testrun2g_build ()
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
	${TOP_SRCDIR}/configure ${CLIENT_BUILDOPTS} $1 $2 >/dev/null 2>&1
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
	
	cp ${SCRIPTDIR}/testrc_2.in testrc_2
	#
	sed --in-place -e 's,file = /tmp,dir = 99/tmp/testrun_samhain,g' testrc_2
	# 
	sed --in-place -e 's,SetUdpActive=no,ReportCheckflags=yes,g' testrc_2
	#
 	echo $SHCLT1 >> testrc_2
 	echo $SHCLT2 >> testrc_2

	echo $SHPW > ./testpw
}

testrun2g_signrc ()
{
    scripts/samhainadmin.pl -s ./test/gnupg/ -m R $1 >/dev/null
    scripts/samhainadmin.pl -s ./test/gnupg/ -k 8A0B337A -m E $1 >/dev/null
}

testrun2g_signdb ()
{
    scripts/samhainadmin.pl -s ./test/gnupg/ -k 8A0B337A -m E ./.samhain_file >/dev/null
}

copy_rc_db_files ()
{
	cp    ./testrc_2       ./rc.${SH_LOCALHOST}
	mv    ./.samhain_file  ./file.${SH_LOCALHOST}
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "No .samhain_file";
	    return 1
	fi
	chmod 644 ./rc.${SH_LOCALHOST}
	chmod 644 ./file.${SH_LOCALHOST}

	cp    ./testrc_2       "./rc.${ALTHOST}"
	cp    ./file.${SH_LOCALHOST} "./file.${ALTHOST}" 2>/dev/null
	chmod 644 ./rc.${ALTHOST}
	chmod 644 ./file.${ALTHOST}
}

MAXTEST=6; export MAXTEST

testrun2g ()
{
    log_start "RUN CLIENT/SERVER CASE TWO";
    #
    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    #
    SH_LOCALHOST=$1; export SH_LOCALHOST
    #


    # Test with missing delta
    #
    gpg --list-keys | grep 8A0B337A >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	echo "You need to do 'gpg --import test/gnupg/public-key.asc' first"
	log_skip 1 $MAXTEST 'Case Two w/signed files'
    else
	testrun2g_build "--with-gpg=/usr/bin/gpg" "--with-keyid=0x8A0B337A"
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "build..";
	    testrun2g_signrc ./testrc_2
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign rc..";
	    testrun2g_prepare
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "prepare..";
	    testrun2g_signdb
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign db..";
	    copy_rc_db_files
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "copy..";
	    do_test_2_g_yule_start
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "start yule..";
	    do_test_2_g_three nodelta
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Case Two w/missing delta";
	else
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Case Two w/missing delta";
	fi
    fi

    # Test with unsigned delta
    #
    gpg --list-keys | grep 8A0B337A >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	echo "You need to do 'gpg --import test/gnupg/public-key.asc' first"
	log_skip 1 $MAXTEST 'Case Two w/signed files'
    else
	testrun2g_build "--with-gpg=/usr/bin/gpg" "--with-keyid=0x8A0B337A"
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "build..";
	    testrun2g_signrc ./testrc_2
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign rc..";
	    testrun2g_prepare
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "prepare..";
	    testrun2g_signdb
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign db..";
	    copy_rc_db_files
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "copy..";
	    do_test_2_g_yule_start
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "start yule..";
	    do_test_2_g_three nosig
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Case Two w/unsigned delta";
	else
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Case Two w/unsigned delta";
	fi
    fi

    # Test with signed files, no sig client
    #
    gpg --list-keys | grep 8A0B337A >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	echo "You need to do 'gpg --import test/gnupg/public-key.asc' first"
	log_skip 1 $MAXTEST 'Case Two w/signed files'
    else
	testrun2g_build
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "build..";
	    testrun2g_signrc ./testrc_2
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign rc..";
	    testrun2g_prepare
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "prepare..";
	    testrun2g_signdb
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign db..";
	    copy_rc_db_files
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "copy..";
	    do_test_2_g_yule_start
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "start yule..";
	    do_test_2_g_three
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Case Two w/signed files+nosig client";
	else
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Case Two w/signed files+nosig client";
	fi
    fi

    # Test with signed files
    #
    gpg --list-keys | grep 8A0B337A >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	echo "You need to do 'gpg --import test/gnupg/public-key.asc' first"
	log_skip 1 $MAXTEST 'Case Two w/signed files'
    else
	testrun2g_build "--with-gpg=/usr/bin/gpg" "--with-keyid=0x8A0B337A"
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "build..";
	    testrun2g_signrc ./testrc_2
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign rc..";
	    testrun2g_prepare
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "prepare..";
	    testrun2g_signdb
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "sign db..";
	    copy_rc_db_files
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "copy..";
	    do_test_2_g_yule_start
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_ok    "start yule..";
	    do_test_2_g_three
	fi
	if [ $? -eq 0 ]; then
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Case Two w/signed files";
	else
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Case Two w/signed files";
	fi
    fi

    # Test with non-signed files
    #
    testrun2g_build
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "build..";
	testrun2g_prepare
    fi
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "prepare..";
	copy_rc_db_files
    fi
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "copy..";
	do_test_2_g_yule_start
    fi
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "start yule..";
	do_test_2_g_one
    fi
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   2 ${MAXTEST} "Case Two w/unsigned files";
    else
	[ -z "$quiet" ] && log_fail 2 ${MAXTEST} "Case Two w/unsigned files";
    fi



    #
    testrun2g_prepare
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "prepare..";
	copy_rc_db_files
    fi
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "copy..";
	do_test_2_g_yule_start
    fi
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_ok    "start yule..";
	do_test_2_g_two
    fi
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] && log_ok   3 ${MAXTEST} "Case Two w/o delta";
    else
	[ -z "$quiet" ] && log_fail 3 ${MAXTEST} "Case Two w/o delta";
    fi


    log_end "RUN CLIENT/SERVER CASE TWO"
}
