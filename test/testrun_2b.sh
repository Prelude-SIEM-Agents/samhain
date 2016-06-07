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
RCFILE_C="$PW_DIR/testrc_1.dyn";  export RCFILE_C

SERVER_BUILDOPTS="--quiet  $TRUST  --enable-network=server --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-logserver=${SH_LOCALHOST}  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock"; export SERVER_BUILDOPTS

CLIENT_BUILDOPTS="--quiet  $TRUST --enable-micro-stealth=137 --enable-debug --enable-network=client --enable-srp --prefix=$PW_DIR --with-tmp-dir=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER${RCFILE_C} --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-logserver=localhost  --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock"; export CLIENT_BUILDOPTS

testrun2b_internal ()
{
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

    ${TOP_SRCDIR}/configure --with-gpg=${GPG} --with-checksum=no ${CLIENT_BUILDOPTS} >/dev/null 2>&1

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
    
    SKIP=`awk '/^__ARCHIVE_FOLLOWS__/ { print NR + 1; exit 0; }' ${SCRIPTDIR}/test.sh`
    
    tail -n "+$SKIP" ${SCRIPTDIR}/test.sh >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	tail -n "+$SKIP" ${SCRIPTDIR}/test.sh | gunzip -c - 2>/dev/null | tar xf - &&  \
	    mv "./testrc.gpg.asc" "${RCFILE_C}"
    else
	tail "+$SKIP" ${SCRIPTDIR}/test.sh | gunzip -c - 2>/dev/null | tar xf - &&  \
	    mv "./testrc.gpg.asc" "${RCFILE_C}"
    fi
    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "extract gpg signed files...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "extract gpg signed files...";
	return 1
    fi

    # save binary and build server

    cp samhain samhain.build || return 1
    $MAKE clean >/dev/null || return 1
    
    ${TOP_SRCDIR}/configure ${SERVER_BUILDOPTS}

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

    
    cp    "${RCFILE_C}"              ./rc.${SH_LOCALHOST}
    mv    $PW_DIR/.samhain_file.asc  ./file.${SH_LOCALHOST}

    ALTHOST=`find_hostname`
    cp    "${RCFILE_C}"          "./rc.${ALTHOST}"
    cp    ./file.${SH_LOCALHOST} "./file.${ALTHOST}" 2>/dev/null
}

MAXTEST=1; export MAXTEST

testrun2b ()
{
    log_start "RUN FULL CLIENT/SERVER W/GPG";
    #
    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    #
    GPG=`find_path gpg`
    if [ -z "$GPG" ]; then
	log_skip 1 $MAXTEST 'gpg not found in $PATH'
    else
	eval "$GPG" --list-keys 0F571F6C >/dev/null 2>/dev/null
	if [ $? -ne 0 ]; then
	    log_skip 1 $MAXTEST 'public PGP key 0x0F571F6C not present'
	else
	    
	    SH_LOCALHOST=$1; export SH_LOCALHOST
    
	    testrun2b_internal "$GPG"

	    SAVE_VALGRIND="${VALGRIND}"; VALGRIND=''; export VALGRIND
	    do_test_1_a
	    VALGRIND="${SAVE_VALGRIND}"; export VALGRIND 
	    if [ $? -eq 0 ]; then
		[ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Client download+logging w/gpg";
	    else
		[ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client download+logging w/gpg";
	    fi
    
	    if [ -n "$cleanup" ]; then
		rm -f ./rc.${SH_LOCALHOST}
		rm -f ./file.${SH_LOCALHOST}
		ALTHOST=`find_hostname`
		rm -f "./file.${ALTHOST}"
		rm -f "./rc.${ALTHOST}"
	    fi
	fi
    fi
    log_end "RUN FULL CLIENT/SERVER W/GPG"
}

