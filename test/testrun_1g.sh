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

BUILDOPTS="--quiet $TRUST --enable-debug --enable-xml-log --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
export BUILDOPTS

MAXTEST=1; export MAXTEST

testrun_deltadb ()
{
    tcount=1

    if test -r "Makefile"; then
	$MAKE distclean >/dev/null 
    fi
    
    ${TOP_SRCDIR}/configure ${BUILDOPTS} 
    
    if test x$? = x0; then
	[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
	$MAKE  >/dev/null 2>>test_log
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

    prep_init
    check_err $? ${tcount}; errval=$?

    if [ $errval -eq 0 ]; then
	prep_testdata
	check_err $? ${tcount}; errval=$?
    fi
    if [ $errval -eq 0 ]; then
	prep_testpolicy   1
	check_err $? ${tcount}; errval=$?
    fi

    rm "${BASE}/a/a/b/x"
    rm -f file.*.*-*-*-*-*

    ./samhain --create-database=./tmp_list_file

    check_err $? ${tcount}; errval=$?
    if [ $errval -eq 0 ]; then
	num=$( ./samhain -a -d file.*.*-*-*-*-* | grep "1970-01-01T00:00:00" >/dev/null | wc -l )
	if [ $num -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_ok "list...";
	else
	    [ -z "$quiet" ] &&       log_msg_fail "list...";
	    log_fail ${tcount} ${MAXTEST};
	fi
    else
	[ -z "$quiet" ] &&       log_msg_fail "create...";
	log_fail ${tcount} ${MAXTEST};
    fi

    if [ $errval -eq 0 ]; then
	./samhain --verify-database file.*.*-*-*-*-*
    fi

    check_err $? ${tcount}; errval=$?
    if [ $errval -eq 0 ]; then
	echo "o_O" > "${BASE}/a/a/b/y"
	./samhain --verify-database file.*.*-*-*-*-*
    fi
    if [ $? -eq 0 ]; then
	[ -z "$quiet" ] &&       log_msg_fail "detect modify...";
	check_err 1 ${tcount}; errval=1
    fi

    if [ $errval -eq 0 ]; then
	[ -z "$quiet" ] && log_ok ${tcount} ${MAXTEST};
    fi

    [ -z "$cleanup" ] || rm -f file.*.*-*-*-*-*
    return 0
}

testrun1g ()
{
    log_start "RUN CL Create DeltaDB"

    testrun_deltadb

    log_end "RUN CL Create DeltaDB"
    return 0
}

