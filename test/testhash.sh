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

MAXTEST=2; export MAXTEST

testhash ()
{
	log_start "HASH FUNCTION"

	C_LOGFILE=""

	ls /lib/libpcre* >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    C_LOGFILE=" --enable-logfile-monitor "
	else
	    ls /usr/lib/libpcre* >/dev/null 2>&1
	    if [ $? -eq 0 ]; then
		C_LOGFILE=" --enable-logfile-monitor "
	    else
                ls /usr/lib/*/libpcre* >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    C_LOGFILE=" --enable-logfile-monitor "
                else
                    ls /usr/local/lib/libpcre* >/dev/null 2>&1
                    if [ $? -eq 0 ]; then
                        C_LOGFILE=" --enable-logfile-monitor "
                    fi
                fi
	    fi
	fi
	if [ x"${C_LOGFILE}" = x ]; then
	    log_msg_ok  "Not testing  --enable-logfile-monitor";
	fi

	#
	# test standalone compilation
	#
	TEST="${S}standalone agent${E}"
	#
	if test -r "Makefile"; then
		$MAKE distclean
	fi
	#
	${TOP_SRCDIR}/configure --enable-debug=gdb --quiet $TRUST --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file --enable-db-reload '--enable-login-watch' '--enable-mounts-check' ${C_LOGFILE} '--enable-port-check' '--enable-process-check' '--enable-message-queue' '--enable-suidcheck' '--disable-dnmalloc'
	#
	fail=0
	#
	if test x$? = x0; then
		[ -z "$verbose" ] || log_msg_ok  "configure...";
		$MAKE  > /dev/null 2>> test_log
		if test x$? = x0; then
		    [ -z "$verbose" ] || log_msg_ok "make...";
 		else
		    [ -z "$quiet" ] &&   log_msg_fail "make...";
		    fail=1
		fi
	else
		[ -z "$quiet" ] && log_msg_fail "configure...";
		fail=1
	fi
	#
	if [ $fail -eq 1 ]; then
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST};
	    return 1
	fi
	#
	echo "Test results of the TIGER hash algorithm" > testhash.tmp
	echo >> testhash.tmp
	echo "(use samhain -H string to test)" >> testhash.tmp
	echo >> testhash.tmp
	./samhain -H "" >> testhash.tmp
	./samhain -H "abc" >> testhash.tmp
	./samhain -H "Tiger" >> testhash.tmp
	./samhain -H "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-" >> testhash.tmp
	./samhain -H "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789" >> testhash.tmp
	./samhain -H "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham" >> testhash.tmp
	./samhain -H "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge." >> testhash.tmp
	./samhain -H "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996." >> testhash.tmp
	./samhain -H "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-" >> testhash.tmp
	#
	RESU=`diff testhash.tmp ${SCRIPTDIR}/testtiger.txt 2>/dev/null`
	if test "x${RESU}" = "x"; then
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST};
	else
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST};
	    return 1
	fi
        #
        #
        #
        TEST="${S}files${E}"
        #
        case $SCRIPTDIR in
            /*)
                testpath="${SCRIPTDIR}/testtiger.txt";;
            *)
                testpath="`pwd`/${SCRIPTDIR}/testtiger.txt";;
        esac
        #
        RESU=`./samhain -H ${testpath}`
        #
        if test x"$RESU" = x"${testpath}: 8125E439 4E7E20F9 24FD8E37  BC4D90C7 FC67F40C 1681F05D"; then
            [ -z "$quiet" ] && log_ok   2 ${MAXTEST};
        else
            [ -z "$quiet" ] && log_fail 2 ${MAXTEST};
            return 1
        fi
        #
	log_end "HASH FUNCTION"
	return 0
}



