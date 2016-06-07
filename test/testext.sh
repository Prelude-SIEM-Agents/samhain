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

MAXTEST=2; export MAXTEST

testext0 ()
{
        COMP=`which gcc`
	if test "x$?" = x1 ; then
	    COMP="cc"
	else
	    COMP=`which gcc | sed -e "s%\([a-z:]\) .*%\1%g"` 
	    if test "x$COMP" = x; then
		COMP="cc"
	    elif test "x$COMP" = xno; then
		COMP="cc"
	    else
	    if test "x$COMP" = "xwhich:"; then
		COMP="cc"
	    else
		COMP="gcc"
		gcc -v >/dev/null 2>&1 || COMP="gcc"
	    fi
	    fi
	fi
	log_start "EXTERNAL PROGRAM"
	[ -z "$verbose" ] || echo MAKE is $MAKE
	[ -z "$verbose" ] || { echo COMP is $COMP; echo; }
	#
	# standalone compilation
	#
	[ -z "$verbose" ] || { echo; echo "${S}Building standalone agent${E}"; echo; }
	#
	if test -r "Makefile"; then
	    ${MAKE} distclean >/dev/null
	fi
	#
	${TOP_SRCDIR}/configure --quiet --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$PW_DIR/testrc_1ext --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file 
	#
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
	#
	# prepare the program
	#
	cat test/test_ext.c.in | sed -e "s%MYPWDIR%$PW_DIR/test_ext.res%g" > test_ext.c
    
	${COMP} -o test_ext test_ext.c 
	if test "x$?" != x0; then
	    log_msg_fail "${COMP} -o test_ext test_ext.c"
	    return 1
	fi
	chmod +rx  test_ext
	if test "x$?" != x0; then
	    log_msg_fail "chmod +rx  test_ext"
	    return 1
	fi
    
	# compute checksum and fix config file
	#
	cp test/testrc_1ext.in testrc_1ext
	CHKSUM=`./samhain -H $PW_DIR/test_ext |  awk '{ print $2$3$4$5$6$7}'`
	echo "OpenCommand=$PW_DIR/test_ext" >> testrc_1ext
	echo "SetType=log"                  >> testrc_1ext
	echo "SetChecksum=$CHKSUM"          >> testrc_1ext
	echo "SetEnviron=TZ=Europe/Berlin"  >> testrc_1ext
	echo "SetFilterOr=ALERT"            >> testrc_1ext
	echo "CloseCommand"                 >> testrc_1ext
	echo "OpenCommand=$PW_DIR/test_ext" >> testrc_1ext
	echo "SetType=log"                  >> testrc_1ext
	echo "SetChecksum=$CHKSUM"          >> testrc_1ext
	echo "SetFilterOr=ALERT"            >> testrc_1ext
	echo "CloseCommand"                 >> testrc_1ext
    
	rm -f $PW_DIR/test_ext.res
	rm -f $PW_DIR/pdbg.child
	rm -f $PW_DIR/pdbg.main
	./samhain -p none
    
	# The shell is too fast ...
	one_sec_sleep
	[ -z "$verbose" ] || { 
	    echo; 
	    echo "${S}Logged by external C program test_ext (filtered: ALERT only):${E}"; 
	    echo;
	    cat $PW_DIR/test_ext.res
	    echo
	}

	tmp=`cat $PW_DIR/test_ext.res | wc -l`
	if [ $tmp -eq 8 ]; then
	    tmp=`egrep 'RECV: \[EOF\]' $PW_DIR/test_ext.res | wc -l`
	    if [ $tmp -eq 4 ]; then
		tmp=`egrep 'RECV: ALERT' $PW_DIR/test_ext.res | wc -l`
		if [ $tmp -eq 4 ]; then
		    log_ok 1 ${MAXTEST};
		else
		    log_fail 1 ${MAXTEST};
		fi
	    else
		log_fail 1 ${MAXTEST};
	    fi
	else
	    log_fail 1 ${MAXTEST};
	fi

	ORIGINAL="SetChecksum=${CHKSUM}"
	REPLACEMENT="SetChecksum=DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

	ex -s "$PW_DIR/testrc_1ext" <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF

	rm -f $PW_DIR/test_ext.res
	rm -f $PW_DIR/pdbg.child
	rm -f $PW_DIR/pdbg.main
	./samhain -p none
    
	one_sec_sleep

	if [ -f $PW_DIR/test_ext.res ]; then
	    log_fail 2 ${MAXTEST};
	else
	    log_ok   2 ${MAXTEST};
	fi

	rm -f $PW_DIR/.samhain_file
	rm -f $LOGFILE
	rm -f $PW_DIR/.samhain_lock

	log_end "EXTERNAL PROGRAM"
}

