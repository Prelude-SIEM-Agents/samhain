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

PREBUILDOPTS="--quiet $TRUST --enable-debug --enable-static --enable-xml-log --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
export PREBUILDOPTS

MAXTEST=1; export MAXTEST

testrun_stealth ()
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

    CONVERT=`find_path convert`
    if [ x"$CONVERT" = x ]; then
	[ -z "$verbose" ] || log_msg_fail "ImageMagick convert not found";
	return 1
    fi
    "$CONVERT" --help | grep  ImageMagick >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Convert utility is not ImageMagick convert";
	return 1
    fi
    "${CONVERT}" +compress stealth_template.jpg stealth_template.ps
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Converting stealth_template.jpg failed";
	return 1
    fi
    
    $MAKE samhain_stealth >/dev/null 2>>test_log
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "make samhain_stealth";
	return 1
    fi
    capacity=`./samhain_stealth -i stealth_template.ps | awk '{ print $7 }'`

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

    if [ $errval -eq 0 ]; then
	fill=`cat "${RCFILE}" | wc -c`
	check_err $? ${tcount}; errval=$?
    fi
    if [ $errval -eq 0 ]; then
	let "capacity = capacity - fill" >/dev/null
	let "capacity = capacity - 100" >/dev/null
	until [ "$capacity" -le 0 ]
	  do
	  echo "###############################" >>"${RCFILE}"
	  let "capacity = capacity - 32" >/dev/null
	done

	./samhain_stealth -s stealth_template.ps "${RCFILE}" >/dev/null
	check_err $? ${tcount}; errval=$?
    fi
    if [ $errval -eq 0 ]; then
	cp stealth_template.ps "${RCFILE}"
	check_err $? ${tcount}; errval=$?
    fi

    if [ $errval -eq 0 ]; then
	run_init
	check_err $? ${tcount}; errval=$?
    fi
    if [ $errval -eq 0 ]; then
	eval mod_testdata_1
	check_err $? ${tcount}; errval=$?
    fi
    if [ $errval -eq 0 ]; then
	run_check
	check_err $? ${tcount}; errval=$?
    fi
    if [ $errval -eq 0 ]; then
	eval chk_testdata_1
	check_err $? ${tcount}; errval=$?
    fi
    if [ $testrun1_setup -eq 0 ]; then
	if [ $errval -eq 0 ]; then
	    run_update
	    check_err $? ${tcount}; errval=$?
	fi
	if [ $errval -eq 0 ]; then
	    run_check_after_update
	    check_err $? ${tcount}; errval=$?
	fi
    fi

    if [ $errval -eq 0 ]; then
	[ -z "$quiet" ] && log_ok ${tcount} ${MAXTEST};
    fi
    return 0
}

testrun1a ()
{
    log_start "RUN STANDALONE W/STEALTH"
    #
    # micro-stealth
    #
    #BUILDOPTS="$PREBUILDOPTS --enable-micro-stealth=137"; export BUILDOPTS
    #testrun_internal

    CONVERT=`find_path convert`
    if [ x"$CONVERT" = x ]; then
	log_skip 1 ${MAXTEST} "ImageMagick convert not found";
	return 0
    fi
    BUILDOPTS="$PREBUILDOPTS --enable-stealth=137"; export BUILDOPTS
    testrun_stealth
    check_err $? ${tcount};
    log_end "RUN STANDALONE W/STEALTH"
    return 0
}

