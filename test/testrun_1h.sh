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

# --enable-login-watch --enable-xml-log 
# --enable-debug --enable-suidcheck --with-prelude

BUILDOPTS="--quiet $TRUST --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file --enable-debug"
export BUILDOPTS

BASE="${PW_DIR}/testrun_testdata"; export BASE
TDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c"; export TDIRS
TFILES="x y z"; export TFILES
TFILES_PART="c/miss c/add c/change c/leave"; export TFILES_PART

###########################################################
#
# ---- [Define tests here] ----
#

# 1 for testing new tests
testrun1_setup=0

MAXTEST=5; export MAXTEST

PARTIAL_OUTFILE=".samhain_file_partial"; export PARTIAL_OUTFILE
PARTIAL_FILTER="c/create c/miss c/change c/leave"; export PARTIAL_FILTER

TEST_PART_POLICY_1="
[ReadOnly]
dir=${BASE}
"
mod_testdata_partial_1 () {
    one_sec_sleep
    rm "${BASE}/a/a/c/x"   # delete 
}
EXPECT_1="nullok"

TEST_PART_POLICY_2="
[ReadOnly]
dir=${BASE}
"
mod_testdata_partial_2 () {
    one_sec_sleep
    echo "foobar" > "${BASE}/foo"   # new 
}
EXPECT_2="nullok"

TEST_PART_POLICY_3="
[ReadOnly]
dir=${BASE}
"
mod_testdata_partial_3 () {
    one_sec_sleep
    rm -f "${BASE}/c/miss"
}
EXPECT_3=""

TEST_PART_POLICY_4="
[ReadOnly]
dir=${BASE}
"
mod_testdata_partial_4 () {
    one_sec_sleep
    echo foo >"${BASE}/c/create"
}
EXPECT_4=""

TEST_PART_POLICY_5="
[ReadOnly]
dir=${BASE}
"
mod_testdata_partial_5 () {
    one_sec_sleep
    echo toodledoo >"${BASE}/c/change"
}
EXPECT_5=""

#
# $2 == "nullok" means no mods should be detected,
# else it is an error to detect no mods
#
run_check_partial_verify ()
{
    if [ "x$1" = "x"  ]; then
	logsev=debug
    else
	logsev=$1
    fi
    if ! test -f ${PARTIAL_OUTFILE}; then
	[ -z "$quiet" ]   && log_msg_fail  "missing ${PARTIAL_OUTFILE} ...";
	return 1
    fi

    rm -f test_log_valgrind

    ${VALGRIND} ./samhain -p =err --verify-database ${PARTIAL_OUTFILE} 2>>test_log_valgrind
 
    if test x$? = x0; then
	if [ "x$2" != "xnullok"  ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "check (1a)...";
	    return 1
	fi
    else
	if [ "x$2" = "xnullok"  ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "check (1b)...";
	    return 1
	fi
    fi

    LL=`wc -l test_log_valgrind | awk '{ print $1; }'`
    if ! test x$LL = x0; then
	[ -z "$quiet" ]   && log_msg_fail  "check (2)...";
	[ -z "$quiet" ]   && cat test_log_valgrind
	return 1
    fi
    
    [ -z "$verbose" ] || log_msg_ok    "check...";
}

run_update_partial_verify ()
{
    ${VALGRIND} ./samhain -t update -p none -l debug 2>>test_log_valgrind

    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "update...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "update...";
	return 1
    fi
}

run_check_after_update_partial ()
{
    rm -rf $LOGFILE

    run_check_partial_verify debug nullok
}

create_partial ()
{
    echo "${BASE}/c" > test_filter.txt
    for ff in ${TFILES_PART}; do
	echo "${BASE}/${ff}" >> test_filter.txt
    done

    ./samhain -o "${PARTIAL_OUTFILE}" --binary --list-filter=test_filter.txt --list-database=./.samhain_file

    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "create partial DB...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "create partial DB...";
	return 1
    fi

    if test -f "${PARTIAL_OUTFILE}"; then
	[ -z "$verbose" ] || log_msg_ok    "partial DB exists...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "partial DB exists...";
	return 1
    fi
    rm -f test_filter.txt
}

prep_partial_testpolicy ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    eval echo '"$'"TEST_PART_POLICY_$1"'"' >>"${RCFILE}"
}

prep_testdata_partial ()
{
    prep_testdata
    if test x$? = x0; then
	touch "${BASE}/c/miss"
	touch "${BASE}/c/change"
	touch "${BASE}/c/leave"
    else
	return 1
    fi
}

testrun_internal_partial_verify ()
{
	[ -z "$verbose" ] || echo Working directory: $PW_DIR
	[ -z "$verbose" ] || { echo MAKE is $MAKE; echo; }

	#
	# test standalone compilation
	#
	[ -z "$verbose" ] || { echo; echo "${S}Building standalone agent${E}"; echo; }

	if test -r "Makefile"; then
		$MAKE distclean >/dev/null 
	fi

	${TOP_SRCDIR}/configure ${BUILDOPTS} 

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

	[ -z "$verbose" ] || { echo; echo "${S}Running test suite${E}"; echo; }

	tcount=1
	POLICY=`eval echo '"$'"TEST_PART_POLICY_$tcount"'"'`

	until [ -z "$POLICY" ]
	do
	  prep_init
	  check_err $? ${tcount}; errval=$?
	  if [ $errval -eq 0 ]; then
	      prep_testdata_partial
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_partial_testpolicy   ${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_init
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      create_partial
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      eval mod_testdata_partial_${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      arg2=`eval echo '"$'"EXPECT_$tcount"'"'`
	      run_check_partial_verify debug $arg2
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $testrun1_setup -eq 0 ]; then
	      if [ $errval -eq 0 ]; then
		  run_update_partial_verify
		  check_err $? ${tcount}; errval=$?
	      fi
	      if [ $errval -eq 0 ]; then
		  create_partial
		  check_err $? ${tcount}; errval=$?
	      fi
	      if [ $errval -eq 0 ]; then
		  run_check_after_update_partial
		  check_err $? ${tcount}; errval=$?
	      fi
	  fi
	  #
	  if [ $errval -eq 0 ]; then
	      [ -z "$quiet" ] && log_ok ${tcount} ${MAXTEST};
	  fi
	  #
	  let "tcount = tcount + 1" >/dev/null
	  #
	  POLICY=`eval echo '"$'"TEST_PART_POLICY_$tcount"'"'`
	done
	    
	return 0
}

testrun1h ()
{
    log_start "RUN CL Partial DB Verify"
    testrun_internal_partial_verify
    log_end "RUN CL Partial DB Verify"
    return 0
}



