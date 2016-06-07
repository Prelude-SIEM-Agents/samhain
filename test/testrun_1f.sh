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

BUILDOPTS="--quiet $TRUST --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file --enable-debug --with-gpg=/usr/bin/gpg --with-keyid=0x8A0B337A  --with-fp=DCCBBB6625591ECE2B8F3AC94ED99E4E8A0B337A"
export BUILDOPTS

BASE="${PW_DIR}/testrun_testdata"; export BASE
TDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c"; export TDIRS
TFILES="x y z"; export TFILES

###########################################################
#
# ---- [Define tests here] ----
#

# 1 for testing new tests
testrun1_setup=0

MAXTEST=17; export MAXTEST

TESTPOLICY_17="
[ReadOnly]
dir=${BASE}
"
mod_testdata_17 () {
    one_sec_sleep
    rm "${BASE}/a/a/c/x"   # delete 
}

TESTPOLICY_16="
[ReadOnly]
dir=${BASE}
"
mod_testdata_16 () {
    one_sec_sleep
    echo "foobar" > "${BASE}/foo"   # new 
}

prep_sign_file ()
{
    scripts/samhainadmin.pl -s ./test/gnupg/ -m R $1 >/dev/null
    scripts/samhainadmin.pl -s ./test/gnupg/ -k 8A0B337A -m E $1 >/dev/null
}


run_check_CLverify ()
{
    if [ "x$1" = "x"  ]; then
	logsev=debug
    else
	logsev=$1
    fi
    if test -f ./.samhain_file; then
	mv ./.samhain_file ./.samhain_file_clverify
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "mv ./.samhain_file ...";
	    return 1
	fi
    else
	[ -z "$quiet" ]   && log_msg_fail  "test -f ./.samhain_file ...";
	return 1
    fi

    rm -f test_log_valgrind

    ${VALGRIND} ./samhain -p =err --verify-database ./.samhain_file_clverify 2>>test_log_valgrind
 
    if test x$? = x0; then
	if [ "x$2" != "xnullok"  ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "check (1)...";
	    return 1
	fi
    else
	if [ "x$2" = "xnullok"  ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "check (1)...";
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

run_update_CLverify ()
{
    if test -f ./.samhain_file_clverify; then
	mv ./.samhain_file_clverify ./.samhain_file
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "mv ./.samhain_file_clverify ...";
	    return 1
	fi
    else
	[ -z "$quiet" ]   && log_msg_fail  "test -f ./.samhain_file_clverify ...";
	return 1
    fi

    ${VALGRIND} ./samhain -t update -p none -l debug 2>>test_log_valgrind

    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "update...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "update...";
	return 1
    fi
}

run_check_after_update_CLverify ()
{
    rm -rf $LOGFILE

    run_check_CLverify debug nullok
}

testrun_internal_CLverify ()
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
	POLICY=`eval echo '"$'"TESTPOLICY_$tcount"'"'`

	until [ -z "$POLICY" ]
	do
	  prep_init
	  check_err $? ${tcount}; errval=$?
	  if [ $errval -eq 0 ]; then
	      prep_testdata
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_testpolicy   ${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_sign_file  "${RCFILE}"
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_init
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_sign_file  ./.samhain_file
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      eval mod_testdata_${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_check_CLverify
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $testrun1_setup -eq 0 ]; then
	      if [ $errval -eq 0 ]; then
		  prep_sign_file  "${RCFILE}"
		  check_err $? ${tcount}; errval=$?
	      fi
	      if [ $errval -eq 0 ]; then
		  run_update_CLverify
		  check_err $? ${tcount}; errval=$?
	      fi
	      if [ $errval -eq 0 ]; then
		  prep_sign_file  ./.samhain_file
		  check_err $? ${tcount}; errval=$?
	      fi
	      if [ $errval -eq 0 ]; then
		  run_check_after_update_CLverify
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
	  if [ $tcount -eq 10 ]; then
	      if [ -z "$doall" ]; then
		  log_skip 10 $MAXTEST 'ACL/SELinux test (or use --really-all)'
		  log_skip 11 $MAXTEST 'ACL/SELinux test (or use --really-all)'
		  let "tcount = tcount + 2" >/dev/null
	      else
		  # 'id -u' is posix
		  #
		  if test -f /usr/xpg4/bin/id
		  then
		      my_uid=`/usr/xpg4/bin/id -u`
		  else
		      my_uid=`id -u`
		  fi
		  #
		  if [ ${my_uid} -ne 0 ]; then
		      log_skip 10 $MAXTEST 'ACL/SELinux test (you are not root)'
		      log_skip 11 $MAXTEST 'ACL/SELinux test (you are not root)'
		      let "tcount = tcount + 2" >/dev/null
		  else

		      SETFATTR=`find_path setfattr`
		      if [ -z "$SETFATTR" ]; then
			  log_skip 10 $MAXTEST 'ACL/SELinux test (setfattr not in path)'
			  log_skip 11 $MAXTEST 'ACL/SELinux test (setfattr not in path)'
			  let "tcount = tcount + 2" >/dev/null
		      fi
		  fi
	      fi
	  fi
	  #
	  POLICY=`eval echo '"$'"TESTPOLICY_$tcount"'"'`
	done
	    
	return 0
}

testrun1f ()
{
    log_start "RUN CL Verify"
    gpg --list-keys | grep 8A0B337A >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	echo "You need to do 'gpg --import test/gnupg/public-key.asc' first"
	for ff in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do
	    log_skip $ff $MAXTEST 'CL verify'
	done
    else
	testrun_internal_CLverify
    fi
    log_end "RUN CL Verify"
    return 0
}



