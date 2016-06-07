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

BUILDOPTS="--quiet $TRUST --enable-xml-log --enable-process-check --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
export BUILDOPTS

MAXTEST=3; export MAXTEST

PROCPOLICY_3="
[ReadOnly]
file=${BASE}
[ProcessCheck]
ProcessCheckActive = yes
ProcessCheckPsPath = ${PW_DIR}/${SCRIPTDIR}/testrun_1d.sh
ProcessCheckPsArg = --fake
ProcessCheckMaxPid = 67000
"

chk_procdata_3 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[Process\] Fake pid: 66666[[:space:]]' $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Fake pid";
	return 1
    fi
    egrep 'CRIT.*POLICY \[Process\] Fake pid: [012345789]+[[:space:]]' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Fake pids incorrect";
	return 1
    fi
}

PROCPOLICY_2="
[ReadOnly]
file=${BASE}
[ProcessCheck]
ProcessCheckActive = yes
"

chk_procdata_2 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[Process\] Hidden pid' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Hidden pids (ps)";
	return 1
    fi
}


PROCPOLICY_1="
[ReadOnly]
file=${BASE}
[ProcessCheck]
ProcessCheckActive = yes
ProcessCheckPsPath = ${PW_DIR}/${SCRIPTDIR}/testrun_1d.sh
ProcessCheckPsArg = --hide
"


chk_procdata_1 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[Process\] Hidden pid: [[:digit:]][[:space:]]' $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Hidden pids";
	return 1
    fi
    egrep 'CRIT.*POLICY \[Process\] Hidden pid: [[:digit:]][[:digit:]]+[[:space:]]' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Hidden pids incorrect";
	return 1
    fi
}

prep_procpolicy ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    eval echo '"$'"PROCPOLICY_$1"'"' >>"${RCFILE}"
}

testrun_internal_1d ()
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

	tcount=1
	${TOP_SRCDIR}/configure ${BUILDOPTS} 

	#
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
		$MAKE >/dev/null 2>&1
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

	POLICY=`eval echo '"$'"PROCPOLICY_$tcount"'"'`

	until [ -z "$POLICY" ]
	do
	  prep_init
	  check_err $? ${tcount}; errval=$?
	  if [ $errval -eq 0 ]; then
	      prep_testdata
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_procpolicy   ${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_init
	      check_err $? ${tcount}; errval=$?
	  fi
	  for iseq in 0 1 2 3 4 5 6 7 8 9; do
	      rm -f "$LOGFILE"
	      if [ $errval -eq 0 ]; then
		  run_check info
		  check_err $? ${tcount}; errval=$?
	      fi
	      if [ $errval -eq 0 ]; then
		  eval chk_procdata_${tcount}
		  check_err $? ${tcount}; errval=$?
	      fi
	  done
	  #
	  if [ $errval -eq 0 ]; then
	      [ -z "$quiet" ] && log_ok ${tcount} ${MAXTEST};
	  fi
	  let "tcount = tcount + 1" >/dev/null
	  POLICY=`eval echo '"$'"PROCPOLICY_$tcount"'"'`

	done
	    
	return 0
}

testrun1d ()
{
    log_start "RUN STANDALONE W/PROCESSCHECK"
    testrun_internal_1d
    log_end "RUN STANDALONE W/PROCESSCHECK"
    return 0
}

proc_pspath ()
{
    PS=ps
    for ff in /usr/ucb /bin /usr/bin; do
	if test -x "$ff/ps"; then
	    PS="$ff/ps"
	    break
	fi
    done
    echo "$PS"
}

proc_psarg ()
{
    OS=`uname -s`
    case $OS in
	*Linux*|*linux*)
	    PSARG="-eT";;
        *OpenBSD*)
            PSARG="akx";;
	*)
	    PS=`proc_pspath`
	    $PS ax >/dev/null 2>&1
	    if test $? -eq 0; then
		one=`$PS ax | wc -l`
	    else
		one=0
	    fi
	    $PS -e >/dev/null 2>&1
	    if test $? -eq 0; then
		two=`$PS -e | wc -l`
	    else
		two=0
	    fi
	    if test $one -ge $two 
		then
		PSARG="ax"
	    else
		PSARG="-e"
	    fi
	    ;;
    esac
    echo "$PSARG"
}

proc_hide()
{
    PSPATH=`proc_pspath`
    PSARG=`proc_psarg`

    "${PSPATH}" "${PSARG}" | egrep -v '^[[:space:]]*[[:digit:]]{1}[[:space:]]+'
}

proc_fake()
{
    FAKE_PID=2
    PSPATH=`proc_pspath`
    PSARG=`proc_psarg`

    "${PSPATH}" "${PSARG}"
    if [ x"${PSARG}" = x-eT ]; then
	echo "66666 66666 pts/2    S      0:14 THIS_IS_FAKE"
    else
	echo "66666 pts/2    S      0:14 THIS_IS_FAKE"
    fi
}

if [ "x$1" = "x--hide" ]; then
    proc_hide;
    exit 0;
fi

if [ "x$1" = "x--fake" ]; then
    proc_fake;
    exit 0;
fi

