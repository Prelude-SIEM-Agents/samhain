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

BUILDOPTS="--quiet $TRUST --enable-xml-log --enable-suidcheck --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
export BUILDOPTS

MAXTEST=7; export MAXTEST

## Quarantine SUID/SGID files if found
#
# SuidCheckQuarantineFiles = yes

## Method for Quarantining files:
#  0 - Delete or truncate the file.
#  1 - Remove SUID/SGID permissions from file.
#  2 - Move SUID/SGID file to quarantine dir.
#
# SuidCheckQuarantineMethod = 0

## For method 0 and 2, really delete instead of truncating
# 
# SuidCheckQuarantineDelete = yes

SUIDPOLICY_7="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckExclude = ${BASE}/a/a
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = no
SuidCheckQuarantineMethod = 2
SuidCheckQuarantineDelete = yes
"

mod_suiddata_7 () {
    one_sec_sleep
    chmod 4444 "${BASE}/a/a/y"
    chmod 4444 "${BASE}/a/a/a/y"
    mkdir "${BASE}/a/abc"
    touch "${BASE}/a/abc/y"
    chmod 4444 "${BASE}/a/abc/y"
}

chk_suiddata_7 () {
    one_sec_sleep
    tmp=`ls -l "${BASE}/a/a/y" 2>/dev/null | awk '{ print $1}' | cut -c 1-10`
    if [ "x$tmp" = "x-r-Sr--r--" ]; then
	egrep "CRIT.*POLICY \[SuidCheck\].*${BASE}/a/a/y" $LOGFILE >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y";
	    return 1
	fi
	egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/y" $LOGFILE >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y";
	    return 1
	fi
    else
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (suid not kept)";
	return 1
    fi
    tmp=`ls -l "${BASE}/a/a/a/y" 2>/dev/null | awk '{ print $1}' | cut -c 1-10`
    if [ "x$tmp" = "x-r-Sr--r--" ]; then
	egrep "CRIT.*POLICY \[SuidCheck\].*${BASE}/a/a/a/y" $LOGFILE >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/a/y";
	    return 1
	fi
	egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/a/y" $LOGFILE >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/a/y";
	    return 1
	fi
    else
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/a/y (suid not kept)";
	return 1
    fi
    tmp=`ls -l "${BASE}/a/abc/y" 2>/dev/null | awk '{ print $1}' | cut -c 1-10`
    if [ "x$tmp" = "x-r-Sr--r--" ]; then
	egrep "CRIT.*POLICY \[SuidCheck\].*${BASE}/a/abc/y" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/abc/y";
	    return 1
	fi
	egrep "CRIT.*POLICY ADDED.*${BASE}/a/abc/y" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/abc/y";
	    return 1
	fi
	return 0;
    else
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/abc/y (suid not kept)";
	return 1
    fi
}


SUIDPOLICY_6="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = no
SuidCheckQuarantineMethod = 2
SuidCheckQuarantineDelete = yes
"

mod_suiddata_6 () {
    one_sec_sleep
    chmod 4755 "${BASE}/a/a/y"
}

chk_suiddata_6 () {
    one_sec_sleep
    tmp=`ls -l "${BASE}/a/a/y" 2>/dev/null | awk '{ print $1}' | cut -c 1-10`
    if [ "x$tmp" = "x-rwsr-xr-x" ]; then
	egrep "CRIT.*POLICY \[SuidCheck\].*${BASE}/a/a/y" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y";
	    return 1
	fi
	egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/y" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y";
	    return 1
	fi
	return 0;
    else
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (suid not kept)";
	return 1
    fi
}

SUIDPOLICY_5="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = yes
SuidCheckQuarantineMethod = 2
SuidCheckQuarantineDelete = yes
"

mod_suiddata_5 () {
    one_sec_sleep
    chmod 4755 "${BASE}/a/a/y"
}

chk_suiddata_5 () {
    one_sec_sleep
    if [ ! -f "${BASE}/a/a/x" ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/x (erroneously deleted)";
	return 1
    fi
    if [ -f "${BASE}/a/a/y" ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (not deleted)";
	return 1
    fi
    if [ -f .quarantine/y ]; then
	if [ -f .quarantine/y.info ]; then
	    return 0;
	else
	    [ -z "$verbose" ] || log_msg_fail ".quarantine/y.info (missing)";
	    return 1
	fi
    else
	[ -z "$verbose" ] || log_msg_fail ".quarantine/y (missing)";
	return 1
    fi
}

SUIDPOLICY_4="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = yes
SuidCheckQuarantineMethod = 2
SuidCheckQuarantineDelete = no
"

mod_suiddata_4 () {
    one_sec_sleep
    chmod 4755 "${BASE}/a/a/y"
}

chk_suiddata_4 () {
    one_sec_sleep
    tmp=`cat "${BASE}/a/a/y" 2>/dev/null | wc -c`
    if [ $tmp -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (not truncated)";
	return 1
    fi
    if [ -f .quarantine/y ]; then
	if [ -f .quarantine/y.info ]; then
	    return 0;
	else
	    [ -z "$verbose" ] || log_msg_fail ".quarantine/y.info (missing)";
	    return 1
	fi
    else
	[ -z "$verbose" ] || log_msg_fail ".quarantine/y (missing)";
	return 1
    fi
}

SUIDPOLICY_3="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = yes
SuidCheckQuarantineMethod = 1
SuidCheckQuarantineDelete = no
"

mod_suiddata_3 () {
    one_sec_sleep
    chmod 4755 "${BASE}/a/a/y"
}

chk_suiddata_3 () {
    one_sec_sleep
    tmp=`ls -l "${BASE}/a/a/y" 2>/dev/null | awk '{ print $1}' | cut -c 1-10`
    if [ "x$tmp" = "x-rwxr-xr-x" ]; then
	return 0;
    else
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (suid not removed)";
	return 1
    fi
}

SUIDPOLICY_2="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = yes
SuidCheckQuarantineMethod = 0
SuidCheckQuarantineDelete = no
"

mod_suiddata_2 () {
    one_sec_sleep
    chmod 4755 "${BASE}/a/a/y"
}

chk_suiddata_2 () {
    one_sec_sleep
    tmp=`cat "${BASE}/a/a/y" 2>/dev/null | wc -c`
    if [ $tmp -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (not truncated)";
	return 1
    fi
}

SUIDPOLICY_1="
[ReadOnly]
file=${BASE}
[SuidCheck]
SuidCheckActive = yes
SuidCheckInterval = 10
SeveritySuidCheck = crit
SuidCheckQuarantineFiles = yes
SuidCheckQuarantineMethod = 0
SuidCheckQuarantineDelete = yes
"

mod_suiddata_1 () {
    one_sec_sleep
    chmod 4755 "${BASE}/a/a/y"
}

chk_suiddata_1 () {
    one_sec_sleep
    if [ -f "${BASE}/a/a/y" ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y (not removed)";
	return 1
    fi
}

prep_suidpolicy ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    eval echo '"$'"SUIDPOLICY_$1"'"' >>"${RCFILE}"
    if [ "x$1" = "x5" ]; then
	chmod 4755 "${BASE}/a/a/x"
    fi
}

testrun_internal_1c ()
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
		$MAKE  'DBGDEF=-DSH_SUIDTESTDIR=\"${BASE}\"' >/dev/null 2>&1
		if test x$? = x0; then
		    [ -z "$verbose" ] || log_msg_ok "make DBGDEF=-DSH_SUIDTESTDIR=${BASE} ..."; 
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
	POLICY=`eval echo '"$'"SUIDPOLICY_$tcount"'"'`

	until [ -z "$POLICY" ]
	do
	  prep_init
	  check_err $? ${tcount}; errval=$?
	  if [ $errval -eq 0 ]; then
	      prep_testdata
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_suidpolicy   ${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_init
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      eval mod_suiddata_${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_check
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      eval chk_suiddata_${tcount}
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
	  #
	  if [ $errval -eq 0 ]; then
	      [ -z "$quiet" ] && log_ok ${tcount} ${MAXTEST};
	  fi
	  let "tcount = tcount + 1" >/dev/null
	  POLICY=`eval echo '"$'"SUIDPOLICY_$tcount"'"'`
	done
	    
	return 0
}

testrun1c ()
{
    log_start "RUN STANDALONE W/SUIDCHK"
    testrun_internal_1c
    log_end "RUN STANDALONE W/SUIDCHK"
    return 0
}

