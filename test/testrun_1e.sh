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

BUILDOPTS="--quiet $TRUST --enable-debug=gdb --enable-xml-log --enable-port-check --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE --with-log-file=$LOGFILE --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
export BUILDOPTS

MAXTEST=5; export MAXTEST

PORTPOLICY_5="
[ReadOnly]
file=${BASE}
[PortCheck]
PortCheckActive = yes
PortCheckUDP = no
PortCheckInterface = 127.0.0.1
"

chk_portdata_5 () {
    one_sec_sleep

    if [ -z "$PM" ]; then
	log_skip 5 $MAXTEST 'prelude-manager not found in $PATH'
    elif [ -z "$doall" ]; then
	log_skip 5 $MAXTEST 'logging to prelude (or use --really-all)'
    else
	tmp=`egrep 'Service: port=5500 .unknown. protocol=tcp' test_log_prelude 2>/dev/null | wc -l`
	if [ $tmp -lt 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "port 5500";
	    [ -z "$quiet" ] && log_fail 5 ${MAXTEST};
	    return 1
	fi
    #
	[ -z "$quiet" ] && log_ok 5 ${MAXTEST};
    fi
    return 0
}

refine_portpolicy_5 ()
{
    echo "PortCheckIgnore=2026/tcp" >>"${RCFILE}"
    echo "PortCheckIgnore=2027/udp" >>"${RCFILE}"
    echo "PortCheckIgnore=2028/tcp" >>"${RCFILE}"
    echo "PortCheckIgnore=2029/udp" >>"${RCFILE}"    
}

PORTPOLICY_4="
[ReadOnly]
file=${BASE}
[PortCheck]
PortCheckActive = yes
PortCheckUDP = no
"

chk_portdata_4 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[ServiceNew\]' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || egrep 'CRIT.*POLICY \[ServiceNew\]' $LOGFILE
	[ -z "$verbose" ] || log_msg_fail "Open ports";
	return 1
    fi
}

refine_portpolicy_4 ()
{
    cat "$LOGFILE" | grep ServiceNew | sed 's/.*port: //' | awk '{ print $1 }' | \
    while read line; do
	echo "PortCheckSkip=$line" >>"${RCFILE}"
    done
    echo "PortCheckIgnore=2026/tcp" >>"${RCFILE}"
    echo "PortCheckIgnore=2027/udp" >>"${RCFILE}"
    echo "PortCheckIgnore=2028/tcp" >>"${RCFILE}"
    echo "PortCheckIgnore=2029/udp" >>"${RCFILE}"
}

PORTPOLICY_3="
[ReadOnly]
file=${BASE}
[PortCheck]
PortCheckActive = yes
PortCheckUDP = no
"

chk_portdata_3 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[ServiceNew\]' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	
	[ -z "$verbose" ] || log_msg_fail "Open ports";
	return 1
    fi
}

refine_portpolicy_3 ()
{
    cat "$LOGFILE" | grep ServiceNew | sed 's/.*port: //' | awk '{ print $1 }' | \
    while read line; do
	echo "PortCheckIgnore=$line" >>"${RCFILE}"
    done
    echo "PortCheckIgnore=2026/tcp" >>"${RCFILE}"
    echo "PortCheckIgnore=2027/udp" >>"${RCFILE}"
    echo "PortCheckIgnore=2028/tcp" >>"${RCFILE}"
    echo "PortCheckIgnore=2029/udp" >>"${RCFILE}"
}


PORTPOLICY_2="
[ReadOnly]
file=${BASE}
[PortCheck]
PortCheckActive = yes
PortCheckUDP = no
"

chk_portdata_2 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[ServiceNew\]' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	
	[ -z "$verbose" ] || log_msg_fail "Open ports";
	return 1
    fi
}

refine_portpolicy_2 ()
{
    cat "$LOGFILE" | grep ServiceNew | sed 's/.*port: //' | awk '{ print $1 }' | \
    while read line; do
	echo "PortCheckOptional=$line" >>"${RCFILE}"
    done
}

PORTPOLICY_1="
[ReadOnly]
file=${BASE}
[PortCheck]
PortCheckActive = yes
PortCheckUDP = no
"

chk_portdata_1 () {
    one_sec_sleep

    egrep 'CRIT.*POLICY \[ServiceNew\]' $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	
	[ -z "$verbose" ] || log_msg_fail "Open ports";
	return 1
    fi
}

refine_portpolicy_1 ()
{
    cat "$LOGFILE" | grep ServiceNew | sed 's/.*port: //' | awk '{ print $1 }' | \
    while read line; do
	echo "PortCheckRequired=$line" >>"${RCFILE}"
    done
}

prep_portpolicy ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    eval echo '"$'"PORTPOLICY_$1"'"' >>"${RCFILE}"
}

run_check_prelude()
{
    ./samhain -t check -p none -l info --set-prelude-severity=info --prelude --server-addr 127.0.0.1:5500 >/dev/null
 
    if test x$? = x0; then

	./samhain -j -L $LOGFILE >"${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "${LOGFILE}"

	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "mv logfile...";
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "check...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "check...";
	return 1
    fi
}


testrun_internal_1e ()
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

	POLICY=`eval echo '"$'"PORTPOLICY_$tcount"'"'`

	until [ -z "$POLICY" ]
	do
	  prep_init
	  check_err $? ${tcount}; errval=$?
	  if [ $errval -eq 0 ]; then
	      prep_testdata
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      prep_portpolicy   ${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_init
	      check_err $? ${tcount}; errval=$?
	  fi
	  #
	  if [ $errval -eq 0 ]; then
	      eval refine_portpolicy_${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  #
	  rm -f "$LOGFILE"
	  #
	  PRELUDEPID=0
	  #
	  if test ${tcount} -eq 5; 
	  then

	      PM=`find_path prelude-manager`

	      if [ -z "$PM" ]; then
		  if [ $errval -eq 0 ]; then
		      run_check
		      check_err $? ${tcount}; errval=$?
		  fi
	      elif [ -z "$doall" ]; then
		  if [ $errval -eq 0 ]; then
		      run_check
		      check_err $? ${tcount}; errval=$?
		  fi
	      else
		  #
		  #
		  ${TOP_SRCDIR}/configure ${BUILDOPTS} --with-prelude
		  #
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
		  #
		  #
		  if ! test -d /var/run/prelude-manager
		  then
		      [ -z "$verbose" ] || log_msg_ok    "create /var/run/prelude-manager...";
		      sudo mkdir /var/run/prelude-manager
		      sudo chown prelude:rainer /var/run/prelude-manager
		      sudo chmod 770 /var/run/prelude-manager
		  fi
		  if ! test -d /var/spool/prelude/samhain/global
		  then
		      [ -z "$verbose" ] || log_msg_ok    "create /var/spool/prelude/samhain/global...";
		      sudo mkdir -p /var/spool/prelude/samhain/global
		      sudo chown prelude:rainer /var/spool/prelude/samhain/global
		      sudo chmod 770 /var/spool/prelude/samhain/global
		  fi

		  #
		  #
		  [ -z "$verbose" ] || { echo " starting prelude-manager.."; echo " ($PM --textmod -l $PW_DIR/test_log_prelude --listen 127.0.0.1:5500 >/dev/null 2>&1 &)"; }
		  "$PM" --textmod -l $PW_DIR/test_log_prelude --listen 127.0.0.1:5500 >/dev/null 2>&1 &
		  PRELUDEPID=$!
		  #
		  #
		  five_sec_sleep
		  #
		  #
		  if [ $errval -eq 0 ]; then
		      run_check_prelude
		      check_err $? ${tcount}; errval=$?
		  fi
	      fi

	  else
	      if [ $errval -eq 0 ]; then
		  run_check
		  check_err $? ${tcount}; errval=$?
	      fi
	  fi
	  #
	  if [ $errval -eq 0 ]; then
	      eval chk_portdata_${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  #
	  if [ $errval -eq 0 ]; then
	      if test ${tcount} -ne 5; then
		  [ -z "$quiet" ] && log_ok ${tcount} ${MAXTEST};
	      fi
	  fi
	  let "tcount = tcount + 1" >/dev/null
	  POLICY=`eval echo '"$'"PORTPOLICY_$tcount"'"'`

	  if test $PRELUDEPID -ne 0;
	  then
	      kill $PRELUDEPID
	  fi

	done
	    
	return 0
}

testrun1e ()
{
    log_start "RUN STANDALONE W/PORTCHECK"
    testrun_internal_1e
    log_end "RUN STANDALONE W/PORTCHECK"
    return 0
}


