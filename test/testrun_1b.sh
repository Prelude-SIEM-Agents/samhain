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

MAXTEST=7; export MAXTEST
LOGFILE="$PW_DIR/.samhain_log"; export LOGFILE
RCFILE="$PW_DIR/testrc_1.dyn";  export RCFILE

testrun1b_modrc ()
{
        ORIGINAL="\[EOF\]"
        REPLACEMENT="\[PortCheck\]"
        ex -s $RCFILE <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF

        echo "PortCheckActive = yes" >>"$RCFILE"
        echo "PortCheckInterface = 127.0.0.1" >>"$RCFILE"
}

testrun1b_internal ()
{
	BUILDOPTS="$1"
	#
	# test standalone compilation
	#
	[ -z "$verbose" ] || { echo; echo "${S}Building standalone agent${E}"; echo; }
	#
	if test -r "Makefile"; then
		$MAKE distclean >/dev/null >&1
	fi
	#
	# Bootstrapping
	#
	${TOP_SRCDIR}/configure >/dev/null 2>/dev/null
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure (bootstrap)..."; 
		$MAKE  > /dev/null 2>&1
		if test x$? = x0; then
		    [ -z "$verbose" ] || log_msg_ok "make (bootstrap)..."; 
		else
		    [ -z "$quiet" ] &&   log_msg_fail "make (bootstrap)..."; 
		    return 1
		fi

	else
		[ -z "$quiet" ] &&       log_msg_fail "configure (bootstrap)...";
		return 1
	fi
	#
	#
	${TOP_SRCDIR}/configure ${BUILDOPTS} 2>/dev/null | \
	    egrep 'use existing [./[:alnum:]]+ for gpg checksum' >/dev/null
	#
	#
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
		$MAKE  > /dev/null 2>&1
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
		mv "./testrc.gpg.asc" "$RCFILE"
	else
	    tail "+$SKIP" ${SCRIPTDIR}/test.sh | gunzip -c - 2>/dev/null | tar xf - &&  \
		mv "./testrc.gpg.asc" "$RCFILE"
	fi
	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "extract gpg signed files...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "extract gpg signed files...";
	    return 1
	fi

	if test "x$2" = "x"; then
	    :
	else
	    CONVERT="$2"
	    if test -f "${TOP_SRCDIR}/stealth_template.jpg"; then
		[ -z "$verbose" ] || log_msg_ok "convert..."
		"${CONVERT}" +compress "${TOP_SRCDIR}/stealth_template.jpg" stealth_template.ps >/dev/null
	    else
		[ -z "$quiet" ]   && log_msg_fail  "cannot find file stealth_template.jpg"
		return 1
	    fi
	    if [ $? -ne 0 ]; then
		[ -z "$quiet" ]   && log_msg_fail  "${CONVERT} +compress ${TOP_SRCDIR}/stealth_template.jpg stealth_template.ps";
		return 1
	    fi

	    [ -z "$verbose" ] || log_msg_ok "hide..."
	    ./samhain_stealth -s stealth_template.ps "$RCFILE" >/dev/null
	    if [ $? -ne 0 ]; then
		[ -z "$quiet" ]   && log_msg_fail  "${CONVERT} +compress ${TOP_SRCDIR}/stealth_template.jpg stealth_template.ps";
		return 1
	    fi

	    mv -f stealth_template.ps "$RCFILE"
	    if [ $? -ne 0 ]; then
		[ -z "$quiet" ]   && log_msg_fail  "mv -f stealth_template.ps $RCFILE";
		return 1
	    fi

	fi

	rm -f ./.samhain_file
	rm -f ./.samhain_log
	rm -f ./.samhain_lock

	./samhain -t init -p none -l info

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "init...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "init...";
	    return 1
	fi

	mv $PW_DIR/.samhain_file.asc $PW_DIR/.samhain_file
}

testrun1b_nogpg ()
{
	BUILDOPTS="$1"
	#
	# test standalone compilation
	#
	[ -z "$verbose" ] || { echo; echo "${S}Building standalone agent${E}"; echo; }
	#
	if test -r "Makefile"; then
		$MAKE distclean >/dev/null >&1
	fi

	${TOP_SRCDIR}/configure ${BUILDOPTS} 2>/dev/null 
        #
	#
	if test x$? = x0; then
		[ -z "$verbose" ] ||     log_msg_ok "configure..."; 
		$MAKE  > /dev/null 2>&1
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

	rm -f ./.samhain_file
	rm -f ./.samhain_log
	rm -f ./.samhain_lock

	cp "${SCRIPTDIR}/testrc_1" "${RCFILE}"

	if test "x$2" = "xmodrc"; then
	    [ -z "$verbose" ] || log_msg_ok    "mod rc...";
	    testrun1b_modrc
	fi

	./samhain -t init -p none -l info

	if test x$? = x0; then
	    [ -z "$verbose" ] || log_msg_ok    "init...";
	else
	    [ -z "$quiet" ]   && log_msg_fail  "init...";
	    return 1
	fi

}

do_test_1b () {

    ./samhain -t check -p none -l info
    
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
    #
    tmp=`egrep "Checking.*/etc(>|\")" $LOGFILE 2>/dev/null | wc -l`
    if [ $tmp -ne 2 ]; then
	[ -z "$verbose" ] || log_msg_fail "/etc";
	return 1
    fi
    tmp=`egrep "Checking.*(>|\")" $LOGFILE 2>/dev/null | wc -l`
    if [ $tmp -ne 10 ]; then
	[ -z "$verbose" ] || log_msg_fail "checking";
	return 1
    fi
    egrep "ADDED" $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "init was incomplete";
	return 1
    fi
    #
    return 0
}

do_test_1b_2 () {

    rm -f $PW_DIR/test_log_prelude

    [ -z "$verbose" ] || { echo " starting prelude-manager.."; echo " ($PM --textmod -l $PW_DIR/test_log_prelude --listen 127.0.0.1:5500 >/dev/null 2>&1 &)"; }
    "$PM" --textmod -l $PW_DIR/test_log_prelude --listen 127.0.0.1:5500 >/dev/null 2>&1 &
    PID=$!

    five_sec_sleep

    ./samhain -t check -p none -l info --set-prelude-severity=info --prelude --server-addr 127.0.0.1:5500 >/dev/null
    
    if test x$? = x0; then
	./samhain -j -L $LOGFILE >"${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "${LOGFILE}"
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ]   && log_msg_fail  "mv logfile...";
	    kill $PID
	    return 1
	fi
	[ -z "$verbose" ] || log_msg_ok    "check...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "check...";
	kill $PID
	return 1
    fi
    #
    tmp=`egrep 'File original:.*name=etc.*path=/etc' test_log_prelude 2>/dev/null | wc -l`
    if [ $tmp -lt 1 ]; then
	[ -z "$verbose" ] || log_msg_fail "/etc";
	kill $PID
	return 1
    fi
    tmp=`egrep 'Classification text: Checking' test_log_prelude 2>/dev/null | wc -l`
    if [ $tmp -lt 1 ]; then
	[ -z "$verbose" ] || log_msg_fail "checking";
	kill $PID
	return 1
    fi
    #
    if test "x$2" = "xmodrc"; then
	tmp=`egrep 'Classification text: Service opened' test_log_prelude 2>/dev/null | wc -l`
	if [ $tmp -lt 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "service";
	    kill $PID
	    return 1
	fi
	tmp=`egrep 'Service: port=5500' test_log_prelude 2>/dev/null | wc -l`
	if [ $tmp -lt 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "port 5500";
	    kill $PID
	    return 1
	fi
    fi
    #
    kill $PID
    return 0
}

testrun1b ()
{
    log_start "RUN STANDALONE W/STEALTH W/GPG"
    GPG=`find_path gpg`
    if [ -z "$GPG" ]; then
	log_skip 1 $MAXTEST 'gpg not found in $PATH'
	log_skip 2 $MAXTEST 'gpg not found in $PATH'
	log_skip 3 $MAXTEST 'gpg not found in $PATH'
	log_skip 4 $MAXTEST 'gpg not found in $PATH'
	log_skip 5 $MAXTEST 'gpg not found in $PATH'
	log_skip 6 $MAXTEST 'gpg not found in $PATH'
	log_skip 7 $MAXTEST 'gpg not found in $PATH'
    else
	eval "$GPG" --list-keys 0F571F6C >/dev/null 2>/dev/null
	if [ $? -ne 0 ]; then
	    log_skip 1 $MAXTEST 'public PGP key 0x0F571F6C not present'
	    log_skip 2 $MAXTEST 'public PGP key 0x0F571F6C not present'
	    log_skip 3 $MAXTEST 'public PGP key 0x0F571F6C not present'
	    log_skip 4 $MAXTEST 'public PGP key 0x0F571F6C not present'
	    log_skip 5 $MAXTEST 'public PGP key 0x0F571F6C not present'
	    log_skip 6 $MAXTEST 'public PGP key 0x0F571F6C not present'
	    log_skip 7 $MAXTEST 'public PGP key 0x0F571F6C not present'
	else
	    #
	    # -------------  first test -------------
	    #
	    BUILDOPTS="--quiet $TRUST --enable-debug --with-gpg=${GPG} --enable-micro-stealth=137 --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
	    testrun1b_internal "${BUILDOPTS}" 
	    do_test_1b
	    if [ $? -eq 0 ]; then
		log_ok   1 $MAXTEST 'gpg signed config/database files'
	    else
		log_fail 1 $MAXTEST 'gpg signed config/database files'
	    fi


	    #
	    # -------------  second test -------------
	    #
	    BUILDOPTS="--quiet $TRUST --enable-debug --with-gpg=${GPG} --with-checksum --enable-micro-stealth=137 --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
	    testrun1b_internal "${BUILDOPTS}" 
	    do_test_1b
	    if [ $? -eq 0 ]; then
		log_ok   2 $MAXTEST 'gpg signed config/database files'
	    else
		log_fail 2 $MAXTEST 'gpg signed config/database files'
	    fi


	    #
	    # -------------  third test -------------
	    #
	    BUILDOPTS="--quiet $TRUST --enable-debug --with-gpg=${GPG} --with-checksum --with-fp=EF6CEF54701A0AFDB86AF4C31AAD26C80F571F6C --enable-micro-stealth=137 --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
	    testrun1b_internal "${BUILDOPTS}" 
	    do_test_1b
	    if [ $? -eq 0 ]; then
		log_ok   3 $MAXTEST 'gpg signed config/database files'
	    else
		log_fail 3 $MAXTEST 'gpg signed config/database files'
	    fi


	    #
	    # -------------  fourth test -------------
	    #
	    PRECONV=`find_path convert`
	    "${PRECONV}" --help | grep  ImageMagick >/dev/null 2>&1 && \
 		CONVERT="${PRECONV}"

	    if [ -z "$CONVERT" ]; then
		log_skip 2 $MAXTEST 'ImageMagick convert not found in $PATH'
	    else
		BUILDOPTS="--quiet $TRUST --enable-debug --with-gpg=${GPG} --with-checksum --enable-stealth=137 --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
		testrun1b_internal "${BUILDOPTS}" "$CONVERT"
		do_test_1b
		if [ $? -eq 0 ]; then
		    log_ok   4 $MAXTEST 'gpg signed config/database files'
		else
		    log_fail 4 $MAXTEST 'gpg signed config/database files'
		fi
	    fi


	    #
	    # -------------  fifth test -------------
	    #
	    if ! test -d /var/run/prelude-manager
	    then
		    [ -z "$verbose" ] || log_msg_ok    "create /var/run/prelude-manager...";
		    sudo mkdir /var/run/prelude-manager
		    sudo chown prelude:rainer /var/run/prelude-manager
		    sudo chmod 770 /var/run/prelude-manager
	    fi
	    #
	    PM=`find_path prelude-manager`
	    if [ -z "$PM" ]; then
		log_skip 5 $MAXTEST 'prelude-manager not found in $PATH'
	    elif [ -z "$doall" ]; then
		log_skip 5 $MAXTEST 'logging to prelude (or use --really-all)'
	    else
		BUILDOPTS="--quiet $TRUST --enable-debug --with-prelude --with-gpg=${GPG} --with-checksum --enable-micro-stealth=137 --enable-login-watch --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
		testrun1b_internal "${BUILDOPTS} CFLAGS=-DSH_NOFAILOVER=1"
		do_test_1b_2
		if [ $? -eq 0 ]; then
		    log_ok   5 $MAXTEST 'logging to prelude'
		else
		    log_fail 5 $MAXTEST 'logging to prelude'
		fi
	    fi

	    #
	    # -------------  sixth test -------------
	    #
	    if ! test -d /var/run/prelude-manager
	    then
		    [ -z "$verbose" ] || log_msg_ok    "create /var/run/prelude-manager...";
		    sudo mkdir /var/run/prelude-manager
		    sudo chown prelude:rainer /var/run/prelude-manager
		    sudo chmod 770 /var/run/prelude-manager
	    fi
	    #
	    PM=`find_path prelude-manager`
	    if [ -z "$PM" ]; then
		log_skip 6 $MAXTEST 'prelude-manager not found in $PATH'
	    elif [ -z "$doall" ]; then
		log_skip 6 $MAXTEST 'logging to prelude (or use --really-all)'
	    else
		BUILDOPTS="--quiet $TRUST --with-prelude --enable-login-watch --enable-mounts-check --enable-process-check --enable-port-check --enable-suidcheck --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
		testrun1b_nogpg "${BUILDOPTS} CFLAGS=-DSH_NOFAILOVER=1"
		do_test_1b_2
		if [ $? -eq 0 ]; then
		    log_ok   6 $MAXTEST 'logging to prelude'
		else
		    log_fail 6 $MAXTEST 'logging to prelude'
		fi
	    fi

	    #
	    # -------------  seventh test -----------
	    #
	    if ! test -d /var/run/prelude-manager
	    then
		    [ -z "$verbose" ] || log_msg_ok    "create /var/run/prelude-manager...";
		    sudo mkdir /var/run/prelude-manager
		    sudo chown prelude:rainer /var/run/prelude-manager
		    sudo chmod 770 /var/run/prelude-manager
	    fi
	    #
	    PM=`find_path prelude-manager`
	    if [ -z "$PM" ]; then
		log_skip 7 $MAXTEST 'prelude-manager not found in $PATH'
	    elif [ -z "$doall" ]; then
		log_skip 7 $MAXTEST 'logging to prelude (or use --really-all)'
	    else
		BUILDOPTS="--quiet $TRUST --with-prelude --enable-login-watch --enable-mounts-check --enable-process-check --enable-port-check --enable-suidcheck --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=$RCFILE  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-data-file=$PW_DIR/.samhain_file"
		testrun1b_nogpg "${BUILDOPTS} CFLAGS=-DSH_NOFAILOVER=1" "modrc"
		do_test_1b_2
		if [ $? -eq 0 ]; then
		    log_ok   7 $MAXTEST 'logging to prelude'
		else
		    log_fail 7 $MAXTEST 'logging to prelude'
		fi
	    fi

	fi
    fi
    log_end "RUN STANDALONE W/STEALTH W/GPG"
    return 0
}

