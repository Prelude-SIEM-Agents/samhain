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

SERVER_BUILDOPTS="--quiet  $TRUST --enable-xml-log --enable-debug --enable-network=server --prefix=$PW_DIR --localstatedir=$PW_DIR --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-logserver=${SH_LOCALHOST}  --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock --with-database=postgresql"; export SERVER_BUILDOPTS

CLIENT_BUILDOPTS="--quiet  $TRUST --prefix=$PW_DIR --with-tmp-dir=$PW_DIR --localstatedir=$PW_DIR --enable-network=client --disable-mail --disable-external-scripts --enable-login-watch --enable-xml-log --enable-db-reload --with-logserver=localhost --with-config-file=REQ_FROM_SERVER$PW_DIR/testrc_2 --with-data-file=REQ_FROM_SERVER$PW_DIR/.samhain_file --with-log-file=$PW_DIR/.samhain_log --with-pid-file=$PW_DIR/.samhain_lock"; export CLIENT_BUILDOPTS

create_pgpass () {
touch ~/.pgpass
chmod 600 ~/.pgpass
cat > ~/.pgpass << EOF
localhost:*:samhain:samhain:samhain
EOF
}

check_psql_log () {
    DATE="$1"

    rm -f test_log_db
    # PGPASSWORD=samhain; export PGPASSWORD
    create_pgpass
    psql -o test_log_db -U samhain -d samhain -c "SELECT * FROM log WHERE entry_status = 'NEW' and log_time > '${DATE}';"
    #
    egrep "START.*Yule" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Server start (psql)";
	return 1
    fi
    egrep "NEW CLIENT" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Client connect (psql)";
	return 1
    fi
    egrep "Checking.*/bin" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Client file check (psql)";
	return 1
    fi
    egrep "EXIT.*Samhain" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Client exit (psql)";
	return 1
    fi
    egrep "EXIT.*Yule.*SIGTERM" test_log_db >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "Server exit (psql)";
	return 1
    fi
    return 0
}

MAXTEST=1; export MAXTEST

testrun2d ()
{
    log_start "RUN FULL CLIENT/SERVER W/POSTGRESQL"
    #
    if [ -z "$doall" ]; then
	log_skip 1 $MAXTEST 'Client/server w/postgresql (or use --really-all)'
	return 0
    fi
    if [ x"$1" = x ]; then
	[ -z "$quiet" ] && log_msg_fail "Missing hostname"
    fi
    PSQL=`find_path psql`
    if [ -z "$PSQL" ]; then
	log_skip 1 $MAXTEST "psql not found";
	return 1
    else
	# PGPASSWORD="samhain"; export PGPASSWORD
	create_pgpass
	TEST=`psql -U samhain -d samhain -c "SELECT * FROM log LIMIT 1;" 2>/dev/null`
	if [ $? -ne 0 -o -z "$TEST" ]; then
	    log_skip 1 $MAXTEST "psql not default setup"
	    return 1
	fi
    fi
    #
    SH_LOCALHOST=$1; export SH_LOCALHOST
    #
    DATE=`date '+%Y-%m-%d %T'`
    #
    testrun2a_internal
    #
    for ff in ./rc.*; do
    ORIGINAL="SetUdpActive=no"
    REPLACEMENT="ReportCheckflags=yes"
    ex -s rc.morrigan.localdomain <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF
    done
    #
    ORIGINAL="DatabaseSeverity=none"
    REPLACEMENT="DatabaseSeverity=info"
    ex -s $RCFILE <<EOF
%s/$ORIGINAL/$REPLACEMENT/g
wq
EOF
    #
    do_test_1_a
    #
    if [ $? -ne 0 ]; then
	[ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client/server w/postgresql";
    else
    #
	check_psql_log "${DATE}"
	if [ $? -ne 0 ]; then
	    [ -z "$quiet" ] && log_fail 1 ${MAXTEST} "Client/server w/postgresql";
	else
	    [ -z "$quiet" ] && log_ok   1 ${MAXTEST} "Client/server w/postgresql";
	fi
    fi
    #
    if [ -n "$cleanup" ]; then
	rm -f ./rc.${SH_LOCALHOST}
	rm -f ./file.${SH_LOCALHOST}
	ALTHOST=`find_hostname`
	rm -f "./file.${ALTHOST}"
	rm -f "./rc.${ALTHOST}"
    fi
    #
    log_end "RUN FULL CLIENT/SERVER W/POSTGRESQL"
}

