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

###########################################################
#
# ---- [Define tests here] ----
#

# 1 for testing new tests
testrun1_setup=0

MAXTEST=15; export MAXTEST
MAXTEST_3=15; export MAXTEST_3

test_dirs () {
    for ff in $CDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	fi
	#
    done
    for ff in $NDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -eq 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
    done
}


TESTPOLICY_15="
[Misc]
DigestAlgo=SHA1
RedefReadOnly = +TXT
[ReadOnly]
dir=${BASE}
"
mod_testdata_15 () {
    mod_testdata_1
}
chk_testdata_15 () {
    chk_testdata_1
}

TESTPOLICY_14="
[Misc]
DigestAlgo=MD5
RedefReadOnly = +TXT
[ReadOnly]
dir=${BASE}
"
mod_testdata_14 () {
    mod_testdata_1
}
chk_testdata_14 () {
    chk_testdata_1
}

# 
# combine file check schedule with one-shot mode 
# 
TESTPOLICY_13="
[ReadOnly]
dir=99${BASE}
"

mod_testdata_13 () {
    one_sec_sleep 
    echo "foobar" >"${BASE}/c/x"; # bad
    chmod 0555  "${BASE}/a/y";    # bad
    ORIGINAL='SetFilecheckTime=60'
    REPLACEMENT='FileCheckScheduleOne = 6 12 * * *'
    ex -s $RCFILE <<EOF
%s/${ORIGINAL}/${REPLACEMENT}/g
wq
EOF
}

chk_testdata_13 () {
    # CDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 2 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/c/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] -----M--T-.*${BASE}/a/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/y";
	return 1
    fi
    CDIRS="a a/a a/b a/c c b a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    NDIRS="";
    test_dirs;
    return $?
}

TESTPOLICY_12="
[ReadOnly]
dir=99${BASE}
[IgnoreAll]
dir=-1${BASE}/b
[Attributes]
dir=1${BASE}/a
"

mod_testdata_12 () {
    one_sec_sleep
    echo "foobar" >"${BASE}/b/x"; # ok
    echo "foobar" >"${BASE}/c/x"; # bad
    echo "foobar" >"${BASE}/a/x"; # ok
    chmod 0555  "${BASE}/a/a/x";  # bad
    chmod 0555  "${BASE}/a/a/a/x";# ok
    chmod 0555  "${BASE}/a/y";    # bad
}

chk_testdata_12 () {
    # CDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 3 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/c/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/a/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/y";
	return 1
    fi
    CDIRS="a a/a a/b a/c c";
    NDIRS="b a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    test_dirs;
    return $?
}

#
# --- ACL/SELinux test case
#
TESTPOLICY_11="
[Misc]
UseAclCheck=yes
UseSelinuxCheck=yes
[ReadOnly]
dir=99${BASE}
[IgnoreAll]
dir=-1${BASE}/b
[Attributes]
dir=1${BASE}/a
[Misc]
UseSelinuxCheck = no
UseAclCheck = no
"

mod_testdata_11 () {
    one_sec_sleep
    setfacl -m 'user:nobody:r--' "${BASE}/b/x"; # ok (ign)
    setfacl -m 'user:nobody:r--' "${BASE}/c/x"; # bad
    setfacl -m 'user:nobody:r--' "${BASE}/a/x"; # bad
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/b/y";    # ok (ign)
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/a/a/a/x";# ok (depth)
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/a/x";    # bad
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/a/y";    # bad
}

chk_testdata_11 () {
    # CDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 1 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] --------T-.*${BASE}/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/c/x";
	return 1
    fi
    CDIRS="a a/a a/b a/c c";
    NDIRS="b a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    test_dirs;
    return $?
}

TESTPOLICY_10="
[Misc]
UseAclCheck=yes
UseSelinuxCheck=yes
[ReadOnly]
dir=99${BASE}
[IgnoreAll]
dir=-1${BASE}/b
[Attributes]
dir=1${BASE}/a
"

mod_testdata_10 () {
    one_sec_sleep
    setfacl -m 'user:nobody:r--' "${BASE}/b/x"; # ok (ign)
    setfacl -m 'user:nobody:r--' "${BASE}/c/x"; # bad
    setfacl -m 'user:nobody:r--' "${BASE}/a/x"; # bad
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/b/y";    # ok (ign)
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/a/a/a/x";# ok (depth)
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/a/x";    # bad
    setfattr -n 'security.selinux' -v "system_u:object_r:etc_t\000" "${BASE}/a/y";    # bad
}

chk_testdata_10 () {
    # CDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 5 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] -----M--T-.*${BASE}/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/c/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/y";
	return 1
    fi
    CDIRS="a a/a a/b a/c c";
    NDIRS="b a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    test_dirs;
    return $?
}

TESTPOLICY_9="
[ReadOnly]
dir=0${BASE}/b
[Attributes]
dir=2${BASE}/a/a
"

mod_testdata_9 () {
    echo "foobar" >"${BASE}/b/x"; 
    echo "foobar" >"${BASE}/a/x"; 
    echo "foobar" >"${BASE}/x"; 
}

chk_testdata_9 () {
    # CDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 1 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    CDIRS="b a/a a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    NDIRS="a c a/b a/c";
    test_dirs;
    return $?
}

TESTPOLICY_8="
[ReadOnly]
dir=1${BASE}
[Attributes]
dir=1${BASE}/a/a
"

mod_testdata_8 () { 
    echo "foobar" >"${BASE}/a/x"; 
    chmod 0555 "${BASE}/a/a/a/b/x"; 
}

chk_testdata_8 () {
    # CDIRS="a b c a/a a/b a/c a/a/a a/a/b a/a/c a/a/a/a a/a/a/b a/a/a/c";
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 1 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    CDIRS="a b c a/a a/a/a a/a/b a/a/c";
    NDIRS="a/b a/c a/a/a/a a/a/a/b a/a/a/c";
    test_dirs;
    return $?
}


TESTPOLICY_7="
[ReadOnly]
dir=${BASE}
[Attributes]
dir=${BASE}/a/a
[GrowingLogFiles]
dir=${BASE}/a/a/a
[IgnoreAll]
file=${BASE}/a/a/a/z
dir=${BASE}/b
[Misc]
IgnoreMissing=${BASE}/a/[[:alnum:]]+/[[:alnum:]]+\$
IgnoreAdded=${BASE}/a/(b|c)/[[:alnum:]]+\$
"

mod_testdata_7 () {
    one_sec_sleep 
    echo "foobar" >"${BASE}/a/a/a/z" # ok
    echo "foobar" >"${BASE}/a/a/a/x" # bad
    echo "foobar" >"${BASE}/a/a/x"   # ok
    echo "foobar" >"${BASE}/a/x"     # bad
    chmod 0555     "${BASE}/a"       # bad
    chmod 0555     "${BASE}/b"       # ok

    rm    "${BASE}/a/c/z"
    touch "${BASE}/a/c/zz2"
}


chk_testdata_7 () {
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 4 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    egrep "ERROR.*POLICY MISSING.*${BASE}/a/c/z" $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/c/z";
	return 1
    fi
    egrep "CRIT.*POLICY ADDED.*${BASE}/a/c/zz2" $LOGFILE >/dev/null 2>&1
    if [ $? -eq 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/c/zz2";
	return 1
    fi
    egrep "CRIT.*POLICY \[GrowingLogs\] C--------S.*${BASE}/a/a/a/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/a/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] -----M--T-.*${BASE}/a" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/a/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/x";
	return 1
    fi
}


TESTPOLICY_6="
[ReadOnly]
dir=${BASE}
[Attributes]
file=${BASE}/a/y
file=${BASE}/b/y
file=${BASE}/c/y
file=${BASE}/a/a/y
file=${BASE}/a/b/y
file=${BASE}/a/c/y
file=${BASE}/a/a/a/y
file=${BASE}/a/a/b/y
file=${BASE}/a/a/c/y
file=${BASE}/a/a/a/a/y
file=${BASE}/a/a/a/b/y
file=${BASE}/a/a/a/c/y
"

mod_testdata_6 () {
    one_sec_sleep
    for ff in $TDIRS; do
	echo "foobar" >"${BASE}/${ff}/x"
	chmod 0555     "${BASE}/${ff}/y"
	echo "foobar" >"${BASE}/${ff}/z"
    done
}

chk_testdata_6 () {
    count6=0
    for ff in $TDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	fi
	#
	for gg in $TFILES; do
	    egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (checking)";
	    fi
	    tmp=`egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE 2>/dev/null | wc -l`
	    if [ $tmp -ne 1 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (multiple)";
	    fi
	done
	egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/${ff}/x" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/x";
	    return 1
	fi
	let "count6 = count6 + 1" >/dev/null
	egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/${ff}/z" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/z";
	    return 1
	fi
	let "count6 = count6 + 1" >/dev/null
	egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/${ff}/y" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/y";
	    return 1
	fi
	let "count6 = count6 + 1" >/dev/null
    done
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne $count6 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
}

TESTPOLICY_5="
[Attributes]
dir=${BASE}
file=${BASE}/a/a/c/x
[ReadOnly]
file=${BASE}/a/a/c/y
[GrowingLogFiles]
dir=${BASE}/a/a/c
dir=${BASE}/a/a/b
dir=${BASE}/a/b
"

mod_testdata_5 () {
    mod_testdata_4
    echo "1 This is a xxxx file" > "${BASE}/a/a/b/x"     # GrowingLogFiles
    echo "1 This is a test file" > "${BASE}/a/a/b/y"     # GrowingLogFiles
    echo "2 This is a test file" >> "${BASE}/a/a/b/y"    # GrowingLogFiles
    echo "1 This is a xxxx file bad" > "${BASE}/a/a/b/z" # GrowingLogFiles
    echo "2 This is a xxxx file bad" >>"${BASE}/a/a/b/z" # GrowingLogFiles
    echo "3 This is a xxxx file bad" >>"${BASE}/a/a/b/z" # GrowingLogFiles
}

chk_testdata_5 () {
    for ff in $TDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	fi
	#
	for gg in $TFILES; do
	    egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (checking)";
	    fi
	    tmp=`egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE 2>/dev/null | wc -l`
	    if [ $tmp -ne 1 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (multiple)";
	    fi
	done
    done
    egrep "CRIT.*POLICY \[GrowingLogs\] C---------.*${BASE}/a/a/b/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/b/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[GrowingLogs\] C---------.*${BASE}/a/a/b/z" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/b/z";
	return 1
    fi
    egrep "CRIT.*POLICY \[GrowingLogs\] -----M----.*${BASE}/a/b/z" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/z";
	return 1
    fi
    egrep "CRIT.*POLICY \[GrowingLogs\] -----M----.*${BASE}/a/a/c/z" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/z";
	return 1
    fi
    egrep "CRIT.*POLICY \[GrowingLogs\] C--------S.*${BASE}/a/b/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/y";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/a/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/x";
	return 1
    fi
    egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/c/foo" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/foo";
	return 1
    fi
    egrep "CRIT.*POLICY ADDED.*033\[1;30m" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/\033[1;30m";
	return 1
    fi
    egrep "WARN.*Weird filename.*033\[1;30m" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/\033[1;30m";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/a/a/c/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/y";
	return 1
    fi
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 9 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
}


TESTPOLICY_4="
[Attributes]
dir=${BASE}
file=${BASE}/a/a/c/x
[ReadOnly]
file=${BASE}/a/a/c/y
[LogFiles]
dir=${BASE}/a/a/c
dir=${BASE}/a/b
"

mod_testdata_4 () {
    one_sec_sleep
    echo "foobar" >> "${BASE}/a/a/x"    # Attributes
    echo "foobar" > "${BASE}/a/a/c/foo" # new within LogFiles
    echo "foobar" >> "${BASE}/a/a/c/y"  # ReadOnly
    echo "foobar" >> "${BASE}/a/a/c/x"  # Attributes
    chmod 0555 "${BASE}/a/a/c/x"        # Attributes
    chmod 0555 "${BASE}/a/a/c/z"        # LogFiles
    echo "foobar" >> "${BASE}/a/b/x"    # LogFiles
    echo ""       >  "${BASE}/a/b/y"    # LogFiles
    chmod 0555 "${BASE}/a/b/z"          # LogFiles
    touch "${BASE}/a/a/[1;30m"        # non-printable character in filename
}

chk_testdata_4 () {
    for ff in $TDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	fi
	#
	for gg in $TFILES; do
	    egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (checking)";
	    fi
	    tmp=`egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE 2>/dev/null | wc -l`
	    if [ $tmp -ne 1 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (multiple)";
	    fi
	done
    done
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/a/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[LogFiles\] -----M----.*${BASE}/a/b/z" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/z";
	return 1
    fi
    egrep "CRIT.*POLICY \[LogFiles\] -----M----.*${BASE}/a/a/c/z" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/z";
	return 1
    fi
    egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/c/foo" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/foo";
	return 1
    fi
    egrep "CRIT.*POLICY ADDED.*033\[1;30m" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/\033[1;30m";
	return 1
    fi
    egrep "WARN.*Weird filename.*033\[1;30m" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/\033[1;30m";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/a/a/c/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/y";
	return 1
    fi
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 6 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
}

TESTPOLICY_3="
[Attributes]
dir=${BASE}
file=${BASE}/a/a/c/x
[ReadOnly]
file=${BASE}/a/a/c/y
[IgnoreAll]
dir=${BASE}/a/a/c
"
mod_testdata_3 () {
    one_sec_sleep
    echo "foobar" > "${BASE}/a/b/foo"   # new within Attributes
    chmod 0555 "${BASE}/a/b"
    echo "foobar" > "${BASE}/a/a/c/foo" # new within IgnoreAll
    echo "foobar" > "${BASE}/a/a/c/y"   # ReadOnly
    chmod 0555 "${BASE}/a/a/c/x"        # Attributes
    chmod 0555 "${BASE}/a/a/c/z"        # IgnoreAll
}

chk_testdata_3 () {
    for ff in $TDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	fi
	#
	for gg in $TFILES; do
	    egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (checking)";
	    fi
	    tmp=`egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE 2>/dev/null | wc -l`
	    if [ $tmp -ne 1 ]; then
		[ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (multiple)";
	    fi
	done
    done
    egrep "CRIT.*POLICY ADDED.*${BASE}/a/b/foo" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/foo";
	return 1
    fi
    egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/c/foo" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/foo";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/b" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b";
	return 1
    fi
    egrep "CRIT.*POLICY \[Attributes\] -----M----.*${BASE}/a/a/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/a/a/c/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/y";
	return 1
    fi
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 5 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
}

TESTPOLICY_2="
[ReadOnly]
dir=${BASE}
file=${BASE}/a/a/c/x
[IgnoreAll]
dir=${BASE}/a/a/c
"
mod_testdata_2 () {
    # mod_testdata_1;
    one_sec_sleep
    touch "${BASE}/a/a/x"
    chmod 0555 "${BASE}/a/a/y"
    mv "${BASE}/a/b/y" "${BASE}/a/b/yy"; 
    echo "1 This is a test file" >  "${BASE}/a/b/y";
    echo "2 This is a test file" >> "${BASE}/a/b/y";
    echo "4 This is a test file" >> "${BASE}/a/b/z";
    rm "${BASE}/a/b/yy"; # mv/rm to force new inode
    rm "${BASE}/a/b/l_y";
    ln -s "${BASE}/a/b/x" "${BASE}/a/b/l_y";
    echo "foobar" > "${BASE}/a/c/y"
    rm "${BASE}/a/a/c/y"
    echo "foobar" > "${BASE}/a/a/c/foo"
    chmod 0555 "${BASE}/a/a/c/x"
    chmod 0555 "${BASE}/a/a/c/z"
}

chk_testdata_2 () {
    for ff in $TDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	fi
	#
	for gg in $TFILES; do
	    egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		if [ x"${ff}/${gg}" = x"a/a/c/y" ]; then :; else
		    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (checking)";
		    return 1
		fi
	    fi
	done
    done
    egrep "CRIT.*POLICY ADDED.*${BASE}/a/a/c/foo" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/foo";
	return 1
    fi
    egrep "CRIT.*POLICY MISSING.*${BASE}/a/a/c/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/y";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] -----M--T-.*${BASE}/a/a/c/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/c/x";
	return 1
    fi
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 10 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
}

TESTPOLICY_1="
[Misc]
RedefReadOnly = +TXT
[ReadOnly]
dir=${BASE}
"

mod_testdata_1 () {
    one_sec_sleep
    touch "${BASE}/a/a/x"
    chmod 0555 "${BASE}/a/a/y"
    mv "${BASE}/a/b/y" "${BASE}/a/b/yy"; 
    echo "1 This is a test file" >  "${BASE}/a/b/y";
    echo "2 This is a test file" >> "${BASE}/a/b/y";
    echo "4 This is a test file" >> "${BASE}/a/b/z";
    rm "${BASE}/a/b/yy"; # mv/rm to force new inode
    rm "${BASE}/a/b/l_y";
    ln -s "${BASE}/a/b/x" "${BASE}/a/b/l_y";
    echo "foobar" > "${BASE}/a/c/y"
    #
    mv "${BASE}/b/x" "${BASE}/b/xx"; # mv/rm to force new inode 
    mkdir "${BASE}/b/x"
    rm "${BASE}/b/xx";
    #
    mv "${BASE}/b/y" "${BASE}/b/yy"; # mv/rm to force new inode
    ln -s  "${BASE}/b/z" "${BASE}/b/y"
    rm "${BASE}/b/yy";
    #
    rm "${BASE}/b/l_x";  echo "1 This is a test file" >  "${BASE}/b/l_x"; 
}

chk_testdata_1 () {
    for ff in $TDIRS; do
	#
	egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE >/dev/null 2>&1
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (checking)";
	    return 1
	fi
	tmp=`egrep "Checking.*${BASE}/${ff}(>|\")" $LOGFILE 2>/dev/null | wc -l`
	if [ $tmp -ne 1 ]; then
	    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff} (multiple)";
	    return 1
	fi
	#
	for gg in $TFILES; do
	    egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		if [ "${BASE}/${ff}" != "${BASE}/b" ]; then
		    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (checksum)";
		    return 1
		fi
	    fi
	    tmp=`egrep "Checksum.*${BASE}/${ff}/${gg}" $LOGFILE 2>/dev/null | wc -l`
	    if [ $tmp -ne 1 ]; then
		if [ "${BASE}/${ff}" != "${BASE}/b" ]; then
		    [ -z "$verbose" ] || log_msg_fail "${BASE}/${ff}/${gg} (multiple)";
		    return 1
		fi
	    fi
	done
    done
    #
    #
    #
    egrep "CRIT.*POLICY \[ReadOnly\] ----H---T-.*${BASE}/b" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/b";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] CL-I-M--TS.*${BASE}/b/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/b/y";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] CL-.-M--TS.*${BASE}/b/l_x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/b/l_x";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C--IHM--TS.*${BASE}/b/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/b/x";
	return 1
    fi
    #
    #
    #
    egrep "CRIT.*POLICY \[ReadOnly\] --------T-.*${BASE}/a/a/x" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/x";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] -----M--T-.*${BASE}/a/a/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/a/y";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] ---I----T-.*${BASE}/a/b/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/y";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] -L-I----T-.*${BASE}/a/b/l_y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/l_y";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] --------T-.*${BASE}/a/b" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/a/b/z" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/b/z";
	return 1
    fi
    egrep "CRIT.*POLICY \[ReadOnly\] C-------TS.*${BASE}/a/c/y" $LOGFILE >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	[ -z "$verbose" ] || log_msg_fail "${BASE}/a/c/y";
	return 1
    fi
    tmp=`grep CRIT $LOGFILE | wc -l`
    if [ $tmp -ne 11 ]; then
	[ -z "$verbose" ] || log_msg_fail "policy count";
	return 1
    fi
    for ff in x y z; do
	./samhain --list-file "${BASE}/a/a/${ff}" -d "$PW_DIR/.samhain_file" > "$PW_DIR/.samhain_tmp"
	diff "$PW_DIR/.samhain_tmp" "${BASE}/a/a/${ff}" >/dev/null
	if [ $? -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "diff $PW_DIR/.samhain_tmp ${BASE}/a/a/${ff}"
	    return 1
	fi
    done

    return 0
}


##############################################################
#
# Common subroutines
#

mkconfig_misc ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    cat >> "${RCFILE}" <<End-of-data
[Misc]
Daemon=no
SetFilecheckTime=60
TrustedUser=uucp,fax,fnet
SetRecursionLevel=10
SetLoopTime=30
ReportFullDetail = no
ChecksumTest=check

End-of-data
}

mkconfig_log ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    cat >> "${RCFILE}" <<End-of-data
[Log]
MailSeverity=none
LogSeverity=warn
SyslogSeverity=none
PrintSeverity=info
MailSeverity=none
#Restrict to certain classes of messages
#LogClass=RUN
#PreludeSeverity=err
#ExportSeverity=none

End-of-data
}

mkconfig_sev ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    cat >> "${RCFILE}" <<End-of-data
[EventSeverity]
SeverityUser0=crit
SeverityUser1=crit
SeverityReadOnly=crit
SeverityLogFiles=crit
SeverityGrowingLogs=crit
SeverityIgnoreNone=crit
SeverityAttributes=crit
SeverityIgnoreAll=crit
SeverityFiles=err
SeverityDirs=err
SeverityNames=warn

End-of-data
}

prep_testpolicy ()
{
    test -f "${RCFILE}" || touch "${RCFILE}"
    eval echo '"$'"TESTPOLICY_$1"'"' >>"${RCFILE}"
}

prep_init ()
{
    rm -f ./.samhain_file
    rm -f "${LOGFILE}"
    rm -f ./.samhain_lock

    rm -f "${RCFILE}"
    mkconfig_sev
    mkconfig_log
    mkconfig_misc
}

run_init ()
{
    rm -f test_log_valgrind

    ${VALGRIND} ./samhain -t init -p none 2>>test_log_valgrind

    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "init...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "init...";
	return 1
    fi
}

run_check ()
{
    if [ "x$1" = "x"  ]; then
	logsev=debug
    else
	logsev=$1
    fi
    ${VALGRIND} ./samhain -t check -p none -l $logsev 2>>test_log_valgrind
 
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

run_update ()
{
    ${VALGRIND} ./samhain -t update -p none -l debug 2>>test_log_valgrind

    if test x$? = x0; then
	[ -z "$verbose" ] || log_msg_ok    "update...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "update...";
	return 1
    fi
}

run_check_after_update ()
{
    rm -rf $LOGFILE

    ${VALGRIND} ./samhain -t check -p none -l debug 2>>test_log_valgrind

    if test x$? = x0; then
	#
	tmp=`./samhain -j -L $LOGFILE | grep CRIT | wc -l`
	if [ $tmp -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "update not successful(?)";
	    return 1
	fi
	#
	# wtmp may not be readable
	#
	tmp=`./samhain -j -L $LOGFILE | grep ERR | grep -v wtmp | wc -l`
	if [ $tmp -ne 0 ]; then
	    [ -z "$verbose" ] || log_msg_fail "errors during check";
	    return 1
	fi
	#
	[ -z "$VALGRIND" ] || {
	    tmp=`cat test_log_valgrind 2>/dev/null | wc -l`;
	    if [ $tmp -ne 0 ]; then
		[ -z "$verbose" ] || log_msg_fail "valgrind reports errors";
		cat test_log_valgrind
		return 1;
	    fi;
	}
	#
	[ -z "$verbose" ] || log_msg_ok    "check(2)...";
    else
	[ -z "$quiet" ]   && log_msg_fail  "check(2)...";
	return 1
    fi
}

prep_testdata ()
{
    if test -d "$BASE"; then
	if [ -d "${BASE}" ]; then
	    chmod -f -R 0700 "${BASE}" || {
		[ -z "$quiet" ] &&   log_msg_fail "chmod -f -R 0700 ${BASE}"; 
		return 1;
	    }
	fi
    fi

    rm -rf "${BASE}" || {
	[ -z "$quiet" ] &&   log_msg_fail "rm -rf ${BASE}"; 
	return 1;
    }

    mkdir "${BASE}" || {
	[ -z "$quiet" ] &&   log_msg_fail "mkdir ${BASE}"; 
	return 1;
    }

    echo "${BASE}" > ./tmp_list_file

    for ff in $TDIRS; do
	mkdir "${BASE}/${ff}" || { 
	    [ -z "$quiet" ] &&   log_msg_fail "mkdir ${BASE}/${ff}"; 
	    return 1;
	}
	echo "${BASE}/${ff}" >> ./tmp_list_file
	chmod 0755 "${BASE}/${ff}"
	for gg in $TFILES; do
	    echo "1 This is a test file" > "${BASE}/${ff}/${gg}"
	    chmod 0644 "${BASE}/${ff}/${gg}"
	    echo "${BASE}/${ff}/${gg}"  >> ./tmp_list_file
	    ln -s "${BASE}/${ff}/${gg}" "${BASE}/${ff}/l_${gg}"
	    echo "${BASE}/${ff}/l_${gg}"  >> ./tmp_list_file
	done
	echo "2 This is a test file" >> "${BASE}/${ff}/y"
	echo "2 This is a test file" >> "${BASE}/${ff}/z"
	echo "3 This is a test file" >> "${BASE}/${ff}/z"
    done
}

check_err ()
{
    if [ $1 -ne 0 ]; then
	log_fail ${2} ${MAXTEST};
	return 1
    fi
    return 0
}
 
testrun_internal ()
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

	until [ ${tcount} -gt ${MAXTEST_3} ]
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
	      run_init
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      eval mod_testdata_${tcount}
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      run_check
	      check_err $? ${tcount}; errval=$?
	  fi
	  if [ $errval -eq 0 ]; then
	      eval chk_testdata_${tcount}
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

testrun1 ()
{
    log_start "RUN STANDALONE"
    testrun_internal
    log_end "RUN STANDALONE"
    return 0
}



