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

# -----------------------------------------------------------------------
# Be Bourne compatible
# -----------------------------------------------------------------------

if test -n "${ZSH_VERSION+set}" && (emulate sh) >/dev/null 2>&1; then
  emulate sh
  NULLCMD=:
elif test -n "${BASH_VERSION+set}" && (set -o posix) >/dev/null 2>&1; then
  set -o posix
fi

# -----------------------------------------------------------------------
# Make sure we support functions (from the autoconf manual)
# -----------------------------------------------------------------------

TSHELL="${TSHELL-/bin/sh}"
if test x"$1" = "x--re-executed" 
then
    shift
elif "$TSHELL" -c 'foo () { (exit 0); exit 0; }; foo' >/dev/null 2>&1
then
    :
else
    for cmd in sh bash ash bsh ksh zsh sh5; do
	X="$PATH:/bin:/usr/bin:/usr/afsws/bin:/usr/ucb:/usr/xpg4/bin";
	OLD_IFS=${IFS}
	IFS=':'; export IFS 
	for dir in $X; do
	    shell="$dir/$cmd"
	    if (test -f "$shell" || test -f "$shell.exe")
	    then
	        if "$shell" -c  'foo () { (exit 0); exit 0; }; foo' >/dev/null 2>&1
		then
		    TSHELL="$shell"; export TSHELL
		    IFS=${OLD_IFS}; export IFS
		    exec "$shell" "$0" --re-executed ${1+"$@"}
		fi
	    fi
	done
	IFS=${OLD_IFS}; export IFS
    done
    echo "-----------------------------------------------------------------"
    echo "ERROR: Unable to locate a shell interpreter with function support" >&2
    echo "-----------------------------------------------------------------"
    { (exit 1); exit 1; }
fi

# -----------------------------------------------------------------------
# Make sure we support 'let' (from the autoconf manual)
# -----------------------------------------------------------------------

TSHELL="${TSHELL-/bin/sh}"
if test x"$1" = "x--re-run" 
then
    shift
elif "$TSHELL" -c 'a=5; let "a = a + 5"' >/dev/null 2>&1
then
    :
else
    for cmd in sh bash ash bsh ksh zsh sh5; do
	X="$PATH:/bin:/usr/bin:/usr/afsws/bin:/usr/ucb:/usr/xpg4/bin";
	OLD_IFS=${IFS}
	IFS=':'; export IFS 
	for dir in $X; do
	    shell="$dir/$cmd"
	    if (test -f "$shell" || test -f "$shell.exe")
	    then
	        if "$shell" -c  'foo () { (exit 0); exit 0; }; foo' >/dev/null 2>&1
		then
		    if "$shell" -c  'a=5; let "a = a + 5"' >/dev/null 2>&1
		    then
			TSHELL="$shell"; export TSHELL
			IFS=${OLD_IFS}; export IFS
			exec "$shell" "$0" --re-run ${1+"$@"}
		    fi
		fi
	    fi
	done
	IFS=${OLD_IFS}; export IFS
    done
    echo "-----------------------------------------------------------------"
    echo "ERROR: Unable to locate a shell interpreter with support for 'let'" >&2
    echo "-----------------------------------------------------------------"
    { (exit 1); exit 1; }
fi


umask 0022

isok=`test -t 1 2>&1 | wc -c`
if [ "$isok" -eq 0 ]; then
   test -t 1
   isok=$?
fi

# The following two are the ANSI sequences for start and end embolden
if [ x"$isok" = x0 ]; then
    case $TERM in
	vt*|ansi*|con*|xterm*|linux*|screen*|rxvt*)
	    S='[1;30m'
	    R=[31m
	    G=[32m
	    B=[36m
	    E=[m
	    ;;
	*)
	    S=
	    R=
	    G=
	    B=
	    E=
	    ;;
    esac
fi


usage() {
    echo "test.sh [options] <test_number> [hostname]"
    echo "        [-q|--quiet|-v|--verbose] [-s|--stoponerr] [-n|--no-cleanup]"
    echo "        [--srcdir=top_srcdir] [--color=always|never|auto]"
    echo
    echo "  ${S}test.sh  1${E}  -- Compile with many different options"
    echo "  ${S}test.sh  2${E}  -- Hash function            (testrc_1)"
    echo "  ${S}test.sh  3${E}  -- Standalone init/check"
    echo "  ${S}test.sh  4${E}  -- Microstealth init/check"
    echo "  ${S}test.sh  5${E}  -- External program call    (testrc_1ext.in)"
    echo "  ${S}test.sh  6${E}  -- Controlling the daemon"
    echo "  ${S}test.sh  7${E}  -- GnuPG signed files / prelude log"
    echo "  ${S}test.sh  8${E}  -- Suidcheck"
    echo "  ${S}test.sh  9${E}  -- Process check"
    echo "  ${S}test.sh 10${E}  -- Port check"
    echo "  ${S}test.sh 11${E}  -- CL verify option" 
    echo "  ${S}test.sh 12${E}  -- CL create DeltaDB" 
    echo "  ${S}test.sh 13${E}  -- CL create/verify partial DB" 

    echo "  ${S}test.sh 20${E}  -- Test c/s init/check      (testrc_2.in)"
    echo "  ${S}test.sh 21${E}  -- Test full c/s init/check (testrc_2.in)"
    echo "  ${S}test.sh 22${E}  -- Test full c/s w/gpg      (testrc_2.in)"
    echo "  ${S}test.sh 23${E}  -- Test full c/s w/mysql    (testrc_2.in)"
    echo "  ${S}test.sh 24${E}  -- Test full c/s w/postgres (testrc_2.in)"
    echo "  ${S}test.sh 25${E}  -- Test server w/yulectl    (testrc_2.in)"
    echo "  ${S}test.sh 26${E}  -- Test c/s case one        (testrc_2.in)"
    echo "  ${S}test.sh 27${E}  -- Test c/s case two        (testrc_2.in)"
    echo "  ${S}test.sh all${E} -- All tests"
}
scripts () {
    echo 
    echo "Scripts used by tests:"
    echo "  (1) testcompile.sh (2) testhash.sh     (3) testrun_1.sh   (4) testrun_1a.sh"
    echo "  (5) testext.sh     (6) testtimesrv.sh  (7) testrun_1b.sh  (8) testrun_1c.sh" 
    echo "  (9) testrun_1d.sh (10) testrun_1e.sh  (11) testrun_1f.sh (12) testrun_1g.sh" 
    echo " (13) testrun_1h.sh"
    echo " (20) testrun_2.sh  (21) testrun_2a.sh  (22) testrun_2b.sh (23) testrun_2c.sh"
    echo " (24) testrun_2d.sh (25) testrun_2e.sh  (26) testrun_2f.sh (27) testrun_2g.sh"
}

#
# Option parsing
#
verbose=
quiet=
stoponerr=
color=auto
cleanup=on
doall=
usevalgrind=

while [ $# -gt 0 ]
do
    case "$1" in
        -h|--help)     usage; exit 0;;
	--scripts)     usage; scripts; exit 0;;
        -v|--verbose)  verbose=on; quiet= ;;
        -q|--quiet)    quiet=on; verbose= ;;
        -s|--stoponerr)     stoponerr=on;;
	-n|--no-cleanup) cleanup= ;;
	--really-all) doall=on;;
	--valgrind) usevalgrind=on;;
	--srcdir=*)    TOP_SRCDIR=`echo $1 | sed s,--srcdir=,,`; export TOP_SRCDIR;;
	--color=*)     
	    arg=`echo $1 | sed s,--color=,,`
	    case $arg in
		auto) ;;
		never|none|no) 
		    S=
		    R=
		    G=
		    B=
		    E=
		    ;;
		always|yes)
		    S='[1;30m'
		    R=[31m
		    G=[32m
		    G=[36m
		    E=[m
		    ;;
		*) echo "Invalid argument $1"; exit 1;;
	    esac
	    ;;
        -*)  echo "Invalid argument $1"; exit 1;;
	*) break;;
    esac
    shift
done

export verbose
export quiet
export stoponerr
export cleanup
export doall
export S; export R; export G; export B; export E;

SCRIPTDIR=.

#
# 'make test' will copy the 'test' subdirectory and replace TEST_SRCDIR
#
TEST_SRCDIR="XXXSRCXXX";
if test "x${TOP_SRCDIR}" = x; then
    # not within source tree, and not called with 'make testN'
    if test -f "${TEST_SRCDIR}/src/samhain.c"; then
	TOP_SRCDIR="${TEST_SRCDIR}"; export TOP_SRCDIR
        if test -f test/testcompile.sh; then
            SCRIPTDIR=test
        fi
    # not within source tree, not called by 'make', and in 'test' subdir
    elif test -f "../${TEST_SRCDIR}/src/samhain.c"; then
	cd ..
	SCRIPTDIR=test
	TOP_SRCDIR="${TEST_SRCDIR}"; export TOP_SRCDIR
    # within source tree, and not called with 'make testN'
    else
	if test -f ../src/samhain.c; then
	    cd .. 
	    SCRIPTDIR=test
	    TOP_SRCDIR=. 
            export TOP_SRCDIR
	elif test -f ./src/samhain.c; then
	    SCRIPTDIR=test
	    TOP_SRCDIR=.
	    export TOP_SRCDIR
	else
	    echo "Please use --srcdir=DIR, where DIR should be the"
	    echo "top directory in the samhain source tree."
	    exit 1
	fi
    fi
else
    # called by make, or with --srcdir=TOP_SRCDIR
    if   test -f "${TOP_SRCDIR}/src/samhain.c"; then
	SCRIPTDIR="${TOP_SRCDIR}/test"
    elif test -f "../${TOP_SRCDIR}/src/samhain.c"; then
	cd ..; SCRIPTDIR="${TOP_SRCDIR}/test"
    else
	echo "Please use --srcdir=DIR, where DIR should be the"
	echo "top directory in the samhain source tree."
	exit 1
    fi
fi

export SCRIPTDIR

PW_DIR=`pwd`; export PW_DIR

#
# group/world writeable will cause problems
#
chmod go-w .
#
#
#
if test x$UID != x -a x$UID != x0; then
  TRUST="--with-trusted=0,2,$UID"
else
  TRUST="--with-trusted=0,2,1000"
fi
export TRUST
#
# find a good 'make'
#
MAKE=`which gmake`
if test "x$?" = x1 ; then
    MAKE="make -s -j 3"
else
    MAKE=`which gmake | sed -e "s%\([a-z:]\) .*%\1%g"` 
    if test "x$MAKE" = x; then
	MAKE="make -s"
    elif test "x$MAKE" = xno; then
	MAKE="make -s"
    else
	if test "x$MAKE" = "xwhich:"; then
		MAKE="make -s"
	else
		MAKE="gmake -s"
		gmake -v >/dev/null 2>&1 || MAKE="make -s"
	fi
    fi
fi
export MAKE

failcount=0
okcount=0
skipcount=0
global_count=0
last_count=0

# args: #test, #total, status, optional msg
log_msg ()
{
    if   [ x"$COLUMNS" != x ]; then
	TERMWIDTH=$COLUMNS
    elif [ x"$COLS" != x ]; then
	TERMWIDTH=$COLS
    else
	TERMWIDTH=80
    fi
    cols=66; 
    #
    if [ $1 -eq 0 ]; then
	msg=" ${4}"
    else
	if [ ${1} -eq 1 ]; then
	    global_count=${last_count}
	fi
	let "v = $1 + global_count" >/dev/null
	last_count=${v}
	dd=''; if [ $v -lt 10 ]; then dd=" "; fi
	dt=''; if [ $2 -lt 10 ]; then dt=" "; fi
	if [ -z "$4" ]; then
	    msg=" test ${dd}${v}/${dt}${2}"
	else
	    msg=" test ${dd}${v}/${dt}${2}    ${4}"
	fi
    fi
    #
    if   [ x"$3" = xfailure ]; then
	ccode=$R
    elif [ x"$3" = xsuccess ]; then
	ccode=$G
    else
	ccode=$B
    fi
    if [ -z "${R}" ]; then
	echo " [${3}] ${msg}"
    else
	# len=${#...} is not bourne shell
	# also, need to account for terminal control sequences
	len=`echo "$msg" | awk '/1;30m/ { print length()-10; }; !/1;30m/ { print length();}'`
	let "cols = cols - len" >/dev/null
	if [ $cols -ge 0 ]; then
	    moveto='['$cols'C'
	    echo "${msg}${moveto}${ccode}[${3}]${E}"
	else
	    echo "${msg}${ccode}[${3}]${E}"
	fi
    fi
}

log_fail () { 
    [ -z "$quiet" ] && log_msg "$1" "$2" failure "$3"; 
    let "failcount = failcount + 1" >/dev/null; 
    test -z "$stoponerr" || exit 1; 
}
log_ok ()   { 
    [ -z "$quiet" ] && log_msg "$1" "$2" success "$3"; 
    let "okcount = okcount + 1" >/dev/null; 
}
log_skip () { 
    [ -z "$quiet" ] && log_msg "$1" "$2" skipped "$3"; 
    let "skipcount = skipcount + 1" >/dev/null; 
}

log_msg_fail () { log_msg 0 0 failure "$1"; }
log_msg_ok ()   { log_msg 0 0 success "$1"; }
log_msg_skip () { log_msg 0 0 skipped "$1"; }

log_start () {
    if [ -z "$quiet" ]; then
	echo; 
	echo "${S}__ START TEST ${1} __${E}"; 
	echo; 
    fi
}
log_end () {
    if [ -n "$verbose" ]; then
	echo; 
	echo "${S}__ END   TEST ${1} __${E}"; 
	echo; 
    fi
}

# This looks silly, but with solaris10/i386 on vmware,
# 'sleep' occasionally does not sleep...

one_sec_sleep () {
    onesdate=`date`
    onestest=0
    while [ $onestest -eq 0 ]; do
	sleep 1
	twosdate=`date`
	if [ "x$twosdate" = "x$onesdate" ]; then 
	    onestest=0
	else
	    onestest=1
	fi
    done
}

five_sec_sleep () {
    for f in 1 2 3 4 5; do
	one_sec_sleep
    done
}

do_cleanup () {
    rm -f testrc_1.dyn
    rm -f testrc_2
    rm -f testrc_22
    rm -f testrc_1ext
    rm -f ./.samhain_file
    rm -f file.*.*-*-*-*-*
    rm -f ./.samhain_log*
    rm -f ./.samhain_lock*
    test -d testrun_testdata && chmod -f -R 0700 testrun_testdata
    test -d .quarantine && rm -rf .quarantine
    rm -rf testrun_testdata
    rm -f test_log_db
    rm -f test_log_prelude
    rm -f test_log_valgrind*
    rm -f test_log_yulectl
    rm -f yule.html
    rm -f yule.html2
    rm -f test_dnmalloc
    rm -f tmp_list_file
    rm -f test_filter.txt
}

print_summary ()
{
    # let "gcount = okcount + skipcount + failcount" >/dev/null;
    gcount=$MAXTEST;
    let "failcount = gcount - okcount - skipcount" >/dev/null;

    [ -z "$quiet" ] && { 
	echo
	echo "__ ${S}Tests: ${gcount}  Ok: ${okcount} Skipped: ${skipcount} Failed: ${failcount}${E}"
    }
    if [ $failcount -eq 0 ]; then
	[ -z "$quiet" ] && { echo "__ ${G}All tests passed successfully.${E}"; echo; }
    elif [ $failcount -eq 1 ]; then
	[ -z "$quiet" ] && { echo "__ ${R}There was 1 failure.${E}"; echo; }
    else
	[ -z "$quiet" ] && { echo "__ ${R}There were $failcount failures.${E}"; echo; }
    fi
    [ -z "$cleanup" ] || do_cleanup;
}

find_path () { (   
    save_IFS=$IFS; IFS=:

    for dir in $PATH; do
	IFS=$as_save_IFS
	test -z "$dir" && dir=.
	if test -f "$dir/$1"; then
	    echo "$dir/$1";
	    break;
	fi
    done
    IFS=${save_IFS};
); }

find_hostname () {

    uname -a | grep Linux >/dev/null
    if [ $? -eq 0 ]; then
	tmp=`hostname -f 2>/dev/null`
	if [ $? -ne 0 ]; then
	    tmp=`hostname 2>/dev/null`
	fi
    else
	tmp=`hostname 2>/dev/null`
    fi
    if [ -z "$tmp" ]; then
	tmp="localhost"
    fi
    #
    # first one is hostname, others are aliases
    #
    tmp2=`cat /etc/hosts | egrep "^ *[0123456789].* $tmp" | awk '{ print $2 }'`
    if [ -z "$tmp2" ]; then
	echo "$tmp"
    else
	echo "$tmp2"
    fi
}

rm -f ./test_log

# first one is hostname, others are aliases
#
hostname=`cat /etc/hosts | egrep "^ *127.0.0.1" | awk '{ print $2 }'`
if [ x"$hostname" = xlocalhost ]; then
    hostname="127.0.0.1"
fi

# Seems that 'valgrind' causes random hangs :-(
#
if [ -z "$usevalgrind" ]; then
    VALGRIND=
else
    VALGRIND=`find_path valgrind`;
fi
[ -z "$VALGRIND" ] || { 
    VALGRIND="$VALGRIND --quiet --tool=memcheck --suppressions=.test.supp"; 
    export VALGRIND;
    [ -z "$verbose" ] || log_msg_ok "using valgrind"
cat > ".test.supp" <<End-of-data
#
# there are unitialized bytes in the struct...
#
{
   pushdata_01
   Memcheck:Param
   write(buf)
   obj:/lib/ld-*.so
   fun:sh_hash_pushdata
   fun:sh_files_filecheck
   fun:sh_dirs_chk
}
{
   pushdata_02
   Memcheck:Param
   write(buf)
   obj:/lib/ld-*.so
   fun:sh_hash_pushdata
   fun:sh_files_filecheck
   fun:sh_files_checkdir
}
{
   pushdata_03
   Memcheck:Param
   write(buf)
   obj:/lib/ld-*.so
   fun:sh_hash_pushdata
   fun:sh_hash_writeout
   fun:main
}

End-of-data
}

if test x$1 = x1; then
    . ${SCRIPTDIR}/testcompile.sh
    testcompile
    print_summary
    exit $?
fi
if test x$1 = x2; then
    . ${SCRIPTDIR}/testhash.sh
    testhash
    print_summary
    exit $?
fi
if test x$1 = x3; then
    . ${SCRIPTDIR}/testrun_1.sh
    testrun1
    print_summary
    exit $?
fi
if test x$1 = x4; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1a.sh
    testrun1a
    print_summary
    exit $?
fi
if test x$1 = x5; then
    . ${SCRIPTDIR}/testext.sh
    testext0
    print_summary
    exit $?
fi
if test x$1 = x6; then
    . ${SCRIPTDIR}/testtimesrv.sh
    testtime0
    print_summary
    exit $?
fi
if test x$1 = x7; then
    . ${SCRIPTDIR}/testrun_1b.sh
    testrun1b
    print_summary
    exit $?
fi
if test x$1 = x8; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1c.sh
    testrun1c
    print_summary
    exit $?
fi
if test x$1 = x9; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1d.sh
    testrun1d
    print_summary
    exit $?
fi
if test x$1 = x10; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1e.sh
    testrun1e
    print_summary
    exit $?
fi
if test x$1 = x11; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1f.sh
    testrun1f
    print_summary
    exit $?
fi
if test x$1 = x12; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1g.sh
    testrun1g
    print_summary
    exit $?
fi
if test x$1 = x13; then
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1h.sh
    testrun1h
    print_summary
    exit $?
fi
if test x$1 = x20; then
    . ${SCRIPTDIR}/testrun_2.sh 
    testrun2 $hostname
    print_summary
    exit $?
fi
if test x$1 = x21; then
    . ${SCRIPTDIR}/testrun_2a.sh
    testrun2a $hostname
    print_summary
    exit $?
fi
if test x$1 = x22; then
    . ${SCRIPTDIR}/testrun_2a.sh
    . ${SCRIPTDIR}/testrun_2b.sh
    testrun2b $hostname
    print_summary
    exit $?
fi
if test x$1 = x23; then
    . ${SCRIPTDIR}/testrun_2a.sh
    . ${SCRIPTDIR}/testrun_2c.sh 
    testrun2c $hostname
    print_summary
    exit $?
fi
if test x$1 = x24; then
    . ${SCRIPTDIR}/testrun_2a.sh
    . ${SCRIPTDIR}/testrun_2d.sh
    testrun2d $hostname
    print_summary
    exit $?
fi
if test x$1 = x25; then
    . ${SCRIPTDIR}/testrun_2e.sh
    testrun2e $hostname
    print_summary
    exit $?
fi
if test x$1 = x26; then
    . ${SCRIPTDIR}/testrun_2f.sh
    testrun2f $hostname
    print_summary
    exit $?
fi
if test x$1 = x27; then
    . ${SCRIPTDIR}/testrun_2g.sh
    testrun2g $hostname
    print_summary
    exit $?
fi
if test x$1 = xall; then
    TEST_MAX=0
    . ${SCRIPTDIR}/testcompile.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testhash.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1a.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testext.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testtimesrv.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1b.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1c.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1d.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1e.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1f.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1g.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_1h.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2a.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2b.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2c.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2d.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2e.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2f.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    . ${SCRIPTDIR}/testrun_2g.sh
    let "TEST_MAX = TEST_MAX + MAXTEST" >/dev/null
    #
    # ${SCRIPTDIR}/testtimesrv.sh
    # ${SCRIPTDIR}/testrun_1b.sh
    # ${SCRIPTDIR}/testrun_2.sh $2
    # ${SCRIPTDIR}/testrun_2a.sh $2
    #
    MAXTEST=${TEST_MAX}; export MAXTEST
    testcompile
    testhash
    #
    . ${SCRIPTDIR}/testrun_1.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1
    #
    . ${SCRIPTDIR}/testrun_1a.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1a
    #
    testext0
    #
    . ${SCRIPTDIR}/testtimesrv.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testtime0
    #
    . ${SCRIPTDIR}/testrun_1b.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1b
    #
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1c.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1c
    #
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1d.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1d
    #
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1e.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1e
    #
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1f.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1f
    #
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1g.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1g
    #
    . ${SCRIPTDIR}/testrun_1.sh
    . ${SCRIPTDIR}/testrun_1h.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun1h
    #
    . ${SCRIPTDIR}/testrun_2.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2 $hostname
    #
    . ${SCRIPTDIR}/testrun_2a.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2a $hostname
    #
    . ${SCRIPTDIR}/testrun_2b.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2b $hostname
    #
    . ${SCRIPTDIR}/testrun_2c.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2c $hostname
    #
    . ${SCRIPTDIR}/testrun_2d.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2d $hostname
    #
    . ${SCRIPTDIR}/testrun_2e.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2e $hostname
    #
    . ${SCRIPTDIR}/testrun_2f.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2f $hostname
    #
    . ${SCRIPTDIR}/testrun_2g.sh
    MAXTEST=${TEST_MAX}; export MAXTEST
    testrun2g $hostname
    #
    print_summary
    exit 0
fi

usage;

exit 1;

# gpg -a --clearsign --not-dash-escaped testrc.gpg
# gpg -a --clearsign --not-dash-escaped .samhain_file
# tar czvf foo.tgz testrc.gpg.asc .samhain_file.asc
# cat foo.tgz >>test/test.sh

__ARCHIVE_FOLLOWS__
‹ p{U í•=lÛFÇé©Å!sÑ-di‘D&%‹r#Q´™Ö—Ù†Q0Ò‰bÍ•¤d+KÐµk—¢@75kå¡€l}!KaDÔ™:µC=öÐÕ‚“¥Ø–RA
8MûÄñþw÷î½»ã;ÙŽ•ñ(Å#ÛêR 1ìÜœ[2?=^º0þ@€b¼~ËÒ^ÆÇR4ãcX–‚ôå¸3IÑvdBÊ’UY¯î÷ºöÿ)7]nbD‚11“QBpIH&yQ6‚EÙÎ/Àä"Ï ÉtB¸&Ø¹€²pÍ,B¡,bL„Ž	KÈRseèäUêÈ¶e 6xÇ±Ô{EÙ› §jˆ›EN€kÐ0h!YÓÊP3·É¾qG(kºi;P)Ê–l8îØ:ÚQmlˆ–¹­JÔTÂî€1“³6²JjÙcRÛ¯ë¦“Å.	%d8Iä:ì”7ÁÙ×
¶@sü9!1“RÉÙeC+OªgMªÞ¾ÔQÓB’i Iýb±¦õç5Û–-ã\M‰Ç}.†TËæT#gž+’Œ÷c4l`g6Á’¬jg­x¼ –Ï…Ñe[Ó†b–z±p£9ÀÆ’jg6AHFºiànxVÇõ+“G™­”ª#ŽñÒ®˜@™¢e«¦Å4ŽŠQÓ,;±4H ‚i9á¢¦…ƒ„># èÚ±‹z
§+nhÔÝÁåð& SN0ŸZI¼8¼«h8ÛÂ‹Zb<^~$J+³QÕ(î|€šÝŽ‡…ëvzYü‚ÖËü­ô¢w;ÁÖü§tÂŽ—|:}OºãŸ—Ò´^š_ŠâJÅto	,ÑR"¸÷‰(…¤ £«|#àr"Žzèˆ …¦¹÷_ÿþ”Ç–õ<NmŸ¹ÿÇ%]ÃüÏ¾:ÿ³¬ÿ,ÿ3–vó?KûIþ¼üÿëo?õŸ€cž¢`Þ{Ò‡ïñ;C]ÁeTÿª^^qËçN–ãTÆpëPƒÃÃÓÆ7]=<ûkPqjïÁ£?Ô/OPÔÃ£Ó§à&¨|9=¬üþðÉêÆÌ¨üöþ0Œk!ÏDù/ÂúqªúMeð¬2¨¸Õît·[ýÝf³ßkµúµƒn£Õì4v[ûÝ~³ÛÚoWö:m¬7÷z­Z¿zõ"¬‡žœž¼&¸Ÿñžå¢£úw_‚Snùhÿ8uiÁõ«ûµN£±Ûk÷;j»ßÝ¯ïtk½fµW­7v»Õ^§^ëvêõÇ»½NïåàNŽÏzäÆ÷†·¾-„5OAž_óÚj€¿çƒÊVüâæ(¯–” ¢Éó‘$ŸžÛï®¢ì
»¸^HMøb[¼y'ñ…“ëhIæ¼ëw5o2ÒÐb!f|81½ž|·o@ @ @ ð.ò7–<Ì (  
