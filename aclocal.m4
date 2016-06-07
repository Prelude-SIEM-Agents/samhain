dnl aclocal.m4 generated automatically by aclocal 1.3

dnl Copyright (C) 1994, 1995, 1996, 1997, 1998 Free Software Foundation, Inc.
dnl This Makefile.in is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

#
# Check to make sure that the build environment is sane.
#
AC_DEFUN([AM_INIT_AUTOMAKE],
[
AC_REQUIRE([AC_PROG_INSTALL])
PACKAGE=[$1]
AC_SUBST(PACKAGE)
VERSION=[$2]
AC_SUBST(VERSION)
dnl test to see if srcdir already configured
if test "`cd $srcdir && pwd`" != "`pwd`" && test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
fi
ifelse([$3],,
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE")
AC_DEFINE_UNQUOTED(VERSION, "$VERSION"))
AC_REQUIRE([AC_PROG_MAKE_SET])])


# Define a conditional.

AC_DEFUN([AM_CONDITIONAL],
[AC_SUBST($1_TRUE)
AC_SUBST($1_FALSE)
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi])


AC_DEFUN([sh_run_prog],
[if test "$cross_compiling" = "yes"; then
   AC_MSG_ERROR([Can not probe non-portable values when cross compiling])
fi
cat > conftest.$ac_ext <<EOF
[#]line __oline__ "configure"
#include "confdefs.h"
ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C" void exit(int);
#endif
])
[$1]
EOF
if AC_TRY_EVAL(ac_link) && test -s conftest && $2=`(./conftest 2>/dev/null)`
then
dnl Don't remove the temporary files here, so they can be examined.
ifelse([$3], , :, [$3])
else
echo "configure: failed program was:" >&AC_FD_CC
cat conftest.$ac_ext >&AC_FD_CC
ifelse([$4], , , [  rm -fr conftest*
  $4
])
fi
rm -fr conftest* ])

dnl fs type number of the proc filing system
AC_DEFUN([sh_procfs_id],
[AC_MSG_CHECKING([f_type of /proc])
AC_CACHE_VAL([sh_cv_proc_fstype],
[sh_run_prog(
changequote(<<, >>)dnl
<<#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#ifndef Q
#define __Q(x) #x
#define Q(x) __Q(x)
#endif
int main(void)
{
struct statfs fsbuf;
long ft;
if (statfs("/", &fsbuf)!=0)
  exit(1);
ft=fsbuf.f_type;
if (statfs("/proc/1", &fsbuf)!=0)
  exit(1);
if (ft!=fsbuf.f_type)
  printf("0x%08lx", fsbuf.f_type);
else
  puts("statfs useless");
exit(0);
} >>
changequote([, ]), sh_cv_proc_fstype,, sh_cv_proc_fstype="a fatal error occured")])
AC_MSG_RESULT($sh_cv_proc_fstype)
if test "${sh_cv_proc_fstype}" = "a fatal error occured"; then
  $1=$2
  $4
else if test "${sh_cv_proc_fstype}" = "statfs useless"; then
  $1=$2
  $4
else
  $1=$sh_cv_proc_fstype
  $3
fi; fi ])

# Check whether mlock is broken (hpux 10.20 raises a SIGBUS if mlock
# is not called from uid 0 (not tested whether uid 0 works)
dnl AC_CHECK_MLOCK
dnl
define([AC_CHECK_MLOCK],
  [ AC_CHECK_FUNCS(mlock)
    if test "$ac_cv_func_mlock" = "yes"; then
        AC_MSG_CHECKING(whether mlock is broken)
          AC_CACHE_VAL(ac_cv_have_broken_mlock,
             AC_TRY_RUN([
                #include <stdlib.h>
                #include <unistd.h>
                #include <errno.h>
                #include <sys/mman.h>
                #include <sys/types.h>
                #include <fcntl.h>

                int main()
                {
                    char *pool;
                    int err;
                    long int pgsize = getpagesize();

                    pool = malloc( 4096 + pgsize );
                    if( !pool )
                        return 2;
                    pool += (pgsize - ((long int)pool % pgsize));

                    err = mlock( pool, 4096 );
                    if( !err || errno == EPERM )
                        return 0; /* okay */

                    return 1;  /* hmmm */
                }

            ],
            ac_cv_have_broken_mlock="no",
            ac_cv_have_broken_mlock="yes",
            ac_cv_have_broken_mlock="assume-no"
           )
         )
         if test "$ac_cv_have_broken_mlock" = "yes"; then
             AC_DEFINE(HAVE_BROKEN_MLOCK)
             AC_MSG_RESULT(yes)
         else
            if test "$ac_cv_have_broken_mlock" = "no"; then
                AC_MSG_RESULT(no)
            else
                AC_MSG_RESULT(assuming no)
            fi
         fi
    fi
  ])

dnl @synopsis AC_FUNC_VSNPRINTF
dnl
dnl Check whether there is a reasonably sane vsnprintf() function installed.
dnl "Reasonably sane" in this context means never clobbering memory beyond
dnl the buffer supplied, and having a sensible return value.  It is
dnl explicitly allowed not to NUL-terminate the return value, however.
dnl
dnl @version $Id: ac_func_vsnprintf.m4,v 1.1 2001/07/26 02:00:21 guidod Exp $
dnl @author Gaute Strokkenes <gs234@cam.ac.uk>
dnl
AC_DEFUN([SL_CHECK_VSNPRINTF],
[AC_CACHE_CHECK(for working vsnprintf,
  ac_cv_func_vsnprintf,
[AC_TRY_RUN(
[#include <stdio.h>
#include <stdarg.h>

int
doit(char * s, ...)
{
  char buffer[32];
  va_list args;
  int r;

  buffer[5] = 'X';

  va_start(args, s);
  r = vsnprintf(buffer, 5, s, args);
  va_end(args);

  /* -1 is pre-C99, 7 is C99. R.W. 17.01.2003 disallow -1 */

  if (r != 7)
    exit(1);

  /* We deliberately do not care if the result is NUL-terminated or
     not, since this is easy to work around like this.  */

  buffer[4] = 0;

  /* Simple sanity check.  */

  if (strcmp(buffer, "1234"))
    exit(1);

  if (buffer[5] != 'X')
    exit(1);

  exit(0);
}

int
main(void)
{
  doit("1234567");
  exit(1);
}], ac_cv_func_vsnprintf=yes, ac_cv_func_vsnprintf=no, ac_cv_func_vsnprintf=no)])
dnl Note that the default is to be pessimistic in the case 
dnl of cross compilation.
dnl If you know that the target has a sensible vsnprintf(), 
dnl you can get around this
dnl by setting ac_func_vsnprintf to yes, as described in the Autoconf manual.
if test $ac_cv_func_vsnprintf = yes; then
  :
else
  AC_DEFINE(HAVE_BROKEN_VSNPRINTF, 1,
            [Define if you have a broken version of the `vsnprintf' function.])
fi
])# AC_FUNC_VSNPRINTF

dnl SH_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN([SH_CHECK_TYPEDEF],
  [ AC_MSG_CHECKING(for $1 typedef)
    sh_cv_typedef_foo=`echo sh_cv_typedef_$1 | sed -e 's% %_%g'`
    AC_CACHE_VAL( $sh_cv_typedef_foo,
    [AC_TRY_COMPILE([
#include <stdlib.h>
#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif], [
    #undef $1
    int a = sizeof($1);
    ], sh_cv_typedef=yes, sh_cv_typedef=no )])
    AC_MSG_RESULT($sh_cv_typedef)
    if test "$sh_cv_typedef" = yes; then
        AC_DEFINE([$2], [1], [Define if type is defined in stdint.h or inttypes.h])
	sh_$2=yes
    else
	sh_$2=no
    fi
  ])



dnl **********************
dnl *** va_copy checks ***
dnl **********************
AC_DEFUN([SL_CHECK_VA_COPY],
[AC_MSG_CHECKING(for va_copy())
AC_CACHE_VAL(sh_cv_va_copy,[
        AC_TRY_RUN([
        #include <stdarg.h>
        void f (int i, ...) {
        va_list args1, args2;
        va_start (args1, i);
        va_copy (args2, args1);
        if (va_arg (args2, int) != 42)
	  exit (1);
	if (va_arg (args1, int) != 42)
          exit (1);
        va_end (args1); va_end (args2);
        }
        int main() {
          f (0, 42);
          return 0;
        }],
        sh_cv_va_copy=yes
        ,
        sh_cv_va_copy=no
        ,
	sh_cv_va_copy=no)
])
AC_MSG_RESULT($sh_cv_va_copy)
AC_MSG_CHECKING(for __va_copy())
AC_CACHE_VAL(sh_cv___va_copy,[
        AC_TRY_RUN([
        #include <stdarg.h>
        void f (int i, ...) {
        va_list args1, args2;
        va_start (args1, i);
        __va_copy (args2, args1);
        if (va_arg (args2, int) != 42)
	  exit (1);
	if (va_arg (args1, int) != 42)
          exit (1);
        va_end (args1); va_end (args2);
        }
        int main() {
          f (0, 42);
          return 0;
        }],
        sh_cv___va_copy=yes
        ,
        sh_cv___va_copy=no
        ,
	sh_cv___va_copy=no)
])
AC_MSG_RESULT($sh_cv___va_copy)
AC_MSG_CHECKING(whether va_lists can be copied by value)
AC_CACHE_VAL(sh_cv_va_val_copy,[
        AC_TRY_RUN([
        #include <stdarg.h>
        void f (int i, ...) {
        va_list args1, args2;
        va_start (args1, i);
        args2 = args1;
        if (va_arg (args2, int) != 42)
	  exit (1);
	if (va_arg (args1, int) != 42)
          exit (1);
        va_end (args1); va_end (args2);
        }
        int main() {
          f (0, 42);
          return 0;
        }],
        sh_cv_va_val_copy=yes
        ,
        sh_cv_va_val_copy=no
        ,
	sh_cv_va_val_copy=no)
])
if test "x$sh_cv_va_copy" = "xyes"; then
  AC_DEFINE(VA_COPY, va_copy)
else if test "x$sh_cv___va_copy" = "xyes"; then
  AC_DEFINE(VA_COPY, __va_copy)
fi
fi
if test "x$sh_cv_va_val_copy" = "xno"; then
  AC_DEFINE(VA_COPY_AS_ARRAY)
fi
AC_MSG_RESULT($sh_cv_va_val_copy)
])


dnl SH_INIT_PARSE_ARGS()
m4_define([SH_INIT_PARSE_ARGS],
[
m4_divert_push([PARSE_ARGS])dnl

as_cr_letters='abcdefghijklmnopqrstuvwxyz'
as_cr_LETTERS='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
as_cr_Letters=$as_cr_letters$as_cr_LETTERS
as_cr_digits='0123456789'
as_cr_alnum=$as_cr_Letters$as_cr_digits

# Sed expression to map a string onto a valid CPP name.
as_tr_cpp="sed y%*$as_cr_letters%P$as_cr_LETTERS%;s%[[^_$as_cr_alnum]]%_%g"

as_tr_sh="eval sed 'y%*+%pp%;s%[[^_$as_cr_alnum]]%_%g'"
# IFS
# We need space, tab and new line, in precisely that order.
as_nl='
'
IFS=" 	$as_nl"

# CDPATH.
$as_unset CDPATH || test "${CDPATH+set}" != set || { CDPATH=$PATH_SEPARATOR; export CDPATH; }


# Initialize some variables set by options.
ac_init_help=
ac_init_version=false
# The variables have the same names as the options, with
# dashes changed to underlines.
cache_file=/dev/null
AC_SUBST(exec_prefix, NONE)dnl
no_create=
no_recursion=
AC_SUBST(prefix, NONE)dnl
program_prefix=NONE
program_suffix=NONE
AC_SUBST(program_transform_name, [s,x,x,])dnl
silent=
site=
srcdir=
verbose=
x_includes=NONE
x_libraries=NONE
DESTDIR=
SH_ENABLE_OPTS="selinux posix-acl asm ssp db-reload xml-log message-queue login-watch process-check port-check mounts-check logfile-monitor userfiles debug ptrace static network udp nocl stealth micro-stealth install-name identity khide suidcheck base largefile mail external-scripts encrypt srp dnmalloc ipv6 shellexpand suid"
SH_WITH_OPTS="prelude libprelude-prefix database libwrap cflags libs console altconsole timeserver alttimeserver rnd egd-socket port logserver altlogserver kcheck gpg keyid checksum fp recipient sender trusted tmp-dir config-file log-file pid-file state-dir data-file html-file"

# Installation directory options.
# These are left unexpanded so users can "make install exec_prefix=/foo"
# and all the variables that are supposed to be based on exec_prefix
# by default will actually change.
dnl Use braces instead of parens because sh, perl, etc. also accept them.
sbindir='${exec_prefix}/sbin'
sysconfdir='${prefix}/etc'
localstatedir='${prefix}/var'
mandir='${prefix}/share/man'

AC_SUBST([sbindir],        ['${exec_prefix}/sbin'])dnl
AC_SUBST([sysconfdir],     ['${prefix}/etc'])dnl
AC_SUBST([localstatedir],  ['${prefix}/var'])dnl
AC_SUBST([mandir],         ['${prefix}/share/man'])dnl


# Initialize some other variables.
subdirs=
MFLAGS= MAKEFLAGS=
SHELL=${CONFIG_SHELL-/bin/sh}
# Maximum number of lines to put in a shell here document.
ac_max_here_lines=12

ac_prev=
for ac_option
do

  # If the previous option needs an argument, assign it.
  if test -n "$ac_prev"; then
    eval "$ac_prev=\$ac_option"
    ac_prev=
    continue
  fi

  case "$ac_option" in
changequote(, )dnl
  *=*) ac_optarg=`echo "$ac_option" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
changequote([, ])dnl
  *) ac_optarg= ;;
  esac

  # Accept the important Cygnus configure options, so we can diagnose typos.

  case "$ac_option" in

  -build | --build | --buil | --bui | --bu)
    ac_prev=build_alias ;;
  -build=* | --build=* | --buil=* | --bui=* | --bu=*)
    build_alias="$ac_optarg" ;;

  -cache-file | --cache-file | --cache-fil | --cache-fi \
  | --cache-f | --cache- | --cache | --cach | --cac | --ca | --c)
    ac_prev=cache_file ;;
  -cache-file=* | --cache-file=* | --cache-fil=* | --cache-fi=* \
  | --cache-f=* | --cache-=* | --cache=* | --cach=* | --cac=* | --ca=* | --c=*)
    cache_file="$ac_optarg" ;;

  --config-cache | -C)
    cache_file=config.cache ;;

  -disable-* | --disable-*)
    ac_feature=`expr "x$ac_option" : 'x-*disable-\(.*\)'`
    # Reject names that are not valid shell variable names.
    expr "x$ac_feature" : "[.*[^-_$as_cr_alnum]]" >/dev/null &&
      AC_MSG_ERROR([invalid feature name: $ac_feature])
    ac_feature=`echo $ac_feature | sed 's/-/_/g'`
    ac_enable_check_opt=no
    for f in ${SH_ENABLE_OPTS}
    do
	f=`echo $f | sed 's/-/_/g'`
	if test x${f} = x"${ac_feature}"
	then
		ac_enable_check_opt=yes
	fi
    done
    if test x${ac_enable_check_opt} = xno
    then
	AC_MSG_ERROR([unrecognized option: $ac_option
Try `$[0] --help' for more information.])
    fi
    eval "enable_$ac_feature=no" ;;

  -enable-* | --enable-*)
    ac_feature=`expr "x$ac_option" : 'x-*enable-\([[^=]]*\)'`
    # Reject names that are not valid shell variable names.
    expr "x$ac_feature" : "[.*[^-_$as_cr_alnum]]" >/dev/null &&
      AC_MSG_ERROR([invalid feature name: $ac_feature])
    ac_feature=`echo $ac_feature | sed 's/-/_/g'`
    case $ac_option in
      *=*) ac_optarg=`echo "$ac_optarg" | sed "s/'/'\\\\\\\\''/g"`;;
      *) ac_optarg=yes ;;
    esac
    ac_enable_check_opt=no
    for f in ${SH_ENABLE_OPTS}
    do
	f=`echo $f | sed 's/-/_/g'`
	if test x${f} = x"${ac_feature}"
	then
		ac_enable_check_opt=yes
	fi
    done
    if test x${ac_enable_check_opt} = xno
    then
	AC_MSG_ERROR([unrecognized option: $ac_option
Try `$[0] --help' for more information.])
    fi
    eval "enable_$ac_feature='$ac_optarg'" ;;

  -exec-prefix | --exec_prefix | --exec-prefix | --exec-prefi \
  | --exec-pref | --exec-pre | --exec-pr | --exec-p | --exec- \
  | --exec | --exe | --ex)
    ac_prev=exec_prefix 
    ac_exec_prefix_set="yes"
    ;;
  -exec-prefix=* | --exec_prefix=* | --exec-prefix=* | --exec-prefi=* \
  | --exec-pref=* | --exec-pre=* | --exec-pr=* | --exec-p=* | --exec-=* \
  | --exec=* | --exe=* | --ex=*)
    exec_prefix="$ac_optarg" 
    ac_exec_prefix_set="yes"
    ;;

  -gas | --gas | --ga | --g)
    # Obsolete; use --with-gas.
    with_gas=yes ;;

  -help | --help | --hel | --he | -h)
    ac_init_help=long ;;
  -help=r* | --help=r* | --hel=r* | --he=r* | -hr*)
    ac_init_help=recursive ;;
  -help=s* | --help=s* | --hel=s* | --he=s* | -hs*)
    ac_init_help=short ;;

  -host | --host | --hos | --ho)
    ac_prev=host_alias ;;
  -host=* | --host=* | --hos=* | --ho=*)
    host_alias="$ac_optarg" ;;

  -localstatedir | --localstatedir | --localstatedi | --localstated \
  | --localstate | --localstat | --localsta | --localst \
  | --locals | --local | --loca | --loc | --lo)
    ac_prev=localstatedir 
    ac_localstatedir_set="yes"
    ;;
  -localstatedir=* | --localstatedir=* | --localstatedi=* | --localstated=* \
  | --localstate=* | --localstat=* | --localsta=* | --localst=* \
  | --locals=* | --local=* | --loca=* | --loc=* | --lo=*)
    localstatedir="$ac_optarg" 
    ac_localstatedir_set="yes"
    ;;

  -mandir | --mandir | --mandi | --mand | --man | --ma | --m)
    ac_prev=mandir 
    ac_mandir_set="yes"
    ;;
  -mandir=* | --mandir=* | --mandi=* | --mand=* | --man=* | --ma=* | --m=*)
    mandir="$ac_optarg" 
    ac_mandir_set="yes"
    ;;

  -nfp | --nfp | --nf)
    # Obsolete; use --without-fp.
    with_fp=no ;;

  -no-create | --no-create | --no-creat | --no-crea | --no-cre \
  | --no-cr | --no-c | -n)
    no_create=yes ;;

  -no-recursion | --no-recursion | --no-recursio | --no-recursi \
  | --no-recurs | --no-recur | --no-recu | --no-rec | --no-re | --no-r)
    no_recursion=yes ;;

  -prefix | --prefix | --prefi | --pref | --pre | --pr | --p)
    ac_prev=prefix
    ac_prefix_set="yes" 
    ;;
  -prefix=* | --prefix=* | --prefi=* | --pref=* | --pre=* | --pr=* | --p=*)
    prefix="$ac_optarg" 
    ac_prefix_set="yes" 
    ;;

  -q | -quiet | --quiet | --quie | --qui | --qu | --q \
  | -silent | --silent | --silen | --sile | --sil)
    silent=yes ;;

  -sbindir | --sbindir | --sbindi | --sbind | --sbin | --sbi | --sb)
    ac_prev=sbindir 
    ac_sbindir_set="yes" 
    ;;
  -sbindir=* | --sbindir=* | --sbindi=* | --sbind=* | --sbin=* \
  | --sbi=* | --sb=*)
    sbindir="$ac_optarg" 
    ac_sbindir_set="yes" 
    ;;

  -bindir | --bindir | --bindi | --bind | --bin | --bi | --b)
    echo "WARNING: bindir will be ignored, use sbindir" 
    ;;
  -bindir=* | --bindir=* | --bindi=* | --bind=* | --bin=* \
  | --bi=* | --b=*)
    echo "WARNING: bindir will be ignored, use sbindir" 
    ;;

  -datadir | --datadir)
    echo "WARNING: datadir will be ignored" 
   ;;
  -datadir=* | --datadir=*)
    echo "WARNING: datadir will be ignored" 
   ;;
 
  -includedir | --includedir)
    echo "WARNING: includedir will be ignored" 
   ;;
  -includedir=* | --includedir=*)
    echo "WARNING: includedir will be ignored" 
   ;;

  -infodir | --infodir)
    echo "WARNING: infodir will be ignored" 
   ;;
  -infodir=* | --infodir=*)
    echo "WARNING: infodir will be ignored" 
   ;;
 
  -libdir | --libdir)
    echo "WARNING: libdir will be ignored" 
   ;;
  -libdir=* | --libdir=*)
    echo "WARNING: libdir will be ignored" 
   ;;
 
  -libexecdir | --libexecdir)
    echo "WARNING: libexecdir will be ignored" 
   ;;
  -libexecdir=* | --libexecdir=*)
    echo "WARNING: libexecdir will be ignored" 
   ;;

  -sharedstatedir | --sharedstatedir)
    echo "WARNING: sharedstatedir will be ignored" 
   ;;
  -sharedstatedir=* | --sharedstatedir=*)
    echo "WARNING: sharedstatedir will be ignored" 
   ;;
 
  -site | --site | --sit)
    ac_prev=site ;;
  -site=* | --site=* | --sit=*)
    site="$ac_optarg" ;;

  -srcdir | --srcdir | --srcdi | --srcd | --src | --sr)
    ac_prev=srcdir ;;
  -srcdir=* | --srcdir=* | --srcdi=* | --srcd=* | --src=* | --sr=*)
    srcdir="$ac_optarg" ;;

  -sysconfdir | --sysconfdir | --sysconfdi | --sysconfd | --sysconf \
  | --syscon | --sysco | --sysc | --sys | --sy)
    ac_prev=sysconfdir 
    ac_sysconfdir_set="yes" 
    ;;
  -sysconfdir=* | --sysconfdir=* | --sysconfdi=* | --sysconfd=* | --sysconf=* \
  | --syscon=* | --sysco=* | --sysc=* | --sys=* | --sy=*)
    sysconfdir="$ac_optarg" 
    ac_sysconfdir_set="yes" 
    ;;

  -target | --target | --targe | --targ | --tar | --ta | --t)
    ac_prev=target_alias ;;
  -target=* | --target=* | --targe=* | --targ=* | --tar=* | --ta=* | --t=*)
    target_alias="$ac_optarg" ;;

  -v | -verbose | --verbose | --verbos | --verbo | --verb)
    verbose=yes ;;

  -version | --version | --versio | --versi | --vers)
    ac_init_version=: ;;


  -with-* | --with-*)
    ac_package=`expr "x$ac_option" : 'x-*with-\([[^=]]*\)'`
    # Reject names that are not valid shell variable names.
    expr "x$ac_package" : "[.*[^-_$as_cr_alnum]]" >/dev/null &&
      AC_MSG_ERROR([invalid package name: $ac_package])
    ac_package=`echo $ac_package| sed 's/-/_/g'`
    case $ac_option in
      *=*) ac_optarg=`echo "$ac_optarg" | sed "s/'/'\\\\\\\\''/g"`;;
      *) ac_optarg=yes ;;
    esac
    ac_with_check_opt=no
    for f in ${SH_WITH_OPTS}
    do
	f=`echo $f | sed 's/-/_/g'`
	if test x${f} = x"${ac_package}"
	then
		ac_with_check_opt=yes
	fi
    done
    if test x${ac_with_check_opt} = xno
    then
	AC_MSG_ERROR([unrecognized option: $ac_option
Try `$[0] --help' for more information.])
    fi
    eval "with_$ac_package='$ac_optarg'" ;;

  -without-* | --without-*)
    ac_package=`expr "x$ac_option" : 'x-*without-\(.*\)'`
    # Reject names that are not valid shell variable names.
    expr "x$ac_package" : "[.*[^-_$as_cr_alnum]]" >/dev/null &&
      AC_MSG_ERROR([invalid package name: $ac_package])
    ac_package=`echo $ac_package | sed 's/-/_/g'`
    ac_with_check_opt=no
    for f in ${SH_WITH_OPTS}
    do
	f=`echo $f | sed 's/-/_/g'`
	if test x${f} = x"${ac_package}"
	then
		ac_with_check_opt=yes
	fi
    done
    if test x${ac_with_check_opt} = xno
    then
	AC_MSG_ERROR([unrecognized option: $ac_option
Try `$[0] --help' for more information.])
    fi
    eval "with_$ac_package=no" ;;


  -*) AC_MSG_ERROR([unrecognized option: $ac_option
Try `$[0] --help' for more information.])
    ;;

  *=*)
    ac_envvar=`expr "x$ac_option" : 'x\([[^=]]*\)='`
    # Reject names that are not valid shell variable names.
    expr "x$ac_envvar" : "[.*[^_$as_cr_alnum]]" >/dev/null &&
      AC_MSG_ERROR([invalid variable name: $ac_envvar])
    ac_optarg=`echo "$ac_optarg" | sed "s/'/'\\\\\\\\''/g"`
    eval "$ac_envvar='$ac_optarg'"
    export $ac_envvar ;;

  *)
    # FIXME: should be removed in autoconf 3.0.
    AC_MSG_WARN([you should use --build, --host, --target])
    expr "x$ac_option" : "[.*[^-._$as_cr_alnum]]" >/dev/null &&
      AC_MSG_WARN([invalid host type: $ac_option])
    : ${build_alias=$ac_option} ${host_alias=$ac_option} ${target_alias=$ac_option}
    ;;


  esac
done

if test -n "$ac_prev"; then
  AC_MSG_ERROR(missing argument to --`echo $ac_prev | sed 's/_/-/g'`)
fi

# Be sure to have absolute paths.
for ac_var in prefix exec_prefix
do
  eval ac_val=$`echo $ac_var`
  case $ac_val in
    [[\\/$]]* | ?:[[\\/]]* | NONE | '' | OPT | USR ) ;;
    *)  AC_MSG_ERROR([expected an absolute directory name for --$ac_var: $ac_val]);;
  esac
done

# Be sure to have absolute paths.
for ac_var in sbindir sysconfdir localstatedir mandir
do
  eval ac_val=$`echo $ac_var`
  case $ac_val in
    [[\\/$]]* | ?:[[\\/]]* ) ;;
    *)  AC_MSG_ERROR([expected an absolute directory name for --$ac_var: $ac_val]);;
  esac
done

# There might be people who depend on the old broken behavior: `$host'
# used to hold the argument of --host etc.
# FIXME: To remove some day.
build=$build_alias
host=$host_alias
target=$target_alias

# FIXME: To remove some day.
if test "x$host_alias" != x; then
  if test "x$build_alias" = x; then
    cross_compiling=maybe
    AC_MSG_WARN([If you wanted to set the --build type, don't use --host.
    If a cross compiler is detected then cross compile mode will be used.])
  elif test "x$build_alias" != "x$host_alias"; then
    cross_compiling=yes
  fi
fi

ac_tool_prefix=
test -n "$host_alias" && ac_tool_prefix=$host_alias-

test "$silent" = yes && exec AS_MESSAGE_FD>/dev/null

m4_divert_pop([PARSE_ARGS])dnl
])# SH_INIT_PARSE_ARGS

m4_define([SH_INIT_HELP],
[m4_divert_push([HELP_BEGIN])dnl

#
# Report the --help message.
#
if test "$ac_init_help" = "long"; then
  # Omit some internal or obsolete options to make the list less imposing.
  # This message is too long to be a string in the A/UX 3.1 sh.
  cat <<_ACEOF
\`configure' configures m4_ifset([AC_PACKAGE_STRING],
                        [AC_PACKAGE_STRING],
                        [this package]) to adapt to many kinds of systems.

Usage: $[0] [[OPTION]]... [[VAR=VALUE]]...

[To assign environment variables (e.g., CC, CFLAGS...), specify them as
VAR=VALUE.  See below for descriptions of some of the useful variables.

Defaults for the options are specified in brackets.

Configuration:
  -h, --help              display this help and exit
      --help=short        display options specific to this package
      --help=recursive    display the short help of all the included packages
  -V, --version           display version information and exit
  -q, --quiet, --silent   do not print \`checking...' messages
      --cache-file=FILE   cache test results in FILE [disabled]
  -C, --config-cache      alias for \`--cache-file=config.cache'
  -n, --no-create         do not create output files
      --srcdir=DIR        find the sources in DIR [configure dir or \`..']

_ACEOF

  cat <<_ACEOF
Installation directories:
  --prefix=PREFIX         install architecture-independent files in PREFIX
                          [$ac_default_prefix]
  --exec-prefix=EPREFIX   install architecture-dependent files in EPREFIX
                          [PREFIX]

By default, \`make install' will install binaries in \`/usr/local/sbin',
the config file in \`/etc', manpage in \`/usr/local/share/man', and state
data in \`/var/lib/INSTALL_NAME' (FSH layout).  You can specify other
FSH compliant layouts with \`--prefix=OPT' or \`--prefix=USR', or you
can specify a directory with \`--prefix=DIR' to install in \`DIR/sbin',
\`DIR/etc', etc.

For better control, use the options below.

Fine tuning of the installation directories:
  --sbindir=DIR          system admin executables [EPREFIX/sbin]
  --sysconfdir=DIR       read-only single-machine data [PREFIX/etc]
  --localstatedir=DIR    modifiable single-machine data [PREFIX/var]
  --mandir=DIR           man documentation [PREFIX/man]

For even finer tuning, paths can be specified for individual files (see below)

_ACEOF

  cat <<\_ACEOF]
m4_divert_pop([HELP_BEGIN])dnl
dnl The order of the diversions here is
dnl - HELP_BEGIN
dnl   which may be prolongated by extra generic options such as with X or
dnl   AC_ARG_PROGRAM.  Displayed only in long --help.
dnl
dnl - HELP_CANON
dnl   Support for cross compilation (--build, --host and --target).
dnl   Display only in long --help.
dnl
dnl - HELP_ENABLE
dnl   which starts with the trailer of the HELP_BEGIN, HELP_CANON section,
dnl   then implements the header of the non generic options.
dnl
dnl - HELP_WITH
dnl
dnl - HELP_VAR
dnl
dnl - HELP_VAR_END
dnl
dnl - HELP_END
dnl   initialized below, in which we dump the trailer (handling of the
dnl   recursion for instance).
m4_divert_push([HELP_ENABLE])dnl
_ACEOF
fi

if test -n "$ac_init_help"; then
m4_ifset([AC_PACKAGE_STRING],
[  case $ac_init_help in
     short | recursive ) echo "Configuration of AC_PACKAGE_STRING:";;
   esac])
  cat <<\_ACEOF
m4_divert_pop([HELP_ENABLE])dnl
m4_divert_push([HELP_END])dnl
m4_ifset([AC_PACKAGE_BUGREPORT], [
Report bugs to <AC_PACKAGE_BUGREPORT>.])
_ACEOF
fi

if test "$ac_init_help" = "recursive"; then
  # If there are subdirs, report their specific --help.
  ac_popdir=`pwd`
  for ac_dir in : $ac_subdirs_all; do test "x$ac_dir" = x: && continue
    test -d $ac_dir || continue
    _AC_SRCPATHS(["$ac_dir"])
    cd $ac_dir
    # Check for guested configure; otherwise get Cygnus style configure.
    if test -f $ac_srcdir/configure.gnu; then
      echo
      $SHELL $ac_srcdir/configure.gnu  --help=recursive
    elif test -f $ac_srcdir/configure; then
      echo
      $SHELL $ac_srcdir/configure  --help=recursive
    elif test -f $ac_srcdir/configure.ac ||
           test -f $ac_srcdir/configure.in; then
      echo
      $ac_configure --help
    else
      AC_MSG_WARN([no configuration information is in $ac_dir])
    fi
    cd $ac_popdir
  done
fi

test -n "$ac_init_help" && exit 0
m4_divert_pop([HELP_END])dnl
])# SH_INIT_HELP








# Check whether sa_sigaction works.
# Rainer Wichmann <support@la-samhna.de>, 2003.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License.

# serial 1

AC_DEFUN([AM_SA_SIGACTION_WORKS],
  [
   am_cv_val_SA_SIGACTION=no
   AC_CHECK_HEADER(signal.h,
     [
      AM_SI_USER
      AM_SA_SIGINFO
      if test $am_cv_val_SI_USER = yes && test $am_cv_val_SA_SIGINFO = yes
      then
        AC_TRY_RUN([
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

volatile int xnum  = 0;
volatile int xcode = 0; 
jmp_buf      Buf;
int          xsig  = SIGSEGV;

void sighandler (int xsignam, siginfo_t * xsiginfo, void * xsigadd)
{
  static sigset_t x;

  if (xsiginfo == NULL)
    exit(__LINE__);
  if (xsiginfo->si_signo != xsignam)
    exit(__LINE__);
  ++xnum;
  xcode   = xsiginfo->si_code;
  sigemptyset (&x);
  sigprocmask(SIG_SETMASK, &x, NULL);
  longjmp ( Buf, 1);
}

int main ()
{
  struct sigaction newact;

  newact.sa_sigaction = sighandler;
  sigemptyset (&newact.sa_mask);
  newact.sa_flags = SA_SIGINFO;
  if (0 != sigaction (xsig, &newact, NULL))
    exit (__LINE__);
  if(setjmp ( Buf)) {
      if (xnum > 1)
	goto Third;
      goto Second;
  }
  memcpy((void *) 0x0, "test", 5);
 Second:
  if (xcode == SI_USER)
    exit (__LINE__);
  raise(xsig);
 Third:
  if (xcode != SI_USER)
    exit (__LINE__);
  if (xnum != 2)
    exit (__LINE__);
  return (0);
}], am_cv_val_SA_SIGACTION=yes, am_cv_val_SA_SIGACTION=no, am_cv_val_SA_SIGACTION=no)
   fi
      ])
     AC_MSG_CHECKING([whether sa_sigaction is supported])
     if test $am_cv_val_SA_SIGACTION = yes
     then
       AC_MSG_RESULT(yes)
       AC_DEFINE([SA_SIGACTION_WORKS], 1, [Define if sa_sigaction works])
     else
	AC_MSG_RESULT(no)
     fi
     ])

# Check whether SI_USER is available in <signal.h>.
# Rainer Wichmann <support@la-samhna.de>, 2003.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License.

# serial 1


AC_DEFUN([AM_SI_USER],
  [if test $ac_cv_header_signal_h = yes; then
    AC_CACHE_CHECK([for SI_USER in signal.h], am_cv_val_SI_USER,
      [AC_TRY_LINK([#include <signal.h>], [return SI_USER],
       am_cv_val_SI_USER=yes, am_cv_val_SI_USER=no)])
    if test $am_cv_val_SI_USER = yes; then
      AC_DEFINE([HAVE_SI_USER], 1, [Define if you have SI_USER])
    fi
  fi])

# Check whether SA_SIGINFO is available in <signal.h>.
# Rainer Wichmann <support@la-samhna.de>, 2003.
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU Public License.

# serial 1


AC_DEFUN([AM_SA_SIGINFO],
  [if test $ac_cv_header_signal_h = yes; then
    AC_CACHE_CHECK([for SA_SIGINFO in signal.h], am_cv_val_SA_SIGINFO,
      [AC_TRY_LINK([#include <signal.h>], [return SA_SIGINFO],
       am_cv_val_SA_SIGINFO=yes, am_cv_val_SA_SIGINFO=no)])
    if test $am_cv_val_SA_SIGINFO = yes; then
      AC_DEFINE([HAVE_SA_SIGINFO], 1, [Define if you have SA_SIGINFO])
    fi
  fi])

dnl
dnl Useful macros for autoconf to check for ssp-patched gcc
dnl 1.0 - September 2003 - Tiago Sousa <mirage@kaotik.org>
dnl 1.1 - August 2006 - Ted Percival <ted@midg3t.net>
dnl     * Stricter language checking (C or C++)
dnl     * Adds GCC_STACK_PROTECT_LIB to add -lssp to LDFLAGS as necessary
dnl     * Caches all results
dnl     * Uses macros to ensure correct ouput in quiet/silent mode
dnl 1.2 - April 2007 - Ted Percival <ted@midg3t.net>
dnl     * Added GCC_STACK_PROTECTOR macro for simpler (one-line) invocation
dnl     * GCC_STACK_PROTECT_LIB now adds -lssp to LIBS rather than LDFLAGS
dnl
dnl About ssp:
dnl GCC extension for protecting applications from stack-smashing attacks
dnl http://www.research.ibm.com/trl/projects/security/ssp/
dnl
dnl Usage:
dnl Most people will simply call GCC_STACK_PROTECTOR.
dnl If you only use one of C or C++, you can save time by only calling the
dnl macro appropriate for that language. In that case you should also call
dnl GCC_STACK_PROTECT_LIB first.
dnl
dnl GCC_STACK_PROTECTOR
dnl Tries to turn on stack protection for C and C++ by calling the following
dnl three macros with the right languages.
dnl
dnl GCC_STACK_PROTECT_CC
dnl checks -fstack-protector with the C compiler, if it exists then updates
dnl CFLAGS and defines ENABLE_SSP_CC
dnl
dnl GCC_STACK_PROTECT_CXX
dnl checks -fstack-protector with the C++ compiler, if it exists then updates
dnl CXXFLAGS and defines ENABLE_SSP_CXX
dnl
dnl GCC_STACK_PROTECT_LIB
dnl adds -lssp to LIBS if it is available
dnl ssp is usually provided as part of libc, but was previously a separate lib
dnl It does not hurt to add -lssp even if libc provides SSP - in that case
dnl libssp will simply be ignored.
dnl

AC_DEFUN([GCC_STACK_PROTECT_LIB],[
  AC_CACHE_CHECK([whether libssp exists], ssp_cv_lib,
    [ssp_old_libs="$LIBS"
     LIBS="$LIBS -lssp"
     AC_TRY_LINK(,, ssp_cv_lib=yes, ssp_cv_lib=no)
     LIBS="$ssp_old_libs"
    ])
  if test $ssp_cv_lib = yes; then
    LIBS="$LIBS -lssp"
  fi
])

AC_DEFUN([GCC_STACK_PROTECT_CC],[
  AC_LANG_ASSERT(C)
  if test "X$CC" != "X"; then
    AC_CACHE_CHECK([whether ${CC} accepts -fstack-protector-all],
      ssp_cv_cc,
      [ssp_old_cflags="$CFLAGS"
       CFLAGS="$CFLAGS -fstack-protector-all"
       AC_TRY_COMPILE(,, ssp_cv_cc=yes, ssp_cv_cc=no)
       CFLAGS="$ssp_old_cflags"
      ])
    if test $ssp_cv_cc = no; then
      AC_CACHE_CHECK([whether ${CC} accepts -fstack-protector],
        ssp_cv_cc,
        [ssp_old_cflags="$CFLAGS"
         CFLAGS="$CFLAGS -fstack-protector"
         AC_TRY_COMPILE(,, ssp_cv_cc=yes, ssp_cv_cc=no)
         CFLAGS="$ssp_old_cflags"
        ])
      if test $ssp_cv_cc = yes; then
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -fstack-protector"
	LDFLAGS="$LDFLAGS -fstack-protector"
        AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
      fi
    else
      if test $ssp_cv_cc = yes; then
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -fstack-protector-all"
	LDFLAGS="$LDFLAGS -fstack-protector-all"
        AC_DEFINE([ENABLE_SSP_CC], 1, [Define if SSP C support is enabled.])
      fi
    fi
  fi
])

AC_DEFUN([GCC_STACK_PROTECT_CXX],[
  AC_LANG_ASSERT(C++)
  if test "X$CXX" != "X"; then
    AC_CACHE_CHECK([whether ${CXX} accepts -fstack-protector],
      ssp_cv_cxx,
      [ssp_old_cxxflags="$CXXFLAGS"
       CXXFLAGS="$CXXFLAGS -fstack-protector"
       AC_TRY_COMPILE(,, ssp_cv_cxx=yes, ssp_cv_cxx=no)
       CXXFLAGS="$ssp_old_cxxflags"
      ])
    if test $ssp_cv_cxx = yes; then
      CXXFLAGS="$CXXFLAGS -fstack-protector"
      AC_DEFINE([ENABLE_SSP_CXX], 1, [Define if SSP C++ support is enabled.])
    fi
  fi
])

AC_DEFUN([GCC_STACK_PROTECTOR],[
  GCC_STACK_PROTECT_LIB

  AC_LANG_PUSH([C])
  GCC_STACK_PROTECT_CC
  AC_LANG_POP([C])

  AC_LANG_PUSH([C++])
  GCC_STACK_PROTECT_CXX
  AC_LANG_POP([C++])
])


AC_DEFUN([GCC_PIE_CC],[
  AC_LANG_ASSERT(C)
  if test "X$CC" != "X"; then
    AC_CACHE_CHECK([whether ${CC} accepts -pie -fPIE],
      pie_cv_cc,
      [pie_old_cflags="$CFLAGS"
       CFLAGS="$CFLAGS -pie -fPIE"
       AC_TRY_COMPILE(,, pie_cv_cc=yes, pie_cv_cc=no)
       CFLAGS="$pie_old_cflags"
      ])
    if test $pie_cv_cc = yes; then
      case "$host_os" in
      *cygwin*)
      ;;
      *)
      PIE_CFLAGS="-fPIE"
      PIE_LDFLAGS="-pie"
      ;;
      esac
    fi
  fi
])

AC_DEFUN([GCC_STACK_CHECK_CC],[
  AC_LANG_ASSERT(C)
  if test "X$CC" != "X"; then
    AC_CACHE_CHECK([whether ${CC} accepts -fstack-check],
      stackcheck_cv_cc,
      [stackcheck_old_cflags="$CFLAGS"
       CFLAGS="$CFLAGS -fstack-check"
       AC_TRY_COMPILE(,, stackcheck_cv_cc=yes, stackcheck_cv_cc=no)
       CFLAGS="$stackcheck_old_cflags"
      ])
    if test $stackcheck_cv_cc = yes; then
      CFLAGS="$CFLAGS -fstack-check"
    fi
  fi
])

AC_DEFUN([GCC_FLAG_CHECK],[
  AC_LANG_ASSERT(C)
  if test "X$CC" != "X"; then
     AC_MSG_CHECKING([whether ${CC} accepts $1])
     saved_cflags="$CFLAGS"
     CFLAGS="$CFLAGS -Werror $1"
     AC_TRY_COMPILE(,, flag_check_cv=yes, flag_check_cv=no)
     CFLAGS="$saved_cflags"

     if test $flag_check_cv = yes; then
      	CFLAGS="$CFLAGS $1"
	AC_MSG_RESULT([yes])
     else
        AC_MSG_RESULT([no])
     fi
  fi
])

AC_DEFUN([SAMHAIN_POSIX],[
	AC_MSG_CHECKING([whether _POSIX_SOURCE is necessary])
	AC_TRY_COMPILE([#include <stdio.h>
void fileno(int);int fdopen(int, char *); ],,
	[
	AC_MSG_RESULT(yes)
	AC_DEFINE([_POSIX_SOURCE],1,[Define if POSIX functions are required])
	],
	[AC_MSG_RESULT(no)])
])dnl

dnl checks for a known 64 bit programming environment
dnl AC_RUN_IFELSE(PROGRAM,
dnl               [ACTION-IF-TRUE], [ACTION-IF-FALSE],
dnl               [ACTION-IF-CROSS-COMPILING = RUNTIME-ERROR])
dnl
AC_DEFUN([SAMHAIN_PRG_ENV],[
    AC_MSG_CHECKING([for a known 64 bit programming environment])
    # Compile and run a program that determines the programming environment
    AC_RUN_IFELSE([
      AC_LANG_SOURCE([[
#include <stdio.h>
int main(int argc,char **argv)
{
  if (argc > 1) {
#if defined(__arch64__)
  printf("__arch64__\n");
#elif defined(__ia64__)
  printf("__ia64__\n");
#elif defined(__x86_64__)
  printf("__x86_64__\n");
#elif defined(__LP64__)
  printf("__LP64__\n");
#elif defined(__64BIT__)
  printf("__64BIT__\n");
#elif defined(_LP64)
  printf("_LP64\n");
#elif defined(_M_IA64)
  printf("_M_IA64\n");
#elif defined(_MIPS_SZLONG) && (_MIPS_SZLONG == 64)
  printf("_MIPS_64\n");
#else
choke me
#endif
  }
  return 0;
}
      ]])
    ],[
      # Program compiled and ran, so get version by adding argument.
      samhain_prg_ENV=`./conftest$ac_exeext x`
      samhain_64=yes
      AC_MSG_RESULT([$samhain_prg_ENV])
    ],[
      AC_MSG_RESULT([none])
	],[
      AC_MSG_RESULT([none])
	])
])dnl

AC_DEFUN([SAMHAIN_X86_64],[
	AC_MSG_CHECKING([for x86_64])
	AC_TRY_RUN([
int main() {
__asm__ volatile (
"movq %rax, %rax"
);
return 0;
}
	],
	[
	AC_MSG_RESULT(yes)
	samhain_64=yes
	tiger_src=sh_tiger1_64.c
	samhain_64_asm=yes
	],
	[
	AC_MSG_RESULT([no])
	],[
	AC_MSG_RESULT([no])
	])
])dnl


AC_DEFUN([SAMHAIN_64],[
samhain_64=no
tiger_src=sh_tiger1.c
samhain_64_asm=no
#
# if sizeof(unsigned long) = 4, try compiler macros for 64bit
#
if test "x$ac_cv_sizeof_unsigned_long" = x4; then
  if test "x$ac_cv_sizeof_unsigned_long_long" = x8; then
	SAMHAIN_PRG_ENV
	if test "x$samhain_64" = xyes; then
	  tiger_src=sh_tiger1_64.c
        fi
	#
	# if GCC and __i386__, use precompiled assembler
	#
	if test "x$GCC" = xyes; then
	  AC_MSG_CHECKING([for non-apple non-cygwin i386])
	  samhain_i386=no
          $CC -E -dM - < /dev/null | egrep '__i386__' >/dev/null 2>&1 
          if test $? = 0; then
	    case "$host_os" in
	    	 *linux*)
            	 # apples gcc does not understand the assembly we provide
            	 $CC -E -dM - < /dev/null | egrep '(__sun__|__APPLE__|__CYGWIN__)' >/dev/null 2>&1 || samhain_i386=yes
	    	 ;;
	    	 *)
	    	 ;;
	    esac
          fi
	  AC_MSG_RESULT([$samhain_i386])
	  if test "x$samhain_i386" = xyes; then
	    GCC_PIE_CC
	    if test $pie_cv_cc = yes; then
	       tiger_src=sh_tiger1.s
	       AC_DEFINE([TIGER_32_BIT_S],1,[Define to use tiger 32 bit i386 assembler])
	    fi
          fi
	fi
	#
	#
	#
  else
	samhain_64=no
	tiger_src=sh_tiger1.c
  fi
else
  #
  # sizeof(unsigned long) = 8
  #
  tiger_src=sh_tiger1_64.c
  samhain_64=yes
  #
  # check for x86_64 (enables assembly optimizations)
  #
  if test "x$GCC" = xyes; then
     $CC -E -dM - < /dev/null | egrep '__clang__' >/dev/null 2>&1 
     if ! test $? = 0; then
     	 case "$host_os" in
     	     *linux*)
    	     SAMHAIN_X86_64
	     ;;
     	     *bsd*)
    	     SAMHAIN_X86_64
	     ;;
     	     *)
    	     SAMHAIN_X86_64
	     ;;
      	 esac
     fi	
  fi
fi
if test "x$samhain_64" = xyes; then 
	AC_DEFINE([TIGER_64_BIT],1,[Define to use tiger 64 bit implementation])
fi
AC_MSG_CHECKING([for 64 bit environment])
AC_MSG_RESULT([$samhain_64])
AC_MSG_CHECKING([for tiger source to use])
AC_MSG_RESULT([$tiger_src])
AC_SUBST(tiger_src)
])dnl

AC_DEFUN([sh_CHECK_POSIX_ACL],
[
  AC_CHECK_HEADERS(sys/acl.h)
  if test $ac_cv_header_sys_acl_h = yes; then

  	AC_CHECK_LIB([acl], [acl_get_file], sh_lacl=yes, sh_lacl=no)
  	if test x"$sh_lacl" = xyes; then
    		LIBACL=-lacl
  	else
    		LIBACL=
  	fi

  	OLDLIBS="$LIBS"
  	LIBS="$LIBS $LIBACL"
  	AC_CHECK_FUNCS([acl_free acl_get_file acl_get_fd],
                       [sh_facl=yes],[sh_facl=no])
  	LIBS="$OLDLIBS"
  fi	

  if test x"$sh_facl" = xyes; then
  	  AC_DEFINE(USE_ACL, 1, [Define if you want ACL support.])
	  LIBS="$LIBS $LIBACL"
  else
	  if test "x$enable_posix_acl" != xcheck; then
             AC_MSG_FAILURE([--enable-posix-acl was given, but test for acl support failed])
          fi
  fi
])

AC_DEFUN([sh_CHECK_XATTR],
[
  AC_CHECK_HEADERS(attr/xattr.h)
  if test $ac_cv_header_attr_xattr_h = yes; then

  	AC_CHECK_LIB([attr], [getxattr], sh_lattr=yes, sh_lattr=no)
  	if test x"$sh_lattr" = xyes; then
    		LIBATTR=-lattr
  	else
    		LIBATTR=
  	fi
  
  	OLDLIBS="$LIBS"
  	LIBS="$LIBS $LIBATTR"
  	AC_CHECK_FUNCS([getxattr lgetxattr fgetxattr],
                       [sh_fattr=yes],[sh_fattr=no])
  	LIBS="$OLDLIBS"
  fi

  if test x"$sh_fattr" = xyes; then
	  AC_DEFINE(USE_XATTR, 1, [Define if you want extended attributes support.])
	  LIBS="$LIBS $LIBATTR"
  else
	  if test "x$enable_selinux" != xcheck; then
             AC_MSG_FAILURE([--enable-selinux was given, but test for selinux support failed])
          fi
  fi
])

dnl Autoconf macros for libprelude
dnl $id$

# Modified for LIBPRELUDE -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBPRELUDE([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libprelude, and define LIBPRELUDE_PREFIX, LIBPRELUDE_CFLAGS, LIBPRELUDE_PTHREAD_CFLAGS, 
dnl LIBPRELUDE_LDFLAGS, and LIBPRELUDE_LIBS
dnl
AC_DEFUN([AM_PATH_LIBPRELUDE],
[dnl
dnl Get the cflags and libraries from the libprelude-config script
dnl
dnl AC_ARG_WITH(libprelude-prefix,
dnl          [  --with-libprelude-prefix=PFX   Prefix where libprelude is installed (optional)],
dnl          libprelude_config_prefix="$withval", libprelude_config_prefix="")
dnl
dnl  if test x$libprelude_config_prefix != x ; then
dnl     if test x${LIBPRELUDE_CONFIG+set} != xset ; then
dnl        LIBPRELUDE_CONFIG=$libprelude_config_prefix/bin/libprelude-config
dnl     fi
dnl  fi
dnl
dnl  AC_PATH_PROG(LIBPRELUDE_CONFIG, libprelude-config, no)
  min_libprelude_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for libprelude - version >= $min_libprelude_version)
  no_libprelude=""
  if test "$LIBPRELUDE_CONFIG" = "no" ; then
    no_libprelude=yes
  else
    LIBPRELUDE_CFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --cflags`
    LIBPRELUDE_PTHREAD_CFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --pthread-cflags`
    LIBPRELUDE_LDFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --ldflags`
    LIBPRELUDE_LIBS=`$LIBPRELUDE_CONFIG $libprelude_config_args --libs`
    LIBPRELUDE_PREFIX=`$LIBPRELUDE_CONFIG $libprelude_config_args --prefix`
    LIBPRELUDE_CONFIG_PREFIX=`$LIBPRELUDE_CONFIG $libprelude_config_args --config-prefix`
    libprelude_config_version=`$LIBPRELUDE_CONFIG $libprelude_config_args --version`


      ac_save_CFLAGS="$CFLAGS"
      ac_save_LDFLAGS="$LDFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
      LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
      LIBS="$LIBS $LIBPRELUDE_LIBS"
dnl
dnl Now check if the installed libprelude is sufficiently new. Also sanity
dnl checks the results of libprelude-config to some extent
dnl
      rm -f conf.libpreludetest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>

int
main ()
{
    system ("touch conf.libpreludetest");

    if( strcmp( prelude_check_version(NULL), "$libprelude_config_version" ) )
    {
      printf("\n*** 'libprelude-config --version' returned %s, but LIBPRELUDE (%s)\n",
             "$libprelude_config_version", prelude_check_version(NULL) );
      printf("*** was found! If libprelude-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBPRELUDE. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libprelude-config was wrong, set the environment variable LIBPRELUDE_CONFIG\n");
      printf("*** to point to the correct copy of libprelude-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(prelude_check_version(NULL), LIBPRELUDE_VERSION ) )
    {
      printf("\n*** LIBPRELUDE header file (version %s) does not match\n", LIBPRELUDE_VERSION);
      printf("*** library (version %s)\n", prelude_check_version(NULL) );
    }
    else
    {
      if ( prelude_check_version( "$min_libprelude_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBPRELUDE (%s) was found.\n",
                prelude_check_version(NULL) );
        printf("*** You need a version of LIBPRELUDE newer than %s. The latest version of\n",
               "$min_libprelude_version" );
        printf("*** LIBPRELUDE is always available from http://www.prelude-ids.org/download/releases.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libprelude-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBPRELUDE, but you can also set the LIBPRELUDE_CONFIG environment to point to the\n");
        printf("*** correct copy of libprelude-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_libprelude=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
       LDFLAGS="$ac_save_LDFLAGS"
  fi

  if test "x$no_libprelude" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libpreludetest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBPRELUDE_CONFIG" = "no" ; then
       echo "*** The libprelude-config script installed by LIBPRELUDE could not be found"
       echo "*** If LIBPRELUDE was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBPRELUDE_CONFIG environment variable to the"
       echo "*** full path to libprelude-config."
     else
       if test -f conf.libpreludetest ; then
        :
       else
          echo "*** Could not run libprelude test program, checking why..."
          CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
	  LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
          LIBS="$LIBS $LIBPRELUDE_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>
],      [ return !!prelude_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBPRELUDE or finding the wrong"
          echo "*** version of LIBPRELUDE. If it is not finding LIBPRELUDE, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBPRELUDE was incorrectly installed"
          echo "*** or that you have moved LIBPRELUDE since it was installed. In the latter case, you"
          echo "*** may want to edit the libprelude-config script: $LIBPRELUDE_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
	  LDFLAGS="$ac_save_LDFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBPRELUDE_CFLAGS=""
     LIBPRELUDE_LDFLAGS=""
     LIBPRELUDE_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libpreludetest
  AC_SUBST(LIBPRELUDE_CFLAGS)
  AC_SUBST(LIBPRELUDE_PTHREAD_CFLAGS)
  AC_SUBST(LIBPRELUDE_LDFLAGS)
  AC_SUBST(LIBPRELUDE_LIBS)
  AC_SUBST(LIBPRELUDE_PREFIX)
  AC_SUBST(LIBPRELUDE_CONFIG_PREFIX)
])


##### http://autoconf-archive.cryp.to/acx_pthread.html
#
# SYNOPSIS
#
#   ACX_PTHREAD([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
#
# DESCRIPTION
#
#   This macro figures out how to build C programs using POSIX threads.
#   It sets the PTHREAD_LIBS output variable to the threads library and
#   linker flags, and the PTHREAD_CFLAGS output variable to any special
#   C compiler flags that are needed. (The user can also force certain
#   compiler flags/libs to be tested by setting these environment
#   variables.)
#
#   Also sets PTHREAD_CC to any special C compiler that is needed for
#   multi-threaded programs (defaults to the value of CC otherwise).
#   (This is necessary on AIX to use the special cc_r compiler alias.)
#
#   NOTE: You are assumed to not only compile your program with these
#   flags, but also link it with them as well. e.g. you should link
#   with $PTHREAD_CC $CFLAGS $PTHREAD_CFLAGS $LDFLAGS ... $PTHREAD_LIBS
#   $LIBS
#
#   If you are only building threads programs, you may wish to use
#   these variables in your default LIBS, CFLAGS, and CC:
#
#          LIBS="$PTHREAD_LIBS $LIBS"
#          CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
#          CC="$PTHREAD_CC"
#
#   In addition, if the PTHREAD_CREATE_JOINABLE thread-attribute
#   constant has a nonstandard name, defines PTHREAD_CREATE_JOINABLE to
#   that name (e.g. PTHREAD_CREATE_UNDETACHED on AIX).
#
#   ACTION-IF-FOUND is a list of shell commands to run if a threads
#   library is found, and ACTION-IF-NOT-FOUND is a list of commands to
#   run it if it is not found. If ACTION-IF-FOUND is not specified, the
#   default action will define HAVE_PTHREAD.
#
#   Please let the authors know if this macro fails on any platform, or
#   if you have any other suggestions or comments. This macro was based
#   on work by SGJ on autoconf scripts for FFTW (http://www.fftw.org/)
#   (with help from M. Frigo), as well as ac_pthread and hb_pthread
#   macros posted by Alejandro Forero Cuervo to the autoconf macro
#   repository. We are also grateful for the helpful feedback of
#   numerous users.
#
# LAST MODIFICATION
#
#   2007-07-29
#
# COPYLEFT
#
#   Copyright (c) 2007 Steven G. Johnson <stevenj@alum.mit.edu>
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see
#   <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright
#   owner gives unlimited permission to copy, distribute and modify the
#   configure scripts that are the output of Autoconf when processing
#   the Macro. You need not follow the terms of the GNU General Public
#   License when using or distributing such scripts, even though
#   portions of the text of the Macro appear in them. The GNU General
#   Public License (GPL) does govern all other use of the material that
#   constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the
#   Autoconf Macro released by the Autoconf Macro Archive. When you
#   make and distribute a modified version of the Autoconf Macro, you
#   may extend this special exception to the GPL to apply to your
#   modified version as well.

AC_DEFUN([ACX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
acx_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, acx_pthread_ok=yes)
        AC_MSG_RESULT($acx_pthread_ok)
        if test x"$acx_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

acx_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
#      ... -mt is also the pthreads flag for HP/aCC
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthreads/-mt/
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        acx_pthread_flags="-pthreads pthread -mt -pthread $acx_pthread_flags"
        ;;
esac

if test x"$acx_pthread_ok" = xno; then
for flag in $acx_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -pthread)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

		pthread-config)
		AC_CHECK_PROG(acx_pthread_config, pthread-config, yes, no)
		if test x"$acx_pthread_config" = xno; then continue; fi
		PTHREAD_CFLAGS="`pthread-config --cflags`"
		PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
		;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        save_LDFLAGS="$LDFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>],
                    [pthread_t th; pthread_join(th, 0);
                     pthread_attr_init(0); pthread_cleanup_push(0, 0);
                     pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
                    [acx_pthread_ok=yes])

        LIBS="$save_LIBS"
        LDFLAGS="$save_LDFLAGS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($acx_pthread_ok)
        if test "x$acx_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$acx_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
	AC_MSG_CHECKING([for joinable pthread attribute])
	attr_name=unknown
	for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
	    AC_TRY_LINK([#include <pthread.h>], [int attr=$attr; return attr;],
                        [attr_name=$attr; break])
	done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

	# Solaris lossage: default is obsolete semantics for getpwnam_r,
	# getpwuid_r, getgrgid_r, unless _POSIX_PTHREAD_SEMANTICS is defined
        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
            *-aix* | *-freebsd* | *-darwin*) flag="-D_THREAD_SAFE";;
            *-osf* | *-hpux*) flag="-D_REENTRANT";;
	    *solaris*) flag="-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        # Detect PTHREAD_MUTEX_RECURSIVE
	AC_MSG_CHECKING([for recursive mutexes])
	mutex_recursive=no
	AC_TRY_LINK([
#define _XOPEN_SOURCE 500
#include <pthread.h>], [
pthread_mutexattr_t   mta;
pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
return 0;],[mutex_recursive=yes])
	if test "x$mutex_recursive" = "xyes"
	then
	  AC_DEFINE(HAVE_PTHREAD_MUTEX_RECURSIVE,1,[Define if you have recursive mutexes.])
	fi
        AC_MSG_RESULT($mutex_recursive)

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with xlc_r or cc_r
	if test x"$GCC" != xyes; then
          AC_CHECK_PROGS(PTHREAD_CC, xlc_r cc_r, ${CC})
        else
          PTHREAD_CC=$CC
	fi
else
        PTHREAD_CC="$CC"
fi

if test x"$acx_pthread_ok" = xyes; then
   PTHREAD_CFLAGS="${PTHREAD_CFLAGS} -DUSE_MALLOC_LOCK=1"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LDFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$acx_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        acx_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl ACX_PTHREAD




dnl Copyright © 2004 Loic Dachary <loic@senga.org>
dnl
dnl This program is free software; you can redistribute it and/or modify 
dnl it under the terms of the GNU General Public License as published by 
dnl the Free Software Foundation; either version 2 of the License, or (at 
dnl your option) any later version.
dnl
dnl Use ZLIB_HOME instead of option

AC_DEFUN([CHECK_ZLIB],[

if test "x${ZLIB_HOME}" = "x"; then 
	ZLIB_HOME=/usr/local
	if test ! -f "${ZLIB_HOME}/include/zlib.h"
	then
        	ZLIB_HOME=/usr
	fi
fi

zlib_found=no

ZLIB_OLD_LDFLAGS=$LDFLAGS
ZLIB_OLD_CPPFLAGS=$LDFLAGS
if test "x${ZLIB_HOME}" = "x/usr"; then
	:
else
	LDFLAGS="$LDFLAGS -L${ZLIB_HOME}/lib"
	CPPFLAGS="$CPPFLAGS -I${ZLIB_HOME}/include"
fi
AC_LANG_SAVE
AC_LANG_C
AC_CHECK_LIB(z, inflateEnd, [zlib_cv_libz=yes], [zlib_cv_libz=no])
AC_CHECK_HEADER(zlib.h, [zlib_cv_zlib_h=yes], [zlib_cv_zlib_h=no])
AC_LANG_RESTORE
if test "$zlib_cv_libz" = "yes" -a "$zlib_cv_zlib_h" = "yes"
then
        #
        # If both library and header were found, use them
        #
        AC_CHECK_LIB(z, inflateEnd)
        AC_MSG_CHECKING([zlib in ${ZLIB_HOME}])
        AC_MSG_RESULT(ok)
	AC_CHECK_FUNCS([compressBound])
	zlib_found=yes
else
        #
        # If either header or library was not found, revert and bomb
        #
        AC_MSG_CHECKING(zlib in ${ZLIB_HOME})
        LDFLAGS="$ZLIB_OLD_LDFLAGS"
        CPPFLAGS="$ZLIB_OLD_CPPFLAGS"
        AC_MSG_RESULT(failed)
        AC_MSG_WARN([zlib not found in ZLIB_HOME, /usr/local, or /usr])
fi

])

# SH_PROG_LD
# ----------
# find the pathname to the GNU or non-GNU linker
AC_DEFUN([SH_PROG_LD],
[
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([AC_CANONICAL_BUILD])dnl
ac_prog=ld
if test "$GCC" = yes; then
  # Check if gcc -print-prog-name=ld gives a path.
  AC_MSG_CHECKING([for ld used by $CC])
  case $host in
  *-*-mingw*)
    # gcc leaves a trailing carriage return which upsets mingw
    ac_prog=`($CC -print-prog-name=ld) 2>&5 | tr -d '\015'` ;;
  *)
    ac_prog=`($CC -print-prog-name=ld) 2>&5` ;;
  esac
  case $ac_prog in
    # Accept absolute paths.
    [[\\/]]* | ?:[[\\/]]*)
      re_direlt='/[[^/]][[^/]]*/\.\./'
      # Canonicalize the pathname of ld
      ac_prog=`echo $ac_prog| sed 's%\\\\%/%g'`
      while echo $ac_prog | grep "$re_direlt" > /dev/null 2>&1; do
        ac_prog=`echo $ac_prog| sed "s%$re_direlt%/%"`
      done
      test -z "$LD" && LD="$ac_prog"
      ;;
  "")
    # If it fails, then pretend we aren't using GCC.
    ac_prog=ld
    ;;
  *)
    # If it is relative, then search for the first ld in PATH.
    with_gnu_ld=unknown
    ;;
  esac
else
  AC_MSG_CHECKING([for ld])
fi
AC_CACHE_VAL(lt_cv_path_LD,
[if test -z "$LD"; then
  lt_save_ifs="$IFS"; IFS=$PATH_SEPARATOR
  for ac_dir in $PATH; do
    IFS="$lt_save_ifs"
    test -z "$ac_dir" && ac_dir=.
    if test -f "$ac_dir/$ac_prog" || test -f "$ac_dir/$ac_prog$ac_exeext"; then
      lt_cv_path_LD="$ac_dir/$ac_prog"
      # Check to see if the program is GNU ld.  I'd rather use --version,
      # but apparently some variants of GNU ld only accept -v.
      # Break only if it was the GNU/non-GNU ld that we prefer.
      case `"$lt_cv_path_LD" -v 2>&1 </dev/null` in
      *GNU* | *'with BFD'*)
        with_gnu_ld=yes
        ;;
      *)
        with_gnu_ld=no
        ;;
      esac
    fi
  done
  IFS="$lt_save_ifs"
else
  lt_cv_path_LD="$LD" # Let the user override the test with a path.
fi])
LD="$lt_cv_path_LD"
if test -n "$LD"; then
  AC_MSG_RESULT($LD)
else
  AC_MSG_RESULT(no)
fi
test -z "$LD" && AC_MSG_ERROR([no acceptable ld found in \$PATH])
AC_CACHE_CHECK([if the linker ($LD) is GNU ld], lt_cv_prog_gnu_ld,
[# I'd rather use --version here, but apparently some GNU lds only accept -v.
case `$LD -v 2>&1 </dev/null` in
*GNU* | *'with BFD'*)
  lt_cv_prog_gnu_ld=yes
  ;;
*)
  lt_cv_prog_gnu_ld=no
  ;;
esac])
with_gnu_ld=$lt_cv_prog_gnu_ld
])# AC_PROG_LD_GNU

# SH_STRFTIME_Z
# -------------
# check whether strftime supports %z
AC_DEFUN([SH_STRFTIME_Z],
[
AC_MSG_CHECKING([whether strftime supports %z])
AC_TRY_RUN([
#include <time.h>
#include <string.h>
int main()
{
   struct tm tm;
   char tt[64];
   memset(&tm, 0, sizeof(tm));
   strftime(tt, sizeof(tt), "%z", &tm);

   if (strlen(tt) != 5) return 1;
   return 0;
}
],
[
AC_MSG_RESULT([yes])
AC_DEFINE(HAVE_STRFTIME_Z, 1, [strftime supports %z])
],
[
AC_MSG_RESULT([no])
],[
AC_MSG_RESULT([no])
])])

AC_DEFUN([SH_GCC_VERSION], [
  GCC_VERSION=""
  gcc_VERSION_MAJOR=0
  gcc_VERSION_MINOR=0
  AC_MSG_CHECKING([for gcc version])
  if test "x$GCC" = "xyes"
  then
	$CC -dumpversion >/dev/null 2>&1
	if test $? -eq 0
	then
		GCC_VERSION=`$CC -dumpversion`
      		gcc_VERSION_MAJOR=`echo $GCC_VERSION | cut -d'.' -f1`
      		gcc_VERSION_MINOR=`echo $GCC_VERSION | cut -d'.' -f2`
      		AC_DEFINE_UNQUOTED(GCC_VERSION_MAJOR, [${gcc_VERSION_MAJOR}], [gcc version major])
      		AC_DEFINE_UNQUOTED(GCC_VERSION_MINOR, [${gcc_VERSION_MINOR}], [gcc version minor])
		AC_MSG_RESULT([$GCC_VERSION])
	else
		AC_MSG_RESULT([$CC -dumpversion working])
	fi
  else
	AC_MSG_RESULT([compiler is not gcc])
  fi
])



dnl *-*wedit:notab*-*  Please keep this as the last line.

