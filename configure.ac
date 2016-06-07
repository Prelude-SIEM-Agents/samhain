dnl We want to override the standard _AC_INIT_PARSE_ARGS
dnl
AU_ALIAS([_AC_INIT_PARSE_ARGS], [SH_INIT_PARSE_ARGS])
AU_ALIAS([_AC_INIT_help], [SH_INIT_HELP])

AC_INIT(src/samhain.c)


AC_ARG_VAR([LIBS], [libraries to link against, e.g. -lintl])

dnl
dnl start
dnl
AM_INIT_AUTOMAKE(samhain, 4.1.4)
AC_DEFINE([SAMHAIN], 1, [Application is samhain])
AC_CANONICAL_HOST

dnl
dnl     checks for programs
dnl

AC_PROG_CC
if test "$host" != "$build"; then
   AC_CHECK_PROGS(BUILD_CC, gcc cc)
else
   BUILD_CC=$CC
fi
AC_PROG_CPP 
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_AWK
SH_PROG_LD
AC_PATH_PROG(cmd_hostname,hostname)
AC_SUBST(cmd_hostname)
AC_SUBST(BUILD_CC)

if test "x$GCC" = "xyes"; then
   SH_GCC_VERSION
fi

AC_HEADER_STDC

AC_CHECK_HEADERS([sys/ipc.h sys/sem.h sys/msg.h sys/uio.h fcntl.h])


AC_MSG_CHECKING([for OS specific issues])
mydebugflag=no
myneedg3=no
uid_cast="signed long"
selectconfig=linux
mynetbsd=no
sh_use_lcaps="undef"
dnmalloc_ok=yes
sh_use_pie=yes
enable_asm_ok=yes

case "$host_os" in

	*linux*)
	sh_use_lcaps="yes"
	AC_DEFINE(HOST_IS_LINUX)
        AC_DEFINE(HAVE_EXT2_IOCTLS)
	AC_MSG_RESULT([use ioctl to get e2fs flags])
	case "$host_cpu" in 
	   i*86*)
	   AC_DEFINE(HOST_IS_I86LINUX)
	   ;;
	   x86_64)
	   AC_DEFINE([HOST_IS_64LINUX], 1, [Define if host OS is 64bit Linux])
	   ;;
	   *)
	   ;;
	esac
        ;;
	
	*osf*)
	AC_DEFINE([HOST_IS_OSF], 1, [Define if host OS is OSF])
	if test "x$GCC" != "xyes"; then
    	  CFLAGS=`echo $CFLAGS | sed 's%\-g%%' `
	  CFLAGS="$CFLAGS -O2 -assume noaligned_objects"
	  myneedg3=yes
	  AC_MSG_RESULT([compiler needs assume noaligned_objects])
	else
	  AC_MSG_RESULT([none])
        fi
        ;;
	
	*cygwin*) 
	AC_DEFINE(HOST_IS_CYGWIN)
	AC_DEFINE([USE_REGISTRY_CHECK], 1, [Define for registry check])
	dnmalloc_ok=no
	enable_asm_ok=no
	AC_MSG_RESULT([no trusted paths, no dnmalloc. no asm optimize])
	;;

	*darwin*|*apple*) 
	AC_DEFINE(HOST_IS_DARWIN)
	dnmalloc_ok=no
	AC_MSG_RESULT([check resource forks, no dnmalloc])
	;;

	*freebsd8*|*freebsd9*)
	AC_DEFINE(HOST_IS_FREEBSD)
	selectconfig=freebsd
	case "$host_cpu" in
		amd64|x86_64)
		dnmalloc_ok=no
		AC_MSG_RESULT([no dnmalloc])
		;;
		*)
		AC_MSG_RESULT([none])
		;;
	esac
	;;
	
	*freebsd7*)
	AC_DEFINE(HOST_IS_FREEBSD)
	selectconfig=freebsd
	case "$host_cpu" in
		amd64|x86_64)
		sh_use_pie=no
		dnmalloc_ok=no
		AC_MSG_RESULT([no dnmalloc and broken compiler toolchain])
		;;
		*)
		AC_MSG_RESULT([none])
		;;
	esac
	;;
	
	*freebsd*)
	AC_DEFINE(HOST_IS_FREEBSD)
	selectconfig=freebsd
	AC_MSG_RESULT([none])
	;;
	
	*openbsd*)
	AC_DEFINE([HOST_IS_OPENBSD], 1, [Define if host OS is OPENBSD])
	selectconfig=freebsd
	dnmalloc_ok=no
	AC_MSG_RESULT([dnmalloc does not work with pthreads])
	;;

	*netbsd*)
	mynetbsd=yes
	selectconfig=netbsd
	AC_MSG_RESULT([bug with libresolve])
	;;

        *solaris*)
	selectconfig=solaris
	AC_DEFINE(HOST_IS_SOLARIS)
	case "$host_cpu" in
		i*86)
		AC_DEFINE(HOST_IS_I86SOLARIS)
		AC_MSG_RESULT([vsnprintf prototype])
		;;
		*)
		AC_MSG_RESULT([none])
		;;
	esac
	if test "x$GCC" != "xyes"; then
  	  if test ! -z "`echo "$CFLAGS" | grep "\-g" 2> /dev/null`" ; then
    		CFLAGS=`echo $CFLAGS | sed 's%\-g%%' `
  	  fi
  	  if test -z "`echo "$CFLAGS" | grep "\-xO2" 2> /dev/null`"; then
    		CFLAGS="$CFLAGS -xO2"
  	  fi
  	  if test -z "`echo "$CFLAGS" | grep "\-Xa" 2> /dev/null`"; then
    		CFLAGS="$CFLAGS -Xa"
  	  fi
	  LIBS="-lc $LIBS"
	fi
        ;;


        *sun*)
	selectconfig=solaris
	AC_DEFINE(HOST_IS_SOLARIS)
	AC_MSG_RESULT([none])
        ;;

	*aix*)
        AC_DEFINE(HOST_IS_AIX)
	selectconfig=aix5.2.0
	uid_cast="unsigned long"
	if test "x$GCC" != "xyes"; then
  	  if test ! -z "`echo "$CFLAGS" | grep "\-g" 2> /dev/null`" ; then
    		CFLAGS=`echo $CFLAGS | sed 's%\-g%%' `
  	  fi
  	  if test -z "`echo "$CFLAGS" | grep "\-O3" 2> /dev/null`"; then
    		CFLAGS="$CFLAGS -O3"
  	  fi
  	  if test -z "`echo "$CFLAGS" | grep "\-qstrict" 2> /dev/null`"; then
    		CFLAGS="$CFLAGS -qstrict"
  	  fi
          AC_MSG_RESULT([AIX size_t in the accept call and optimize O3 qstrict])
	else
          AC_MSG_RESULT([AIX size_t in the accept call])
        fi
        ;;
	
        *hpux*)
        AC_MSG_RESULT([HPUX need _XOPEN_SOURCE_EXTENDED for h_errno])
	AC_DEFINE(HOST_IS_HPUX)
	if test "x$GCC" != "xyes"; then
  	  if test ! -z "`echo "$CFLAGS" | grep "\-g" 2> /dev/null`" ; then
    		CFLAGS=`echo $CFLAGS | sed 's%\-g%%' `
  	  fi
  	  if test -z "`echo "$CFLAGS" | grep "\+O2" 2> /dev/null`"; then
    		CFLAGS="$CFLAGS +O2"
  	  fi
	fi
        ;;

        *ultrix*)
        AC_MSG_RESULT([ULTRIX getcwd uses popen])
        AC_DEFINE(HAVE_BROKEN_GETCWD)
        ;;

        *)
        AC_MSG_RESULT([none])
        ;;
esac

AC_SUBST(selectconfig)
AC_DEFINE_UNQUOTED(UID_CAST, ${uid_cast})



dnl *****************************************
dnl
dnl     checks for header files
dnl
dnl *****************************************

AC_HEADER_DIRENT
AC_HEADER_MAJOR
AC_HEADER_TIME
dnl used in minilzo.c
AC_HEADER_STAT
AC_DECL_SYS_SIGLIST 

AC_CHECK_HEADERS(stddef.h libgen.h sched.h malloc.h sys/uio.h \
	sys/mman.h sys/param.h sys/inotify.h \
	sys/vfs.h mntent.h \
	sys/select.h sys/socket.h netinet/in.h \
	regex.h glob.h fnmatch.h \
	linux/ext2_fs.h linux/fs.h ext2fs/ext2_fs.h asm/segment.h \
	elf.h linux/elf.h auparse.h \
	paths.h arpa/nameser.h arpa/nameser_compat.h \
	rpc/rpcent.h rpc/rpc.h sys/statvfs.h,
	[],
	[],
	[#include <sys/types.h>] 
)


AC_CHECK_HEADER(utmpx.h, sh_utmpx="yes", sh_utmpx="no")
if test "x$sh_utmpx" = "xyes"; then
  AC_DEFINE(HAVE_UTMPX_H)
  AC_EGREP_HEADER(ut_host, utmpx.h, AC_DEFINE(HAVE_UTHOST) )
  AC_EGREP_HEADER(ut_addr, utmpx.h, AC_DEFINE(HAVE_UTADDR) )
  AC_EGREP_HEADER(ut_addr_v6, utmpx.h, AC_DEFINE(HAVE_UTADDR_V6) )
  AC_EGREP_HEADER(ut_xtime,utmpx.h, AC_DEFINE(HAVE_UTXTIME) )
  AC_EGREP_HEADER(ut_type, utmpx.h, AC_DEFINE(HAVE_UTTYPE) )
else
  AC_EGREP_HEADER(ut_addr, utmp.h, AC_DEFINE(HAVE_UTADDR) )
  AC_EGREP_HEADER(ut_host, utmp.h, AC_DEFINE(HAVE_UTHOST) )
  AC_EGREP_HEADER(ut_type, utmp.h, AC_DEFINE(HAVE_UTTYPE) )
fi

dnl
dnl figure out where acct.h lives
dnl and whether fields are int/comp_t
dnl
dnl GNU Accounting Utilities
dnl Copyright (C) 1993, 1996, 1997, 2003, 2005 Free Software Foundation, Inc.
dnl The GNU Accounting Utilities are free software; you can redistribute
dnl them and/or modify them under the terms of the GNU General Public
dnl License as published by the Free Software Foundation; either version
dnl 2, or (at your option) any later version.
dnl
AC_CHECK_HEADER(sys/acct.h,
		AC_DEFINE(HAVE_SYS_ACCT_H, ,
			  [Define if you have the <sys/acct.h> header file.])
		AC_HEADER_EGREP(ac_utime, sys/acct.h,
				AC_DEFINE(HAVE_ACUTIME, ,
					  [Define if <sys/acct.h> has the AC_UTIME field.])
				AC_HEADER_EGREP(comp_t.*ac_utime, sys/acct.h,
						AC_DEFINE(ACUTIME_COMPT, ,
							  [Define if <sys/acct.h>'s AC_UTIME field is a COMP_T.]))
		)
		AC_HEADER_EGREP(ac_stime, sys/acct.h,
				AC_DEFINE(HAVE_ACSTIME, ,
					  [Define if <sys/acct.h> has the AC_STIME field.])
				AC_HEADER_EGREP(comp_t.*ac_stime, sys/acct.h,
						AC_DEFINE(ACSTIME_COMPT, ,
							  [Define if <sys/acct.h>'s AC_STIME field is a COMP_T.]))
		)
		AC_HEADER_EGREP(ac_etime, sys/acct.h,
				AC_DEFINE(HAVE_ACETIME, ,
					  [Define if <sys/acct.h> has the AC_ETIME field.])
				AC_HEADER_EGREP(comp_t.*ac_etime, sys/acct.h,
						AC_DEFINE(ACETIME_COMPT, ,
							  [Define if <sys/acct.h>'s AC_ETIME field is a COMP_T.]))
		)
		AC_HEADER_EGREP(ac_io,    sys/acct.h,
				AC_DEFINE(HAVE_ACIO, ,
					  [Define if <sys/acct.h> has the AC_IO field.])
				AC_HEADER_EGREP(comp_t.*ac_io,    sys/acct.h,
						AC_DEFINE(ACIO_COMPT, ,
							  [Define if <sys/acct.h>'s AC_IO field is a COMP_T.]))
		)
		AC_HEADER_EGREP(ac_mem,   sys/acct.h,
				AC_DEFINE(HAVE_ACMEM, ,
					  [Define if <sys/acct.h> has the AC_MEM field.])
				AC_HEADER_EGREP(comp_t.*ac_mem,   sys/acct.h,
						AC_DEFINE(ACMEM_COMPT, ,
							  [Define if <sys/acct.h>'s AC_MEM field is a COMP_T.]))
		)
		AC_HEADER_EGREP(ac_minflt,   sys/acct.h,
				AC_HEADER_EGREP(ac_majflt,   sys/acct.h,
						AC_HEADER_EGREP(ac_swaps,   sys/acct.h,
								AC_DEFINE(HAVE_PAGING, ,
									  [Define if <sys/acct.h> has the AC_MINFLT, AC_MAJFLT and AC_SWAPS fields.])
								AC_HEADER_EGREP(comp_t.*ac_minflt, sys/acct.h,
										AC_DEFINE(ACMINFLT_COMPT, ,
											  [Define if <sys/acct.h>'s AC_MINFLT field is a COMP_T.]))
								AC_HEADER_EGREP(comp_t.*ac_mayflt, sys/acct.h,
										AC_DEFINE(ACMAJFLT_COMPT, ,
											  [Define if <sys/acct.h>'s AC_MAJFLT field is a COMP_T.]))
								AC_HEADER_EGREP(comp_t.*ac_swaps, sys/acct.h,
										AC_DEFINE(ACSWAPS_COMPT, ,
											  [Define if <sys/acct.h>'s AC_SWAPS field is a COMP_T.]))
						)
				)
		)
		AC_HEADER_EGREP(comp_t,   sys/acct.h, AC_DEFINE(HAVE_COMP_T, ,
								[Define if <sys/acct.h> uses the COMP_T type.]))
		AC_HEADER_EGREP([struct acct_v3],   sys/acct.h, AC_DEFINE(HAVE_ACCT_V3, ,
								[Define if <sys/acct.h> has struct acct_v3.]))
		AC_HEADER_EGREP([struct acctv2],    sys/acct.h, AC_DEFINE(HAVE_ACCTV2, ,
								[Define if <sys/acct.h> has struct acctv2.]))

 )


dnl need to check because AIX 4.2 does not have it
dnl
AC_CHECK_MEMBERS([struct statfs.f_flags],[],[],[
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
])

AC_SYS_LARGEFILE

dnl
dnl check whether _POSIX_SOURCE is required
dnl
SAMHAIN_POSIX


dnl *****************************************
dnl
dnl Checks for library functions.
dnl
dnl *****************************************
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(memcmp memcpy memmove memset getpwent endpwent fpurge \
	gettimeofday strlcat strlcpy strstr strchr strerror strsignal \
	seteuid setreuid setresuid lstat getwd getcwd ptrace \
	usleep setpriority getpeereid nanosleep \
	strptime basename sched_yield hasmntopt \
	inet_aton gethostbyname setutent setrlimit gethostname uname \
	initgroups getpagesize \
	ttyname fchmod writev mmap tzset \
	getsid getpriority getpgid statvfs \
	strerror_r getgrgid_r getpwnam_r getpwuid_r \
	gmtime_r localtime_r rand_r readdir_r strtok_r \
	mincore posix_fadvise inotify_init1
)
AC_CHECK_FUNC(statfs, AC_DEFINE(HAVE_STATFS) statfs="yes",  statfs="no")
SL_CHECK_VA_COPY
AC_CHECK_FUNCS(vsnprintf, [SL_CHECK_VSNPRINTF])
AC_CHECK_MLOCK
SH_STRFTIME_Z

AC_MSG_CHECKING(how to get filesystem type)
fstype=no
# The order of these tests is important.
AC_TRY_CPP([#include <sys/statvfs.h>
#include <sys/fstyp.h>], AC_DEFINE(FSTYPE_STATVFS) fstype=SVR4)
if test $fstype = no; then
AC_TRY_CPP([#include <sys/statfs.h>
#include <sys/fstyp.h>], AC_DEFINE(FSTYPE_USG_STATFS) fstype=SVR3)
fi
if test $fstype = no; then
AC_TRY_CPP([#include <sys/statfs.h>
#include <sys/vmount.h>], AC_DEFINE(FSTYPE_AIX_STATFS) fstype=AIX)
fi
if test $fstype = no; then
AC_TRY_CPP([#include <mntent.h>], AC_DEFINE(FSTYPE_MNTENT) fstype=4.3BSD)
fi
if test $fstype = no; then
AC_EGREP_HEADER(f_type;, sys/mount.h, AC_DEFINE(FSTYPE_STATFS) fstype=4.4BSD/OSF)
fi
if test $fstype = no; then
AC_TRY_CPP([#include <sys/mount.h>
#include <sys/fs_types.h>], AC_DEFINE(FSTYPE_GETMNT) fstype=Ultrix)
fi
AC_MSG_RESULT($fstype)

sh_libsocket=

dnl Solaris needs -lsocket and -lnsl. Unisys system includes
dnl gethostbyname in libsocket but needs libnsl for socket.
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket, ac_need_libsocket=1, ac_try_nsl=1)
if test x$ac_need_libsocket = x1; then
    LIBS="$LIBS -lsocket"
    sh_libsocket="-lsocket"
fi
if test x$ac_try_nsl = x1; then
    AC_CHECK_LIB(nsl, gethostbyname, ac_need_libnsl=1)
    if test x$ac_need_libnsl = x1
    then
        LIBS="$LIBS -lnsl"
    fi
fi
AC_SUBST(sh_libsocket)

AC_CHECK_LIB(socket, res_search, [
   AC_CHECK_LIB(resolv, dn_skipname)
   AC_CHECK_LIB(resolv, __dn_skipname)
   if test x$ac_need_libsocket = x1; then
     :
   else   
     LIBS="$LIBS -lsocket"
   fi
  ], [
   AC_CHECK_LIB(resolv, res_search, [
     LIBS="$LIBS -lresolv"
     ], [
     AC_CHECK_LIB(resolv, dn_skipname)
     AC_CHECK_LIB(resolv, __dn_skipname)
    ])
  ]) 

AC_CHECK_FUNCS( getnameinfo getaddrinfo )


sh_auparse=no

if test "x$ac_cv_header_auparse_h" = "xyes"
then
   AC_CHECK_LIB(auparse, auparse_find_field, [
   			 LIBS="$LIBS -lauparse"
			 sh_auparse=yes
			 AC_DEFINE(HAVE_AUPARSE_LIB, 1, [Define if you have the auparse lib])
			 ])
fi

dnl arguments for accept

dnl check for Unix98 socklen_t (found on 
dnl xemacs-patches mailing list, written
dnl by Martin Buchholz)
dnl
dnl On Darwin(MacOSX) socklen_t needs to be
dnl an int (see accept man page), on all other
dnl unix systems we need a size_t.

AC_MSG_CHECKING(for socklen_t)
AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
  socklen_t x;
], [],[
  AC_MSG_RESULT(yes)
  AC_DEFINE_UNQUOTED([ACCEPT_TYPE_ARG3],[socklen_t], [type of arg3 of accept])
  AC_DEFINE([HAVE_SOCKLEN_T], 1, [Define if you have socklen_t])
],[
  AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
    int accept (int, struct sockaddr *, size_t *);
    ],[],[
      AC_MSG_RESULT(size_t)
      AC_DEFINE_UNQUOTED([ACCEPT_TYPE_ARG3],[size_t], [type of arg3 of accept])
    ], [
      AC_MSG_RESULT(int)
      AC_DEFINE_UNQUOTED([ACCEPT_TYPE_ARG3],[int], [type of arg3 of accept])
    ]
  )
])

dnl *****************************************
dnl     checks for extended attribute or ACL 
dnl     support
dnl *****************************************

AC_ARG_ENABLE([selinux],
	[AS_HELP_STRING([--enable-selinux], [support checking selinux attributes])],
	[],
	[enable_selinux=check])
if test "x$enable_selinux" != xno; then
   sh_CHECK_XATTR
fi

AC_ARG_ENABLE([posix-acl],
	[AS_HELP_STRING([--enable-posix-acl], [support checking posix acls])],
	[],
	[enable_posix_acl=check])
if test "x$enable_posix_acl" != xno; then
   sh_CHECK_POSIX_ACL
fi

dnl *****************************************
dnl     checks for typedefs
dnl *****************************************

AC_C_LONG_DOUBLE
SH_CHECK_TYPEDEF(long long, HAVE_LONG_LONG)
SH_CHECK_TYPEDEF(uint16_t, HAVE_UINT16_T)
SH_CHECK_TYPEDEF(uint32_t, HAVE_UINT32_T)
SH_CHECK_TYPEDEF(uint64_t, HAVE_UINT64_T)
if test "$sh_HAVE_LONG_LONG" = "yes"; then
   AC_CHECK_SIZEOF(unsigned long long, 4)
   sh_sizeof_unsigned_long_long=`echo "$ac_cv_sizeof_unsigned_long_long" | sed 's%[^0-9]%%g'`
   if test "$sh_sizeof_unsigned_long_long" = "8"; then
      AC_DEFINE(HAVE_LONG_LONG_64, 1, [Define if you have 64bit long long])
   fi
fi

AC_CHECK_TYPE(ptrdiff_t, long)
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(char *, 4)
AC_CHECK_SIZEOF(size_t, 4)

AC_CHECK_SIZEOF(unsigned long,  4)
AC_CHECK_SIZEOF(unsigned int,   4)
AC_CHECK_SIZEOF(unsigned short, 2)
    

sh_sizeof_unsigned_long=`echo "$ac_cv_sizeof_unsigned_long" | sed 's%[^0-9]%%g'`
if test "$sh_sizeof_unsigned_long"  = "4"; then
	AC_DEFINE(HAVE_LONG_32)
fi
if test "$sh_sizeof_unsigned_long"  = "8"; then
	AC_DEFINE(HAVE_LONG_64)
fi
sh_sizeof_unsigned_int=`echo "$ac_cv_sizeof_unsigned_int" | sed 's%[^0-9]%%g'`
if test "$sh_sizeof_unsigned_int"   = "4"; then
	AC_DEFINE(HAVE_INT_32)
fi
sh_sizeof_unsigned_short=`echo "$ac_cv_sizeof_unsigned_short" | sed 's%[^0-9]%%g'`
if test "$sh_sizeof_unsigned_short" = "4"; then
	AC_DEFINE(HAVE_SHORT_32)
fi

dnl 
dnl check for 64 bit programming environment
dnl
SAMHAIN_64


dnl *****************************************
dnl     checks for structures
dnl *****************************************

AC_STRUCT_TM

dnl
dnl  from e2fsprogs
dnl 
AC_MSG_CHECKING(whether struct stat has a st_flags field)
AC_CACHE_VAL(e2fsprogs_cv_struct_st_flags,
        AC_TRY_COMPILE([#include <sys/stat.h>],
                [struct stat stat; stat.st_flags = 0;],
                [e2fsprogs_cv_struct_st_flags=yes],
                [e2fsprogs_cv_struct_st_flags=no]))
AC_MSG_RESULT($e2fsprogs_cv_struct_st_flags)
if test "$e2fsprogs_cv_struct_st_flags" = yes; then
  AC_MSG_CHECKING(whether st_flags field is useful)
  AC_CACHE_VAL(e2fsprogs_cv_struct_st_flags_immut,
        AC_TRY_COMPILE([#include <sys/stat.h>],
                [struct stat stat; stat.st_flags |= UF_IMMUTABLE;],
                [e2fsprogs_cv_struct_st_flags_immut=yes],
                [e2fsprogs_cv_struct_st_flags_immut=no]))
  AC_MSG_RESULT($e2fsprogs_cv_struct_st_flags_immut)
  if test "$e2fsprogs_cv_struct_st_flags_immut" = yes; then
          AC_DEFINE(HAVE_STAT_FLAGS)
  fi
fi

dnl 
dnl from dbus
dnl
AC_MSG_CHECKING(for struct cmsgcred)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
],[
struct cmsgcred cred;

cred.cmcred_pid = 0;
],sh_have_struct_cmsgcred=yes,sh_have_struct_cmsgcred=no)
AC_MSG_RESULT($sh_have_struct_cmsgcred)

if test x$sh_have_struct_cmsgcred = xyes; then
    AC_DEFINE(HAVE_STRUCT_CMSGCRED,1,[Have cmsgcred structure])
fi

AC_MSG_CHECKING(for struct fcred)
AC_TRY_COMPILE([
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ucred.h>
],[
struct fcred sockcred;
],sh_have_struct_fcred=yes,sh_have_struct_fcred=no)
AC_MSG_RESULT($sh_have_struct_fcred)

if test x$sh_have_struct_fcred = xyes; then
    AC_DEFINE(HAVE_STRUCT_FCRED,1,[Have fcred structure])
fi

AC_MSG_CHECKING(for struct sockcred)
AC_TRY_COMPILE([
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ucred.h>
],[
struct sockcred sockcred;
],sh_have_struct_sockcred=yes,sh_have_struct_sockcred=no)
AC_MSG_RESULT($sh_have_struct_sockcred)

if test x$sh_have_struct_sockcred = xyes; then
    AC_DEFINE(HAVE_STRUCT_SOCKCRED,1,[Have sockcred structure])
fi

AC_MSG_CHECKING(for SO_PEERCRED)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
],[
int test = SO_PEERCRED;
],sh_have_SO_PEERCRED=yes,sh_have_SO_PEERCRED=no)
AC_MSG_RESULT($sh_have_SO_PEERCRED)

if test x$sh_have_SO_PEERCRED = xyes; then
    AC_DEFINE(HAVE_SO_PEERCRED,1,[Have SO_PEERCRED define])
fi


dnl *****************************************
dnl     checks for compiler characteristics
dnl *****************************************
AC_C_INLINE
AC_C_CONST
AC_C_BIGENDIAN
AC_C_RESTRICT

AM_SA_SIGACTION_WORKS

AC_ARG_ENABLE(ssp,
	[  --disable-ssp		disable the GCC stack protector],
	[],
	[enable_ssp=yes;]
)

if test "x$GCC" = "xyes"; then

   if test x"${enable_ssp}" = xno; then
      :
   else
	GCC_STACK_PROTECT_LIB
   	GCC_STACK_PROTECT_CC
dnl   GCC_STACK_CHECK_CC
      GCC_PIE_CC
   fi	

fi

dnl *****************************************
dnl
dnl     checks for system services
dnl
dnl *****************************************

dnl
dnl check for /proc filesystem
dnl
if test -d "/proc/$$"
then
        AC_DEFINE([HAVE_PROCFS],[1],[Define if you have a proc fs])
fi

dnl
dnl check for GNU gmp
dnl
AC_CHECK_LIB(gmp, __gmpz_init, [sh_have_gmp=yes], [sh_have_gmp=no])
if test "x${sh_have_gmp}" = xno
then
	AC_CHECK_LIB(gmp, mpz_init, [sh_have_gmp=yes], [sh_have_gmp=no])
fi
if test "x${sh_have_gmp}" = xyes
then
	# LIBS="-lgmp $LIBS"
	AC_DEFINE(HAVE_LIBGMP, 1, [Have GNU gmp library])
fi
AC_CHECK_HEADERS(gmp.h)

AC_MSG_CHECKING([for ps])
PS=
for ff in /usr/ucb /bin /usr/bin; do
    if test -x "$ff/ps"; then
       PS="$ff/ps"
       AC_MSG_RESULT([$PS])
       break
    fi
done
if test x$PS = x
then
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([Cannot find ps in any of /usr/ucb /bin /usr/bin])
fi
AC_DEFINE_UNQUOTED([PSPATH], _("$PS"), [Path to ps])

AC_MSG_CHECKING([how to use ps])
$PS ax >/dev/null 2>&1
if test $? -eq 0; then
   case "$host_os" in
   *openbsd*)
   one=`$PS akx | wc -l`
   ;;
   *)
   one=`$PS ax | wc -l`
   ;;
   esac
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
   case "$host_os" in
   *openbsd*)
	PSARG="akx"
	;;
   *)
	PSARG="ax"
	;;
   esac
else
	PSARG="-e"
fi
AC_DEFINE_UNQUOTED([PSARG], _("$PSARG"), [Argument for ps])
AC_MSG_RESULT([$PS $PSARG])

dnl *****************************************
dnl
dnl     enable features
dnl
dnl *****************************************

AC_ARG_ENABLE(db-reload,
	[  --enable-db-reload		enable database reload on SIGHUP [[no]]],
	[
	if test "x${enable_db_reload}" = xyes; then
		AC_DEFINE(RELOAD_DATABASE)
	fi
	]
)

AC_ARG_ENABLE(xml-log,
	[  --enable-xml-log		enable XML logfile format [[no]]],
	[
	if test "x${enable_xml_log}" = xyes; then
		AC_DEFINE(SH_USE_XML)
	fi
	]
)


AC_ARG_ENABLE(mail,
	[  --disable-mail		disable the internal SMTP mailer],
	[
	if test "x${enable_mail}" = xno; then
		:
	else
		AC_DEFINE(SH_WITH_MAIL)
	fi
	],
	[AC_DEFINE(SH_WITH_MAIL)]
)

AC_ARG_ENABLE(suid,
	[  --enable-suid		allow suid],
	[
	if test "x${enable_suid}" = xyes; then
		AC_DEFINE(SH_ALLOW_SUID, [1], [Define if you want to allow suid execution for samhain])
	fi
	]
)

AC_ARG_ENABLE(shellexpand,
	[  --disable-shellexpand		disable shell expansion in config file],
	[
	if test "x${enable_shellexpand}" = xno; then
		:
	else
		AC_DEFINE(SH_EVAL_SHELL, [1], [Define if you want shell expansion in configuration file])
	fi
	],
	[AC_DEFINE(SH_EVAL_SHELL, [1], [Define if you want shell expansion in configuration file])]
)

AC_ARG_ENABLE(external-scripts,
        [  --disable-external-scripts	disable interface to external scripts],
        [
        if test "x${enableval}" = xno; then
                :
	else
		AC_DEFINE(WITH_EXTERNAL)
        fi
        ],
	[AC_DEFINE(WITH_EXTERNAL)]
)

AC_ARG_ENABLE(message-queue,
       [  --enable-message-queue[[=MODE]]	enable SysV message queue [[MODE=0700]]],
       [
       if test "x${ac_cv_header_sys_msg_h}" = "xyes"; then
	   if test "x${enable_message_queue}" = xyes; then
	       AC_DEFINE(WITH_MESSAGE_QUEUE)
	       AC_DEFINE_UNQUOTED(MESSAGE_QUEUE_MODE, 0700)
	   elif test "x${enable_message_queue}" != xno; then
	       echo "${enableval}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
		   AC_MSG_ERROR([With --enable-message-queue=MODE, MODE must be numeric])
	       echo "${enableval}" | \
		   grep ['0[0123456789][0123456789][0123456789]'] >/dev/null 2>&1 ||
		   AC_MSG_ERROR([With --enable-message-queue=MODE, MODE must be an octal (0nnn) number])
               AC_DEFINE(WITH_MESSAGE_QUEUE)
               AC_DEFINE_UNQUOTED(MESSAGE_QUEUE_MODE, ${enable_message_queue})
           fi
       else
           echo
	   echo "**********************************************"
           echo
           AC_MSG_WARN([sys/msg.h missing, --enable-message-queue disabled])
           echo
           echo "**********************************************"
           echo
       fi
       ]
)

AC_ARG_WITH(cflags,
        [  --with-cflags           		additional flags to pass to compiler],
        [
                if test "x$withval" != "xno" ; then
                        CFLAGS="$CFLAGS $withval"
                fi
        ]
)
AC_ARG_WITH(libs,
        [  --with-libs             		additional libraries to link with],
        [
                if test "x$withval" != "xno" ; then
                        LIBS="$LIBS $withval"
                fi
        ]
)


#
# this is from ssh
#
AC_MSG_CHECKING(whether to use libwrap)
LIBWRAP_LIB=""
LIBWRAP_INC=""
AC_ARG_WITH(libwrap,
[  --with-libwrap[=PATH]		Compile in libwrap (TCP Wrappers) support],
[ AC_MSG_RESULT($withval)
  case "$withval" in
  no)
	;;
  ""|yes)
	LIBWRAP_LIB="-lwrap"
	;;
  *)
	if test -d "$withval"; then
	   LIBWRAP_LIB="-L$withval -lwrap"
	   changequote(<<, >>)dnl
	   sh_libwrap_inc=`echo ${withval} | sed 's%/[^/][^/]*$%%'`
	   LIBWRAP_INC="-I${sh_libwrap_inc}/include"
	   changequote([, ])dnl
	else
	   LIBWRAP_LIB="-lwrap"
	   changequote(<<, >>)dnl
	   sh_libwrap_inc=`echo ${withval} | sed 's%/[^/][^/]*$%%'`
	   LIBWRAP_INC="-I${sh_libwrap_inc}"
	   changequote([, ])dnl
	fi
	;;
  esac
  if test -n "$LIBWRAP_LIB"; then
     # OLDLIBS="$LIBS"
     LIBS="$LIBWRAP_LIB $LIBS"
     # OLDCFLAGS="$CFLAGS"
     CFLAGS="$CFLAGS $LIBWRAP_INC"
     AC_CHECK_HEADER(tcpd.h,
		     [],
		     [ AC_MSG_ERROR([Could not find tcpd.h for libwrap. You need to install tcp_wrappers.]) ])
     AC_TRY_LINK([ #include <tcpd.h>
		   int allow_severity; int deny_severity; ],
		 [ hosts_access((struct request_info *) 0); ],
		 [ AC_DEFINE(SH_USE_LIBWRAP,1,[Build with tcp wrapper support]) ],
		 [ AC_MSG_ERROR([Could not find the libwrap library.]) ])
  fi ],
  AC_MSG_RESULT(no)
)


dnl
dnl  NETWORK OPTIONS
dnl
AC_ARG_ENABLE(network,
        [  --enable-network=[[client|server]]	compile client or server [[no]]],
        [
        if test "x$enable_network" = xclient; then
                mytclient="-DSH_WITH_CLIENT"
		yulectl_prg=
		samhainadmin_prg=
                setpwd_prg="samhain_setpwd"
                sh_main_prg="samhain"
		if test "x${sh_have_gmp}" = xyes
		then
			LIBS="-lgmp $LIBS"
		fi
dnl		AC_CHECK_HEADER(sys/capability.h, 
dnl				[AC_CHECK_LIB(cap, cap_get_proc,,sh_use_lcaps="no")],
dnl				[sh_use_lcaps="no"])
	elif test "x$enable_network" = xserver; then
                mytclient="-DSH_WITH_SERVER"
		yulectl_prg="yulectl"
		samhainadmin_prg="scripts/samhainadmin.pl"
                setpwd_prg="samhain_setpwd"
                sh_main_prg="yule"
		if test "x${sh_have_gmp}" = xyes
		then
			LIBS="-lgmp $LIBS"
		fi
		sh_use_lcaps="undef"
        elif test "x$enable_network" = xno; then
                mytclient="-DSH_STANDALONE"
		yulectl_prg=
		samhainadmin_prg=
                setpwd_prg=
                sh_main_prg="samhain"
dnl		AC_CHECK_HEADER(sys/capability.h, 
dnl				[AC_CHECK_LIB(cap, cap_get_proc,,sh_use_lcaps="no")],
dnl				[sh_use_lcaps="no"])
	else
		AC_MSG_ERROR([With --enable-network=WHAT, WHAT must be client, server, or no])
        fi
        ],
        [
        mytclient="-DSH_STANDALONE"
	setpwd_prg=
	yulectl_prg=
	samhainadmin_prg=
	sh_main_prg="samhain"
dnl	AC_CHECK_HEADER(sys/capability.h, 
dnl			[AC_CHECK_LIB(cap, cap_get_proc,,sh_use_lcaps="no")],
dnl			[sh_use_lcaps="no"])
        ],
)

AC_SUBST(setpwd_prg)
AC_SUBST(yulectl_prg)
AC_SUBST(samhainadmin_prg)
AC_SUBST(sh_main_prg)
AC_SUBST(mytclient)

# needed for the rpm spec
clmytclient=`echo ${mytclient} | sed s%\-%%`
AC_SUBST(clmytclient)

sh_no_gcc_static=no

AC_ARG_ENABLE(static,
        [  --enable-static		enable static linking [[no]]],
        [
        if test x$enable_static = xyes; then
		if test x"$mynetbsd" = xyes
		then
		  tmp_LIBS=`echo $LIBS | sed 's%\-lresolv%%' `
		  LIBS="${tmp_LIBS}"
		fi
		if test x"${sh_auparse}" = xyes
		then
		  tmp_LIBS=`echo $LIBS | sed 's%\-lauparse%%' `
		  LIBS="${tmp_LIBS}"
		fi

                if test "x$GCC" = "xyes"; 
		then
		   case "$host_os" in

		   	*solaris*)
				AC_MSG_WARN([option --enable-static ignored on Solaris])
				;;
			
			*)
				AC_DEFINE(SH_COMPILE_STATIC, 1, [Define if compiling static])
		   		sh_no_gcc_static=no
                        	LDFLAGS="$LDFLAGS -static"
				;;
		    esac
                else
		   AC_DEFINE(SH_COMPILE_STATIC, 1, [Define if compiling static])
		   sh_no_gcc_static=yes
                   case "$host_os" in

                        *aix*)
                                LDFLAGS="$LDFLAGS -bnso -bI:/lib/syscalls.exp"
                                ;;

                        *hpux*)
                                LDFLAGS="$LDFLAGS -Wl,-a,archive"
                                ;;

                        *osf*)
                                LDFLAGS="$LDFLAGS -non_shared"
                                ;;

                        *irix*)
                                LDFLAGS="$LDFLAGS -non_shared"
                                ;;

                        *sco*)
                                LDFLAGS="$LDFLAGS -dn"
                                ;;

                        *sun*)
                                LDFLAGS="$LDFLAGS -Bstatic"
                                ;;

                        *solaris*)
                                LDFLAGS="$LDFLAGS -Bstatic"
                                ;;

                        *)
                        echo "***********************************************"
                        echo "*"
                        echo "* Don't know how to enable static linking"
                        echo "* with your compiler. Please set the environment"
                        echo "* variable LDFLAGS to:"
                        echo "*     ${LDFLAGS}   + the static linking flag"
                        echo "* and run configure again"
                        echo "*"
                        echo "***********************************************"
                        ;;

                   esac
                fi
        fi
        ]
)

if test x"${mytclient}" = x-DSH_STANDALONE -o x"${mytclient}" = x-DSH_WITH_CLIENT;
then
dnl For threaded modules
	ACX_PTHREAD
	CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
	LIBS="$PTHREAD_LIBS $LIBS"
	LDFLAGS="$PTHREAD_CFLAGS $LDFLAGS"
	CC="$PTHREAD_CC"
dnl For MODI_TXT
	CHECK_ZLIB()
fi

if test x$enable_static = xyes; then
   :
else
   if test x$sh_use_pie = xyes; then
      LDFLAGS="$LDFLAGS $PIE_LDFLAGS"
      CFLAGS="$CFLAGS $PIE_CFLAGS"
   fi
fi
AC_CHECK_FUNC(pmap_getmaps, 
	AC_DEFINE([HAVE_PMAP_GETMAPS], [], [Define if pmap_getmaps available]), [],[])

	
#
# this is from the snort configure.in
#
AC_DEFUN(FAIL_MESSAGE,[
   echo 
   echo
   echo "**********************************************"
   echo "  ERROR: unable to find" $1
   echo "  checked in the following places"
   for i in `echo $2`; do
     echo "        $i"
   done
   echo "**********************************************"
   echo
   exit
])

AC_ARG_WITH(libprelude-prefix,
          [  --with-libprelude-prefix=PFX	Prefix where libprelude is installed (optional)],
          libprelude_config_prefix="$withval", libprelude_config_prefix="")

AC_MSG_CHECKING(whether to use prelude)
AC_ARG_WITH(prelude,  
        [  --with-prelude		Prelude IDS support [[no]]],
        [
        if test "x${withval}" = "xno"; then
	     AC_MSG_RESULT(no)
	else
	     AC_MSG_RESULT(yes)
	     if test x$libprelude_config_prefix != x ; then
	       if test x${LIBPRELUDE_CONFIG+set} != xset ; then
	         LIBPRELUDE_CONFIG=$libprelude_config_prefix/bin/libprelude-config
	       fi
	     fi

	     AC_PATH_PROG(LIBPRELUDE_CONFIG, libprelude-config, no)
	     if test x"$LIBPRELUDE_CONFIG" = "xno" ; then
	       HAVE_PRELUDE_CONFIG=no
	     else
	       HAVE_PRELUDE_CONFIG=yes
	     fi
dnl	     AC_CHECK_PROG(HAVE_PRELUDE_CONFIG, libprelude-config, yes, no)
	     if test "$HAVE_PRELUDE_CONFIG" = "yes"; then
	       sh_libprelude_version=`$LIBPRELUDE_CONFIG --version`
	       case "$sh_libprelude_version" in
	       0.8*)
	        AC_MSG_ERROR([You have Libprelude 0.8, which is too old. Version 0.9.6 or higher is required.])
	       ;;
	       *)
	       AM_PATH_LIBPRELUDE([0.9.6],
	       [
		AC_DEFINE(HAVE_LIBPRELUDE,1,[Have libprelude])
		CFLAGS="$CFLAGS $LIBPRELUDE_PTHREAD_CFLAGS"
		LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
		LIBS="$LIBS $LIBPRELUDE_LIBS"
	       ],
	       [
		AC_MSG_ERROR([Could not find libprelude (if you are using --enable-static, the static library libprelude.a might be missing).])
	       ])
	       ;;
	       esac
	     else
	       AC_MSG_ERROR([Could not find libprelude-config.])
	     fi
	fi
	],
	[
		AC_MSG_RESULT(no)
	]
)

#
# partly based on the snort configure.in
#
AC_ARG_WITH(database,
        [  --with-database=[[mysql|postgresql|oracle|odbc]]	database support [[no]]],
        [
        if test x"$enable_xml_log" != xyes; then
                AC_MSG_ERROR([With --with-database,  --enable-xml-log is required as well.])
        fi
        if test "x${withval}" = "xmysql"; then
	  if test "x$zlib_found" = "x"
	  then
		CHECK_ZLIB()
	  fi
	  AC_CHECK_PROG(HAVE_MYSQL_CONFIG, mysql_config, yes, no)
          if test "$HAVE_MYSQL_CONFIG" = "yes"; then
		sh_mysql_libs="`mysql_config --libs`"
		sh_mysql_libs="`eval echo ${sh_mysql_libs}`"
		LIBS="$LIBS ${sh_mysql_libs}"
		sh_mysql_cflags="`mysql_config --cflags`"
		sh_mysql_cflags="`eval echo ${sh_mysql_cflags}`"
		CPPFLAGS="$CPPFLAGS ${sh_mysql_cflags}"
	  else
		AC_MSG_CHECKING([for MySQL in /usr /usr/local /usr/local/mysql MYSQL_HOME])
		mysql_directory="/usr /usr/local /usr/local/mysql ${MYSQL_HOME}"

		for i in $mysql_directory; do
    		  if test -r $i/include/mysql/mysql.h; then
      			MYSQL_DIR=$i
      			MYSQL_INC_DIR=$i/include
			# we use AC_CHECK_HEADERS to check for  mysql/mysql.h
		  fi
		done
		if test -z "$MYSQL_DIR"; then
		  for i in $mysql_directory; do
    		    if test -r $i/include/mysql.h; then
      			MYSQL_DIR=$i
      			MYSQL_INC_DIR=$i/include
    		    fi
		  done
                fi

		if test -z "$MYSQL_DIR"; then
		      tmp=""
		      for i in $mysql_directory; do
		        tmp="$tmp $i/include $i/include/mysql"
		      done
		      FAIL_MESSAGE("mysql headers (mysql.h)", $tmp)
		fi

 		for i in lib lib/mysql; do
 		  str="$MYSQL_DIR/$i/libmysqlclient.*"
 		  for j in `echo $str`; do
		    if test -r $j; then
		      MYSQL_LIB_DIR="$MYSQL_DIR/$i"
 		      break 2
		    fi
		  done
		done

		if test -z "$MYSQL_LIB_DIR"; then
		  for ff in $mysql_directory; do
 		    for i in lib lib/mysql; do
 		      str="$ff/$i/libmysqlclient.*"
 		      for j in `echo $str`; do
		        if test -r $j; then
		          MYSQL_LIB_DIR="$ff/$i"
 		          break 3
		        fi
		      done
		    done
		  done
		fi

		if test -z "$MYSQL_LIB_DIR"; then
		      tmp=""
		      for i in $mysql_directory; do
		        tmp="$i/lib $i/lib/mysql"
		      done
		      FAIL_MESSAGE("mysql library libmysqlclient", $tmp)
		fi

		AC_MSG_RESULT(yes)
		LIBS="$LIBS -L${MYSQL_LIB_DIR} -lmysqlclient"
		# CFLAGS="$CFLAGS -I${MYSQL_INC_DIR}"
		CPPFLAGS="$CPPFLAGS -I${MYSQL_INC_DIR}"
	  fi  
          AC_DEFINE(WITH_MYSQL)
          AC_DEFINE(WITH_DATABASE)
          if test "x$zlib_found" = "xyes"
          then
                LIBS="$LIBS -lz -lm"
          else
		echo
		
		echo " Mysql library was not found or not useable."
		echo " Possible reasons include:"
		echo "  - an old, incompatible version compiled from source"
		echo "  - on Solaris, libmysql is compiled with the Solaris"
		echo "    compiler, thus the mysql_config script provides"
		echo "    compiler options unsuitable for gcc (move"
		echo "    mysql_config out of your PATH)"
		echo " For other problems, check config.log for the error"
		echo " message from the compiler."
		echo
		echo " If your mysql libraries are installed in an"
		echo " unusual place, use --with-libs=-L/path/to/libdirectory"
		echo " where libdirectory is the directory holding libmysql."
		if test x"$enable_static" = xyes; then
		  echo " Note that for compiling a static binary, you need"
		  echo " the static libraries, rather than the shared ones."
		fi
		echo
		AC_MSG_ERROR([Could not find libmysql, or it is not useable.]) 
          fi
	  AC_CHECK_HEADERS(mysql/mysql.h)
        elif test "x${withval}" = "xpostgresql"; then
          AC_DEFINE(WITH_POSTGRES)
          AC_DEFINE(WITH_DATABASE)
	  #
	  PGCONF="no"
	  MY_PATH="${PATH}:/usr/local/bin:/usr/local/pgsql/bin"
	  OLD_IFS="$IFS"
	  IFS=":"
	  for ff in ${MY_PATH}
	  do
	    if test -f "$ff/pg_config"
	    then
		PGCONF="$ff/pg_config"
	    fi
	  done
	  IFS="${OLD_IFS}"
	  #
	  #
	  if test "x${PGCONF}" = "xno"
	  then
	    AC_MSG_CHECKING(for PostgreSQL in /usr/local/pgsql /usr/pgsql /usr/local /usr PGSQL_HOME)
	    pgsql_directory="/usr/local/pgsql /usr/pgsql /usr/local /usr ${PGSQL_HOME}"
  	    for i in $pgsql_directory; do 
    	      if test -r $i/include/pgsql/libpq-fe.h; then
                PGSQL_INC_DIR=$i/include
		PGSQL_DIR=$i
		# use AC_CHECK_HEADERS to check for pgsql/libpq-fe.h
              fi
            done 
            if test -z "$PGSQL_DIR"; then
  	      for i in $pgsql_directory; do 
    	        if test -r $i/include/postgresql/libpq-fe.h; then
                  PGSQL_INC_DIR=$i/include
		  PGSQL_DIR=$i
                fi
              done
	    fi
            if test -z "$PGSQL_DIR"; then
  	      for i in $pgsql_directory; do 
    	        if test -r $i/include/libpq-fe.h; then
                  PGSQL_INC_DIR=$i/include
		  PGSQL_DIR=$i
                fi
              done
	    fi
	    
            if test -z "$PGSQL_DIR"; then
              tmp=""
              for i in $pgsql_directory; do
                tmp="$tmp $i/include $i/include/pgsql $i/include/postgresql"
              done
              FAIL_MESSAGE("PostgreSQL header file (libpq-fe.h)", $tmp)
	    fi

	    for i in lib lib/pgsql lib/postgresql; do
      		str="$PGSQL_DIR/$i/libpq.*"
      		for j in `echo $str`; do
       		 if test -r $j; then
       		   PGSQL_LIB_DIR="$PGSQL_DIR/$i"
       		   break 2
      		  fi
    		done
   	    done

	    if test -z "$PGSQL_LIB_DIR"; then
	      for ff in $pgsql_directory; do
		for i in lib lib/pgsql lib/postgresql; do
      		  str="$ff/$i/libpq.*"
      		  for j in `echo $str`; do
       		    if test -r $j; then
       		      PGSQL_LIB_DIR="$ff/$i"
       		      break 3
      		    fi
    		  done
   	        done
              done
	    fi

	    if test -z "$PGSQL_LIB_DIR"; then
	       tmp=""
	       for i in $pgsql_directory; do
		   tmp="$i/lib $i/lib/pgsql $i/lib/postgresql"
	       done
	       FAIL_MESSAGE("postgresql library libpq", $tmp)
            fi

            AC_MSG_RESULT(yes)

	    LIBS="$LIBS -L${PGSQL_LIB_DIR} -lpq -lm"
	    if test x"$enable_static" = xyes; then
	      LIBS="$LIBS -L${PGSQL_LIB_DIR} -lpq -lcrypt -lm"
	    else
	      LIBS="$LIBS -L${PGSQL_LIB_DIR} -lpq -lm"
	    fi
	    # CFLAGS="$CFLAGS -I${PGSQL_INC_DIR}"
	    CPPFLAGS="$CPPFLAGS -I${PGSQL_INC_DIR}"
	    AC_CHECK_HEADERS(pgsql/libpq-fe.h)
	    AC_CHECK_HEADERS(postgresql/libpq-fe.h)
	  else
	    pg_lib_dir=`${PGCONF} --libdir`
	    if test x"$enable_static" = xyes; then
	      LIBS="$LIBS -L${pg_lib_dir} -lpq -lcrypt -lm"
            else
	      LIBS="$LIBS -L${pg_lib_dir} -lpq -lm"
            fi
	    pg_inc_dir=`${PGCONF} --includedir`
	    # CFLAGS="$CFLAGS -I${pg_inc_dir}"
	    CPPFLAGS="$CPPFLAGS -I${pg_inc_dir}"
	  fi
	elif test "x${withval}" = "xodbc"; then
	  AC_MSG_CHECKING(for odbc in /usr /usr/local ODBC_HOME)
	  odbc_directory="/usr /usr/local"

	  for i in $odbc_directory; do
	    if test -r $i/include/sql.h; then
	      if test -r $i/include/sqlext.h; then
		if test -r $i/include/sqltypes.h; then
		  ODBC_DIR=$i
		  ODBC_INC_DIR=$i/include
		fi 
	      fi 
	    fi
	  done

	  if test -z "$ODBC_DIR"; then
            tmp=""
            for i in $odbc_directory; do
              tmp="$tmp $i/include"
            done
            FAIL_MESSAGE("odbc headers (sql.h sqlext.h sqltypes.h)", $tmp)
          fi

          str="$ODBC_DIR/lib/libodbc.*"
          for j in `echo $str`; do
            if test -r $j; then 
              ODBC_LIB_DIR="$ODBC_DIR/lib"
              ODBC_LIB="odbc"
            fi
          done

          if test -z "$ODBC_LIB_DIR"; then
            FAIL_MESSAGE("odbc library (libodbc)", "$ODBC_DIR/lib")
          fi

          AC_MSG_RESULT(yes)
          CPPFLAGS="${CPPFLAGS} -I${ODBC_INC_DIR}"
          LIBS="${LIBS} -L${ODBC_LIB_DIR} -l$ODBC_LIB"
          AC_DEFINE(WITH_ODBC)
          AC_DEFINE(WITH_DATABASE)

	elif test "x${withval}" = "xoracle"; then

	  AC_MSG_CHECKING(for oracle in ORACLE_HOME /usr/local /usr)

	  oracle_directory="/usr /usr/local ${ORACLE_HOME}"
  	  for i in $oracle_directory; do 

	      ff=`find $i -name oci.h 2>/dev/null | tail -1`
	      if test "x$ff" = "x"; then
	      	 :
	      else
		 ORACLE_INC=`dirname $ff`
	      fi

	      fg=`find $i -name libclntsh.so 2>/dev/null | tail -1`
	      if test "x$fg" = "x"; then
	      	 :
	      else
		 ORACLE_LIB=`dirname $fg`
	      fi

           done
	  
          if test -z "$ORACLE_INC"; then

              tmp=""
              for i in $oracle_directory; do
                tmp="$tmp $i"
              done
              FAIL_MESSAGE("OCI header file (oci.h) please define ORACLE_INC directory where oci.h resides", $tmp)

	  elif test -z "$ORACLE_LIB"; then

              tmp=""
              for i in $oracle_directory; do
                tmp="$tmp $i"
              done
              FAIL_MESSAGE("OCI library file (libclntsh.so) please define ORACLE_LIB directory where libclntsh.so resides", $tmp)

          else

            ORACLE_CPP_FLAGS="-I$ORACLE_INC"
            ORACLE_LIB_DIR="$ORACLE_LIB"

            AC_MSG_RESULT([$ORACLE_INC $ORACLE_LIB])

            CPPFLAGS="${CPPFLAGS} ${ORACLE_CPP_FLAGS}"

            ORACLE_LIBS="-lclntsh"

	    if test -r $ORACLE_LIB_DIR/libnnz11.so; then
	      ORACLE_LIBS="${ORACLE_LIBS} -lnnz11"
	    fi
            if test -r $ORACLE_LIB_DIR/libwtc9.so; then
              ORACLE_LIBS="${ORACLE_LIBS} -lwtc9"
            elif test -r $ORACLE_LIB_DIR/libwtc8.so; then
              ORACLE_LIBS="${ORACLE_LIBS} -lwtc8"
            fi
            LIBS="${LIBS} -L${ORACLE_LIB_DIR} ${ORACLE_LIBS}"
	    if test "x$GCC" != "xyes"; then
	      CFLAGS="${CFLAGS} -fno-strict-aliasing"
	    fi
          fi
          AC_DEFINE(WITH_ORACLE)
          AC_DEFINE(WITH_DATABASE)

        else
          AC_MSG_ERROR([Option --with-database=database used with unsupported database ${withval}])
        fi
        ]
)

AC_ARG_WITH(console,
        [  --with-console=PATH           set path to console device [[/dev/console]]],
        [
	if test "x${withval}" != xno; then
        	mycons="$withval"
        	AC_DEFINE_UNQUOTED(DEFAULT_CONSOLE, _("${mycons}") )
	fi
        ])

AC_ARG_WITH(altconsole,
        [  --with-altconsole=PATH        set path to second console device [[none]]],
        [
	if test "x${withval}" != xno; then
		myaltcons="$withval"
	else
		myaltcons="NULL"
	fi
	],
        [myaltcons="NULL"])
AC_DEFINE_UNQUOTED(ALT_CONSOLE, _("${myaltcons}") )

AC_ARG_WITH(timeserver,
        [  --with-timeserver=HOST        set host address for time server [[none]]],
        [
	if test "x${withval}" != xno; then
        	mytimeserv="$withval"
        	AC_DEFINE(HAVE_NTIME)
	else
		mytimeserv="NULL"
	fi
        ],
        mytimeserv="NULL")
AC_DEFINE_UNQUOTED(DEFAULT_TIMESERVER, _("${mytimeserv}") )

AC_ARG_WITH(alttimeserver,
        [  --with-alttimeserver=HOST     set address for backup time server [[none]]],
        [
	if test "x${withval}" != xno; then
        	myalttimeserv="$withval"
        	AC_DEFINE(HAVE_NTIME)
	else
		myalttimeserv="NULL"
	fi
        ],
        myalttimeserv="NULL")
AC_DEFINE_UNQUOTED(ALT_TIMESERVER, _("${myalttimeserv}") )

AC_ARG_ENABLE(login-watch,
        [  --enable-login-watch		watch for login/logout [[no]]],
        [
        if test "x${enable_login_watch}" = xyes; then
                AC_DEFINE(SH_USE_UTMP)
        fi
        ]
)

AC_ARG_ENABLE(mounts-check,
        [  --enable-mounts-check		check mount options on filesystems [[no]]],
        [
        if test "x${enable_mounts_check}" = xyes; then
                AC_DEFINE(SH_USE_MOUNTS)
        fi
        ]
)

AC_ARG_ENABLE(logfile-monitor,
        [  --enable-logfile-monitor		monitor logfiles [[no]]],
        [
        if test "x${enable_logfile_monitor}" = xyes; then
	   AC_CHECK_HEADER(pcre.h,
                           [ 
			   AC_DEFINE(USE_LOGFILE_MONITOR, 1, [Define if you want the logfile monitor module.])
			   LIBS="-lpcre $LIBS"
			   ],
			   [
				AC_CHECK_HEADER(pcre/pcre.h,
			   	[
			   	AC_DEFINE(USE_LOGFILE_MONITOR, 1, [Define if you want the logfile monitor module.])
				AC_DEFINE(HAVE_PCRE_PCRE_H, 1, [Define if you have pcre/pcre.h.])
			   	LIBS="-lpcre $LIBS"
			   	],
	                   	AC_MSG_ERROR([The --enable-logfile-monitor option requires libpcre. For compiling the pcre development package is needed.])
				)
			  ]
	   )
	   AC_CHECK_LIB(pcre, pcre_dfa_exec, [
	   		      AC_DEFINE([HAVE_PCRE_DFA_EXEC], 1, [Define if you have pcre_dfa_exec])
			      ], [
			      AC_MSG_WARN([pcre_dfa_exec not available])
			      ])
        fi
        ]
)


AC_ARG_ENABLE(process-check,
        [  --enable-process-check	check processes [[no]]],
        [
        if test "x${enable_process_check}" = xyes; then
	  	AC_CHECK_LIB([rt], [sched_getparam], sh_lrt=yes, sh_lrt=no)
		if test x"$sh_lrt" = xyes; then
		   LIBRT=-lrt
		else
		   LIBRT=
		fi
		LIBS="$LIBS $LIBRT"
                AC_DEFINE(SH_USE_PROCESSCHECK, [1], [Define if you want to check processes])
        fi
        ]
)

AC_ARG_ENABLE(port-check,
        [  --enable-port-check		check ports [[no]]],
        [
        if test "x${enable_port_check}" = xyes; then
                AC_DEFINE(SH_USE_PORTCHECK, [1], [Define if you want to check ports])
        fi
        ]
)

AC_ARG_ENABLE(userfiles,
       [  --enable-userfiles		check for users' config files [[no]]],
       [
       if test "x${enableval}" = "xyes"; then
               AC_DEFINE(SH_USE_USERFILES)
       fi
       ]
)

AC_ARG_ENABLE(debug,
        [  --enable-debug		enable debug options [[no]]],
        [
        if test "x${enable_debug}" = "xyes"; then
                if test "x${mydebugflag}" != "xyes"; then
                        AC_DEFINE(MEM_DEBUG)
                fi
                AC_DEFINE(WITH_TPT)
                AC_DEFINE(SL_DEBUG)
		AC_DEFINE(DNMALLOC_CHECKS, 1, [Debug dnmalloc])
		AC_DEFINE(PARANOIA, 0, [Paranoia level for dnmalloc])
                AC_DEFINE(SL_FAIL_ON_ERROR)
                if test "x${myneedg3}" = "xyes"; then
                        mydebugdef="-g3"
                else
                        mydebugdef="-g"
                fi
                mydebugit="yes"
	elif test "x${enable_debug}" = "xgdb"; then
	     	AC_DEFINE(SH_ABORT_ON_ERROR, 1, [Use abort])
                if test "x${myneedg3}" = "xyes"; then
                        mydebugdef="-g3"
                else
                        mydebugdef="-g"
                fi
		mydebugit="yes"
        fi
        ]
)
AC_SUBST(mydebugdef)

if test "x${enable_asm_ok}" = "xyes"; then
   sh_enable_asm=yes
else
   sh_enable_asm=no
fi
AC_ARG_ENABLE(asm,
        [  --disable-asm			disable asm inline code],
        [
        if test "x${enable_asm}" = xno; then
	    sh_enable_asm=no
	fi
	]
)

if test "x${samhain_64_asm}" = xyes; then
   	if test "x${sh_enable_asm}" = xyes; then
	   AC_DEFINE([TIGER_OPT_ASM],1,[Define to use tiger x86_64 optimized assembly])
	fi
fi

AC_ARG_ENABLE(ipv6,
        [  --disable-ipv6			disable ipv6 support],
        [
        if test "x${enable_ipv6}" = xno; then
		AC_DEFINE(USE_IPV4,1,[Define if you do not want IPv6])
        fi
        ]
)

if test "x${dnmalloc_ok}" = "xyes"; then
   sh_dnmalloc_enabled=yes
else
   sh_dnmalloc_enabled=no
fi

AC_ARG_ENABLE(dnmalloc,
        [  --disable-dnmalloc			disable dnmalloc],
        [
        if test "x${enable_dnmalloc}" = xno; then
		sh_dnmalloc_enabled=no
	else
		sh_dnmalloc_enabled=yes	
        fi
        ]
)

dnl Handle the problem that static linking against libc.a on Linux
dnl produces the error "multiple definitions of malloc"
dnl
if test "x$sh_dnmalloc_enabled" = "xyes"; then
   if test x$enable_static = xyes; then
      if test "x$sh_no_gcc_static" = "xyes"; then
      	 sh_dnmalloc_enabled=no
      else
	 if test "x$with_gnu_ld" = "xyes"; then
      	   LDFLAGS="$LDFLAGS -Wl,--allow-multiple-definition"
	 else
           sh_dnmalloc_enabled=no
	 fi
      fi
   fi
fi

if test "x${sh_dnmalloc_enabled}" = xno; then
   AC_DEFINE(USE_SYSTEM_MALLOC,1,[Define if you want to use the system malloc])
fi

AC_ARG_ENABLE(ptrace,
        [  --enable-ptrace		use anti-debugger options [[no]]],
        [
        if test "x${enable_ptrace}" = xyes; then
                if test "x$mydebugit" != "xyes"; then
                        AC_DEFINE(SCREW_IT_UP)
                fi
        fi
        ]
)

dnl
if test "x$GCC" = "xyes"; then
  if test ! -z "`echo "$CFLAGS" | grep "\-g\ " 2> /dev/null`" ; then
    CFLAGS=`echo $CFLAGS | sed 's%\-g%%' `
  fi

dnl  -W is the older name for -Wextra

  
  if test -z "`echo "$CFLAGS" | grep "\-Wall" 2> /dev/null`" ; then
     case "$host_os" in
     	*solaris*)
	   CFLAGS="$CFLAGS -Wall -W -Wno-missing-braces "
	   ;;
	*)
	   CFLAGS="$CFLAGS -Wall -W "
	   ;;
     esac
  fi

  if test -z "`echo "$CFLAGS" | grep "\-fstrength\-reduce" 2> /dev/null`"
  then
   if test -z "`echo "$CFLAGS" | grep "\-fno\-strength\-reduce" 2> /dev/null`" 
   then
	GCC_FLAG_CHECK([-fno-strength-reduce])
   fi
  fi

  if test -z "`echo "$CFLAGS" | grep "\-fomit\-frame\-pointer" 2> /dev/null`"
  then
   if test -z "`echo "$CFLAGS" | grep "\-fno\-omit\-frame\-pointer" 2> /dev/null`" 
   then
        GCC_FLAG_CHECK([-fno-omit-frame-pointer])
   fi
  fi

fi

dnl Test whether gcc supports -Wno-empty-body
dnl Suppresses warnings from glibc pthread_cleanup_pop
dnl
GCC_FLAG_CHECK([-Wno-empty-body])

dnl This one is for clang
dnl
GCC_FLAG_CHECK([-Wno-invalid-source-encoding])


AC_MSG_CHECKING([which random module to use])
AC_ARG_WITH(rnd,
    [  --with-rnd=[[egd|unix|dev|default]]	random number generator [[default]]],
[use_static_rnd=$withval], [use_static_rnd=default] )

if test "$use_static_rnd" = no; then
    use_static_rnd=default
fi

case "$use_static_rnd" in
    egd | dev | unix | default )
      AC_MSG_RESULT($use_static_rnd)
      ;;
    * )
      AC_MSG_RESULT([invalid argument])
      AC_MSG_ERROR([Option --with-rnd=module used with unsupported module ${use_static_rnd}])
      ;;
esac

AC_ARG_WITH(egd-socket,
    [  --with-egd-socket=NAME  	EGD socket name],
            egd_socket_name="$withval", egd_socket_name="" )
AC_DEFINE_UNQUOTED(EGD_SOCKET_NAME, _("$egd_socket_name") )

dnl
dnl See whether the user wants to disable checking for /dev/random

try_dev_random=yes

case "$use_static_rnd" in
dev | default )
  try_dev_random=yes
  ;;
egd)
  AC_DEFINE(HAVE_EGD_RANDOM)
  try_dev_random=no
  ;;
unix)
  AC_DEFINE(HAVE_UNIX_RANDOM)
  try_dev_random=no
  ;;
esac


if test "x$try_dev_random" = "xyes"; then
  AC_MSG_CHECKING(whether /dev/random exists)
    if test -r "/dev/srandom" && test -c "/dev/srandom"; then
        AC_DEFINE(HAVE_URANDOM)
        AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, _("/dev/srandom") )
        AC_MSG_RESULT(yes)
        if test -r "/dev/urandom" && test -c "/dev/urandom"; then
          AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, _("/dev/urandom") )
        fi
    else
        if test -r "/dev/random" && test -c "/dev/random"; then
                AC_DEFINE(HAVE_URANDOM)
                AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, _("/dev/random") )
                AC_MSG_RESULT(yes)
                if test -r "/dev/urandom" && test -c "/dev/urandom"; then
                   AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, _("/dev/urandom") )
                fi
        else
                AC_MSG_RESULT(no)
                AC_DEFINE(HAVE_UNIX_RANDOM)
        fi
    fi
fi


AC_ARG_ENABLE(udp,
        [  --enable-udp			server can listen on port 514/udp [[no]]],
        [
        if test "x${enable_udp}" = xyes; then
                AC_DEFINE(INET_SYSLOG)
        fi
        ]
)

myencrypt=yes
AC_ARG_ENABLE(encrypt,
        [  --disable-encrypt		disable client/server encryption],
        [
        if test "x${enable_encrypt}" = xno; then
	   myencrypt=no
        fi
        ]
)
if test "x${myencrypt}" = "xyes"; then
        AC_DEFINE(SH_ENCRYPT)
        AC_DEFINE(SH_ENCRYPT_2)
fi

sh_use_srp_proto=yes
AC_ARG_ENABLE(srp,
        [  --disable-srp			disable SRP for authentication],
        [
        if test "x${enable_srp}" = xno; then
                sh_use_srp_proto=no
        fi
        ]
)
if test "x${sh_use_srp_proto}" = xyes; then
        AC_DEFINE(USE_SRP_PROTOCOL)
fi

AC_ARG_WITH(port,
        [  --with-port=PORT		set port to use for TCP/IP connection [[49777]]],
        [
	echo "${withval}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
		AC_MSG_ERROR([For --with-port=PORT, PORT must be numeric.])
	myport=${withval}
	],
	[myport="49777"])
AC_DEFINE_UNQUOTED(SH_DEFAULT_PORT, ${myport})
AC_SUBST(myport)

AC_ARG_WITH(logserver,
        [  --with-logserver=HOST		set host address for log server [[none]]],
        [
	case "$withval" in
	*.* | localhost)
	mylogsrv="$withval"
	;;
	*)
	mylogsrv="$withval"
	;;
	esac
	],
        [mylogsrv="NULL"])
AC_DEFINE_UNQUOTED(DEFAULT_LOGSERVER, _("${mylogsrv}") )
AC_SUBST(mylogsrv)

AC_ARG_WITH(altlogserver,
        [  --with-altlogserver=HOST	set address for backup log server [[none]]],
        [
	case "$withval" in
	*.* | localhost)
	myaltlogsrv="$withval"
	;;
	*)
	myaltlogsrv="$withval"
	;;
	esac
	],
        [myaltlogsrv="NULL"])
AC_DEFINE_UNQUOTED(ALT_LOGSERVER, _("${myaltlogsrv}"))



dnl
dnl  STEALTH OPTIONS
dnl
nocl_code=
xor_code=0
AC_ARG_ENABLE(nocl,
        [  --enable-nocl=PW		no CL parsing unless first CL argument is PW],
        [
	if test "x${enableval}" != "x"; then
		AC_DEFINE(SH_STEALTH_NOCL)
	fi
	if test "x${enableval}" = "xstop" || test "x${enableval}" = "xstart"; then
	  AC_MSG_ERROR([For --enable-nocl=PW start/stop/reload/restart/status are reserved words.])
	fi
	if test "x${enableval}" = "xreload" || test "x${enableval}" = "xrestart"; then
	  AC_MSG_ERROR([For --enable-nocl=PW start/stop/reload/restart/status are reserved words.])
	fi
	if test "x${enableval}" = "xstatus"; then
	  AC_MSG_ERROR([For --enable-nocl=PW start/stop/reload/restart/status are reserved words.])
	fi
	if test "x${enableval}" = "xno"; then
	  AC_MSG_ERROR([With --enable-nocl=PW, the use of --enable-nocl=no is ambiguous.])
	fi
	nocl_code="${enable_nocl}"
	]
)
AC_DEFINE_UNQUOTED(NOCL_CODE, _("${nocl_code}") )
AC_SUBST(nocl_code)
AC_ARG_ENABLE(stealth,
        [  --enable-stealth=XOR_VAL	enable stealth mode [[no]]],
        [AC_DEFINE(SH_STEALTH)
	if test "x${enableval}" != "xyes"; then
		echo "${enableval}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
			AC_MSG_ERROR([For --enable-stealth=XOR_VAL, XOR_VAL must be numeric.])
		if test "${enableval}" -lt 127 || test "${enableval}" -gt 255; then
			if test x"${enableval}" = x0
			then
				:
			else
				AC_MSG_ERROR([For --enable-stealth=XOR_VAL, XOR_VAL must be in the range 127 to 255.])
			fi
		fi
		xor_code="${enable_stealth}"
	else
		xor_code=0
	fi
	stegin_prg="samhain_stealth"
	],
	[
	stegin_prg=
	]
)
AC_ARG_ENABLE(micro-stealth,
        [  --enable-micro-stealth=XOR_VAL	enable micro stealth mode [[no]]],
        [
	AC_DEFINE(SH_STEALTH)
	AC_DEFINE(SH_STEALTH_MICRO)
	if test "x${enableval}" != "xyes"; then
		echo "${enableval}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
			AC_MSG_ERROR([For --enable-micro-stealth=XOR_VAL, XOR_VAL must be numeric.])
		if test "${enableval}" -lt 127 || test "${enableval}" -gt 255; then
			if test x"${enableval}" = x0
			then
				:
			else
				AC_MSG_ERROR([For --enable-micro-stealth=XOR_VAL, XOR_VAL must be in the range 127 to 255.])
			fi
		fi
		xor_code="${enable_micro_stealth}"
	else
		xor_code=0
	fi
	]
)
install_name="samhain"
INSTALL_NAME="SAMHAIN"
AC_ARG_ENABLE(install-name,
        [  --enable-install-name=NAME	name under which to install [[samhain|yule]]],
        [
	if test "x${enableval}" != "xyes"; then
		install_name="${enableval}"
		INSTALL_NAME=`echo "${enableval}" | tr [a-z] [A-Z]`
	else
		install_name="${sh_main_prg}"
		INSTALL_NAME=`echo "${sh_main_prg}" | tr [a-z] [A-Z]`
	fi
	],
	[
	install_name="${sh_main_prg}"
	INSTALL_NAME=`echo "${sh_main_prg}" | tr [a-z] [A-Z]`
	]	
)


need_user_install=0

AC_ARG_ENABLE(identity,
        [  --enable-identity=USER	user if dropping root [[daemon]]],
        [
	if test x"$enableval" = xno; then
		myident="daemon"
	else
		myident="$enableval"
	fi
	echo "${myident}" | grep ['[^0123456789]'] >/dev/null 2>&1 || \
		AC_MSG_ERROR([With --enable-identity=USER, please supply a username, not a UID.])
	myident_uid=`(cat /etc/passwd; ypcat passwd) 2>/dev/null |\
	  grep "^${myident}:" | awk -F: '{ print $3; }'`
	if test x"${myident_uid}" = x; then
	  AC_MSG_WARN([Option --enable-identity used, user ${myident} will be added upon install.])
	  need_user_install=1
	fi
	],
        [
	for myident in ${install_name} daemon nobody; do
		AC_MSG_CHECKING(for user ${myident})
		myident_uid=`(cat /etc/passwd; ypcat passwd) 2>/dev/null |\
		  grep "^${myident}:" | awk -F: '{ print $3; }'`
		if test x"${myident_uid}" != x; then
			AC_MSG_RESULT(yes)
			break;
		else
			AC_MSG_RESULT(no)
		fi
	done
	if test x"${myident_uid}" = x; then
	  myident=${install_name}
	  AC_MSG_WARN([--enable-identity: user ${myident} will be added upon install])
	  need_user_install=1
	fi
	])
AC_DEFINE_UNQUOTED(DEFAULT_IDENT, _("${myident}") )
AC_SUBST(myident)
AC_SUBST(need_user_install)

AC_SUBST(install_name)
AC_SUBST(INSTALL_NAME)
AC_SUBST(stegin_prg)
AC_SUBST(xor_code)

AC_DEFINE_UNQUOTED(XOR_CODE, ${xor_code})
AC_DEFINE_UNQUOTED(SH_SYSCALLTABLE, ${sh_syscalltable})


exepack_state0=`${srcdir}/c_random.sh 2>/dev/null`
exepack_state1=`${srcdir}/c_random.sh 2>/dev/null`
exepack_state2=`${srcdir}/c_random.sh 2>/dev/null`

AC_DEFINE_UNQUOTED(EXEPACK_STATE_0, ${exepack_state0})
AC_DEFINE_UNQUOTED(EXEPACK_STATE_1, ${exepack_state1})
AC_DEFINE_UNQUOTED(EXEPACK_STATE_2, ${exepack_state2})


AC_ARG_ENABLE(suidcheck,
	[  --enable-suidcheck		check for suid/sgid files [[no]]],
	[
	if test "x${enableval}" = "xyes"; then 
		AC_DEFINE(SH_USE_SUIDCHK)
	fi
	]
)


AC_ARG_ENABLE(base,
        [  --enable-base=B1,B2		base key (0...2147483647)],
        [
        AC_MSG_CHECKING(base key setting)
        my_key_A=`echo ${enableval} | awk 'BEGIN{FS=","}{print $1}'`
        my_key_B=`echo ${enableval} | awk 'BEGIN{FS=","}{print $2}'`
        AC_MSG_RESULT(${my_key_A} ${my_key_B})
	if test "x${my_key_A}" = x; then
		AC_MSG_ERROR([Option --enable-base=B1,B2 used with invalid first base key (zero length).])
	fi
	if test "x${my_key_B}" = x; then
		AC_MSG_ERROR([Option --enable-base=B1,B2 used with invalid second base key (zero length).])
	fi
	echo "${my_key_A}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
		AC_MSG_ERROR([For --enable-base=B1,B2,  B1 and B2 must be numeric in the range 0 to 2147483647.])
	echo "${my_key_B}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
		AC_MSG_ERROR([For --enable-base=B1,B2,  B1 and B2 must be numeric in the range 0 to 2147483647.])
        ],
        [
        AC_MSG_CHECKING(base key setting .. collecting entropy)
        my_key_1=`${srcdir}/c_random.sh 2>/dev/null`
        my_key_2=`${srcdir}/c_random.sh 2>/dev/null`
        my_key_3=`${srcdir}/c_random.sh 2>/dev/null`
        my_key_4=`${srcdir}/c_random.sh 2>/dev/null`
        my_key_A=`expr $my_key_1 \* 32767`
        my_key_A=`echo ${my_key_A} | sed 's%^0*%%g' 2>/dev/null`
        my_key_A=`expr $my_key_A \+ $my_key_2`
        my_key_B=`expr $my_key_3 \* 32767`
        my_key_B=`echo ${my_key_B} | sed 's%^0*%%g' 2>/dev/null`
        my_key_B=`expr $my_key_B \+ $my_key_4`
        AC_MSG_RESULT(${my_key_A} ${my_key_B})
        ]
        )
AC_SUBST(my_key_A)
AC_SUBST(my_key_B)

dnl low bytes
my_key_1=`expr $my_key_A \% 65536`
dnl high bytes
my_key_2=`expr $my_key_A \/ 65536`
dnl low bytes
my_key_3=`expr $my_key_B \% 65536`
dnl high bytes
my_key_4=`expr $my_key_B \/ 65536`

dnl echo ${my_key_1} ${my_key_2} ${my_key_3} ${my_key_4}

dnl touch ./sh_MK.h
dnl echo "#ifndef SH_MK_H" >> ./sh_MK.h
dnl echo "#define SH_MK_H" >> ./sh_MK.h
dnl ${srcdir}/c_bits.sh ${my_key_1} MKB >> ./sh_MK.h
dnl ${srcdir}/c_bits.sh ${my_key_2} MKA >> ./sh_MK.h
dnl ${srcdir}/c_bits.sh ${my_key_3} MKC >> ./sh_MK.h
dnl ${srcdir}/c_bits.sh ${my_key_4} MKD >> ./sh_MK.h
dnl echo "#endif" >> ./sh_MK.h
AC_SUBST(my_key_1)
AC_SUBST(my_key_2)
AC_SUBST(my_key_3)
AC_SUBST(my_key_4)

AC_MSG_CHECKING(key position)
pos_tf_1=`${srcdir}/c_random.sh 2>/dev/null`
pos_tf_2=`expr $pos_tf_1 \% 8`
pos_tf=`expr $pos_tf_2 + 1`
AC_MSG_RESULT(${pos_tf})
AC_DEFINE_UNQUOTED(POS_TF, ${pos_tf} )

mykeybase=`echo ${my_key_A},${my_key_B}`
AC_DEFINE_UNQUOTED(DEFKEY, ${mykeybase} )
AC_SUBST(mykeybase)


dnl
dnl  GPG/PGP options
dnl 

AC_ARG_WITH(gpg,
        [  --with-gpg=PATH 		use GnuPG to verify database/config [[no]]],
        [
	if test "x${withval}" != "xno"; then
	  if test "x${cross_compiling}" = xyes; then
		mygpg="${withval}"
	  else
		if test -f "${withval}"; then
		  mygpg="${withval}"
		  mychk0=`${withval} --load-extension tiger --print-md TIGER192 ${withval} 2>/dev/null`
		  if test "x$?" != "x0"; then
		    mychktest=no
		    for sampre in ./samhain ./yule /usr/local/sbin/samhain /usr/local/bin/samhain /usr/bin/samhain /usr/sbin/samhain /usr/local/sbin/yule /usr/local/bin/yule /usr/bin/yule /usr/sbin/yule; do
		      if test x"${mychktest}" = xyes
		      then
			:
		      else
		        if test -f ${sampre}
		        then
			  echo "use existing ${sampre} for gpg checksum"
			  mychk0=`${sampre} -H ${withval} 2>/dev/null`
			  if test "x$?" != "x0"; then
			    if test "x${nocl_code}" != "x"; then
			       mychk0=`echo -H ${withval} | ${sampre} ${nocl_code} 2>/dev/null`
			       if test "x$?" != "x0"; then
			       	  :
			       else
			          mychk="${mychk0}"
				  mychktest=yes
			       fi 
			    fi
			  else
			    mychk="${mychk0}"
			    mychktest=yes
			  fi
		        fi
		      fi
		    done
		    if test x${mychktest} = xno; then
		      AC_MSG_WARN([--with-gpg: cannot determine TIGER192 checksum of ${withval}])
		      echo "-------------------------------------------------------------"
		      echo " Your gpg binary does not support the TIGER192 checksum, "
		      echo " and I cannot find an existing samhain binary to use instead."
		      echo " You can:"
		      echo "   (a) run make to compile a samhain binary, then repeat"
		      echo "       ./configure and make"
		      echo "   (b) ignore the failure. The checksum of the gpg binary"
		      echo "       will not get compiled in, thus allowing an attacker"
		      echo "       to replace gpg with a trojan and subverting the gpg"
		      echo "       signature verification of configure and database files."
		      echo
		      echo " PLEASE IGNORE THIS MESSAGE IF YOU ALSO USE --with-checksum"
		      echo "-------------------------------------------------------------"
		    fi
		  else
		    mychk="${mychk0}"
		  fi
		else
		  AC_MSG_ERROR([--with-gpg: cannot find GnuPG PATH=${withval}])
		fi
	  fi
	  AC_DEFINE(WITH_GPG)
	  AC_DEFINE_UNQUOTED(DEFAULT_GPG_PATH, _("${mygpg}") )
	  AC_SUBST(mygpg)
	fi
	]
)



AC_ARG_WITH(keyid,
	[  --with-keyid=KEYID		specify KeyID (0x...) for GPG/PGP functions [[none]]],
	[
	if test "x${withval}" != "x"; then
		echo "${withval}" | awk '{if((length($0)==10)||(length($0)==18)){exit 2}else{exit 0}}' &&
		AC_MSG_ERROR([--with-keyid:${withval} must be "0x" + 8|16 hex digits])
		echo "${withval}" | grep ['[^0][^x][^0123456789ABCDEFabcdef]'] >/dev/null 2>&1 &&
		AC_MSG_ERROR([--with-keyid:${withval} must be "0x" + 8|16 hex digits])
		mykeyid="$withval"
		mykeytag="--default-key"
	else
		mykeyid=""
		mykeytag=""
	fi
	AC_SUBST(mykeyid)
	AC_SUBST(mykeytag)
	]
)

dnl AC_ARG_WITH(pgp,
dnl        [  --with-pgp=PATH		Use PGP to verify database/config (no).],
dnl         [myppg="$withval"
dnl 	AC_DEFINE(WITH_PGP)
dnl 	AC_DEFINE_UNQUOTED(DEFAULT_PGP_PATH, _("${myppg}") )
dnl 	])

AC_ARG_WITH(checksum,
        [  --with-checksum=CHKSUM	compile in gpg/pgp checksum [[yes]]],
        [
	if test "x${withval}" != "xno"; then
		if test "x${withval}" != "xyes"; then
			if test "x${mychk}" != "x"; then
				if test "x${mychk}" != "x${withval}"; then
					AC_MSG_WARN([--with-checksum: possible gpg CHKSUM problem])
					AC_MSG_WARN([--with-checksum: CHKSUM=${withval}])
					AC_MSG_WARN([--with-checksum: autodetected=${mychk}])
				fi
			fi
			mychk="${withval}"
		else
			if test "x${mychk}" = "x"; then
				AC_MSG_ERROR([Option --with-checksum=CHKSUM: checksum CHKSUM of the gpg binary not specified.])
			fi
		fi
		AC_DEFINE(HAVE_GPG_CHECKSUM)
		AC_DEFINE_UNQUOTED(GPG_HASH, _("${mychk}") )
		echo "${mychk}" | sed 's,.*:,,g' | sed 's, ,,g' | sed 's,\(.\),\1:,g' | awk '{ split($0, arr, ":"); m = length($1)/2; print "#ifndef CHKSUM_H"; print "#define CHKSUM_H"; print "char gpgchk[50];"; for (i=1; i <= m; i++) printf "gpgchk[%d] = %c%s%c;\n", i-1, 39, arr[i], 39; printf "gpgchk[48] = %c%c0%c;\n", 39, 92, 39; print "#endif"; }' > sh_gpg_chksum.h 
	fi
	],
	[
	if test "x${mygpg}" != "x"; then
		if test "x${mychk}" != "x"; then
			AC_DEFINE(HAVE_GPG_CHECKSUM)
			AC_DEFINE_UNQUOTED(GPG_HASH, _("${mychk}") )
			echo "${mychk}" | sed 's,.*:,,g' | sed 's, ,,g' | sed 's,\(.\),\1:,g' | awk '{ split($0, arr, ":"); m = length($1)/2; print "#ifndef CHKSUM_H"; print "#define CHKSUM_H"; print "char gpgchk[50];"; for (i=1; i <= m; i++) printf "gpgchk[%d] = %c%s%c;\n", i-1, 39, arr[i], 39; printf "gpgchk[48] = %c%c0%c;\n", 39, 92, 39; print "#endif"; }' > sh_gpg_chksum.h 
		fi
	fi
	]
)

AC_ARG_WITH(fp,
        [  --with-fp=FINGERPRINT		compile in public key fingerprint [[no]]],
        [
	if test "x${withval}" != "xno"; then
		if test "x${withval}" != "xyes"; then
			withval0=`echo ${withval} | sed 's% %%g'`
			echo "${withval0}" | \
			grep ['[^0123456789abcdefABCDEF]'] >/dev/null 2>&1 &&
			AC_MSG_ERROR([In option --with-fp=FINGERPRINT, there is an invalid character(s) in FINGERPRINT=${withval0}.])
			sh_len=`echo ${withval0} | wc -c | sed 's% %%g'`
			sh_len0=`expr ${sh_len} \- 1`
			if test "x${sh_len0}" = "x40" || test "x${sh_len0}" = "x32"
			then
				myfp="${withval0}"
				AC_DEFINE(USE_FINGERPRINT)
				AC_DEFINE_UNQUOTED(SH_GPG_FP, _("${myfp}") )
				echo "${myfp}" | sed 's,.*:,,g' | sed 's, ,,g' | sed 's,\(.\),\1:,g' | awk '{ split($0, arr, ":"); m = length($1)/2; print "#ifndef FINGERPRINT_H"; print "#define FINGERPRINT_H"; printf "char gpgfp[%d];\n", m+1; for (i=1; i <= m; i++) printf "gpgfp[%d] = %c%s%c;\n", i-1, 39, arr[i], 39; printf "gpgfp[%d] = %c%c0%c;\n", m, 39, 92, 39; print "#endif"; }' > sh_gpg_fp.h 
			else
				AC_MSG_ERROR([In option --with-fp=FINGERPRINT, the length (${sh_len0}) of FINGERPRINT ${withval0} is incorrect.])
			fi
		else
			AC_MSG_ERROR([For option --with-fp=FINGERPRINT, FINGERPRINT=yes is invalid, please specify a valid key fingerprint.])
		fi
	fi
	])


dnl
dnl  MAIL OPTIONS
dnl

AC_ARG_WITH(recipient,
        [  --with-recipient=ADDR		set recipient(s) for e-mail [[none]]],
        [
	withval0=`echo ${withval} | sed 's%,% %g'`
	for sh_item in ${withval0}
	do
		case ${sh_item} in
		*@localhost)
		;;
		*@*.*)
		sh_tmp=`echo ${sh_item} | awk '{ if ($1 ~ [/^[a-zA-Z0-9][a-zA-Z0-9\-_\.]*@[a-zA-Z0-9\-\.]+\.([a-zA-Z]+|[0-9]+)$/]) {print 1; } else { print 0}}'`
		if test "x${sh_tmp}" != "x1"
		then
			AC_MSG_ERROR([Option --with-recipient=ADDR used with invalid mail address ${sh_item}.])
		fi 
		;;
		*)
		AC_MSG_ERROR([Option --with-recipient=ADDR used with invalid mail address ${sh_item}.])
		;;
		esac
	done
	myrcp="$withval0"
	],
        [myrcp="NULL"])
AC_DEFINE_UNQUOTED(DEFAULT_MAILADDRESS, _("${myrcp}") )


AC_ARG_WITH(sender,
        [  --with-sender=SENDER		set sender for e-mail [[daemon]]],
        [
	mysender="${withval}"
	],
        [
	mysender="daemon"
	])
AC_DEFINE_UNQUOTED(DEFAULT_SENDER, _("${mysender}") )


dnl
dnl  PATHS
dnl

AC_ARG_WITH(trusted,
        [  --with-trusted=UID		Set uid(s) of trusted users [[0]]],
        [
	sh_tmp_test=no
	sh_tmp=`echo ${withval} | sed 's%,% %g'`
	for sh_tmp1 in ${sh_tmp}
	do
		echo "${sh_tmp1}" | grep ['[^0123456789]'] >/dev/null 2>&1 &&
			AC_MSG_ERROR([Option --with-trusted=UID used with non-numeric UID in ${withval}.])
		if test "x${sh_tmp1}" = "x0"
		then
			sh_tmp_test=yes
		fi
	done
	if test "x${sh_tmp_test}" = "xno"
	then
		withval="0,${withval}"
	fi
	mytrust="${withval}"
	],
        [mytrust="0"] )
AC_DEFINE_UNQUOTED(SL_ALWAYS_TRUSTED, ${mytrust} )
AC_SUBST(mytrust)

mytmpdir=

AC_ARG_WITH(tmp-dir,
        [  --with-tmp-dir=PFX		set directory for temporary files [[HOME]]],
        [
	if test "x${cross_compiling}" = xyes; then
		mytmpdir="$withval"
		AC_DEFINE_UNQUOTED(SH_TMPDIR, _("${mytmpdir}") )
	else
		if test -d "${withval}"; then
			mytmpdir="$withval"
			AC_DEFINE_UNQUOTED(SH_TMPDIR, _("${mytmpdir}") )
		else
			mytmpdir="$withval"
			AC_DEFINE_UNQUOTED(SH_TMPDIR, _("${mytmpdir}") )
			AC_MSG_WARN([--with-tmp-dir: tmp directory ${withval} does not exist])
		fi
	fi
	]
)

AC_SUBST(mytmpdir)


dnl
dnl PATH DEFAULTS
dnl

if test "x${ac_prefix_set}" = xyes
then
	if test "x${exec_prefix}" = xNONE
	then
		exec_prefix="${prefix}"
	fi

	if test "x${prefix}" = xOPT
	then
		tmp_sbindir="/opt/${install_name}/bin"
		tmp_sysconfdir="/etc/opt"
		tmp_mandir="/opt/${install_name}/man"
		tmp_localstatedir="/var/opt/${install_name}"
	elif test "x${prefix}" = xUSR
	then
		tmp_sbindir="/usr/sbin"
		tmp_sysconfdir="/etc"
		tmp_mandir="/usr/share/man"
		tmp_localstatedir="/var"
	else
		tmp_sbindir=`eval echo ${sbindir}`
		tmp_sysconfdir=`eval echo ${sysconfdir}`
		tmp_mandir=`eval echo ${mandir}`
		tmp_localstatedir=`eval echo ${localstatedir}`
	fi
else
	prefix=""
	if test "x${ac_exec_prefix_set}" = xyes
	then
		tmp_sbindir=`eval echo ${sbindir}`
	else
		tmp_sbindir="/usr/local/sbin"
	fi
	tmp_sysconfdir="/etc"
	# share/man -> man (FHS) 11.10.2002
	tmp_mandir="/usr/local/man"
	tmp_localstatedir="/var"
fi


if test "x${ac_sbindir_set}" = xyes
then
	:
else
	sbindir=`eval echo ${tmp_sbindir}`
fi
	

if test "x${ac_sysconfdir_set}" = xyes
then
	:
else
	sysconfdir=`eval echo ${tmp_sysconfdir}`
fi

if test "x${ac_mandir_set}" = xyes
then
	:
else
	mandir=`eval echo ${tmp_mandir}`
fi

if test "x${ac_localstatedir_set}" = xyes
then
	:
else
	localstatedir=`eval echo ${tmp_localstatedir}`
fi



AC_ARG_WITH(config-file,
        [  --with-config-file=FILE	configuration file [[/etc/{install_name}rc]]],
        [
	myconffile="${withval}"
	changequote(<<, >>)dnl
        tmp=`echo ${withval} | sed 's%^REQ_FROM_SERVER%%'`
	sysconfdir=`echo ${tmp} | sed 's%/[^/][^/]*$%%'`
	myrpmconffile="${tmp}"
	changequote([, ])dnl
	],
	[
	myconffile="${sysconfdir}/${install_name}rc"
	myrpmconffile="${myconffile}"
	]
)
AC_DEFINE_UNQUOTED(DEFAULT_CONFIGFILE, _("${myconffile}") )
AC_SUBST(myconffile)
AC_SUBST(myrpmconffile)

AC_ARG_WITH(log-file,
        [  --with-log-file=FILE		path of log file [[/var/log/{install_name}_log]]],
        [
	mylogfile="$withval"
	changequote(<<, >>)dnl
	mylogdir=`echo ${withval} | sed 's%/[^/][^/]*$%%'`
	changequote([, ])dnl
	],
	[
	if test "x${mytclient}" = "x-DSH_WITH_SERVER"; then
	  mylogfile="${localstatedir}/log/${install_name}/${install_name}_log"
	  mylogdir="${localstatedir}/log/${install_name}"
	else
	  mylogfile="${localstatedir}/log/${install_name}_log"
	  mylogdir="${localstatedir}/log"
	fi
	]
)
AC_DEFINE_UNQUOTED(DEFAULT_ERRFILE, _("${mylogfile}") )
AC_DEFINE_UNQUOTED(DEFAULT_LOGDIR, _("${mylogdir}") )
AC_SUBST(mylogfile)
AC_SUBST(mylogdir)

AC_ARG_WITH(pid-file,
        [  --with-pid-file=FILE		set path of pid file [[/var/run/{install_name}.pid]]],
        [
	mylockfile="$withval"
	changequote(<<, >>)dnl
	mylockdir=`echo ${withval} | sed 's%/[^/][^/]*$%%'`
	changequote([, ])dnl
	],
	[
	if test -h /var/run && test -d /run; then
		mylockfile="/run/${install_name}.pid"
		mylockdir="/run"
	else
		mylockfile="${localstatedir}/run/${install_name}.pid"
		mylockdir="${localstatedir}/run"
	fi
	]
)
AC_DEFINE_UNQUOTED(DEFAULT_ERRLOCK, _("${mylockfile}") )
AC_DEFINE_UNQUOTED(DEFAULT_PIDDIR, _("${mylockdir}") )
AC_SUBST(mylockfile)
AC_SUBST(mylockdir)

AC_ARG_WITH(state-dir,
        [  --with-state-dir=PFX		set state data directory [[/var/lib/{install_name}]]],
        [
	mydataroot="$withval"
	],
	[
	mydataroot="${localstatedir}/lib/${install_name}"
	]
	)
AC_ARG_WITH(data-file,
        [  --with-data-file=FILE		set path of data file],
        [
	mydatafile="$withval"
	changequote(<<, >>)dnl
        tmp=`echo ${withval} | sed 's%^REQ_FROM_SERVER%%'`
	mydataroot=`echo ${tmp} | sed 's%/[^/][^/]*$%%'`
	myrpmdatafile="${tmp}"
	changequote([, ])dnl
	if test x"${tmp}" = x
	then
		echo "No local path in data file ${withval}"
		echo "This will not work for initializing the database."
		if test x"${withval}" = xREQ_FROM_SERVER
		then
			echo "It should be REQ_FROM_SERVER/some/local/path"
		fi
		AC_MSG_ERROR([Option --with-data-file=FILE used with invalid path ${withval}.])
	fi
	],
        [
	mydatafile="${mydataroot}/${install_name}_file"
	myrpmdatafile="${mydatafile}"
	])
AC_DEFINE_UNQUOTED(DEFAULT_DATA_FILE, _("${mydatafile}") )
AC_SUBST(mydatafile)
AC_SUBST(myrpmdatafile)

AC_DEFINE_UNQUOTED(DEFAULT_DATAROOT, _("${mydataroot}") )
AC_SUBST(mydataroot)

AC_DEFINE_UNQUOTED(DEFAULT_QDIR, _("${mydataroot}/.quarantine") )
AC_SUBST(myqdir)


AC_ARG_WITH(html-file,
        [  --with-html-file=FILE		set path of html file,],
        [
	myhtmlfile="$withval"
	],
	[
        myhtmlfile="${mylogdir}/${install_name}.html"
	])
AC_DEFINE_UNQUOTED(DEFAULT_HTML_FILE, _("${myhtmlfile}") )
AC_SUBST(myhtmlfile)


mydefargs=$ac_configure_args
# if test -z "`echo "$mydefargs" | grep "\-\-enable\-static" 2> /dev/null`" 
# then
#	mydefargs="--enable-static $mydefargs"
# fi
if test -z "`echo "$mydefargs" | grep "\-\-enable\-base" 2> /dev/null`"
then
	mydefargs="--enable-base=${mykeybase} $mydefargs"
fi
AC_SUBST(mydefargs)


AC_DEFINE_UNQUOTED(SH_INSTALL_DIR,  _("${sbindir}"))
AC_DEFINE_UNQUOTED(SH_INSTALL_PATH, _("${sbindir}/${install_name}"))
AC_DEFINE_UNQUOTED(SH_INSTALL_NAME, _("${install_name}"))

AC_CONFIG_HEADER(config.h)

AC_OUTPUT(
[
Makefile
samhain-install.sh
init/samhain.startLSB
init/samhain.startLinux
init/samhain.startGentoo
init/samhain.startFreeBSD
init/samhain.startSolaris
init/samhain.startHPUX
init/samhain.startIRIX
init/samhain.startMACOSX
samhain.spec
rules.deb
rules.deb-light
hp_ux.psf
scripts/logrotate
scripts/samhain.spec
scripts/redhat_i386.client.spec
scripts/samhain.ebuild
scripts/samhain.ebuild-light
scripts/samhainadmin.pl
scripts/yuleadmin.pl
scripts/check_samhain.pl
deploy.sh
],
[
echo timestamp > stamp-h
chmod +x samhain-install.sh
chmod +x scripts/samhainadmin.pl
chmod +x scripts/yuleadmin.pl
chmod +x scripts/check_samhain.pl
]
)

chmod +x deploy.sh

if test "x${cross_compiling}" = xyes
then

echo "--------------------------------------------------------------"
echo
echo "You are using a cross-compiler. The following system dependent"
echo "values may have been set to default values that may be"
echo "incorrect for your target system: "
echo
echo "ac_cv_c_bigendian           bigendian byte order    ${ac_cv_c_bigendian}"
echo "ac_cv_c_long_double         long double exists      ${ac_cv_c_long_double}"
echo "ac_cv_sizeof_char_p         size of pointer to char ${ac_cv_sizeof_char_p}"
echo "ac_cv_sizeof_char_p         size of size_t          ${ac_cv_sizeof_size_t}"
echo "ac_cv_sizeof_unsigned_int   size of unsigned int    ${ac_cv_sizeof_unsigned_int}"
echo "ac_cv_sizeof_unsigned_long  size of unsigned long   ${ac_cv_sizeof_unsigned_long}"
echo "ac_cv_sizeof_unsigned_short size of unsigned short  ${ac_cv_sizeof_unsigned_short}"
echo
echo "If these values are incorrect, change them in the file "
echo "config.cache and run configure again."
echo
echo "--------------------------------------------------------------"

fi

if test x${silent} != xyes
then

	# A=`eval echo ${sbindir}` ;    A=`eval echo ${A}`
	# B=`eval echo ${myconffile}` ; B=`eval echo ${B}`
	# C=`eval echo ${mandir}` ;     C=`eval echo ${C}`
	# D=`eval echo ${mylockfile}` ; D=`eval echo ${D}`
	# E=`eval echo ${mylogfile}` ;  E=`eval echo ${E}`
	# F=`eval echo ${mydataroot}` ; F=`eval echo ${F}`

	echo 
	echo " samhain has been configured as follows:"
	echo "     System binaries: ${sbindir}"
	echo "  Configuration file: ${myconffile}"
	echo "        Manual pages: ${mandir}"
	echo "      Data directory: ${mydataroot}"
	echo "       Database file: ${mydatafile}"
	echo "            PID file: ${mylockfile}"
	echo "            Log file: ${mylogfile}"
	echo "            Base key: ${mykeybase}"
	if test x"$mykeyid" != x
	then
	    echo "  target GPG/PGP key: ${mykeyid}"
	fi
	echo
	if test x"$mytclient" = x"-DSH_WITH_SERVER"
	then
	    echo "    Selected rc file: yulerc"
	else
	    echo "    Selected rc file: samhainrc.${selectconfig}"
	fi

fi

