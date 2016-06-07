
#ifndef CONFIG_H
#define CONFIG_H


@TOP@

/* ---- compile options        ------------   */

/* Define if you want database support        */
#undef WITH_DATABASE

/* Define if the database is unixODBC         */
#undef WITH_ODBC

/* Define if the database is oracle           */
#undef WITH_ORACLE

/* Define if the database is mysql            */
#undef WITH_MYSQL

/* Define if the database is postgresql       */
#undef WITH_POSTGRES

/* Define if the server may listen on 514/udp */
#undef INET_SYSLOG

/* Define if you want logfile in XML format   */
#undef SH_USE_XML

/* Define if you want external programs.      */
#undef WITH_EXTERNAL

/* Define if you want to reload the database  */
/* on SIGHUP.                                 */
#undef RELOAD_DATABASE

/* Define if you want SysV message queue.     */
#undef WITH_MESSAGE_QUEUE

/* Define the mode of the message queue.      */
#undef MESSAGE_QUEUE_MODE

/* Define which users are always trusted.     */
/* default = 0 ( = root)                      */
#undef SL_ALWAYS_TRUSTED

/* Define if you want network time.           */
/* default = no                               */
#undef HAVE_NTIME

/* The time server host address.              */
/* default = "NULL"                           */
#undef DEFAULT_TIMESERVER
#undef ALT_TIMESERVER

/* Define if you want to use the mail code.   */
/* default = yes                              */
#undef  SH_WITH_MAIL

/* Define if you want client/server encryption*/
#undef  SH_ENCRYPT

/* Define if you want version 2 encryption    */
#undef  SH_ENCRYPT_2

/* Define if you want to watch for login/-out.*/
/* default = no                               */
#undef  SH_USE_UTMP

/* Define if you want to check mount options on filesystems */
/* default = no                               */
#undef SH_USE_MOUNTS

/* Define if you want to keep an eye on       */
/* sensitive files that your users own        */
#undef SH_USE_USERFILES

/* Define if you want to watch for suid/sgid  */
/* files                                      */
#undef  SH_USE_SUIDCHK

/* Define if you want to check kernel syscall */
/* table to detect LKM rootkits.              */
/* default = no                               */
#undef  SH_USE_KERN

/* Define if you want to use the Kernel       */
/* module to hide samhain.                    */
#undef  SH_USE_LKM

/* Define if you have a vanilla  Kernel       */
/* (2.4 or 2.2)                               */
#undef  SH_VANILLA_KERNEL

/* Define to the name of the MAGIC_HIDE       */
/* string if you use the Kernel module to     */
/* hide samhain.                              */
#undef  SH_MAGIC_HIDE

/* Define if you want 'micro' stealth mode.   */
/* default = no                               */
#undef SH_STEALTH_MICRO

/* Define if you want to use stealth mode.    */
/* default = no                               */
#undef SH_STEALTH

/* Define if you want stealth w/o CL parsing. */
/* default = no                               */
#undef SH_STEALTH_NOCL

/* The magic argv[1] to re-enable CL parsing. */
/* default = "yes"                            */
#undef NOCL_CODE

/* XOR value to hide literal strings.         */
/* default = 0                                */
#undef XOR_CODE

/* The port number for TCP/IP connection.     */
/* default = 49777                            */
#undef SH_DEFAULT_PORT

/* The identity to assume when dropping root  */
/* default = "nobody"                         */
#undef DEFAULT_IDENT

/* Directory for tmp files                    */
#undef SH_TMPDIR

/* The data root directory.                   */
/* default="/var/lib/samhain"                 */
#undef DEFAULT_DATAROOT

/* The quarantine directory.                  */
/* default="/var/lib/samhain/.quarantine      */
#undef DEFAULT_QDIR

/* The location of the log file.              */
/* default="/var/log/samhain_log"             */
#undef DEFAULT_ERRFILE

/* The directory of the log file.             */
/* default="/var/log"                         */
#undef DEFAULT_LOGDIR

/* The location of the pid file.              */
/* default="/var/run/samhain.pid"             */
#undef DEFAULT_ERRLOCK

/* The location of the pid file directory.    */
/* default="/var/run            "             */
#undef DEFAULT_PIDDIR

/* The location of the configuration file.    */ 
/* default="/etc/samhainrc"                   */
#undef DEFAULT_CONFIGFILE

/* The location of the checksum data.         */
/* default="/var/lib/samhain/samhain_file"    */
#undef DEFAULT_DATA_FILE

/* The location of the html report.           */
/* default="/var/log/.samhain.html"           */
#undef DEFAULT_HTML_FILE

/* The install directory.                     */
/* default="/usr/local/sbin"                  */
#undef SH_INSTALL_DIR

/* The install path.                          */
/* default="/usr/local/sbin/samhain"          */
#undef SH_INSTALL_PATH
#undef SH_INSTALL_YULE_PATH

/* The install name.                          */
/* default="samhain"                          */
#undef SH_INSTALL_NAME

/* The sender name to use.                    */
/* default = "daemon"                         */
#undef  DEFAULT_SENDER 

/* The address to send mail to.               */ 
/* default = "NULL"                           */
#undef  DEFAULT_MAILADDRESS 
#undef  ALT_MAILADDRESS 

/* The log server.                            */ 
/* default = "NULL"                           */
#undef  DEFAULT_LOGSERVER 
#undef  ALT_LOGSERVER 

/* The console.                               */ 
/* default = "NULL"                           */
#undef  DEFAULT_CONSOLE 
#undef  ALT_CONSOLE 

/* The default base for one-time pads.        */ 
/* default = compile_time,compile_time        */
#undef  DEFKEY

/* Define if you want more debug options.     */
/* default = no                               */
#undef MEM_DEBUG

/* Define if you want more debug output.      */
/* default = no                               */
#undef WITH_TPT

/* Define if you want tracing.                */
/* default = no                               */
#undef WITH_TRACE

/* Define if you want slib debug.             */
/* default = no                               */
#undef SL_DEBUG

/* Define if you want slib to abort on errors.*/
/* default = no                               */
#undef SL_FAIL_ON_ERROR

/* Define if you want to use SRP authenticaton*/
#undef USE_SRP_PROTOCOL

/* Define if you want to use GnuPG to         */
/* verify database and configuation file.     */
#undef WITH_GPG

/* The full path to GnuPG                     */
#undef DEFAULT_GPG_PATH

/* Define if using the gpg/pgp checksum.      */
#undef HAVE_GPG_CHECKSUM

/* The tiger checksum of the gpg/pgp binary.  */
#undef GPG_HASH

/* Define if you want to compile in the       */
/* public key fingerprint.                    */
#undef USE_FINGERPRINT

/* The public key fingerprint.                */
#undef SH_GPG_FP

/* Use ptrace - screw up signal handling.     */
#undef SCREW_IT_UP

/* ---- misc                   ------------   */

/* Define the package name.                   */
#undef PACKAGE

/* Define the package version.                */
#undef VERSION

/* Define to the position of the key (1...8). */
#undef POS_TF

/* Init key for exepack.                      */
#undef EXEPACK_STATE_0
#undef EXEPACK_STATE_1
#undef EXEPACK_STATE_2

/* ---- system-specific options ------------  */

/* Define to the address of sys_call_table */
#undef SH_SYSCALLTABLE

/* Define to use SVR4 statvfs to get filesystem type.  */
#undef FSTYPE_STATVFS

/* Define to use SVR3.2 statfs to get filesystem type.  */
#undef FSTYPE_USG_STATFS

/* Define to use AIX3 statfs to get filesystem type.  */
#undef FSTYPE_AIX_STATFS

/* Define to use 4.3BSD getmntent to get filesystem type.  */
#undef FSTYPE_MNTENT

/* Define to use 4.4BSD and OSF1 statfs to get filesystem type.  */
#undef FSTYPE_STATFS

/* Define to use Ultrix getmnt to get filesystem type.  */
#undef FSTYPE_GETMNT

/* the basic type to which we can cast a uid
 */
#undef UID_CAST

/* for ext2fs flags                           */
#undef HAVE_EXT2_IOCTLS
#undef HAVE_STAT_FLAGS

/* obvious                                    */
#undef HOST_IS_LINUX
#undef HOST_IS_I86LINUX

/* obvious                                    */
#undef HOST_IS_CYGWIN

/* obvious                                    */
#undef HOST_IS_DARWIN

/* obvious                                    */
#undef HOST_IS_FREEBSD

/* obvious                                    */
#undef HOST_IS_AIX

/* obvious                                    */
#undef HOST_IS_SOLARIS

/* obvious                                    */
#undef HOST_IS_I86SOLARIS

/* obvious                                    */
#undef HOST_IS_HPUX

/* Define to the name of the random devices.  */
#undef NAME_OF_DEV_RANDOM

#undef NAME_OF_DEV_URANDOM

/* Define if you have long long.              */
#undef HAVE_LONG_LONG

/* Define if short is 32 bits.                */
#undef HAVE_SHORT_32

/* Define if int is 32 bits.                  */
#undef HAVE_INT_32

/* Define if long is 32 bits.                 */
#undef HAVE_LONG_32

/* Define if long is 64 bits.                 */
#undef HAVE_LONG_64

/* Define if UINT64 is 32 bits.                 */
#undef UINT64_IS_32

/* Define if you have uint64_t.               */
#undef HAVE_UINT16_T

/* Define if you have uint64_t.               */
#undef HAVE_UINT64_T

/* Define if you have utmpx.h.                */
#undef HAVE_UTMPX_H

/* Define if your struct utmpx has ut_xtime.  */
#undef HAVE_UTXTIME

/* Define if your struct utmp has ut_type.    */
#undef HAVE_UTTYPE

/* Define if your struct utmp has ut_host.    */
#undef HAVE_UTHOST

/* Define if your struct utmp has ut_addr.    */
#undef HAVE_UTADDR

/* Define if your struct utmp has ut_addr_v6  */
#undef HAVE_UTADDR_V6

/* Define if your includes are broken.        */
#undef HAVE_BROKEN_INCLUDES

/* Define if your getcwd uses 'popen'.        */
#undef HAVE_BROKEN_GETCWD

/* Define if your vsnprintf is broken.        */
#undef HAVE_BROKEN_VSNPRINTF

/* Define if you have va_copy.                */
#undef VA_COPY

/* Define if va_list may be copied as array.  */
#undef VA_COPY_AS_ARRAY

/* Define if you need unix entropy gatherer.  */
#undef HAVE_UNIX_RANDOM

/* Define if you have EGD.                    */
#undef HAVE_EGD_RANDOM

/* Define if you have /dev/random.            */
#undef HAVE_URANDOM

/* Soket name for EGD.                        */
#undef EGD_SOCKET_NAME

/* Define if your mlock() is broken.          */
#undef HAVE_BROKEN_MLOCK

/* Define the proc f_type.                    */
#undef SH_PROC_MAGIC

/* Define if you have statfs.                 */
#undef HAVE_STATFS

/* Define if statfs works.                    */
#undef STATFS_WORKS

/* Define to long if not defined.             */
#undef ptrdiff_t

@BOTTOM@

/* dont modify this, unless you know what you do
 */
#define SRP_GENERATOR_1024      "2"
#define SRP_MODULUS_1024_1        \
_("f488fd584e49dbcd20b49de49107366b336c380d451d0f7c88b31c7c5b2d8ef6") 
#define SRP_MODULUS_1024_2        \
_("f3c923c043f0a55b188d8ebb558cb85d38d334fd7c175743a31d186cde33212c") 
#define SRP_MODULUS_1024_3        \
_("b52aff3ce1b1294018118d7c84a70a72d686c40319c807297aca950cd9969fab")
#define SRP_MODULUS_1024_4        \
_("d00a509b0246d3083d66a45d419f9c7cbd894b221926baaba25ec355e92f78c7")

#define SDG_0RETU _("return.\n")
#define SDG_TERRO _("ERROR: file=<%s>, line=<%d>, reason=<%s>\n")
#define SDG_AERRO _("ERROR: file=<%s>, line=<%d>, failed_assertion=<%s>\n")
#define SDG_AFAIL _("FAILED: file=<%s>, line=<%d>, assertion=<%s>\n")
#define SDG_ENTER _("enter=<%s>\n")
#define SDG_RETUR _("return=<%s>.\n")
#define SDG_ERROR _("error=<%ld>.\n")

#ifdef SH_STEALTH
char * globber(const char * string);
#define _(string) globber(string) 
#define N_(string) string
#else
#define _(string)  string 
#define N_(string) string
#endif

#endif
