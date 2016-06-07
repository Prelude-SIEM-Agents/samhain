/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
/*                                                                         */
/*  This program is free software; you can redistribute it                 */
/*  and/or modify                                                          */
/*  it under the terms of the GNU General Public License as                */
/*  published by                                                           */
/*  the Free Software Foundation; either version 2 of the License, or      */
/*  (at your option) any later version.                                    */
/*                                                                         */
/*  This program is distributed in the hope that it will be useful,        */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*  GNU General Public License for more details.                           */
/*                                                                         */
/*  You should have received a copy of the GNU General Public License      */
/*  along with this program; if not, write to the Free Software            */
/*  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              */

#include "config_xor.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>


#include "samhain.h"
#include "sh_error.h"
#include "sh_getopt.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_utils.h"
#include "sh_mail.h"
#include "sh_xfer.h"
#include "sh_hash.h"
#include "sh_dbIO.h"
#include "sh_dbCheck.h"
#include "sh_dbCreate.h"
#include "sh_sem.h"

#if defined(WITH_EXTERNAL)
#include "sh_extern.h"
#endif

extern int      sh_calls_set_bind_addr (const char *);

#undef  FIL__
#define FIL__  _("sh_getopt.c")

#define HAS_ARG_NO  0
#define HAS_ARG_YES 1
#define DROP_PRIV_NO  0
#define DROP_PRIV_YES 1


typedef struct options {
  const char * longopt;
  const char   shortopt;
  const char * usage;
  int          hasArg;
  int (*func)(const char * opt);
} opttable_t;

/*@noreturn@*/
static int sh_getopt_usage (const char * dummy);
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
static int sh_getopt_forever (const char * dummy);
static int sh_getopt_outpath (const char * dummy);
#endif
static int sh_getopt_copyright (const char * dummy);
static int sh_getopt_version (const char * dummy);

static opttable_t op_table[] = {

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  { N_("set-checksum-test"),  
    't', 
    N_("Set checksum testing to 'init', 'update', or 'check'"),  
    HAS_ARG_YES, 
    sh_util_setchecksum },
  { N_("interactive"),  
    'i', 
    N_("Run update in interactive mode"),  
    HAS_ARG_NO, 
    sh_util_set_interactive },
  { N_("listfile"),  
    '-', 
    N_("Run update with listfile"),  
    HAS_ARG_YES, 
    sh_util_update_file },
#endif
#if defined(SH_WITH_SERVER) || defined(SH_WITH_CLIENT)
  { N_("server-port"),  
    '-', 
    N_("Set the server port to connect to"),  
    HAS_ARG_YES, 
    sh_xfer_server_port },
  { N_("server-host"),  
    '-', 
    N_("Set the server host to connect to"),  
    HAS_ARG_YES, 
    sh_xfer_set_logserver },
#endif
#ifdef SH_WITH_SERVER
  { N_("server"),  
    'S', 
    N_("Run as log server (obsolete)"),  
    HAS_ARG_NO, 
    sh_util_setserver },
  { N_("qualified"),  
    'q', 
    N_("Log fully qualified name of client host"),  
    HAS_ARG_NO, 
    sh_xfer_set_strip },
  { N_("chroot"),  
    '-', 
    N_("Chroot to specified directory"),  
    HAS_ARG_YES, 
    sh_unix_set_chroot },
#endif
  { N_("daemon"),  
    'D', 
    N_("Run as daemon"),  
    HAS_ARG_NO, 
    sh_unix_setdeamon },
  { N_("foreground"),  
    '-', 
    N_("Stay in the foreground"),  
    HAS_ARG_NO, 
    sh_unix_setnodeamon },
  { N_("bind-address"),  
    '-', 
    N_("Bind to this address (interface) for outgoing connections"),  
    HAS_ARG_YES, 
    sh_calls_set_bind_addr },
#if defined(SH_WITH_SERVER) || defined(SH_WITH_CLIENT)
  { N_("set-export-severity"),  
    'e', 
    N_("Set severity threshold for export to remote log server"),  
    HAS_ARG_YES, 
    sh_error_setexport },
#endif
  { N_("set-syslog-severity"),  
    's', 
    N_("Set severity threshold for syslog"),  
    HAS_ARG_YES, 
    sh_error_set_syslog },
#ifdef WITH_EXTERNAL
  { N_("set-extern-severity"),  
    'x', 
    N_("Set severity threshold for logging by external program(s)"),  
    HAS_ARG_YES, 
    sh_error_set_external },
#endif
#ifdef HAVE_LIBPRELUDE
  { N_("set-prelude-severity"),  
    '-', 
    N_("Set severity threshold for logging to prelude"),  
    HAS_ARG_YES, 
    sh_error_set_prelude },
#endif
#if defined(WITH_DATABASE)
  { N_("set-database-severity"),  
    '-', 
    N_("Set severity threshold for logging to RDBMS"),  
    HAS_ARG_YES, 
    sh_error_set_database },
#endif
  { N_("set-log-severity"),  
    'l', 
    N_("Set severity threshold for logfile"),  
    HAS_ARG_YES, 
    sh_error_setlog },
#if defined(SH_WITH_MAIL)
  { N_("set-mail-severity"),  
    'm', 
    N_("Set severitythreshold  for e-mail"),  
    HAS_ARG_YES, 
    sh_error_setseverity },
#endif
  { N_("set-print-severity"),  
    'p', 
    N_("Set the severity threshold for terminal/console log"),  
    HAS_ARG_YES, 
    sh_error_setprint },
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  { N_("recursion"),  
    'r', 
    N_("Set recursion level for directories"),  
    HAS_ARG_YES, 
    sh_files_setrecursion },
#endif
  { N_("verify-log"),  
    'L', 
    N_("Verify the audit trail"),  
    HAS_ARG_YES, 
    sh_error_logverify },
  { N_("just-list"),  
    'j', 
    N_("Modify -L to just list the audit trail"),  
    HAS_ARG_NO, 
    sh_error_logverify_mod },
#if defined(SH_WITH_MAIL)
  { N_("verify-mail"),  
    'M', 
    N_("Verify the mailbox"),  
    HAS_ARG_YES, 
    sh_mail_sigverify 
  },
#endif
  { N_("add-key"),  
    'V', 
    N_("Add key for the mail/log signature"),  
    HAS_ARG_YES, 
    sh_util_set_newkey
  },
  { N_("hash-string"),  
    'H', 
    N_("Print the hash of a string"),  
    HAS_ARG_YES, 
    sh_error_verify },
#if defined (SH_WITH_SERVER) 
  { N_("password"),  
    'P', 
    N_("Compute a client registry entry for password"),  
    HAS_ARG_YES, 
    sh_xfer_make_client },
  { N_("gen-password"),  
    'G', 
    N_("Generate a random password"),  
    HAS_ARG_NO, 
    sh_xfer_create_password },
#endif

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  { N_("forever"),  
    'f', 
    N_("Loop forever, even if not daemon"),  
    HAS_ARG_NO, 
    sh_getopt_forever},
  { N_("outfile"),  
    'o', 
    N_("Pathname for output file"),  
    HAS_ARG_YES, 
    sh_getopt_outpath},
  { N_("list-file"),  
    '-', 
    N_("Modify -d to show content of a single file"),  
    HAS_ARG_YES, 
    set_list_file},
  { N_("list-filter"),  
    '-', 
    N_("Modify -d to filter by file list given in text file"),  
    HAS_ARG_YES, 
    sh_dbIO_list_filter},
  { N_("full-detail"),  
    'a', 
    N_("Modify -d to show full details"),  
    HAS_ARG_NO, 
    set_full_detail},
  { N_("delimited"),  
    '-', 
    N_("Modify -d to show full details, comma delimited"),  
    HAS_ARG_NO, 
    set_list_delimited},
  { N_("binary"),  
    '-', 
    N_("Modify -d to output in binary database format"),  
    HAS_ARG_NO, 
    sh_dbIO_list_binary},
  { N_("list-database"),  
    'd', 
    N_("List database content (like ls -l)"),  
    HAS_ARG_YES, 
    sh_dbIO_list_db},
  { N_("init2stdout"),  
    '-', 
    N_("Write database to stdout on init"),  
    HAS_ARG_NO, 
    sh_dbIO_writeout_stdout},
  { N_("verify-database"),  
    '-', 
    N_("Verify the given database"),  
    HAS_ARG_YES, 
    sh_dbCheck_verify},
  { N_("create-database"),  
    '-', 
    N_("Create database from file list"),  
    HAS_ARG_YES, 
    sh_dbCreate},
  { N_("wait-on-check"),  
    'w', 
    N_("Timed wait for end of filecheck (0 for no timeout)"),  
    HAS_ARG_YES, 
    sh_sem_wait},
#endif
  { N_("trace-logfile"),  
    '-', 
    N_("Logfile for trace"),  
    HAS_ARG_YES, 
    sl_trace_file },
  { N_("trace-enable"),  
    '-', 
    N_("Enable tracing"),  
    HAS_ARG_NO, 
    sl_trace_use },
  { N_("copyright"),  
    'c', 
    N_("Print copyright information"),  
    HAS_ARG_NO, 
    sh_getopt_copyright },
  { N_("help"),  
    'h', 
    N_("Print usage information"),  
    HAS_ARG_NO, 
    sh_getopt_usage },
  { N_("version"),  
    'v', 
    N_("Show version and compiled-in options"),  
    HAS_ARG_NO, 
    sh_getopt_version },
#if defined(HAVE_LIBPRELUDE)
  /* need to skip over these */
  { N_("prelude"),  
    '-', 
    N_("Prelude generic options"),  
    HAS_ARG_NO, 
    NULL },
  { N_("profile"),  
    '-', 
    N_("Profile to use for this analyzer"),  
    HAS_ARG_YES, 
    NULL },
  { N_("heartbeat-interval"),  
    '-', 
    N_("Number of seconds between two heartbeats"),  
    HAS_ARG_YES, 
    NULL },
  { N_("server-addr"),  
    '-', 
    N_("Address where this sensor should report to"),  
    HAS_ARG_YES, 
    NULL },
  { N_("analyzer-name"),  
    '-', 
    N_("Name for this analyzer"),  
    HAS_ARG_YES, 
    NULL },
#endif
  /* last entry -- required !! -- */
  { NULL, 
    '\0',     
    NULL,  
    HAS_ARG_NO, 
    NULL }
};


static void sh_getopt_print_log_facilities (void)
{
  int num = 0;

  fputs (_("Compiled-in log facilities:\n"), stdout);

#ifndef DEFAULT_CONSOLE
  if (num > 0) fputc ('\n', stdout);
  printf ("%s", _(" console (/dev/console)")); ++num;
#else
  if (num > 0) fputc ('\n', stdout);
  if (0 == strcmp (DEFAULT_CONSOLE, _("NULL")))
    { printf ("%s", _("console (/dev/console)"));  ++num; }
  else
    { printf (_("console (%s)"), DEFAULT_CONSOLE);  ++num; }
#endif
  if (num > 0) fputc ('\n', stdout);
  fputs  (_(" syslog"), stdout); ++num;
  if (num > 0) fputc ('\n', stdout);
  printf (_(" logfile (%s)"), DEFAULT_ERRFILE); ++num;

#if defined(WITH_EXTERNAL)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" external program"), stdout); ++num;
#endif

#if defined(WITH_MESSAGE_QUEUE)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" message queue"), stdout); ++num;
#endif
 
#if defined(WITH_DATABASE)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" database"), stdout); ++num;
#ifdef WITH_ODBC
  fputs (_(" (odbc)"), stdout);
#endif
#ifdef WITH_ORACLE
  fputs (_(" (Oracle)"), stdout);
#endif
#ifdef WITH_POSTGRES
  fputs (_(" (PostgreSQL)"), stdout);
#endif
#ifdef WITH_MYSQL 
  fputs (_(" (MySQL)"), stdout);
#endif
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" server"), stdout); ++num;
#endif

#if defined(SH_WITH_MAIL)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" email"), stdout); ++num;
#endif

#ifdef HAVE_LIBPRELUDE
  if (num > 0) fputc ('\n', stdout); ++num;
  fputs (_(" prelude (0.9.6+)"), stdout);
#endif

  if (num == 0)
    fputs (_(" none"), stdout);
  fputc ('\n', stdout);
  return;
}

static void sh_getopt_print_options (void)
{
  int num = 0;


#if defined(SH_STANDALONE)
  if (num > 0) fputc ('\n', stdout);
  fputs (_("Standalone executable"), stdout); ++num;
#endif
#if defined(SH_WITH_CLIENT)
  if (num > 0) fputc ('\n', stdout);
  printf (_("Client executable (port %d)"), SH_DEFAULT_PORT); ++num;
#endif
#if defined(SH_WITH_SERVER)
  if (num > 0) fputc ('\n', stdout);
  printf (_("Server executable (port %d, user %s)"), 
	  SH_DEFAULT_PORT, DEFAULT_IDENT); 
  ++num;
#endif
#if defined(USE_IPVX)
  fputs (_(", IPv6 supported"), stdout);
#endif

  fputs (_(", compiled-in options:"), stdout);

#if defined(USE_SYSTEM_MALLOC)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" using system malloc"), stdout); ++num;
#else
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" using dnmalloc"), stdout); ++num;
#endif

#if defined(HAVE_EGD_RANDOM)
  if (num > 0) fputc ('\n', stdout);
  printf (_(" using entropy gathering daemon (%s)"), EGD_SOCKET_NAME); ++num;
#endif
#if defined(HAVE_UNIX_RANDOM)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" using unix entropy gatherer"), stdout); ++num;
#endif
#if defined(HAVE_URANDOM)
  if (num > 0) fputc ('\n', stdout);
  printf (_(" using entropy device (%s)"), NAME_OF_DEV_RANDOM); ++num;
#endif

#ifdef WITH_GPG
  if (num > 0) fputc ('\n', stdout);
  printf (_(" GnuPG signatures (%s)"), DEFAULT_GPG_PATH); ++num;
#ifdef HAVE_GPG_CHECKSUM
  if (num > 0) fputc ('\n', stdout);
  printf (_("   -- GnuPG checksum:  %s"), GPG_HASH); ++num;
#endif
#ifdef USE_FINGERPRINT
  if (num > 0) fputc ('\n', stdout);
  printf (_("   -- Key fingerprint: %s"), SH_GPG_FP); ++num;
#endif
#endif

#if defined(SH_EVAL_SHELL)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" shell expansion in configuration file supported"), stdout); ++num;
#endif

#if defined(SL_DEBUG)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" debug build (do not use for production)"), stdout); ++num;
#endif
#if defined(SCREW_IT_UP)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" anti-debugger"), stdout); ++num;
#endif
#if defined(SH_USE_XML)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" xml log format"), stdout); ++num;
#endif
#if defined(HAVE_NTIME)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" using time server"), stdout); ++num;
#endif
#if defined(HAVE_REGEX_H)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" posix regex support"), stdout); ++num;
#endif


#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
#if defined(HAVE_LIBZ)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" optionally store full text for files"), stdout); ++num;
#endif
#if !defined(SH_COMPILE_STATIC) && defined(__linux__) && defined(HAVE_AUPARSE_H) && defined(HAVE_AUPARSE_LIB)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" optionally report auditd record of changed file"), stdout); ++num;
#endif
#if defined(USE_XATTR)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" check SELinux attributes"), stdout); ++num;
#endif
#if defined(USE_ACL)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" check Posix ACLs"), stdout); ++num;
#endif
#if defined(RELOAD_DATABASE)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" fetch database on reload"), stdout); ++num;
#endif
#endif

#if defined(SH_WITH_SERVER)

#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && !defined(HAVE_STRUCT_CMSGCRED) && !defined(HAVE_STRUCT_FCRED) && !(defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" command socket authentication: use SetSocketPassword"), stdout); 
  ++num;
#else
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" command socket authentication: use SetSocketAllowUID"), stdout); 
  ++num;
#endif

#if defined(SH_USE_LIBWRAP)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" support tcp wrapper"), stdout); ++num;
#endif
#if defined(INET_SYSLOG)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" support listening on 514/udp (syslog)"), stdout); ++num;
#endif
#endif

  if (num == 0)
    fputs (_(" none"), stdout);
  fputc ('\n', stdout);
  return;
}

static void sh_getopt_print_modules (void)
{
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  int num = 0;
  
  fputs (_("Compiled-in modules:\n"), stdout);
#ifdef SH_USE_UTMP
  if (num > 0) fputc (',', stdout);
  fputs (_(" login/logout"), stdout); ++num;
#endif
#ifdef SH_USE_MOUNTS
  if (num > 0) fputc (',', stdout);
  fputs (_(" mount options"), stdout); ++num;
#endif
#ifdef SH_USE_USERFILES
  if (num > 0) fputc (',', stdout);
  fputs (_(" userfiles"), stdout); ++num;
#endif
#ifdef SH_USE_KERN
  if (num > 0) fputc (',', stdout);
  fputs (_(" kernel"), stdout); ++num;
#endif
#ifdef SH_USE_SUIDCHK
  if (num > 0) fputc (',', stdout);
  fputs (_(" suid"), stdout); ++num;
#endif
#ifdef SH_USE_PROCESSCHECK
  if (num > 0) fputc (',', stdout);
  fputs (_(" processes"), stdout); ++num;
#endif
#ifdef SH_USE_PORTCHECK
  if (num > 0) fputc (',', stdout);
  fputs (_(" ports"), stdout); ++num;
#endif
#ifdef USE_LOGFILE_MONITOR
  if (num > 0) fputc (',', stdout);
  fputs (_(" logfile monitor"), stdout); ++num;
#endif
#if defined(USE_REGISTRY_CHECK)
  if (num > 0) fputc ('\n', stdout);
  fputs (_(" Windows registry"), stdout); ++num;
#endif
  if (num == 0)
    fputs (_(" none"), stdout);
  fputc ('\n', stdout);
#endif
  return;
}

static int sh_getopt_version (const char * dummy)
{
  (void) dummy;
  fprintf (stdout,
	   _("This is samhain (%s), "\
	     "(c) 1999-2008 Rainer Wichmann (http://la-samhna.de).\n"),
	   VERSION);
  fprintf (stdout, "%s",_("This software comes with ABSOLUTELY NO WARRANTY. "));
  fprintf (stdout, "%s",_("Use at own risk.\n\n"));

  sh_getopt_print_log_facilities ();
  sh_getopt_print_modules ();
  sh_getopt_print_options ();

  _exit (EXIT_SUCCESS);
  /*@notreached@*/
  return 0; /* make compilers happy */
}
static int sh_getopt_copyright (const char * dummy)
{
  fprintf (stdout, "%s",
	   _("Copyright (C) 1999-2008 Rainer Wichmann"\
	     " (http://la-samhna.de).\n\n"));

  fprintf (stdout, "%s",
	   _("This program is free software; "\
	     "you can redistribute it and/or modify\n"));
  fprintf (stdout, "%s",_("it under the terms of the GNU General "\
		     "Public License as published by\n"));
  fprintf (stdout, "%s",_("the Free Software Foundation; either version 2 "\
		     "of the License, or\n"));
  fprintf (stdout, "%s",_("(at your option) any later version.\n\n"));

  fprintf (stdout, "%s",_("This program is distributed in the hope "\
		     "that it will be useful,\n"));
  fprintf (stdout, "%s",_("but WITHOUT ANY WARRANTY; "\
		     "without even the implied warranty of\n"));
  fprintf (stdout, "%s",_("MERCHANTABILITY or FITNESS FOR A PARTICULAR "\
		     "PURPOSE. See the\n"));
  fprintf (stdout, "%s",_("GNU General Public License for more details.\n\n"));

  fprintf (stdout, "%s",_("You should have received a copy of the "\
		     "GNU General Public License\n"));
  fprintf (stdout, "%s",_("along with this program; "\
		     "if not, write to the Free Software\n"));
  fprintf (stdout, "%s",_("Foundation, Inc., 59 Temple Place - Suite 330, "\
		     "Boston, MA  02111-1307, USA.\n\n"));

  fprintf (stdout, "%s",_("This product makes use of the reference "\
		     "implementation of the TIGER message\n"));
  fprintf (stdout, "%s",_("digest algorithm. This code is copyright Eli Biham "\
		     "(biham@cs.technion.ac.il)\n"));
  fprintf (stdout, "%s",_("and Ross Anderson (rja14@cl.cam.ac.uk). It can be used "\
		     "freely without any\n"));
  fprintf (stdout, "%s",_("restrictions.\n"));
#if defined(USE_SRP_PROTOCOL) && !defined(SH_STANDALONE)
#if (!defined(HAVE_LIBGMP) || !defined(HAVE_GMP_H))
  fprintf (stdout, "%s",_("This product makes use of the 'bignum' library by "\
		     "Henrik Johansson\n"));
  fprintf (stdout, "%s",_("(Henrik.Johansson@Nexus.Comm.SE). If you are "\
		     "including this library in a\n"));
  fprintf (stdout, "%s",_("commercial product, be sure to distribute ALL of"\
		     " it with the product.\n"));
#endif
  fprintf (stdout, "%s",_("This product uses the 'Secure Remote Password' "\
		     "cryptographic\n"));
  fprintf (stdout, "%s",_("authentication system developed by Tom Wu "\
		     "(tjw@CS.Stanford.EDU).\n"));
#endif
  fprintf (stdout, "%s",_("\nPlease refer to the file COPYING in the source "\
		     "distribution for a"));
  fprintf (stdout, "%s",_("\nfull list of incorporated code and associated "\
		     "licenses.\n"));

  if (dummy)
    _exit (EXIT_SUCCESS);
  else
    _exit (EXIT_SUCCESS);
  /*@notreached@*/
  return 0; /* make compilers happy */
}

/*@noreturn@*/
static int sh_getopt_usage (const char * dummy)
{
  int  i;
  char fmt[64];

  char opts[64];

  for (i = 0; i < 64; ++i) /* splint does not grok char opts[64] = { '\0' }; */
    opts[i] = '\0';

  fprintf (stdout,
	   _("This is samhain (%s), "\
	     "(c) 1999-2006 Rainer Wichmann (http://la-samhna.de).\n"),
	   VERSION);
  fprintf (stdout, "%s",_("This software comes with ABSOLUTELY NO WARRANTY. "));
  fprintf (stdout, "%s",_("Use at own risk.\n"));

  fprintf (stdout, "%s",_("Usage:\n\n"));

  for (i = 0; op_table[i].longopt != NULL; ++i) {

    if (i == 63)
      break;

    if (op_table[i].shortopt != '-' && 
	strchr(opts, op_table[i].shortopt) != NULL)
      fprintf (stdout, "%s",_("Short option char collision !\n"));
    opts[i] = op_table[i].shortopt;


    if (op_table[i].hasArg == HAS_ARG_NO) {
      if (sl_strlen(op_table[i].longopt) < 10) 
	sl_strlcpy(fmt,_("%c%c%c        --%-s,\t\t\t %s\n"), sizeof(fmt));
      else if (sl_strlen(op_table[i].longopt) < 17)
	sl_strlcpy(fmt, _("%c%c%c        --%-s,\t\t %s\n"), sizeof(fmt));
      else 
	sl_strlcpy(fmt, _("%c%c%c        --%-s,\t %s\n"), sizeof(fmt));
      /* flawfinder: ignore */
      fprintf (stdout, fmt,
	       (op_table[i].shortopt == '-') ? ' ' : '-',
	       (op_table[i].shortopt == '-') ? ' ' : op_table[i].shortopt,
	       (op_table[i].shortopt == '-') ? ' ' : ',',
	       _(op_table[i].longopt),
	       _(op_table[i].usage));
    } else {
      if (sl_strlen(op_table[i].longopt) < 12) 
	sl_strlcpy(fmt, _("%c%c %s  --%-s=<arg>,\t\t %s\n"), sizeof(fmt));  
      else 
	sl_strlcpy(fmt, _("%c%c %s  --%-s=<arg>,\t %s\n"), sizeof(fmt));   
      /* flawfinder: ignore */
      fprintf (stdout, fmt,
	       (op_table[i].shortopt == '-') ? ' ' : '-',
	       (op_table[i].shortopt == '-') ? ' ' : op_table[i].shortopt,
	       (op_table[i].shortopt == '-') ? _("      ") : _("<arg>,"),
	       _(op_table[i].longopt),
	       _(op_table[i].usage));
    }
  }

  fprintf (stdout, "%s",
	   _("\nPlease report bugs to support@la-samhna.de.\n"));

  (void) fflush(stdout);

  if ( dummy != NULL) 
    {
      if (sl_strcmp( dummy, _("fail")) == 0 ) 
	  _exit (EXIT_FAILURE);
    }

  _exit (EXIT_SUCCESS);
  /*@notreached@*/
  return 0; /* make compilers happy */
}

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
static int sh_getopt_forever (const char * dummy)
{
  (void) dummy;
  SL_ENTER(_("sh_getopt_forever"));
  sh.flag.loop = S_TRUE;
  SL_RETURN(0, _("sh_getopt_forever"));
}

static int sh_getopt_outpath (const char * str)
{
  if (str)
    {
      if (sh.outpath)
	SH_FREE(sh.outpath);
      sh.outpath = sh_util_strdup(str);
      return 0;
    }
  return -1;
}
#endif  

int sh_getopt_get (int argc, char * argv[])
{
  int           count   = 0;
  size_t        len     = 0;
  int           foundit = 0;
  int           i;
  size_t        k;
  char        * theequal;

  SL_ENTER(_("sh_getopt_get"));

  /* -- Return if no args. --
   */
  if (argc < 2) 
    SL_RETURN(0, _("sh_getopt_get"));
 
  while (argc > 1  && argv[1][0] == '-') 
    {

      /* Initialize
       */
      foundit = 0;
      len     = sl_strlen (argv[1]);
    
      /* a '-' with no argument: error
       */
      if (len == 1)
	(void) sh_getopt_usage(_("fail"));

      /* a '--' with no argument: stop argument processing
       */
      if (len == 2 && argv[1][1] == '-') 
	SL_RETURN( count, _("sh_getopt_get"));

      /* a short option: process it
       */
      if (len >= 2 && argv[1][1] != '-') 
	{
	  for (k = 1; k < len; ++k)
	    {
	      for (i = 0; op_table[i].shortopt != '\0'; ++i) 
		{
		  
		  if ( op_table[i].shortopt == argv[1][k] ) 
		    {
		      foundit = 1;
		      if ( op_table[i].hasArg == HAS_ARG_YES ) 
			{
			  if (k != (len - 1))
			    {
			      /* not last option
			       */
			      fprintf (stderr, "%s",
				       _("Error: short option with argument is not last in option string\n"));
			      (void) sh_getopt_usage(_("fail"));
			    }
			  if (argc < 3) 
			    { 
			      /* argument required, but no avail 
			       */
			      fprintf (stderr, "%s",
				       _("Error: missing argument\n"));
			      (void) sh_getopt_usage(_("fail"));
			    } 
			  else 
			    {
			      /* call function with argument */
			      --argc; ++argv;
			      if (NULL != op_table[i].func &&
				  0 != (* op_table[i].func )(argv[1]))
				fprintf (stderr, 
					 _("Error processing option -%c\n"),
					 op_table[i].shortopt);
			      break;
			    }
			} 
		      else 
			{
			  if (NULL != op_table[i].func &&
			      0 != (* op_table[i].func )(NULL))
			    fprintf (stderr, 
				     _("Error processing option -%c\n"),
				     op_table[i].shortopt);
			  break;
			}
		    }
		}
	    }

	  /* 'break' should get here 
	   */
	  if (foundit == 1) 
	    {
	      --argc; ++argv;
	      continue;
	    } 
	  else 
	    {
	      /* unrecognized short option */
	      fprintf (stderr, "%s",_("Error: unrecognized short option\n"));
	      (void) sh_getopt_usage(_("fail"));
	    }
	}

      /* a long option: process it
       */
      if (len > 2) 
	{

	  for (i = 0; op_table[i].longopt != NULL; ++i) 
	    {

	      if (sl_strncmp(_(op_table[i].longopt), 
			     &argv[1][2], 
			     sl_strlen(op_table[i].longopt)) == 0 ) 
		{
		  foundit = 1; 
		  if ( op_table[i].hasArg == HAS_ARG_YES ) 
		    {
		      theequal = strchr(argv[1], '=');
		      if (theequal == NULL) 
			{ 
			  if (argc < 3) 
			    { 
			      /* argument required, but no avail 
			       */
			      fprintf (stderr, "%s",
				       _("Error: missing argument\n"));
			      (void) sh_getopt_usage(_("fail"));
			    } 
			  else 
			    {
			      /* call function with argument */
			      --argc; ++argv;
			      if (NULL != op_table[i].func &&
				  0 != (* op_table[i].func )(argv[1]))
				fprintf (stderr, 
					 _("Error processing option -%s\n"),
					 op_table[i].longopt);
			      break;
			    }
			} 
		      else 
			{
			  if (sl_strlen (theequal) > 1) 
			    {
			      ++theequal;
			      /* call function with argument */
			      if (NULL != op_table[i].func &&
				  0 != (* op_table[i].func )(theequal))
				fprintf (stderr, 
					 _("Error processing option -%s\n"),
					 op_table[i].longopt);
			      break;
			    } 
			  else 
			    {
			      fprintf (stderr, "%s",
				       _("Error: invalid argument\n"));
			      /* argument required, but no avail */
			      (void) sh_getopt_usage(_("fail"));
			    }
			}
		    } 
		  else 
		    {
		      if (NULL != op_table[i].func && 
			  0 != (* op_table[i].func )(NULL))
			fprintf (stderr, 
				 _("Error processing option -%s\n"),
				 op_table[i].longopt);
		      break;
		    }
		}
	    }

	  /* 'break' should get here */
	  if (foundit == 1) 
	    {
	      ++count;
	      --argc; 
	      ++argv;
	      continue;
	    } 
	  else 
	    {
	      /* unrecognized long option */
	      fprintf (stderr, "%s",_("Error: unrecognized long option\n"));
	      (void) sh_getopt_usage(_("fail"));
	    }
	}
    }

  SL_RETURN( count, _("sh_getopt_get"));
}
