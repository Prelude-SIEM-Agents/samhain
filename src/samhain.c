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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* samhainctl */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>


#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#ifdef HAVE_SETPRIORITY
#include <sys/resource.h>
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#endif

/* for FLT_EPSILON
 */
#include <float.h>

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_error.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_getopt.h"
#include "sh_readconf.h"
#include "sh_hash.h"
#include "sh_dbIO.h"
#include "sh_restrict.h"

#include "sh_nmail.h"

#include "sh_tiger.h"
#include "sh_gpg.h"
#include "sh_mem.h"
#include "sh_xfer.h"
#include "sh_tools.h"
#include "sh_hash.h"
#if defined(WITH_EXTERNAL)
#include "sh_extern.h"
#endif
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
#include "sh_modules.h"
#include "sh_ignore.h"
#include "sh_prelink.h"
#include "sh_sem.h"
#endif

#undef  FIL__
#define FIL__  _("samhain.c")


/**************************************************
 *
 * Needed to compile the key into the code.
 *
 **************************************************/

extern UINT32  ErrFlag[2];
#include "sh_MK.h"

/**************************************************
 *
 * Variables for signal handling.
 *
 **************************************************/

volatile  int      sig_raised;
volatile  int      sig_urgent;
volatile  int      sig_debug_switch;       /* SIGUSR1 */
volatile  int      sig_suspend_switch;     /* SIGUSR2 */
volatile  int      sh_global_suspend_flag;
volatile  int      sig_fresh_trail;        /* SIGIOT  */
volatile  int      sh_thread_pause_flag = S_FALSE;
volatile  int      sig_config_read_again;  /* SIGHUP  */
volatile  int      sig_terminate;          /* SIGQUIT */
volatile  int      sig_termfast;           /* SIGTERM */
volatile  int      sig_force_check;        /* SIGTTOU */
volatile  int      sig_force_silent;       /* SIGTSTP */
volatile  int      sh_global_check_silent;
volatile  int      sh_load_delta_flag;
long int           eintr__result;
char               sh_sig_msg[SH_MINIBUF];


#ifdef SH_STEALTH
/**************************************************
 *
 * The following set of functions is required for
 * the 'stealth' mode.
 *
 **************************************************/

#ifndef SH_MAX_GLOBS
#define SH_MAX_GLOBS 16
#endif

#ifndef GLOB_LEN
#define GLOB_LEN 511
#endif

#ifdef HAVE_PTHREAD
struct gt {
  size_t g_count;
  char * g_glob;
};

pthread_key_t g_key;

int sh_g_thread()
{
  struct gt * ptr = calloc(1,sizeof(struct gt));
  if (!ptr)
    return -1;
  ptr->g_count    = 0;
  ptr->g_glob     = calloc(1, SH_MAX_GLOBS * (GLOB_LEN+1));
  if (!(ptr->g_glob))
    {
      free(ptr);
      return -1;
    }
  return pthread_setspecific(g_key, ptr);
}

void sh_g_destroy(void * data)
{
  struct gt * ptr = (struct gt *) data;
  free(ptr->g_glob);
  free(ptr);
  return;
}

void sh_g_init(void)
{
#if !defined(USE_SYSTEM_MALLOC) && defined(USE_MALLOC_LOCK)
  extern int dnmalloc_pthread_init(void);
  dnmalloc_pthread_init();
#endif

  if (0 != pthread_key_create(&g_key, sh_g_destroy))
    {
      perror("1");
      exit(EXIT_FAILURE);
    }

  if (0 != sh_g_thread())
    {
      perror("2");
      exit(EXIT_FAILURE);
    }
  return;
}
#define SH_G_INIT sh_g_init()
#else
#define SH_G_INIT ((void)0)
#endif

char * globber(const char * str)
{
  size_t i;
  size_t j;

#ifndef HAVE_PTHREAD
  static   size_t  count = 0;
  static   char glob[SH_MAX_GLOBS * (GLOB_LEN+1)];
#else
  struct gt * ptr = pthread_getspecific(g_key);
  size_t count;
  char *  glob;

  if (ptr) {
    count = ptr->g_count;
    glob  = ptr->g_glob;
  } else {
    return NULL;
  }
#endif

  if (str != NULL)
    j = strlen(str);
  else
    return NULL;

  ASSERT((j <= GLOB_LEN), _("j <= GLOB_LEN"))

  if (j > GLOB_LEN) 
    j = GLOB_LEN;

  /* Overwrap the buffer.
   */
  if ( (count + j) >= (SH_MAX_GLOBS * (GLOB_LEN+1)))
    {
      count = 0;
    }

  for (i = 0; i < j; ++i)
    {
      if (str[i] != '\n' && str[i] != '\t' && str[i] != '\r' && str[i] != '"')
	glob[count + i] = str[i] ^ XOR_CODE;
      else
	glob[count + i] = str[i];
    }
  glob[count + j] = '\0';

  i     = count;
#ifdef HAVE_PTHREAD
  ptr->g_count = count + j + 1;
#else
  count = count + j + 1;
#endif
  return &glob[i];
}

void sh_do_encode (char * str, int len)
{
  register          int i;

  /* this is a symmetric operation
   */
  for (i = 0; i < len; ++i)
    {
      str[i] = str[i] ^ XOR_CODE;
    }
  return;
}

#else
/* not stealth */
#define SH_G_INIT ((void)0)
#endif

/**************************************************
 *
 * Global variables.
 *
 **************************************************/

sh_struct   sh;
/*@null@*/ sh_key_t  * skey = NULL;

extern unsigned char TcpFlag[8][PW_LEN+1];

/**************************************************
 *
 * Initializing.
 *
 **************************************************/

static int is_samhainctl_init = S_FALSE;

static
void sh_init (void)
{
  unsigned char * dez = NULL;
  int             i;
#if defined(SH_WITH_MAIL)
  char          * p;
  char            q[SH_PATHBUF];
#endif

  SL_ENTER(_("sh_init"));

#ifdef MKA_09
  ErrFlag[0] |= (1 << 8);
#endif
#ifdef MKA_10
  ErrFlag[0] |= (1 << 9);
#endif
#ifdef MKA_11
  ErrFlag[0] |= (1 << 10);
#endif
#ifdef MKA_12
  ErrFlag[0] |= (1 << 11);
#endif

  sh.delayload = 0;

#ifdef MKA_13
  ErrFlag[0] |= (1 << 12);
#endif
#ifdef MKA_14
  ErrFlag[0] |= (1 << 13);
#endif
#ifdef MKA_15
  ErrFlag[0] |= (1 << 14);
#endif
#ifdef MKA_16
  ErrFlag[0] |= (1 << 15);
#endif

  /* Signal handling.
   */
  sig_raised             = 0;
  sig_config_read_again  = 0;           /* SIGHUP  */
  sig_debug_switch       = 0;           /* SIGUSR1 */
  sig_suspend_switch     = 0;           /* SIGUSR2 */
  sh_global_suspend_flag = 0;           /* SIGUSR2 */
  sig_fresh_trail        = 0;           /* SIGIOT  */
  sig_terminate          = 0;           /* SIGQUIT */
  sig_termfast           = 0;           /* SIGTERM */
  sig_force_check        = 0;           /* SIGTTOU */
  sig_force_silent       = 0;           /* SIGTSTP */
  sh_global_check_silent = 0;
  sh_load_delta_flag     = 0;
  strcpy ( sh_sig_msg, _("None"));

#ifdef MKB_01
  ErrFlag[1] |= (1 << 0);
#endif
#ifdef MKB_02
  ErrFlag[1] |= (1 << 1);
#endif
#ifdef MKB_03
  ErrFlag[1] |= (1 << 2);
#endif
#ifdef MKB_04
  ErrFlag[1] |= (1 << 3);
#endif
#ifdef MKB_05
  ErrFlag[1] |= (1 << 4);
#endif
#ifdef MKB_06
  ErrFlag[1] |= (1 << 5);
#endif
#ifdef MKB_07
  ErrFlag[1] |= (1 << 6);
#endif
#ifdef MKB_08
  ErrFlag[1] |= (1 << 7);
#endif

#if defined(SH_WITH_SERVER) && !defined(SH_WITH_CLIENT)
  strncpy(sh.prg_name, _("Yule"), 8);
  sh.prg_name[4] = '\0';
#else
  strncpy(sh.prg_name, _("Samhain"), 8);
  sh.prg_name[7] = '\0';
#endif

  sh.pid = (UINT64) getpid();

  sh.outpath = NULL;

  /* The flags.
   */
  if (is_samhainctl_init == S_FALSE)
    sh.flag.checkSum        = SH_CHECK_NONE;
  sh.flag.update          = S_FALSE;
  sh.flag.opts            = S_FALSE;
  sh.flag.started         = S_FALSE;
  if (is_samhainctl_init == S_FALSE)
    sh.flag.isdaemon        = S_FALSE;
  sh.flag.isserver        = S_FALSE;
  sh.flag.islocked        = S_FALSE;
  sh.flag.smsg            = S_FALSE;
  sh.flag.log_start       = S_TRUE;
  sh.flag.reportonce      = S_TRUE;
  sh.flag.fulldetail      = S_FALSE;
  sh.flag.audit           = S_FALSE;
  sh.flag.nice            = 0;
  sh.flag.aud_mask        = 0xFFFFFFFFUL;
  sh.flag.client_severity = S_FALSE;
  sh.flag.client_class    = S_FALSE;
  sh.flag.hidefile        = S_FALSE;
  sh.flag.loop            = S_FALSE;
  sh.flag.inotify         = 0;

#ifdef MKB_09
  ErrFlag[1] |= (1 << 8);
#endif
#ifdef MKB_10
  ErrFlag[1] |= (1 << 9);
#endif
#ifdef MKB_11
  ErrFlag[1] |= (1 << 10);
#endif
#ifdef MKB_12
  ErrFlag[1] |= (1 << 11);
#endif
#ifdef MKB_13
  ErrFlag[1] |= (1 << 12);
#endif
#ifdef MKB_14
  ErrFlag[1] |= (1 << 13);
#endif
#ifdef MKB_15
  ErrFlag[1] |= (1 << 14);
#endif
#ifdef MKB_16
  ErrFlag[1] |= (1 << 15);
#endif

  /* The stats.
   */
  sh.statistics.bytes_speed   = 0;
  sh.statistics.bytes_hashed  = 0;
  sh.statistics.files_report  = 0;
  sh.statistics.files_error   = 0;
  sh.statistics.files_nodir   = 0;

  sh.statistics.mail_success = 0;
  sh.statistics.mail_failed  = 0;
  sh.statistics.time_start   = time(NULL);
  sh.statistics.time_check   = (time_t) 0;

#ifdef MKC_01
  ErrFlag[0] |= (1 << 16);
#endif
#ifdef MKC_02
  ErrFlag[0] |= (1 << 17);
#endif
#ifdef MKC_03
  ErrFlag[0] |= (1 << 18);
#endif
#ifdef MKC_04
  ErrFlag[0] |= (1 << 19);
#endif
#ifdef MKC_05
  ErrFlag[0] |= (1 << 20);
#endif
#ifdef MKC_06
  ErrFlag[0] |= (1 << 21);
#endif
#ifdef MKC_07
  ErrFlag[0] |= (1 << 22);
#endif
#ifdef MKC_08
  ErrFlag[0] |= (1 << 23);
#endif


  /* The local host.
   */
  (void) sl_strlcpy (sh.host.name,  _("localhost"),  SH_MINIBUF);
  sh.host.system[0]     = '\0'; /* flawfinder: ignore *//* ff bug */
  sh.host.release[0]    = '\0';
  sh.host.machine[0]    = '\0';

#ifdef MKC_09
  ErrFlag[0] |= (1 << 24);
#endif
#ifdef MKC_10
  ErrFlag[0] |= (1 << 25);
#endif
#ifdef MKC_11
  ErrFlag[0] |= (1 << 26);
#endif
#ifdef MKC_12
  ErrFlag[0] |= (1 << 27);
#endif
#ifdef MKC_13
  ErrFlag[0] |= (1 << 28);
#endif
#ifdef MKC_14
  ErrFlag[0] |= (1 << 29);
#endif
#ifdef MKC_15
  ErrFlag[0] |= (1 << 30);
#endif
#ifdef MKC_16
  ErrFlag[0] |= (1UL << 31);
#endif

  /* The paths.
   */
  (void) sl_strlcpy (sh.conf.path,  DEFAULT_CONFIGFILE,    SH_PATHBUF);
  sh.conf.hash[0] = '\0';
  (void) sl_strlcpy (sh.data.path,  DEFAULT_DATA_FILE,     SH_PATHBUF);
  sh.data.hash[0] = '\0';
  sh.exec.path[0] = '\0';
  sh.exec.hash[0] = '\0';

#ifdef MKD_01
  ErrFlag[1] |= (1 << 16);
#endif
#ifdef MKD_02
  ErrFlag[1] |= (1 << 17);
#endif
#ifdef MKD_03
  ErrFlag[1] |= (1 << 18);
#endif
#ifdef MKD_04
  ErrFlag[1] |= (1 << 19);
#endif
#ifdef MKD_05
  ErrFlag[1] |= (1 << 20);
#endif
#ifdef MKD_06
  ErrFlag[1] |= (1 << 21);
#endif
#ifdef MKD_07
  ErrFlag[1] |= (1 << 22);
#endif
#ifdef MKD_08
  ErrFlag[1] |= (1 << 23);
#endif

  /* The addresses.
   */
#if defined(SH_WITH_MAIL)
  if (0 != strcmp (DEFAULT_MAILADDRESS, _("NULL")))
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
      char * saveptr;
      (void) sl_strncpy(q, DEFAULT_MAILADDRESS, SH_PATHBUF);
      p = strtok_r (q, ", \t", &saveptr);
      if (p)
	{
	  (void) sh_nmail_add_compiled_recipient (p);
	  while (NULL != (p = strtok_r (NULL, ", \t", &saveptr)))
	    (void) sh_nmail_add_compiled_recipient (p);
	}
#else
      (void) sl_strncpy(q, DEFAULT_MAILADDRESS, SH_PATHBUF);
      p = strtok (q, ", \t");
      if (p)
	{
	  (void) sh_nmail_add_compiled_recipient (p);
	  while (NULL != (p = strtok (NULL, ", \t")))
	    (void) sh_nmail_add_compiled_recipient (p);
	}
#endif
    }
#endif

  if (0 == strcmp (ALT_TIMESERVER, _("NULL")))
    sh.srvtime.alt[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvtime.alt, ALT_TIMESERVER,        SH_PATHBUF);
  if (0 == strcmp (DEFAULT_TIMESERVER, _("NULL")))
    sh.srvtime.name[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvtime.name, DEFAULT_TIMESERVER,   SH_PATHBUF);


  if (0 == strcmp (ALT_LOGSERVER, _("NULL")))
    sh.srvexport.alt[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvexport.alt,  ALT_LOGSERVER,  SH_PATHBUF);
  if (0 == strcmp (DEFAULT_LOGSERVER, _("NULL")))
    sh.srvexport.name[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvexport.name,  DEFAULT_LOGSERVER, SH_PATHBUF);


  if (0 == strcmp (DEFAULT_ERRLOCK, _("NULL")))
    sh.srvlog.alt[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvlog.alt,  DEFAULT_ERRLOCK,       SH_PATHBUF);
  if (0 == strcmp (DEFAULT_ERRFILE, _("NULL")))
    sh.srvlog.name[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvlog.name,  DEFAULT_ERRFILE,      SH_PATHBUF);

  if (0 == strcmp (ALT_CONSOLE, _("NULL")))
    sh.srvcons.alt[0] = '\0';
  else
    (void) sl_strlcpy (sh.srvcons.alt,  ALT_CONSOLE,          SH_PATHBUF);
#ifndef DEFAULT_CONSOLE
  (void) sl_strlcpy (sh.srvcons.name, _("/dev/console"),    SH_PATHBUF);
#else
  if (0 == strcmp (DEFAULT_CONSOLE, _("NULL")))
    (void) sl_strlcpy (sh.srvcons.name, _("/dev/console"),    SH_PATHBUF);
  else
    (void) sl_strlcpy (sh.srvcons.name,  DEFAULT_CONSOLE,     SH_PATHBUF);
#endif

#ifdef MKD_09
  ErrFlag[1] |= (1 << 24);
#endif
#ifdef MKD_10
  ErrFlag[1] |= (1 << 25);
#endif
#ifdef MKD_11
  ErrFlag[1] |= (1 << 26);
#endif
#ifdef MKD_12
  ErrFlag[1] |= (1 << 27);
#endif
#ifdef MKD_13
  ErrFlag[1] |= (1 << 28);
#endif
#ifdef MKD_14
  ErrFlag[1] |= (1 << 29);
#endif
#ifdef MKD_15
  ErrFlag[1] |= (1 << 30);
#endif
#ifdef MKD_16
  ErrFlag[1] |= (1UL << 31);
#endif


  /* The timers.
   */
  sh.fileCheck.alarm_last     = 0;
  sh.fileCheck.alarm_interval = 600; /* ten minutes */

  sh.mailTime.alarm_last     = 0;
  sh.mailTime.alarm_interval = 86400;

  sh.mailNum.alarm_last      = 0;
  sh.mailNum.alarm_interval  = 10;

  sh.looptime     = 60;

#ifdef SCREW_IT_UP
  sh.sigtrap_max_duration = 500000; /* 500ms */
#endif

  /* The struct to hold privileged information.
   */
  skey = calloc(1,sizeof(sh_key_t));
  if (skey != NULL)
    {

      skey->mlock_failed = S_FALSE;
      skey->rngI         = BAD;
      /* properly initialized later 
       */
      skey->rng0[0] = 0x03; skey->rng0[1] = 0x09; skey->rng0[2] = 0x17;
      skey->rng1[0] = 0x03; skey->rng1[1] = 0x09; skey->rng1[2] = 0x17;
      skey->rng2[0] = 0x03; skey->rng2[1] = 0x09; skey->rng2[2] = 0x17;
      
      for (i = 0; i < KEY_BYT; ++i)
	skey->poolv[i] = '\0';
      
      skey->poolc        = 0;
      
      skey->ErrFlag[0]   = ErrFlag[0];
      ErrFlag[0]         = 0;
      skey->ErrFlag[1]   = ErrFlag[1];
      ErrFlag[1]         = 0;
      
      dez = &(TcpFlag[POS_TF-1][0]);
      for (i = 0; i < PW_LEN; ++i)
	{ 
	  skey->pw[i] = (char) (*dez); 
	  (*dez)      = '\0';
	  ++dez; 
	}
      
      skey->sh_sockpass[0]  = '\0';
      skey->sigkey_old[0]   = '\0';
      skey->sigkey_new[0]   = '\0';
      skey->mailkey_old[0]  = '\0';
      skey->mailkey_new[0]  = '\0';
      skey->crypt[0]        = '\0'; /* flawfinder: ignore *//* ff bug */
      skey->session[0]      = '\0';
      skey->vernam[0]       = '\0';
    }
  else
    {
      perror(_("sh_init"));
      _exit (EXIT_FAILURE);
    }

  sh_unix_memlock();
  SL_RET0(_("sh_init"));
}


#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#include <sys/mman.h>
#endif

#if defined(SH_USE_XML)
extern int    sh_log_file    (char * message, char * inet_peer);
#endif

/*******************************************************
 * 
 * Exit Handler
 *
 *******************************************************/
static void exit_handler(void)
{
  /* --- Clean up modules, if any. ---
   */
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  int modnum;
#endif
#if defined(SH_WITH_SERVER)
  extern int sh_socket_remove (void);
  extern int sh_html_zero();
#endif

#if defined(SH_WITH_SERVER)
  sh_socket_remove ();
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
    {
      if (modList[modnum].initval == SH_MOD_ACTIVE)
	(void) modList[modnum].mod_cleanup();
    }
#ifdef HAVE_PTHREAD
  sh_pthread_cancel_all();
#endif
#endif

  /* --- Push out all pending messages. ---
   */
#if defined(SH_WITH_MAIL)
  if (sh.mailNum.alarm_last > 0) 
    {
      (void) sh_nmail_flush ();
    }
#endif

  /* --- Write the server stat. ---
   */
#if defined(SH_WITH_SERVER)
  /* zero out the status file at exit, such that the status
   * of client becomes unknown in the beltane interface
   */
  sh_html_zero();
#endif

  /* --- Clean up memory to check for problems. ---
   */
#ifdef MEM_DEBUG
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  sh_files_deldirstack ();
  sh_files_delfilestack ();
  sh_files_delglobstack ();
  sh_hash_hashdelete();
  sh_files_hle_reg (NULL);
  /*
   * Only flush on exit if running as deamon.
   * Otherwise we couldn't run another instance
   * while the deamon is running (would leave the
   * deamon with flushed ruleset).
   */
  if (sh.flag.isdaemon == S_TRUE)
    {
      sh_audit_delete_all ();
    }
#endif
#if defined(SH_WITH_SERVER)
  sh_xfer_free_all ();
#endif
#if defined(SH_WITH_MAIL)
  sh_nmail_free();
#endif
  delete_cache();
  sh_userid_destroy ();
  sh_mem_stat();
#endif

#ifdef MEM_DEBUG
  sh_unix_count_mlock();
#endif

  /* --- Checksum of executable. ---
   */
  {
    volatile  int sig_store = sig_termfast;

    sig_termfast = 0;
    (void) sh_unix_self_check();
    sig_termfast = sig_store;
  }


  /* --- Exit Message. ---
   */
  if (sh.flag.exit == EXIT_FAILURE && !strcmp(sh_sig_msg, _("None")))
    sl_strlcpy(sh_sig_msg, _("exit_failure"), SH_MINIBUF);
  if (sh.flag.exit == EXIT_SUCCESS && !strcmp(sh_sig_msg, _("None")))
    sl_strlcpy(sh_sig_msg, _("exit_success"), SH_MINIBUF);
  sh_error_handle ((-1), FIL__, __LINE__, sh.flag.exit, MSG_EXIT_NORMAL, 
		   sh.prg_name, sh_sig_msg);
#ifdef SH_USE_XML
  (void) sh_log_file (NULL, NULL);
#endif


  /* --- Restrict error logging to stderr. ---
   */
  close_ipc ();
  sh_error_only_stderr (S_TRUE);

  /* --- Remove lock, delete critical information. ---
   */
  (void) sh_unix_rm_lock_file (sh.srvlog.name);
  if (sh.flag.isdaemon == S_TRUE)
    (void) sh_unix_rm_pid_file ();
  if (skey != NULL)
    memset (skey, (int) '\0', sizeof(sh_key_t));
  
  /* --- Exit. ---
   */
  SL_RET0(_("exit_handler"));
}

/***********************************************************
 *
 */
#ifndef SIGHUP
#define SIGHUP   1
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef SIGKILL
#define SIGKILL  9
#endif

#if defined(__linux__) || defined(sun) || defined(__sun) || defined(__sun__)
#include <dirent.h>
static pid_t * procdirSamhain (void)
{
  pid_t        * pidlist;
  struct dirent * d;
  DIR *        dp;
  long         ino;
  struct stat  buf;
  int          i;
  pid_t        pid, mypid = getpid();
  char       * tail;
  char         exef[128];

  if (0 != stat(SH_INSTALL_PATH, &buf))
    {
      return NULL;
    }

  ino = (long) buf.st_ino;
    
  if (NULL == (dp = opendir(_("/proc"))))
    {
      return NULL;
    }

  SH_MUTEX_LOCK(mutex_readdir);

  pidlist =  calloc(1, sizeof(pid_t) * 65535);
  if (!pidlist)
    goto unlock_and_out;

  for (i = 0; i < 65535; ++i) pidlist[i] = 0;

  i = 0;
  while (NULL != (d = readdir(dp)) && i < 65535)
    {
      if (0 != strcmp(d->d_name, ".") && 0 != strcmp(d->d_name, ".."))
	{
	  errno = 0;
	  pid = (pid_t) strtol (d->d_name, &tail, 0);
	  if (*tail != '\0' || errno != 0)
	    continue;
	  if (pid == mypid)
	    continue;
#if defined(__linux__) 
          sprintf(exef, _("/proc/%d/exe"), (int) pid); /* known to fit  */
#else
          sprintf(exef, _("/proc/%d/object/a.out"),    /* known to fit  */
		  (int) pid);
#endif
	  if (0 == stat(exef, &buf) && ino == (long) buf.st_ino)
	    { pidlist[i] = (pid_t) pid; ++i; }
	}
    }

 unlock_and_out:
  ;
  SH_MUTEX_UNLOCK(mutex_readdir);

  closedir(dp);
  return pidlist;
}
#else
static pid_t * procdirSamhain (void)
{
  return NULL;
}
#endif

static int killprocSamhain (pid_t pid)
{
  int i;

  /* fprintf(stderr, "Killing %d\n", pid); */
  if (pid > 0 && 0 == kill (pid, SIGTERM))
    {
      for (i = 0; i < 16; ++i)
	{
	  (void) retry_msleep(1, 0);
	  if (0 != kill (pid, 0) && errno == ESRCH)
	    return (0);
	}
      
      (void) kill (pid, SIGKILL);
      return (0);
    }
  if (pid > 0)
    {
      if (errno == ESRCH)
	return 7;
      if (errno == EPERM)
	return 4;
      return 1;
    }
  else
    return (7);
}

static pid_t pidofSamhain (int flag)
{
  FILE      * fp;
  char        line[256];
  char      * tail;
  char      * p;
  pid_t       pid;
  long        inpid;
  struct stat buf;
 
  fp = fopen (DEFAULT_ERRLOCK, "r");

  if (!fp)
    { if (errno != ENOENT) perror(_("fopen")); return 0; }
  if (NULL == fgets(line, sizeof(line), fp))
    { perror(_("fgets")); (void) sl_fclose(FIL__, __LINE__, fp); return 0; }
  (void) sl_fclose(FIL__, __LINE__, fp); 
  p = line; 
  while (*p == ' '  || *p == '\f' || *p == '\n' || 
	 *p == '\r' || *p == '\t' || *p == '\v')
    ++p;
  errno = 0;
  inpid = strtol (p, &tail, 0);
  if (p == tail || errno != 0)
    { perror(_("strtol")); return 0; }

  pid = (pid_t) inpid;
  if (inpid != (long) pid)
    { perror(_("strtol")); return 0; }

  /* remove stale pid file
   */
  if (flag == 1 && pid > 0 && 0 != kill(pid, 0) && errno == ESRCH)
    {
      if /*@-unrecog@*/ (0 == lstat (DEFAULT_ERRLOCK, &buf))/*@+unrecog@*/
	{
	  if /*@-usedef@*/(S_ISREG(buf.st_mode))/*@+usedef@*/ 
	    {
	      (void) unlink(DEFAULT_ERRLOCK);
	    }
	}
      else 
	{
	  perror(_("lstat")); return 0;
	}
      pid = 0;
    }
  return pid;
}

/* 1: start 2:stop 3:reload 4:status
 */
/*@-exitarg@*/
static int samhainctl(int ctl, int * argc, char * argv[])
{
  char * fullpath;
  pid_t  pid;
  int    status;
  int    res;
  pid_t  respid;
  int    times;
  char * argp[32];
  pid_t       * pidlist;
  int         i;
#ifdef WCONTINUED
      int wflags = WNOHANG|WUNTRACED|WCONTINUED;
#else
      int wflags = WNOHANG|WUNTRACED;
#endif

  fullpath = strdup (SH_INSTALL_PATH);
  if (fullpath == NULL)
    { perror(_("strdup")); exit (1); }

  argp[0]  = strdup (SH_INSTALL_PATH);
  if (argp[0] == NULL)
    { perror(_("strdup")); exit (1); }

  for (times = 1; times < 32; ++times)  argp[times] = NULL;

  res = (*argc > 32) ? 32 : *argc;

  for (times = 2; times < res; ++times)  
    {
      argp[times-1] = strdup (argv[times]);
      if (argp[times-1] == NULL)
	{ perror(_("strdup")); exit (1); }
    }

  if (ctl == 1)
    {
      pid = pidofSamhain(1);

      if (pid != 0 && 0 == kill (pid, 0)) /* already started */
	exit (0);

      pid = fork();
      switch (pid) {
      case ((pid_t) -1):
	perror(_("fork"));
	exit (1);
      case  0:
	if (0 != sl_close_fd (FIL__, __LINE__, 0))
	  {
	    _exit(4);
	  }
	(void) execv(fullpath, argp); /* flawfinder: ignore *//* wtf? */
	if (errno == EPERM)
	  _exit(4);
	else if (errno == ENOENT)
	  _exit(5);
	_exit (1);
      default:
	times = 0;
	while (times < 300) {
	  respid = waitpid(pid, &status, wflags);
	  if ((pid_t)-1 == respid)
	    {
	      perror(_("waitpid"));
	      exit (1);
	    }
	  else if (pid == respid)
	    {
#ifndef USE_UNO
	      if (0 != WIFEXITED(status))
		{
		  res = WEXITSTATUS(status);
		  exit (res == 0 ? 0 : res );
		}
	      else
		exit (1);
#else
	      exit (1);
#endif
	    }
	  ++times;
	  (void) retry_msleep(1, 0);
	}
	exit (0); /* assume that it runs ok */
      }
    }

  pid = pidofSamhain(0);

  if (ctl == 2)  /* stop */
    {
      pidlist = procdirSamhain ();
      if (pid == 0 && NULL == pidlist) /* pid file not found */ 
	{
	  free(fullpath);
	  return (0);
	}
	  
      status = 0;
      if (pid != 0)
	 status = killprocSamhain(pid);
      if (pidlist != NULL)
	{
	  i = 0; 
	  while (i < 65535 && pidlist[i] != 0)
	    { 
	      if (pidlist[i] != pid) 
		status = killprocSamhain(pidlist[i]);
	      ++i;
	    }
	}
      free(fullpath);
      if (status == 7)
	return 0;
      else
	return status;
    }
	
  if (ctl == 3)  /* reload */
    {
      if (pid == 0)
        exit (7);
      if (0 == kill (pid, SIGHUP))
        exit (0);
      else
	{
	  if (errno == EPERM)
	    exit (4);
	  if (errno == ESRCH)
	    exit (7);
	  exit (1);
	}
    }

  if (ctl == 4)  /* status */
    {
      if (pid == 0)
	exit (3);
      if (0 == kill (pid, 0))
	exit (0);
      else
	{
	  if (errno == EPERM)
	    exit (4);
	  if (errno == ESRCH)
	    exit (1);
	}
    }
  free(fullpath); /* silence smatch false positive */
  exit (1); /* no exit handler installed yet */
  /*@notreached@*/
  return (0);
}
/*@+exitarg@*/

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
#include "sh_schedule.h"
static sh_schedule_t * FileSchedOne = NULL;
static sh_schedule_t * FileSchedTwo = NULL;

/* free a linked list of schedules
 */
static sh_schedule_t *  free_sched (sh_schedule_t * isched)
{
  sh_schedule_t * current = isched;
  sh_schedule_t * next    = NULL;

  while (current != NULL)
    {
      next = current->next;
      SH_FREE(current);
      current = next;
    }
  return NULL;
}

/* Add a new schedule to the linked list of schedules
 */
static sh_schedule_t * sh_set_schedule_int (const char * str, 
					    sh_schedule_t * FileSchedIn, 
					    /*@out@*/ int * status)
{
  sh_schedule_t * FileSched;

  SL_ENTER(_("sh_set_schedule_int"));

  if (0 == sl_strncmp(str, _("NULL"), 4))
    {
      (void) free_sched(FileSchedIn);
      FileSchedIn = NULL;
      *status = 0;
      SL_RETURN(NULL, _("sh_set_schedule_int"));
    }

  FileSched = SH_ALLOC(sizeof(sh_schedule_t));
  *status = create_sched(str, FileSched);
  if (*status != 0)
    {
      SH_FREE(FileSched);
      FileSched = NULL;
      SL_RETURN(FileSchedIn , _("sh_set_schedule_int"));
    }
  else {
    FileSched->next = FileSchedIn;
  }
  SL_RETURN(FileSched , _("sh_set_schedule_int"));
}

/* Add a new schedule to the linked list FileSchedOne
 */
int sh_set_schedule_one (const char * str)
{
  int status;
  FileSchedOne = sh_set_schedule_int (str, FileSchedOne, &status);
  return status;
}

/* Add a new schedule to the linked list FileSchedTwo
 */
int sh_set_schedule_two (const char * str)
{
  int status;
  FileSchedTwo = sh_set_schedule_int (str, FileSchedTwo, &status);
  return status;
}

static int sh_flag_silent = S_FALSE;

int sh_set_silent_full (const char * str)
{
  int status = sh_util_flagval(str, &sh_flag_silent);
  return status;
}


void do_reconf()
{
  int status, modnum;

  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_RECONF);
  
  sh_thread_pause_flag = S_TRUE;

  for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
    {
      if (0 != (SH_MODFL_NEEDPAUSED & modList[modnum].flags) &&
	  modList[modnum].initval == SH_MOD_THREAD)
	{
	  int count = 50;
	  while (count && 0 == (SH_MODFL_ISPAUSED & modList[modnum].flags))
	    retry_msleep(0, 100), --count;
	}
    }
  
#if defined(WITH_EXTERNAL)
  /* delete list of external tasks
   */
  (void) sh_ext_cleanup();
#endif
#if defined(SH_WITH_MAIL)
  sh_nmail_free();
#endif
  
  /* delete the file list, make all database
   * entries visible (allignore = FALSE)
   */
  (void) sh_files_deldirstack ();
  (void) sh_files_delfilestack ();
  (void) sh_files_delglobstack ();
  (void) sh_ignore_clean ();
  (void) hash_full_tree ();
  sh_audit_delete_all ();
  
  
#if defined(SH_WITH_CLIENT)
  reset_count_dev_server();
#endif
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  sh_restrict_purge ();
  
  
  FileSchedOne = free_sched(FileSchedOne);
  FileSchedTwo = free_sched(FileSchedTwo);
  
  for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
    {
      /* sh_thread_pause_flag is true, and we block in lock
       * until check has returned, so we are sure check will
       * not run until sh_thread_pause_flag is set to false
       */
      /* if (modList[modnum].initval >= SH_MOD_ACTIVE) */
      (void) modList[modnum].mod_reconf();
    }
#endif
  
  reset_count_dev_console();
  reset_count_dev_time();
  
  (void) sh_unix_maskreset();
  
#ifdef RELOAD_DATABASE
  sh_hash_hashdelete();

  if (0 != sl_strcmp(file_path('D', 'R'), _("REQ_FROM_SERVER")))
    {
      char hashbuf[KEYBUF_SIZE];
      (void) sl_strlcpy(sh.data.hash,
			sh_tiger_hash (file_path('D', 'R'), 
				       TIGER_FILE, TIGER_NOLIM, 
				       hashbuf, sizeof(hashbuf)), 
			KEY_LEN+1);
    }
#endif
  (void) sl_trust_purge_user();
  (void) sh_files_hle_reg (NULL);
  (void) sh_prelink_run (NULL, NULL, 0, 0);
  
  /* --------------------------
   * --- READ CONFIGURATION ---
   * --------------------------
   */
  (void) sh_readconf_read ();
  sig_config_read_again = 0;
  (void) sh_files_setrec();
  (void) sh_files_test_setup();
  sh_audit_commit ();
  
  if (0 != sh.flag.nice)
    {
#ifdef HAVE_SETPRIORITY
      setpriority(PRIO_PROCESS, 0, sh.flag.nice);
#else
      nice(sh.flag.nice);
#endif
    }
  
  if (sh.flag.checkSum == SH_CHECK_INIT)
    {
      sh.flag.isdaemon = S_FALSE;
      sh.flag.loop     = S_FALSE;
    }
  
  
  /* --- Initialize modules. ---
   */
  TPT((0, FIL__, __LINE__, _("msg=<Initialize modules.>\n")));
  for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
    {
      status = modList[modnum].mod_init(&(modList[modnum]));
      
      if (status < 0)
	{
	  if (status == (-1)) {
	    sh_error_handle (SH_ERR_NOTICE, FIL__, __LINE__, 
			     status, MSG_MOD_FAIL,
			     _(modList[modnum].name),
			     status+SH_MOD_OFFSET);
	  } else {
	    sh_error_handle ((-1), FIL__, __LINE__, 
			     status, MSG_MOD_FAIL,
			     _(modList[modnum].name),
			     status+SH_MOD_OFFSET);
	  }
	  modList[modnum].initval = SH_MOD_FAILED;
	}
      else
	{
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_MOD_OK,
			   _(modList[modnum].name));
	  modList[modnum].initval = status;
	}
    }
  
  /* module is properly set up now
   */
  sh_thread_pause_flag = S_FALSE;

  return;
}

static void check_signals (volatile int *flag_check_1, 
			   volatile int * flag_check_2)
{
  if (sig_raised > 0) 
    {
      
      TPT((0, FIL__, __LINE__, _("msg=<Process a signal.>\n")))
	
	if (sig_termfast == 1)  /* SIGTERM */
	  {
	    TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	    --sig_raised; --sig_urgent;
	    aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
	  }
      
      if (sig_force_check == 1) /* SIGTTOU / SIGTSTP */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Check run triggered.>\n")));
	  *flag_check_1 = 1; *flag_check_2 = 1;
	  sig_force_check = 0; --sig_raised;
	  if (sig_force_silent)
	    {
	      sig_force_silent       = 0;
	      sh_global_check_silent = (sh_flag_silent == S_FALSE) ? SH_SILENT_STD : SH_SILENT_FULL;
	    }
	  sh_sem_trylock();
	}
      
      if (sig_config_read_again == 1 && /* SIGHUP */
	  sh_global_suspend_flag == 0)
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Re-read configuration.>\n")));
	  do_reconf();
	  --sig_raised;
	}
      
      if (sig_fresh_trail == 1) /* SIGIOT */
	{
	  if (sh_global_suspend_flag == 0)
	    {
	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      
	      /* Logfile access 
	       */
#ifdef SH_USE_XML
	      (void) sh_log_file (NULL, NULL);
#endif
	      TPT((0, FIL__, __LINE__, _("msg=<Logfile stop/restart.>\n")));
	      sh_error_only_stderr (S_TRUE);
	      (void) sh_unix_rm_lock_file(sh.srvlog.name);
	      (void) retry_msleep(3, 0);
	      sh.flag.log_start = S_TRUE;
	      sh_error_only_stderr (S_FALSE);
	      sh_thread_pause_flag = S_FALSE;
	      sig_fresh_trail       = 0;
	      --sig_raised;
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	    }
	}
      
      if (sig_terminate == 1)  /* SIGQUIT */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	  strncpy (sh_sig_msg, _("Quit"), 20);
	  --sig_raised;
	  aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
	}
	  
      if (sig_debug_switch == 1)  /* SIGUSR1 */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Debug switch.>\n")));
	  sh_error_dbg_switch();
	  sig_debug_switch = 0;
	  --sig_raised;
	}
	  
      if (sig_suspend_switch > 0)  /* SIGUSR2 */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Suspend switch.>\n")));
	  if (sh_global_suspend_flag != 1) {
	    SH_MUTEX_LOCK_UNSAFE(mutex_thread_nolog);
	    sh_global_suspend_flag = 1;
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_SUSPEND, 
			    sh.prg_name);
	  } else {
	    sh_global_suspend_flag = 0;
	    SH_MUTEX_UNLOCK_UNSAFE(mutex_thread_nolog);
	  }
	  --sig_suspend_switch;
	  --sig_raised; --sig_urgent;
	}

      if (sh_load_delta_flag > 0 &&
	  sh_global_suspend_flag == 0)  /* DELTA Command */
	{
	  if (0 == sh_dbIO_load_delta())
	    {
	      --sh_load_delta_flag; --sig_raised;
	    } 
	}

      sig_raised = (sig_raised < 0) ? 0 : sig_raised;
      sig_urgent = (sig_urgent < 0) ? 0 : sig_urgent;
      TPT((0, FIL__, __LINE__, _("msg=<End signal processing.>\n")));
    }
  return;
}

void check_for_delta_db()
{
  /* Need to contact the server.
   */
  if (sh_global_check_silent < SH_SILENT_FULL)
    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_CHECK_2);

  if (sig_raised > 0 && sh_load_delta_flag > 0)  /* DELTA Command */
    {
      /* There was a DELTA Command
       */
      if (0 == sh_dbIO_load_delta())
	{
	  --sh_load_delta_flag; --sig_raised;
	} 
    }
  return;
}

#endif

/*******************************************************
 * 
 * Main program
 *
 *******************************************************/
#if !defined(SH_CUTEST)
int main(int argc, char * argv[])
#else
int undef_main(int argc, char * argv[])
#endif
{
#if defined(INET_SYSLOG)
  extern int    sh_xfer_create_syslog_socket (int flag);
#endif
#if defined(SH_WITH_SERVER)
  extern int    sh_create_tcp_socket(void);
#endif

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  int           modnum;
  time_t        runtim;
  float         st_1, st_2;
  int           status;
  volatile long          cct = 0; /* main loop iterations */

  volatile int           flag_check_1 = 0;
  volatile int           flag_check_2 = 0;

  int           check_done   = 0;
#endif

  volatile time_t        told;
  volatile time_t        tcurrent;
  size_t        tzlen;
  char *        tzptr;
  int           res;

#if defined (SH_STEALTH_NOCL)
  char    command_line[256];
  int     my_argc = 0;
  char  * my_argv[32];
#endif

#if !defined(USE_SYSTEM_MALLOC)
  typedef void assert_handler_tp(const char * error, const char *file, int line);
  extern assert_handler_tp *dnmalloc_set_handler(assert_handler_tp *new);
  (void) dnmalloc_set_handler(safe_fatal);
#endif

  SH_G_INIT; /* Must precede any use of _() */

  SL_ENTER(_("main"));

  /* --- Close all but first three file descriptors. ---
   */
  sh_unix_closeall(3, -1, S_FALSE); /* at program start */


  if (argc >= 2 && 0 != getuid() &&
      (0 == strcmp(argv[1], _("start")) ||
       0 == strcmp(argv[1], _("stop")) ||
       0 == strcmp(argv[1], _("reload")) ||
       0 == strcmp(argv[1], _("force-reload")) ||
       0 == strcmp(argv[1], _("status")) ||
       0 == strcmp(argv[1], _("restart"))))
    {
      return 4;
    }
       
  if (argc >= 2 && 0 == getuid())
    {
      /* return codes:
       * 0    Success
       * 1    Can not send signal / start program
       * 2    Pid file does not exist
       */
      if      (0 == strcmp(argv[1], _("start")))
	{
	  (void) samhainctl (1, &argc, argv); /* does not return */
	}
      else if (0 == strcmp(argv[1], _("stop")))
        return (samhainctl (2, &argc, argv));
      else if (0 == strcmp(argv[1], _("reload")))
	(void) samhainctl (3, &argc, argv);   /* does not return */
      else if (0 == strcmp(argv[1], _("force-reload")))
	(void) samhainctl (3, &argc, argv);   /* does not return */
      else if (0 == strcmp(argv[1], _("status")))
	(void) samhainctl (4, &argc, argv);   /* does not return */
      else if (0 == strcmp(argv[1], _("restart")))
	{
	  res = samhainctl (2, &argc, argv);
	  if (res == 0 || res == 7)
	    {
	      (void) samhainctl (1, &argc, argv); /* does not return */
	    }
	  else
	    return (res);
	}
    }
  
  /* if fd 0 is closed, presume that we want to be daemon and
   * run in check mode
   */
  if ((-1) == retry_fcntl(FIL__, __LINE__, 0, F_GETFL, 0) && 
	   errno == EBADF)
    {
      sh.flag.opts = S_TRUE;
      (void) sh_unix_setdeamon(NULL);
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
      sh.flag.checkSum = SH_CHECK_CHECK;
      /* (void) sh_util_setchecksum(_("check")); */
#endif
      is_samhainctl_init = S_TRUE;
      sh.flag.opts = S_FALSE;
    }


  /* --- Install the exit handler. ---
   */
  (void) atexit(exit_handler);

  /* --- Zero the mailer key, and fill it. ---
   */
  memset (ErrFlag, 0, 2*sizeof(UINT32));

#ifdef MKA_01
  ErrFlag[0] |= (1 << 0);
#endif
#ifdef MKA_02
  ErrFlag[0] |= (1 << 1);
#endif
#ifdef MKA_03
  ErrFlag[0] |= (1 << 2);
#endif
#ifdef MKA_04
  ErrFlag[0] |= (1 << 3);
#endif
#ifdef MKA_05
  ErrFlag[0] |= (1 << 4);
#endif
#ifdef MKA_06
  ErrFlag[0] |= (1 << 5);
#endif
#ifdef MKA_07
  ErrFlag[0] |= (1 << 6);
#endif
#ifdef MKA_08
  ErrFlag[0] |= (1 << 7);
#endif

#if defined(SCREW_IT_UP)
  BREAKEXIT(sh_sigtrap_prepare);
  (void) sh_sigtrap_prepare();
#endif

  /* Save the timezone.
   */
  if (NULL != (tzptr = getenv("TZ"))) /* flawfinder: ignore */
    {
      tzlen       = strlen(tzptr);
      if (tzlen < 1024)
	{
	  sh.timezone = calloc(1, tzlen + 1);
	  if (sh.timezone != NULL)
	    (void) sl_strlcpy (sh.timezone, tzptr, tzlen + 1);
	}
      else
	sh.timezone = NULL;
    }
  else
     sh.timezone = NULL;


  /* --------  INIT  --------    
   */
  sh_unix_ign_sigpipe();

  /* Restrict error logging to stderr.
   */
  sh_error_only_stderr (S_TRUE);

  /* Check that first three descriptors are open.
   */
  if ( retry_fcntl(FIL__, __LINE__, 0, F_GETFL, 0) == (-1))
    (void) aud_open(FIL__, __LINE__, SL_NOPRIV, _("/dev/null"), O_RDWR, 0);
  if ( retry_fcntl(FIL__, __LINE__, 1, F_GETFL, 0) == (-1))
    (void) aud_open(FIL__, __LINE__, SL_NOPRIV, _("/dev/null"), O_RDWR, 1);
  if ( retry_fcntl(FIL__, __LINE__, 2, F_GETFL, 0) == (-1))
    (void) aud_open(FIL__, __LINE__, SL_NOPRIV, _("/dev/null"), O_RDWR, 2);

  /* --- Set default values. ---
   */
  BREAKEXIT(sh_init);
  sh_init ();    /* we are still privileged here, so we can mlock skey */
#if (defined (SH_WITH_SERVER) && !defined (SH_WITH_CLIENT))
  sh.flag.isserver = S_TRUE;
#endif

  /* --- First check for an attached debugger (after setting
         sh.sigtrap_max_duration which has to be done before). ---
   */
  BREAKEXIT(sh_derr);
  (void) sh_derr();

  /* --- Get local hostname. ---
   */
  BREAKEXIT(sh_unix_localhost);
  sh_unix_localhost();

  /* --- Read the command line. ---
   */
  sh.flag.opts = S_TRUE;

#if !defined(SH_STEALTH_NOCL)
  sh_argc_store = argc;
  sh_argv_store = argv;
  (void) sh_getopt_get (argc, argv);
#else
  if (argc > 1 && argv[1] != NULL && 
      strlen(argv[1]) > 0 && strlen(NOCL_CODE) > 0)
    {
      if ( 0 == strcmp(argv[1], NOCL_CODE) )
	{
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
	  char * saveptr;
#endif
	  my_argv[0] = argv[0]; ++my_argc;  
	  command_line[0] = '\0';
	  if (NULL != fgets (command_line, sizeof(command_line), stdin))
	    command_line[sizeof(command_line)-1] = '\0';

	  do {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_STRTOK_R)
	    my_argv[my_argc] = 
	      strtok_r( (my_argc == 1) ? command_line : NULL, " \n", &saveptr);
#else
	    my_argv[my_argc] = 
	      strtok( (my_argc == 1) ? command_line : NULL, " \n");
#endif 
	    if (my_argv[my_argc] != NULL) {
	      ++my_argc;
	    } else {
	      break;
	    }
	  } while (my_argc < 32);

	  sh_argc_store = my_argc;
	  sh_argv_store = my_argv;

	  (void) sh_getopt_get (my_argc, my_argv);
	}
      else
	{
	  /* discard command line */
	  /* _exit(EXIT_FAILURE)  */  ; 
	}
    }
#endif
  sh.flag.opts = S_FALSE;
  

  /* --- Get user info. ---
   */
  TPT((0, FIL__, __LINE__, _("msg=<Get user name.>\n")))
  if (0 != sh_unix_getUser ())
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1,
		       sh.prg_name);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }


  /* *****************************
   *
   *  Read the configuration file.
   *
   * *****************************/

  TPT((0, FIL__, __LINE__, _("msg=<Read the configuration file.>\n")))
  BREAKEXIT(sh_readconf_read);
  (void) sh_readconf_read ();

  sh_calls_enable_sub();

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  if (sh.flag.checkSum == SH_CHECK_NONE)
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		       _("No action specified: init, update, or check"), 
		       _("main"));
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1,
		       sh.prg_name);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }
#endif

  /* do not append to database if run SUID
   */
  if ((sh.flag.checkSum == SH_CHECK_INIT) && (0 != sl_is_suid())) 
    {
      (void) dlog(1, FIL__, __LINE__, 
	   _("Cannot initialize database when running with SUID credentials.\nYou need to run this with the user ID %d.\nYour current user ID is %d."), 
	   (int) geteuid(), (int) sh.real.uid);
      sh_error_handle ((-1), FIL__, __LINE__, EACCES, MSG_ACCESS,
		       (long) sh.real.uid, sh.data.path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  /* avoid daemon mode for initialization 
   */
  if (sh.flag.checkSum == SH_CHECK_INIT)
    {
      sh.flag.isdaemon = S_FALSE;
      sh.flag.loop     = S_FALSE;
    }

  /* --- load database; checksum of database
   */
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  if (0 == sh.delayload)
    sh_hash_init_and_checksum();
#endif

  /* --- initialize signal handling etc.; fork daemon
   */
  if (sh_unix_init(sh.flag.isdaemon) == -1) 
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1,
		       sh.prg_name);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  if (sh.delayload)
    {
      sleep(sh.delayload);
      sh_hash_init_and_checksum();
    }
#endif

  /* --- drop privileges eventually ---
   */
#if defined(SH_WITH_SERVER)
  sh_create_tcp_socket ();
#if defined(INET_SYSLOG)
  sh_xfer_create_syslog_socket (S_TRUE);
#endif
  SL_REQUIRE(sl_policy_get_real(DEFAULT_IDENT) == SL_ENONE, 
	     _("sl_policy_get_real(DEFAULT_IDENT) == SL_ENONE"));
#else
  SL_REQUIRE(sl_policy_get_user(DEFAULT_IDENT) == SL_ENONE, 
	     _("sl_policy_get_user(DEFAULT_IDENT) == SL_ENONE"));
#endif

  /* --- Get user info (again). ---
   */
  TPT((0, FIL__, __LINE__, _("msg=<Get user name.>\n")))
  if (0 != sh_unix_getUser ())
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1,
		       sh.prg_name);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  /* --- now check whether we really wanted it; if not, close ---
   */
#if defined(INET_SYSLOG) && defined(SH_WITH_SERVER)
  sh_xfer_create_syslog_socket (S_FALSE);
#endif


  /* --- Enable full error logging --- 
   */
  sh_error_only_stderr (S_FALSE);

  sh.flag.started = S_TRUE;

  /****************************************************
   *
   *   SERVER 
   *
   ****************************************************/

#if defined(SH_WITH_SERVER) && !defined(SH_WITH_CLIENT)

#if (defined(WITH_GPG) || defined(WITH_PGP))
  /* log startup */
  sh_gpg_log_startup ();
#else
  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_1H,
		   sh.prg_name, (long) sh.real.uid, 
		   (sh.flag.hidefile == S_TRUE) ? 
		   _("(hidden)") : file_path('C','R'), 
		   sh.conf.hash);
#endif

#else

  /****************************************************
   *
   *   CLIENT/STANDALONE
   *
   ****************************************************/

  BREAKEXIT(sh_error_handle);

  if (sh.flag.checkSum == SH_CHECK_CHECK) 
    {
#if (defined(WITH_GPG) || defined(WITH_PGP))
      /* log startup */
      sh_gpg_log_startup ();
#else
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_2H,
		       sh.prg_name, (long) sh.real.uid,
		       (sh.flag.hidefile == S_TRUE) ? _("(hidden)") : file_path('C', 'R'), sh.conf.hash,
		       (sh.flag.hidefile == S_TRUE) ? _("(hidden)") : file_path('D', 'R'), sh.data.hash);
#endif
    }
  else
    {
#if (defined(WITH_GPG) || defined(WITH_PGP))
      /* log startup */
      sh_gpg_log_startup ();
#else
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_START_1H,
		       sh.prg_name, (long) sh.real.uid,
		       (sh.flag.hidefile == S_TRUE) ? _("(hidden)") : file_path('C', 'R'), sh.conf.hash);
#endif
    }
#endif

 
  if ((skey == NULL) || (skey->mlock_failed == S_TRUE))
    sh_error_handle ((-1), FIL__, __LINE__, EPERM, MSG_MLOCK);

  /* timer
   */
  tcurrent                   = time (NULL);
  told                       = tcurrent;
  sh.mailTime.alarm_last     = told;


  /****************************************************
   *
   *   SERVER 
   *
   ****************************************************/

#if defined(SH_WITH_SERVER)
  TPT((0, FIL__, __LINE__, _("msg=<Start server.>\n")))

#if defined (SH_WITH_CLIENT)
  if (sh.flag.isserver == S_TRUE)
    { 
      sh_xfer_start_server();
      TPT((0, FIL__, __LINE__, _("msg=<End server.>\n")))
      aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
    }
#else
  sh_xfer_start_server();
  TPT((0, FIL__, __LINE__, _("msg=<End server.>\n")))
  aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
#endif

#endif

  /****************************************************
   *
   *   CLIENT/STANDALONE
   *
   ****************************************************/
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)


  /* --- Initialize modules. ---
   */
  TPT((0, FIL__, __LINE__, _("msg=<Initialize modules.>\n")))
  for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
    {
      status = modList[modnum].mod_init(&(modList[modnum]));
      if ( status < 0 )
	{
	  if (status == (-1)) {
	    sh_error_handle (SH_ERR_NOTICE, FIL__, __LINE__, status, 
			     MSG_MOD_FAIL,
			     _(modList[modnum].name),
			     status+SH_MOD_OFFSET);
	  } else {
	    sh_error_handle ((-1), FIL__, __LINE__, status, MSG_MOD_FAIL,
			     _(modList[modnum].name),
			     status+SH_MOD_OFFSET);
	  }
	  modList[modnum].initval = SH_MOD_FAILED;
	}
      else
	{
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_MOD_OK,
			   _(modList[modnum].name));
	  modList[modnum].initval = status;
	}
    }
    
  /*  --------  TEST SETUP  ---------
   */
  (void) sh_files_setrec();
  (void) sh_files_test_setup();
  sh_audit_commit ();

  /* --------  NICE LEVEL   ---------
   */
  if (0 != sh.flag.nice)
    {
#ifdef HAVE_SETPRIORITY
      /*@-unrecog@*/
      (void) setpriority(PRIO_PROCESS, 0, sh.flag.nice);
      /*@+unrecog@*/
#else
      (void) nice(sh.flag.nice);
#endif
    }

  /*  --------  CREATE SEMAPHORE  ---------
   */
  sh_sem_open();

  /*  --------  MAIN LOOP  ---------
   */
  sh.statistics.bytes_speed   = 0;
  sh.statistics.bytes_hashed  = 0;
  sh.statistics.files_report  = 0;
  sh.statistics.files_error   = 0;
  sh.statistics.files_nodir   = 0;

  while (1 == 1) 
    {
      ++cct;

      BREAKEXIT(sh_error_handle);

      TPT((0, FIL__, __LINE__, _("msg=<Start main loop.>, iter=<%ld>\n"), cct))

      tcurrent = time (NULL);

      do {
	check_signals(&flag_check_1, &flag_check_2);
	if (sh_global_suspend_flag == 1)
	  (void) retry_msleep (1, 0);
      } while (sh_global_suspend_flag == 1);
      
      /* see whether its time to check files
       */
      if      (sh.flag.checkSum == SH_CHECK_INIT ||
	       (sh.flag.inotify & SH_INOTIFY_DOSCAN) != 0 ||
	       (sh.flag.checkSum == SH_CHECK_CHECK &&
		(sh.flag.isdaemon == S_FALSE && sh.flag.loop == S_FALSE)))
	{
	  flag_check_1 = 1;
	  if (FileSchedTwo != NULL) 
	    flag_check_2 = 1;
	}
      else if (sh.flag.checkSum == SH_CHECK_CHECK || 
	       (sh.flag.update == S_TRUE && 
		(sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE)))
	{
	  if (FileSchedOne == NULL)
	    {
	      /* use interval if we have no schedule
	       */
	      if (tcurrent - sh.fileCheck.alarm_last >= 
		  sh.fileCheck.alarm_interval)
		flag_check_1 = 1;
	    }
	  else
	    {
	      flag_check_1 = test_sched(FileSchedOne);
	      if (FileSchedTwo != NULL) 
		flag_check_2 = test_sched(FileSchedTwo);
	      if (flag_check_2 == 1) 
		flag_check_1 = 1;
	    }
	}

      check_done = 0;

      if (sh.flag.checkSum != SH_CHECK_NONE &&
	  (flag_check_1 == 1 || flag_check_2 == 1))
	{
	  sh_sem_trylock();

	  /* Starting a check now, so make sure to fetch delta DB
	   * if there is one to download.
	   */
	  check_for_delta_db();

	  SH_INOTIFY_IFUSED( sh.flag.inotify |= SH_INOTIFY_INSCAN; );
	  /* Refresh list files matching glob patterns.
	   */
	  if (sh.flag.checkSum != SH_CHECK_INIT)
	    sh_files_check_globPatterns();

	  /* 
	   * check directories and files
	   * ORDER IS IMPORTANT -- DIRZ FIRST
	   */
	  sh.statistics.bytes_hashed   = 0;
	  sh.statistics.time_start     = time (NULL);
	  sh.statistics.dirs_checked   = 0;
	  sh.statistics.files_checked  = 0;
	  sh.statistics.files_report   = 0;
	  sh.statistics.files_error    = 0;
	  sh.statistics.files_nodir    = 0;

	  TPT((0, FIL__, __LINE__, _("msg=<Check directories.>\n")))
	  BREAKEXIT(sh_dirs_chk);
	  if (flag_check_1 == 1)
	    {
	      (void) sh_dirs_chk  (1);
#ifndef SH_PROFILE
	      (void) retry_aud_chdir (FIL__, __LINE__, "/");
#endif
	    }
	  if (flag_check_2 == 1)
	    {
	      (void) sh_dirs_chk  (2); 
#ifndef SH_PROFILE
	      (void) retry_aud_chdir (FIL__, __LINE__, "/");
#endif
	    }
	  TPT((0, FIL__, __LINE__, _("msg=<Check files.>\n")))
	  BREAKEXIT(sh_files_chk);
	  if (flag_check_1 == 1)
	    (void) sh_files_chk ();

	  if (sig_urgent > 0) { sh_sem_unlock(sh.statistics.files_report); sh_global_check_silent = 0; continue; }
	  /*
	   * check for files not visited
	   */
	  if (flag_check_2 == 1 || FileSchedTwo == NULL)
	    {
	      TPT((0, FIL__, __LINE__, _("msg=<Check for missing files.>\n")))
	      sh_hash_unvisited (ShDFLevel[SH_ERR_T_FILE]);
	    }

	  if (sig_urgent > 0) { sh_sem_unlock(sh.statistics.files_report); sh_global_check_silent = 0; continue; }

	  /* reset
	   */
	  TPT((0, FIL__, __LINE__, _("msg=<Reset status.>\n")))
	  sh_dirs_reset  ();

	  if (sig_urgent > 0) { sh_sem_unlock(sh.statistics.files_report); sh_global_check_silent = 0; continue; }

	  sh_files_reset ();
	  check_done   = 1;

	  flag_check_1 = 0;
	  flag_check_2 = 0;
	  sh_sem_unlock(sh.statistics.files_report);

	  SH_INOTIFY_IFUSED( sh.flag.inotify &= ~SH_INOTIFY_INSCAN; );
	  SH_INOTIFY_IFUSED( sh.flag.inotify &= ~SH_INOTIFY_DOSCAN; );

	  (void) sh_prelink_run (NULL, NULL, 0, 0);

	  if (sig_urgent > 0) { sh_global_check_silent = 0; continue; }

	  runtim = time(NULL) - sh.statistics.time_start;
	  sh.statistics.time_check = runtim;
	
	  if ((sh.statistics.dirs_checked == 0) && 
	      (sh.statistics.files_checked == 0) &&
	      (sh_global_check_silent < SH_SILENT_FULL))
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_CHECK_0);

	  else
	    {
	      st_1 = (float) sh.statistics.bytes_hashed;
	      st_2 = (float) runtim;


	      if (st_1 > FLT_EPSILON && st_2 > FLT_EPSILON) 
		st_1 = st_1/st_2;
	      else if (st_1 > FLT_EPSILON)
		st_1 = (float) (st_1 * 1.0);
	      else
		st_1 = 0.0;

	      sh.statistics.bytes_speed = (unsigned long) st_1;

	      if (sh_global_check_silent < SH_SILENT_FULL)
		sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_CHECK_1,
				 (long) runtim, 
				 0.001 * st_1);

	      if (sh.flag.checkSum != SH_CHECK_INIT)
		sh_efile_report();
	    }
	  
	  if (0 == sh_global_check_silent)
	    sh.fileCheck.alarm_last = time (NULL);

	  sh_global_check_silent = 0;
	  
	  if (sig_urgent > 0) continue;

	  /*
	   * flush mail queue
	   */
#if defined(SH_WITH_MAIL)
	  TPT((0, FIL__, __LINE__, _("msg=<Flush mail queue.>\n")))
	  (void) sh_nmail_flush ();
#endif
	}
      
      if (sig_urgent > 0) continue;
      
      /* execute modules
       */
      TPT((0, FIL__, __LINE__, _("msg=<Execute modules.>\n")))
      for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
	{
	  if (modList[modnum].initval == SH_MOD_ACTIVE &&
	      0 != modList[modnum].mod_timer(tcurrent))
	    if (0 != (status = modList[modnum].mod_check()))
	      sh_error_handle ((-1), FIL__, __LINE__, status, MSG_MOD_EXEC,
			       _(modList[modnum].name), (long) (status+SH_MOD_OFFSET));
	}
      
      /* 27.05.2002 avoid empty database
       * 22.10.2002 moved here b/o suid check initialization
       */ 
      if      (sh.flag.checkSum == SH_CHECK_INIT)
	sh_dbIO_data_write (NULL, NULL);

      /* write out database
       */
      if (sh.flag.checkSum == SH_CHECK_CHECK && 
	  sh.flag.update == S_TRUE && 
	  check_done == 1)
	sh_dbIO_writeout_update ();

      /* no-op unless MEM_LOG is defined in sh_mem.c
       */
#ifdef MEM_DEBUG
      sh_mem_dump ();
#endif

      {
	char * stale;

	stale = sl_check_stale();
	if (stale)
	  {
	    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    stale, _("sl_check_stale"));
	  }

	stale = sl_check_badfd();
	if (stale)
	  {
	    sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    stale, _("sl_check_stale"));
	  }
      }

      /* no loop if not daemon
       */
      if (sh.flag.isdaemon != S_TRUE && sh.flag.loop == S_FALSE) break;
      if (sig_urgent > 0) continue;

      /* see whether its time to send mail
       */
#if defined(SH_WITH_MAIL)
      if (tcurrent - sh.mailTime.alarm_last >= sh.mailTime.alarm_interval) 
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Flush mail queue.>\n")))
	  (void) sh_nmail_flush ();
	  sh.mailTime.alarm_last = time (NULL);
	}
#endif
      if (sig_urgent > 0) continue;
            
      /* log the timestamp
       */
      if ((int)(tcurrent - told) >= sh.looptime )
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Log the timestamp.>\n")))
	  told = tcurrent;
#ifdef MEM_DEBUG
	  sh_mem_check();
	  sh_unix_count_mlock();
#else
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_STAMP);
#endif
	}
    
      /* seed / re-seed the PRNG if required
       */
      (void) taus_seed();
      
      if (sig_urgent > 0) continue;
      
      /* reset cache
       */
      sh_userid_destroy();

      /* go to sleep
       */
      (void) retry_msleep (1, 0);

      BREAKEXIT(sh_derr);
      (void) sh_derr();
    }
  
  /*   ------  END  -----------
   */



  /*
   * cleanup
   */
  TPT((0, FIL__, __LINE__, _("msg=<Cleanup.>\n")));
  sh_hash_hashdelete(); 

#if defined(SH_WITH_MAIL)
  if (sh.mailNum.alarm_last > 0) 
    (void)sh_nmail_flush ();
#endif

  /* #if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) */
#endif

  aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
  SL_RETURN(0, _("main"));
}
