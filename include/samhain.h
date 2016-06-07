/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
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

#ifndef SAMHAIN_H
#define SAMHAIN_H

#include <sys/types.h>
#include "slib.h"

#ifdef SH_ENCRYPT
#include "rijndael-api-fst.h"
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)
#define SH_GNUC_SENTINEL __attribute__((__sentinel__))
#else
#define SH_GNUC_SENTINEL
#endif

#if defined(__GNUC__) && (__GNUC__ >= 3)
#undef  SH_GNUC_PURE
#define SH_GNUC_PURE     __attribute__((pure))
#undef  SH_GNUC_CONST
#define SH_GNUC_CONST	 __attribute__((const))
#undef  SH_GNUC_NORETURN
#define SH_GNUC_NORETURN __attribute__((noreturn))
#undef  SH_GNUC_MALLOC
#define SH_GNUC_MALLOC   __attribute__((malloc))
#else
#undef  SH_GNUC_PURE
#define SH_GNUC_PURE
#undef  SH_GNUC_CONST
#define SH_GNUC_CONST
#undef  SH_GNUC_NORETURN
#define SH_GNUC_NORETURN
#undef  SH_GNUC_MALLOC
#define SH_GNUC_MALLOC
#endif

/**************************************************
 *
 * STANDARD DEFINES
 *
 **************************************************/

/* IPv6 */
#if defined(HAVE_GETNAMEINFO) && defined(HAVE_GETADDRINFO)

#if defined(SH_COMPILE_STATIC) && defined(__linux__)
#undef USE_IPVX
#define SH_SOCKMAX 1
#else

#if defined(USE_IPV4)
#undef USE_IPVX
#else
#define USE_IPVX 1
#endif

#define SH_SOCKMAX 8
#endif

#else
#undef USE_IPVX
#define SH_SOCKMAX 1
#endif

/* end IPv6 */

/* Standard buffer sizes. 
 * IPv6 is 8 groups of 4 hex digits seperated by colons.
 */
#define SH_IP_BUF        48
#define SH_MINIBUF       64
#define SH_BUFSIZE     1024
#define SH_MAXBUF      4096
#define SH_PATHBUF      256
#define SH_MSG_BUF    64512

#define SH_ERRBUF_SIZE   64

/* MAX_PATH_STORE must be >= KEY_LEN
 */
#define MAX_PATH_STORE 12287

/* Sizes for arrays (user, group, timestamp).
 */
#define SOCKPASS_MAX 14
#define USER_MAX     20
#define GROUP_MAX    20
#define TIM_MAX      32

#define CMODE_SIZE   11

#define ATTRBUF_SIZE 16
#define ATTRBUF_USED 12

/* The number of bytes in a key,  
 * the number of chars in its hex repesentation,
 * and the block size of the hash algorithm.
 */
#define KEY_BYT   24
#define KEY_LEN   48
#define KEY_BLOCK 24
#define KEYBUF_SIZE (KEY_LEN+1)

/* The length of the compiled-in password.
 */
#define PW_LEN     8

#undef  S_TRUE
#define S_TRUE    1
#undef  S_FALSE
#define S_FALSE   0

#undef  GOOD
#define GOOD  S_TRUE
#undef  BAD
#define BAD   S_FALSE

#define SH_SILENT_FULL 2
#define SH_SILENT_STD  1


#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#if !defined(HAVE_UINT16_T)
#define UINT16 unsigned short
#else
#define UINT16 uint16_t
#endif

#if !defined(HAVE_UINT32_T)

/* An unsigned integer guaranteed to be 32 bit.
 */
#if defined(HAVE_INT_32)
#define UINT32 unsigned int
#define SINT32 int
#elif defined(HAVE_LONG_32)
#define UINT32 unsigned long
#define SINT32 long
#elif defined(HAVE_SHORT_32)
#define UINT32 unsigned short
#define SINT32 short
#else
#error "No 32 bit integer type found"
#endif

#else
#define UINT32 uint32_t
#define SINT32 int32_t

#endif

#if !defined(HAVE_UINT64_T)

#ifdef HAVE_LONG_LONG_64
#define  UINT64 unsigned long long
#else
#ifdef HAVE_LONG_64
#define  UINT64 unsigned long
#else
#error "no 64bit type found"
#endif
#endif

#else
#define  UINT64 uint64_t
#endif



#define UBYTE unsigned char

enum {
  SH_TIGER192    = 0, 
  SH_SHA1        = 1,
  SH_MD5         = 2,
  SH_SHA256      = 3
};


enum {
  SH_CHECK_NONE    = 0, 
  SH_CHECK_INIT    = 1,
  SH_CHECK_CHECK   = 2
};

#define SH_MOD_THREAD  1
#define SH_MOD_ACTIVE  0
#define SH_MOD_FAILED -1
#define SH_MOD_OFFSET 10

/* Flags for file status
 */
#define SH_FFLAG_ALLIGNORE (1<<0)
#define SH_FFLAG_VISITED   (1<<1)
#define SH_FFLAG_CHECKED   (1<<3)
#define SH_FFLAG_REPORTED  (1<<3)
#define SH_FFLAG_SUIDCHK   (1<<4)
#define SH_FFLAG_ENOENT    (1<<5)

#define SH_FFLAG_ALLIGNORE_SET(a)   (((a) & SH_FFLAG_ALLIGNORE) != 0)
#define SET_SH_FFLAG_ALLIGNORE(a)   ((a) |= SH_FFLAG_ALLIGNORE)
#define CLEAR_SH_FFLAG_ALLIGNORE(a) ((a) &= ~SH_FFLAG_ALLIGNORE)

#define SH_FFLAG_VISITED_SET(a)     (((a) & SH_FFLAG_VISITED) != 0)
#define SET_SH_FFLAG_VISITED(a)     ((a) |= SH_FFLAG_VISITED)
#define CLEAR_SH_FFLAG_VISITED(a)   ((a) &= ~SH_FFLAG_VISITED)

#define SH_FFLAG_CHECKED_SET(a)     (((a) & SH_FFLAG_VISITED) != 0)
#define SET_SH_FFLAG_CHECKED(a)     ((a) |= SH_FFLAG_VISITED)
#define CLEAR_SH_FFLAG_CHECKED(a)   ((a) &= ~SH_FFLAG_VISITED)

#define SH_FFLAG_REPORTED_SET(a)    (((a) & SH_FFLAG_REPORTED) != 0)
#define SET_SH_FFLAG_REPORTED(a)    ((a) |= SH_FFLAG_REPORTED)
#define CLEAR_SH_FFLAG_REPORTED(a)  ((a) &= ~SH_FFLAG_REPORTED)

#define SH_FFLAG_SUIDCHK_SET(a)     (((a) & SH_FFLAG_SUIDCHK) != 0)
#define SET_SH_FFLAG_SUIDCHK(a)     ((a) |= SH_FFLAG_SUIDCHK)
#define CLEAR_SH_FFLAG_SUIDCHK(a)   ((a) &= ~SH_FFLAG_SUIDCHK)

#define SH_FFLAG_ENOENT_SET(a)      (((a) & SH_FFLAG_ENOENT) != 0)
#define SET_SH_FFLAG_ENOENT(a)      ((a) |= SH_FFLAG_ENOENT)
#define CLEAR_SH_FFLAG_ENOENT(a)    ((a) &= ~SH_FFLAG_ENOENT)

/* Flags for inotify
 */
#define SH_INOTIFY_USE      (1<<0)
#define SH_INOTIFY_DOSCAN   (1<<1)
#define SH_INOTIFY_NEEDINIT (1<<2)
#define SH_INOTIFY_INSCAN   (1<<3)
#define SH_INOTIFY_IFUSED(a)   if ((sh.flag.inotify & SH_INOTIFY_USE) != 0) { a }


/**************************************************
 *
 * TYPEDEFS
 *
 **************************************************/

enum {
  SH_LEVEL_READONLY    = 1, 
  SH_LEVEL_LOGFILES    = 2,
  SH_LEVEL_LOGGROW     = 3,
  SH_LEVEL_NOIGNORE    = 4,
  SH_LEVEL_ALLIGNORE   = 5,
  SH_LEVEL_ATTRIBUTES  = 6,
  SH_LEVEL_USER0       = 7,
  SH_LEVEL_USER1       = 8,
  SH_LEVEL_USER2       = 9,
  SH_LEVEL_USER3       = 10,
  SH_LEVEL_USER4       = 11,
  SH_LEVEL_PRELINK     = 12
};

typedef struct {
  time_t  alarm_interval;
  time_t  alarm_last;
} sh_timer_t;

typedef struct {
  char   path[SH_PATHBUF];
  char   hash[KEY_LEN+1];
} sh_sh_df;

typedef struct {
  char   user[USER_MAX];
  char   group[GROUP_MAX];
  char   home[SH_PATHBUF];
  uid_t  uid;
  gid_t  gid;
} sh_sh_user;

typedef struct {
  char   name[SH_PATHBUF];      /* local hostname                  */
  char   system[SH_MINIBUF];    /* system                          */
  char   release[SH_MINIBUF];   /* release                         */
  char   machine[SH_MINIBUF];   /* machine                         */
} sh_sh_local;

typedef struct {
  char   name[SH_PATHBUF];
  char   alt[SH_PATHBUF];
} sh_sh_remote;

typedef struct {
  unsigned long   bytes_hashed;  /* bytes     last check */
  unsigned long   bytes_speed;   /* bytes/sec last check */
  unsigned long   mail_success;  /* mails sent           */ 
  unsigned long   mail_failed;   /* mails not sent       */
  time_t          time_start;    /* start     last check */
  time_t          time_check;    /* time      last check */
  unsigned long   dirs_checked;  /* #dirs     last check */
  unsigned long   files_checked; /* #files    last check */
  unsigned long   files_report;  /* #file reports        */
  unsigned long   files_error;   /* #file access error   */
  unsigned long   files_nodir;   /* #file not a directory*/
} sh_sh_stat;

typedef struct {
  int    exit;                     /* exit value                      */
  int    checkSum;                 /* whether to init/check checksums */
  int    update;                   /* update db                       */
  int    opts;                     /* reading cl options              */
  int    started;                  /* finished with startup stuff     */
  int    isdaemon;                 /* daemon or not                   */
  int    loop;                     /* go in loop even if not daemon   */
  int    nice;                     /* desired nicety                  */
  int    isserver;                 /* server or not                   */
  int    islocked;                 /* BAD if logfile not locked       */
  int    smsg;                     /* GOOD if end message sent        */
  int    log_start;                /* TRUE if new audit trail         */
  int    reportonce;               /* TRUE if bad files only once rep.*/
  int    fulldetail;               /* TRUE if full details requested  */
  int    client_severity;          /* TRUE if client severity used    */
  int    client_class;             /* TRUE if client class used       */
  int    hidefile;                 /* TRUE if file not shown in log   */
  int    inotify;                  /* Flags for inotify               */
  int    audit;
  unsigned long aud_mask;
} sh_sh_flag;

typedef struct {

  char   prg_name[8];

  UINT64 pid;  
 
  sh_sh_df     exec;
  sh_sh_df     conf;
  sh_sh_df     data;

  sh_sh_user   real;
  sh_sh_user   effective;
  sh_sh_user   run;

  sh_sh_local  host;

  sh_sh_remote srvtime;
  sh_sh_remote srvmail;
  sh_sh_remote srvexport;
  sh_sh_remote srvcons;
  sh_sh_remote srvlog;

  sh_sh_stat   statistics;
  sh_sh_flag   flag;

#ifdef SH_STEALTH
  unsigned long off_data;
#endif

  sh_timer_t mailNum;
  sh_timer_t mailTime;
  sh_timer_t fileCheck;

  int    looptime;                 /* timing for main loop            */
  /*@null@*//*@out@*/ char   * timezone;

  int delayload;

#ifdef SCREW_IT_UP
  int sigtrap_max_duration;
#endif

  char * outpath;
} sh_struct;


extern volatile  int      sig_raised;
extern volatile  int      sig_urgent;
extern volatile  int      sig_debug_switch;       /* SIGUSR1 */
extern volatile  int      sig_suspend_switch;     /* SIGUSR2 */
extern volatile  int      sh_global_suspend_flag;
extern volatile  int      sig_fresh_trail;        /* SIGIOT  */
extern volatile  int      sh_thread_pause_flag;
extern volatile  int      sig_config_read_again;  /* SIGHUP  */
extern volatile  int      sig_terminate;          /* SIGQUIT */
extern volatile  int      sig_termfast;           /* SIGTERM */
extern volatile  int      sig_force_check;        /* SIGTTOU */
extern volatile  int      sig_force_silent;       /* SIGTSTP */
extern volatile  int      sh_global_check_silent;
extern volatile  int      sh_load_delta_flag;

extern long int eintr__result;

extern int     sh_argc_store;
extern char ** sh_argv_store;

#include "sh_calls.h"


typedef struct {
  char   sh_sockpass[2*SOCKPASS_MAX+2];
  char   sigkey_old[KEY_LEN+1];
  char   sigkey_new[KEY_LEN+1];
  char   mailkey_old[KEY_LEN+1];
  char   mailkey_new[KEY_LEN+1];
  char   crypt[KEY_LEN+1]; 
  char   session[KEY_LEN+1]; 
  char   vernam[KEY_LEN+1];
  int    mlock_failed;

  char   pw[PW_LEN];

  char   poolv[KEY_BYT];
  int    poolc;

  int    rngI;
  UINT32 rng0[3];
  UINT32 rng1[3];
  UINT32 rng2[3];

  UINT32 res_vec[6];

  UINT32 ErrFlag[2];

#ifdef SH_ENCRYPT
  /*@out@*/ keyInstance             keyInstE;
  /*@out@*/ keyInstance             keyInstD;
#endif
} sh_key_t;

extern sh_struct sh; 
/*@null@*/ extern sh_key_t  *skey; 

/**************************************************
 *
 * macros
 *
 **************************************************/

#if defined(SH_ABORT_ON_ERROR)
#define SH_ABORT abort()
#else
#define SH_ABORT 
#endif



/* The semantics of the built-in are that it is expected that expr == const
 * for __builtin_expect ((expr), const)
 */
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define SH_LIKELY(expr)   (__builtin_expect((expr), 1))
#define SH_UNLIKELY(expr) (__builtin_expect((expr), 0))
#else
#define SH_LIKELY(expr) (expr)
#define SH_UNLIKELY(expr) (expr)
#endif

/* signal-safe log function
 */
int  safe_logger (int thesignal, int method, char * details);
void safe_fatal  (const char * details, const char *f, int l);

#define SH_VALIDATE_EQ(a,b) \
     do { \
         if ((a) != (b)) safe_fatal(#a " != " #b, FIL__, __LINE__);\
     } while (0)

#define SH_VALIDATE_NE(a,b) \
     do { \
         if ((a) == (b)) safe_fatal(#a " == " #b, FIL__, __LINE__);\
     } while (0)

#define SH_VALIDATE_GE(a,b) \
     do { \
         if ((a) < (b)) safe_fatal(#a " < " #b, FIL__, __LINE__);\
     } while (0)

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#ifdef USE_SUID
#define MLOCK(a, b) \
      if ((skey != NULL) && skey->mlock_failed == S_FALSE){ \
        (void) sl_set_suid(); \
	if (sh_unix_mlock(FIL__, __LINE__, a, b) < 0) skey->mlock_failed = S_TRUE; \
        (void) sl_unset_suid(); }
#else
#define MLOCK(a, b) \
      if ((skey != NULL) && skey->mlock_failed == S_FALSE){ \
        if (sh_unix_mlock(FIL__, __LINE__, a, b) < 0) skey->mlock_failed = S_TRUE; }
#endif 
#else
#define MLOCK(a, b) \
  ;
#endif

#if defined(HAVE_MLOCK) && !defined(HAVE_BROKEN_MLOCK)
#ifdef USE_SUID
#define MUNLOCK(a, b) \
      if ((skey != NULL) && skey->mlock_failed == S_FALSE){ \
        (void) sl_set_suid(); \
	(void) sh_unix_munlock( a, b );\
        (void) sl_unset_suid(); }
#else
#define MUNLOCK(a, b) \
      if ((skey != NULL) && skey->mlock_failed == S_FALSE){ \
        (void) sh_unix_munlock( a, b ); }
#endif 
#else
#define MUNLOCK(a, b) \
  ;
#endif

#ifdef SH_STEALTH
void sh_do_encode (char * str, int len);
#define sh_do_decode sh_do_encode
#endif

/* #if defined(SCREW_IT_UP)
 * extern volatile int sh_not_traced;
 * inline int  sh_sigtrap_prepare();
 * inline int  sh_derr();
 * #endif
 */

#if defined(SCREW_IT_UP) && (defined(__FreeBSD__) || defined(__linux__)) && defined(__i386__)
#define BREAKEXIT(expr) \
  do { \
    int ixi; \
    for (ixi = 0; ixi < 8; ++ixi) { \
      if ((*(volatile unsigned *)((unsigned) expr + ixi) & 0xff) == 0xcc) \
        _exit(EXIT_FAILURE); \
      } \
    } \
  while (1 == 0)
#else
#define BREAKEXIT(expr)
#endif
 


#include "sh_cat.h"
#include "sh_trace.h"
#include "sh_mem.h"

#endif

/* CRIT:                                       */
/* NEW_CLIENT  <client>                        */
/* BAD_CLIENT  <client> -- <details>           */
/* ERR_CLIENT  <client> -- <details>           */

/* ALERT:                                      */
/* LOG_KEY     samhain|yule <key>              */
/* STARTUP     samhain|yule -- user <username> */
/* EXIT        samhain|yule                    */
/* GOODSIG     <file> <user>                   */
/* FP_KEY      <fingerprint>                   */
/* GOODSIG_DAT <file> <user>                   */
/* FP_KEY_DAT  <fingerprint>                   */
/* TIGER_CFG   <file> <checksum>               */
/* TIGER_DAT   <file> <checksum>               */

/* PANIC       -- <details>                    */
/* ERROR       -- <details>                    */

/* Policy                                      */
/* POLICY      <code> <file>                   */
/* <code> = MISSING || ADDED || NOT_A_DIRECTORY || <policy> */



