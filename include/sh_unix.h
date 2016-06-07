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



#ifndef SH_UNIX_H
#define SH_UNIX_H

/* For PATH_MAX */
#include <limits.h>
#if !defined(PATH_MAX)
#define PATH_MAX 1024
#endif

#include <unistd.h>
#include "samhain.h"
#include "sh_error.h"


typedef enum {
  SH_ISLOG,
  SH_ISFILE,
  SH_ISDIR,
  SH_ISDATA
} ShOpenType;

typedef enum {
  SH_DATA_RAW,
  SH_DATA_LINE
} ShDataType;

typedef enum {
  SH_FILE_REGULAR,
  SH_FILE_SYMLINK,
  SH_FILE_DIRECTORY,
  SH_FILE_CDEV,
  SH_FILE_BDEV,
  SH_FILE_FIFO,
  SH_FILE_SOCKET,
  SH_FILE_DOOR,
  SH_FILE_PORT,
  SH_FILE_UNKNOWN
} ShFileType;

/* -- Attributes to check. --
 */

/* checksum     */
#define MODI_CHK (1 << 0)
/* link         */
#define MODI_LNK (1 << 1)
/* inode        */
#define MODI_INO (1 << 2)

/* user         */
#define MODI_USR (1 << 3)
/* group        */
#define MODI_GRP (1 << 4)
/* mtime        */
#define MODI_MTM (1 << 5)

/* ctime        */
#define MODI_CTM (1 << 6)
/* atime        */
#define MODI_ATM (1 << 7)
/* size         */
#define MODI_SIZ (1 << 8)

/* file mode    */
#define MODI_MOD (1 << 9)
/* hardlinks    */
#define MODI_HLN (1 << 10)
/* device type   */
#define MODI_RDEV (1 << 11)

/* size may grow   */
#define MODI_SGROW (1 << 12)
/* use prelink     */
#define MODI_PREL (1 << 13)
/* get content     */
#define MODI_TXT ((1 << 14)|MODI_CHK)
#define MODI_TXT_ENABLED(a) (((a)&(1 << 14))!=0)

/* get audit record  */
#define MODI_AUDIT (1 << 15)
#define MODI_AUDIT_ENABLED(a) (((a)&(1 << 15))!=0)
/* do not check  */
#define MODI_NOCHECK (1 << 16)
/* do not check  */
#define MODI_ALLIGNORE (1 << 17)

#define MODI_TIGER192  0x01000000UL
#define MODI_SHA1      0x02000000UL
#define MODI_MD5       0x03000000UL
#define MODI_SHA256    0x04000000UL
#define MODI_HASHTYPE  0x0F000000UL

#define MODI_INIT 0xD0000000UL
#define MODI_INITIALIZED(a) (((a) & 0xF0000000UL) == MODI_INIT)

#define MODI_SET(a, b) ((a) |= (b))
#define MODI_CLEAR(a, b) ((a) &= ~(b))
#define MODI_ISSET(a, b) (((a) & (b)) != 0)

#define SH_TXT_MAX 9200

#define MASK_ALLIGNORE_  0
extern  unsigned long mask_ALLIGNORE;
#define MASK_ATTRIBUTES_ (MODI_MOD|MODI_USR|MODI_GRP|MODI_RDEV)
extern  unsigned long mask_ATTRIBUTES;
#define MASK_LOGFILES_   (MASK_ATTRIBUTES_|MODI_HLN|MODI_LNK|MODI_INO)
extern  unsigned long mask_LOGFILES;
#define MASK_LOGGROW_    (MASK_LOGFILES_|MODI_SIZ|MODI_SGROW|MODI_CHK) 
extern  unsigned long mask_LOGGROW;
#define MASK_READONLY_   (MASK_LOGFILES_|MODI_CHK|MODI_SIZ|MODI_MTM|MODI_CTM)
extern  unsigned long mask_READONLY;
#define MASK_NOIGNORE_   (MASK_LOGFILES_|MODI_CHK|MODI_SIZ|MODI_ATM|MODI_MTM)
extern  unsigned long mask_NOIGNORE;
#define MASK_USER_       (MASK_READONLY_|MODI_ATM)
extern  unsigned long mask_USER0;
extern  unsigned long mask_USER1;
extern  unsigned long mask_USER2;
extern  unsigned long mask_USER3;
extern  unsigned long mask_USER4;
/* like READONLY, but without MTM,CTM,SIZ,INO, and with PREL)
 */
#define MASK_PRELINK_   (MASK_ATTRIBUTES_|MODI_HLN|MODI_LNK|MODI_CHK|MODI_PREL)
extern  unsigned long mask_PRELINK;

typedef struct file_struct {
  unsigned long    check_flags;
  int              file_reported;
  char             fullpath[PATH_MAX];
  ShFileType       type;
  dev_t            dev;
  ino_t            ino;
  mode_t           mode;
  nlink_t          hardlinks;
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  unsigned long    attributes;
  char             c_attributes[ATTRBUF_SIZE];
#endif
  char             c_mode[CMODE_SIZE];
  uid_t            owner;
  char             c_owner[USER_MAX+2];
  gid_t            group;
  char             c_group[GROUP_MAX+2];
  dev_t            rdev;
  off_t            size;
  unsigned long    blksize;
  unsigned long    blocks;
  time_t           atime;
  time_t           mtime;
  time_t           ctime;

  char           * link_path;
  mode_t           linkmode;
  char             link_c_mode[11];
  int              linkisok;
  char           * attr_string;
} file_type;

extern int sh_unix_check_selinux;
extern int sh_unix_check_acl;

/* destroy userid cache 
 */
void sh_userid_destroy ();

/* --- run a command, securely --- 
 */
int sh_unix_run_command (const char * str);

/* Ignore SIGPIPE
 */
void sh_unix_ign_sigpipe();

/* mlock utilities
 */
int sh_unix_mlock(const char * file, int line, void * addr, size_t len);
int sh_unix_munlock(void * addr, size_t len);
int sh_unix_count_mlock(void);
/* public for unit tests */
int sh_unix_pagesize(void);
unsigned long sh_unix_lookup_page(void * in_addr, size_t len, int * num_pages);

/* chroot directory
 */
int sh_unix_set_chroot(const char * str);

/* whether to use localtime for file timesatams in logs
 */
int sh_unix_uselocaltime (const char * c);

/* whether to perform selinux/acl checks
 */ 
#ifdef USE_XATTR
int sh_unix_setcheckselinux (const char * c);
#endif
#ifdef USE_ACL
int sh_unix_setcheckacl (const char * c);
#endif

/* set I/O limit
 */
int  sh_unix_set_io_limit (const char * c);
void sh_unix_io_pause (void);

/* get file type
 */
int sh_unix_get_ftype(char * fullpath);

/* reset masks for policies
 */
int sh_unix_maskreset(void);

/* return true if database is remote
 */
int file_is_remote (void);

/* return the path to the configuration/database file
 */
char * file_path(char what, char flag);

/* return current time as unsigned long
 */
unsigned long sh_unix_longtime (void);

/* close all files >= fd, except possibly one
 */
void sh_unix_closeall (int fd, int except, int inchild);

/* Check whether directory for pid file exists
 */
int sh_unix_check_piddir (char * pidpath);

/* write lock for filename
 */
int sh_unix_write_lock_file(char * filename);

/* rm lock(s) for log file(s)
 */
int sh_unix_rm_lock_file(char * filename);

/* write the PID file
 */
int sh_unix_write_pid_file(void);

/* rm the PID file
 */
int sh_unix_rm_pid_file(void);


/* checksum of own binary
 */
int sh_unix_self_hash (const char * c);

/* return BAD on failure
 */
int sh_unix_self_check (void);

/* add a trusted user to the list 
 */
int tf_add_trusted_user(const char *);

/* check a file 
 */
int tf_trust_check (const char * file, int mode);

/* initialize group vector
 */
#ifdef HOST_IS_OSF
int  sh_unix_initgroups  (      char * in_user, gid_t in_gid);
#else
int  sh_unix_initgroups  (const char * in_user, gid_t in_gid);
#endif
int  sh_unix_initgroups2 (uid_t         in_pid, gid_t in_gid);

/* set the timeserver address
 */
int sh_unix_settimeserver (const char * address);
void reset_count_dev_time(void);

/* lock the key
 */
void sh_unix_memlock(void);

/* deamon mode 
 */
int sh_unix_setdeamon  (const char * dummy);
int sh_unix_setnodeamon(const char * dummy);

/* Test whether file exists
 */
int sh_unix_file_exists(char * path);

/* test whether file exists with proper attributes
 */
int sh_unix_device_readable(int fd);

/* local host
 */
void sh_unix_localhost(void);

/* check whether /proc exists and is a proc filesystem
 */ 
int sh_unix_test_proc(void);

/* check whether a directory is secure 
 * (no symlink in path, not world-writeable)
 */
/* int sh_unix_is_secure_dir (ShErrLevel level, char * tmp); */

/* check whether there's a rotated log with the correct inode and checksum 
 */
int sh_check_rotated_log (const char * path,  
			  UINT64 old_size, UINT64 old_inode, const char * old_hash, unsigned long mask);

/* obtain file info
 */
int sh_unix_getinfo (int level, const char * filename, file_type * theFile, 
		     char * fileHash, int flagrel);

/* read file, return length read
 */
int sh_unix_getline (SL_TICKET fd, char * line, int sizeofline);

/* call with goDaemon == 1 to make daemon process
 */
int  sh_unix_init(int goDaemon);

/* for local time use thetime = 0, returns pointer to buffer 
 */
char * sh_unix_time (time_t thetime, char * buffer, size_t len);

/* convert to GMT time, returns pointer to buffer
 */
char * sh_unix_gmttime (time_t thetime, char * buffer, size_t len);

/* effective user info
 */
int  sh_unix_getUser (void);

/* get home directory, , returns pointer to out
 */
char *  sh_unix_getUIDdir (int level, uid_t uid, char * out, size_t len);

/* get a group GID 
 */
long sh_group_to_gid (const char * g, int * fail);

#ifdef HAVE_GETTIMEOFDAY
unsigned long sh_unix_notime (void);
#endif

/* check whether a directory
 */
int sh_unix_isdir (char * dirName, int level);

#ifdef SH_STEALTH
int  sh_unix_getline_stealth  (SL_TICKET fd, char * str, int len);
void sh_unix_xor_code (char * str, int len);
#endif

#if defined(SCREW_IT_UP)
/* for raise() 
 */
#include <signal.h>
#include <errno.h>

void   sh_sigtrap_handler (int signum);

#ifdef HAVE_GETTIMEOFDAY
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
#endif

struct sh_sigtrap_variables {
  int not_traced;
#ifdef HAVE_GETTIMEOFDAY
  struct timeval save_tv;
#endif
};

struct sh_sigtrap_variables * sh_sigtrap_variables_get();

int sh_sigtrap_max_duration_set (const char * str);

static inline
int  sh_sigtrap_prepare()
{
  struct sigaction act_trap;
  int              val_retry;
  act_trap.sa_handler   = &sh_sigtrap_handler;   /* signal action     */
  act_trap.sa_flags     = 0;                     /* init sa_flags     */
  sigemptyset ( &act_trap.sa_mask );             /* set an empty mask */
  do {
    val_retry = sigaction(SIGTRAP, &act_trap, NULL);
  } while (val_retry < 0 && errno == EINTR);
  return 0;
}

/*@unused@*/ static inline 
int sh_derr(void)
{
  struct sh_sigtrap_variables * sigtrap_variables;
  sigtrap_variables = sh_sigtrap_variables_get();
  if (sigtrap_variables == NULL) {
    /* Perhaps, its better to not die, and to continue using Samhain,
       even if this part does not work. */
    return (0);
  }

  sigtrap_variables->not_traced = 0;

#ifdef HAVE_GETTIMEOFDAY
  gettimeofday(&sigtrap_variables->save_tv, NULL);
#endif

  /* raise() sends to same thread, like pthread_kill(pthread_self(), sig); 
   */
  raise(SIGTRAP);
  
  if (sigtrap_variables->not_traced == 0)
    _exit(5);

  sigtrap_variables->not_traced = 0;
  return (0);
}

#else

/*@unused@*/ static inline 
int sh_derr(void)
{
  return 0;
}
/* #if defined(SCREW_IT_UP) */
#endif

#endif


