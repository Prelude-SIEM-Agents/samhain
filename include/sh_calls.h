#ifndef SH_CALLS_H
#define SH_CALLS_H

#define  AUD_CHDIR  (1UL <<  0)
#define  AUD_CHMOD  (1UL <<  1)
#define  AUD_CHOWN  (1UL <<  2)
#define  AUD_CREAT  (1UL <<  3)
#define  AUD_DUP    (1UL <<  4)
#define  AUD_EXEC   (1UL <<  5)
#define  AUD_EXIT   (1UL <<  6)
#define  AUD_FORK   (1UL <<  7)
#define  AUD_KILL   (1UL <<  8)
#define  AUD_LINK   (1UL <<  9)
#define  AUD_MKDIR  (1UL << 10)
#define  AUD_MKFIFO (1UL << 11)
#define  AUD_OPEN   (1UL << 12)
#define  AUD_PIPE   (1UL << 13)
#define  AUD_RENAME (1UL << 14)
#define  AUD_RMDIR  (1UL << 15)
#define  AUD_SETGID (1UL << 16)
#define  AUD_SETUID (1UL << 17)
#define  AUD_UNLINK (1UL << 18)
#define  AUD_UTIME  (1UL << 19)

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <utime.h>

/*@-fixedformalarray@*/

#include "config_xor.h"
#if defined(__GNUC__) && (__GNUC__ >= 3)
#undef  SH_GNUC_NORETURN
#define SH_GNUC_NORETURN __attribute__((noreturn))
#else
#undef  SH_GNUC_NORETURN
#define SH_GNUC_NORETURN
#endif


/* Set aud functions
 */
int sh_aud_set_functions(const char * str_s);

#ifdef SH_IPVX_H
long int retry_accept(const char * file, int line, 
		      int fd, struct sh_sockaddr *serv_addr, int * addrlen);
#endif

void sh_calls_enable_sub();
int  sh_calls_set_sub (const char * str);

long int retry_stat (const char * file, int line, 
		     const char *file_name, struct stat *buf);
long int retry_fstat(const char * file, int line, 
		     int filed,             struct stat *buf);
long int retry_lstat_ns(const char * file, int line, 
			const char *file_name, struct stat *buf);
long int retry_lstat(const char * file, int line, 
		     const char *file_name, struct stat *buf);
long int retry_fcntl(const char * file, int line, 
		     int fd, int cmd, long arg);

long int retry_msleep (int sec, int millisec);

long int retry_sigaction(const char * file, int line, 
			 int signum,  const  struct  sigaction  *act,
			 struct sigaction *oldact);

int      sh_calls_set_bind_addr (const char *);
long int retry_connect(const char * file, int line,
		       int fd, struct sockaddr *serv_addr, int addrlen);

long int retry_aud_dup2    (const char * file, int line, int fd, int fd2);
long int retry_aud_execve  (const char * file, int line, 
			    const  char *dateiname, char * argv[],
			    char *envp[]);
long int retry_aud_dup     (const char * file, int line, 
			    int fd);
long int retry_aud_chdir   (const char * file, int line, 
			    const char *path);
long int retry_aud_unlink  (const char * file, int line, 
			    char * path);
long int retry_aud_utime   (const char * file, int line, 
			    char * path, struct utimbuf *buf);

long int aud_open           (const char * file, int line, int privs,
			     const char *pathname, int flags, mode_t mode);
long int aud_open_noatime   (const char * file, int line, int privs,
			     const char *pathname, int flags, mode_t mode,
			     int * o_noatime);
/*@noreturn@*/
void     aud_exit   (const char * file, int line, int fd) SH_GNUC_NORETURN;
/*@noreturn@*/
void     aud__exit  (const char * file, int line, int fd) SH_GNUC_NORETURN;
pid_t    aud_fork   (const char * file, int line);
int      aud_pipe   (const char * file, int line, int modus[2]);
int      aud_setuid (const char * file, int line, uid_t uid);
int      aud_setgid (const char * file, int line, gid_t gid);
long int aud_kill   (const char * file, int line, pid_t pid, int sig);

#endif 
