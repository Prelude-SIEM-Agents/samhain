#include "config_xor.h"

#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_MINCORE)
#define _XOPEN_SOURCE 600
#define _BSD_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#ifdef HAVE_STDINT_H
/* for SIZE_MAX */
#include <stdint.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_MINCORE)
#include <sys/mman.h>
#endif

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
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef FD_SET
#define NFDBITS         32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#endif /* !FD_SET */
#ifndef FD_SETSIZE
#define FD_SETSIZE      32
#endif
#ifndef FD_ZERO
#define FD_ZERO(p)      memset((char *)(p), '\0', sizeof(*(p)))
#endif

#define SH_REAL_SET

#include "slib.h"
#include "sh_calls.h"
#define SH_NEED_PWD_GRP 1
#include "sh_static.h"
#include "sh_pthread.h"
#include "sh_string.h"

#undef  FIL__
#define FIL__  _("slib.c")

const uid_t sh_uid_neg = ((uid_t) -1);
const gid_t sh_gid_neg = ((gid_t) -1);
 
#undef BREAKEXIT
#if defined(SCREW_IT_UP) && defined(__linux__) && defined(__i386__)

#ifdef SH_DEBUG
#define BREAKEXIT(expr) \
  do { \
    int ixi; \
    for (ixi = 0; ixi < 8; ++ixi) { \
      if ((*(volatile unsigned *)((unsigned) expr + ixi) & 0xff) == 0xcc)  \
        { dlog(0, FIL__, __LINE__, _("BREAKEXIT")); _exit(EXIT_FAILURE); } \
      } \
    } \
  while (1 == 0)
#else
#define BREAKEXIT(expr) \
  do { \
    int ixi; \
    for (ixi = 0; ixi < 8; ++ixi) { \
      if ((*(volatile unsigned *)((unsigned) expr + ixi) & 0xff) == 0xcc) \
        _exit(EXIT_FAILURE); \
      } \
    } \
  while (1 == 0)
#endif

#else
#define BREAKEXIT(expr)
#endif

/****************************************************************
 *
 *  The debug/trace subsystem
 *
 ****************************************************************/

int slib_do_trace          = 0;
int slib_trace_fd          = -1;

static char trace_log[256] = { '\0' };
static int trace_level     = 0;
static FILE * trace_fp     = NULL;

int  sl_trace_use (const char * dummy)
{
  (void) dummy;
  slib_do_trace = 1;
  return 0;
}

int  sl_trace_file (const char * str)
{
  if (!str)
    return -1;
  if (str[0] != '/')
    return -1;
  sl_strlcpy(trace_log, str, 256);
  return 0;
}

FILE * sl_tracefile_open(const char * file, const char * mode)
{
  FILE * xp = NULL;
  slib_trace_fd = open(file, O_WRONLY|O_CREAT|O_APPEND, 0600);
  if (slib_trace_fd >= 0)
    xp = fdopen(slib_trace_fd, mode);
  return xp;
}

void sl_trace_in(const char * str, const char * file, int line)
{
  int    i;
  if (trace_log[0] == '\0')
    {
      fprintf(stderr, "++ ");
      for (i = 0; i < trace_level; ++i)
	fprintf(stderr, ".  ");
      fprintf(stderr, "[%2d] %s \t - File %c%s%c at line %d\n", 
	     trace_level, str, 0x22, file, 0x22, line);
    }
  else if (!sl_is_suid())
    {
      if (!trace_fp)
	trace_fp = sl_tracefile_open(trace_log, "a");
      if (trace_fp)
	{
	  fprintf(trace_fp, "++ ");
	  for (i = 0; i < trace_level; ++i)
	    fprintf(trace_fp, ".  ");
	  fprintf(trace_fp, "[%2d] %s \t - File %c%s%c at line %d\n", 
		 trace_level, str, 0x22, file, 0x22, line);
	  fflush(trace_fp);
	}
      else
	{
	  perror(_("sl_trace_in: fopen"));
	  _exit(1);
	}
    }
  ++trace_level;
}

void sl_trace_out(const char * str, const char * file, int line)
{
  int    i;

  --trace_level; if (trace_level < 0) trace_level = 0;

  if (trace_log[0] == '\0')
    {
      fprintf(stderr, "-- ");
      for (i = 0; i < trace_level; ++i)
	fprintf(stderr, ".  ");
      fprintf(stderr, _("[%2d] %s \t - File %c%s%c at line %d\n"), 
	     trace_level, str, 0x22, file, 0x22, line);
    }
  else if (!sl_is_suid())
    {
      if (!trace_fp)
	trace_fp = sl_tracefile_open(trace_log, "a");
      if (trace_fp)
	{
	  fprintf(trace_fp, "-- ");
	  for (i = 0; i < trace_level; ++i)
	    fprintf(trace_fp, ".  ");
	  fprintf(trace_fp, _("[%2d] %s \t - File %c%s%c at line %d\n"), 
		 trace_level, str, 0x22, file, 0x22, line);
	  fflush(trace_fp);
	}
      else
	{
	  perror(_("sl_trace_out: fopen"));
	  _exit(1);
	}
    }
}

extern int sh_log_console (const char * msg);

static int dlogActive = 0;

/* this is called from sh_error_setprint()
 */
void dlog_set_active(int flag)
{
  dlogActive = flag;
}

/* flag = 0 debug messages
 *      = 1 descriptive error messages
 *      = 3 backtrace
 */
int dlog (int flag, const char * file, int line,  const char *fmt, ...)
{
  va_list     ap;
  char        val[81];
  char        msg[512];
  char        tmp[512];
  int         retval = 0;
  int         i;

#ifdef SH_STEALTH
  /* 
   * do not even print descriptive failure messages in stealth mode
   */
  if (dlogActive == 0)
    return 0;
  if (dlogActive == 1 && flag == 0) /* debug requires debug level */
    return 0;
#else
  if (dlogActive <= 1 && flag == 0) /* debug requires debug level */
    return 0;
#endif

  if (flag == 1)
    {
      sl_snprintf    (val, 81, _("\n---------  %10s "), file);
      sl_strlcpy     (msg,    val,   80);
      sl_snprintf    (val, 81, _(" --- %6d ---------\n"), line);
      sl_strlcat     (msg,     val,   80);
      sh_log_console (msg);
    }

  va_start (ap, fmt);
  if (flag == 1)
    sl_strlcpy(tmp, fmt, 512);
  else
    sl_strlcpy(tmp, fmt, 256);
  retval = strlen(tmp);
  if (retval > 0 && tmp[retval-1] == '\n')
    tmp[retval-1] = '\0';
  retval = 0;
  if (flag == 1)
    {
      sl_vsnprintf (msg, 511, tmp, ap);
    }
  else
    {
      sl_strlcpy   (msg,    "## ", 256);
      for (i = 0; i < trace_level; ++i)
	sl_strlcat (msg, ".  ", 256);
      sprintf      (val, _("[%2d] "), trace_level);
      sl_strlcat   (msg,     val,   256);
      sl_vsnprintf (&msg[strlen(msg)], 255, tmp, ap);
      sl_snprintf  (tmp, 255, _(" \t - File %c%s%c at line %d"), 
		    0x22, file, 0x22, line);
      sl_strlcat   (msg,     tmp,   512);
    }
  va_end (ap);
  if (flag != 0 || sl_is_suid())
    retval = sh_log_console (msg);
  else
    {
      if (trace_log[0] == '\0')
	{
	  /* sh_log_console (msg); */
	  fprintf(stderr, "%s\n", msg);
	}
      else
	{
	  if (!trace_fp)
	    trace_fp = sl_tracefile_open(trace_log, "a");
	  if (trace_fp)
	    {
	      fprintf(trace_fp, "%s\n", msg);
	    }
	  else
	    {
	      perror(_("dlog: fopen"));
	      _exit(1);
	    }
	}
    }
  if (flag == 1)
    sh_log_console (_("\n----------------------------------------------\n"));
  return retval;
}

extern char aud_err_message[64];
static char alt_err_message[64];
char * sl_get_errmsg()
{
  if (aud_err_message[0] == '\0')
    {
      sl_strlcpy(alt_err_message, sl_error_string(sl_errno), 64);
      return &alt_err_message[0];
    }
  return &aud_err_message[0];
}


#if defined(SL_DEBUG)
#define SL_MAX_MYSTACK 128

static char sl_mystack[SL_MAX_MYSTACK][32];
static int  sl_mystack_count = 0; 

void sl_stack_push(char * c, char * file, int line )
{
  if (slib_do_trace)
    sl_trace_in(c, file, line);
  if (c && sl_mystack_count < SL_MAX_MYSTACK)
    {
      strncpy(sl_mystack[sl_mystack_count], c, 31);
      sl_mystack[sl_mystack_count][31] = '\0';
      ++sl_mystack_count;
      /*
      fprintf(stderr, "#%03d %s\n", sl_mystack_count, 
	      sl_mystack[sl_mystack_count-1]);
      */
    }
  return;
}

void sl_stack_pop(char * c, char * file, int line)
{
  if (slib_do_trace)
    sl_trace_out(c, file, line);
  if (sl_mystack_count > 0)
    {
      /*
      fprintf(stderr, " <- #%03d %s\n", sl_mystack_count,
	      sl_mystack[sl_mystack_count-1]);
      */
      --sl_mystack_count;
    }
  return;
}

void sl_stack_print()
{
  int  i;
  /* FILE * dfile; */

  if (sl_mystack_count > 0)
    {
      sh_log_console(_("\nBacktrace:\n"));
      /* dlog(3, FIL__, __LINE__, _("\nBacktrace:\n")); */
      for (i = 0; i < sl_mystack_count; ++i)
	sh_log_console(sl_mystack[i]);
      /* dlog(3, FIL__, __LINE__, _("#%03d %s\n"), i, sl_mystack[i]); */
    } 
  return;
}

#endif


/*
 *  The global errno.
 *  On error, this is set to the return value of the function.
 */
long int sl_errno;


/* ---------------------------------------------------------------- 
 *
 *    Capability routines
 *
 * ---------------------------------------------------------------- */

int sl_useCaps = 0;

#ifdef FANCY_LIBCAP
#include <sys/capability.h>

/*
 * While these routines are tested and work, we don't use POSIX 
 * capabilities, as they don't seem to be useful (root can write 
 * to root-owned files anyway). Things would be more interesting
 * if we could switch to a non-root UID with just a few capabilities
 * enabled.
 */
int sl_drop_cap ()
{
  int              error;
  cap_t            caps;
  cap_flag_t       capflag;
  cap_flag_value_t capfval = CAP_CLEAR;
  cap_value_t      capvals_e[] =
  { 
    CAP_CHOWN,            CAP_FOWNER,        CAP_FSETID,
    CAP_LINUX_IMMUTABLE,  CAP_MKNOD,         CAP_NET_ADMIN,
    CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW,
    CAP_SYS_ADMIN,        CAP_SYS_BOOT,      CAP_SYS_CHROOT,
    CAP_SYS_PACCT,        CAP_SYS_PTRACE,    CAP_SYS_RAWIO,
    CAP_SYS_RESOURCE,     CAP_SYS_TIME,      CAP_SYS_TTY_CONFIG,
    CAP_SETGID,           CAP_SETUID,        CAP_KILL,
    CAP_DAC_OVERRIDE,
#if !defined(WITH_MESSAGE_QUEUE)
    CAP_IPC_OWNER,
#endif
    CAP_SYS_MODULE,       CAP_LEASE
  };
  cap_value_t      capvals_p[] =
  { 
    CAP_CHOWN,            CAP_LEASE,         CAP_FSETID,
    CAP_LINUX_IMMUTABLE,  CAP_MKNOD,         CAP_NET_ADMIN,
    CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW,
    CAP_SYS_ADMIN,        CAP_SYS_BOOT,      CAP_SYS_CHROOT,
    CAP_SYS_PACCT,        CAP_SYS_PTRACE,    CAP_SYS_RAWIO,
    CAP_SYS_RESOURCE,     CAP_SYS_TIME,      CAP_SYS_TTY_CONFIG,
#if !defined(WITH_EXTERNAL) && !defined(HAVE_UNIX_RANDOM)
    CAP_SETGID,           CAP_SETUID,        CAP_KILL,
#endif
#if !defined(SH_USE_SUIDCHK)
    CAP_DAC_OVERRIDE,     CAP_FOWNER,        
#endif
#if !defined(WITH_MESSAGE_QUEUE)
    CAP_IPC_OWNER,
#endif
    CAP_SYS_MODULE
  };

  if (0 == sl_useCaps) /* 0 = S_FALSE */
    {
      return 0;
    }

  if(NULL == (caps = cap_get_proc()))
    {
      return errno;
    }

  capflag = CAP_EFFECTIVE;
  if (0 != cap_set_flag(caps, capflag, sizeof(capvals_e)/sizeof(cap_value_t),
			capvals_e, capfval))
    {
      error = errno;
      cap_free(caps);
      return error;
    }
  if (0 != cap_set_proc(caps))
    {
      error = errno;
      cap_free(caps);
      return error;
    }

  capflag = CAP_PERMITTED;
  if (0 != cap_set_flag(caps, capflag, sizeof(capvals_p)/sizeof(cap_value_t),
			capvals_p, capfval))
    {
      error = errno;
      cap_free(caps);
      return error;
    }
  if (0 != cap_set_proc(caps))
    {
      error = errno;
      cap_free(caps);
      return error;
    }
  cap_free(caps);
  return 0;
}

int sl_drop_cap_int(int what)
{
#if defined(SL_DEBUG)
  char           * captext;
#endif
  cap_flag_t       capflag = CAP_EFFECTIVE;
  cap_flag_value_t capfval = CAP_CLEAR;
  cap_value_t      capvals_a[] = { CAP_SETGID, CAP_SETUID, CAP_KILL };
  cap_value_t      capvals_b[] = { CAP_DAC_OVERRIDE, CAP_FOWNER };
  cap_value_t    * capvals;
  int              nvals;
  int              error = 0;
  cap_t            caps = cap_get_proc();

  if (0 == sl_useCaps) /* 0 = S_FALSE */
    {
      return 0;
    }

  if (caps == NULL)
    {
      return errno;
    }

  switch (what) {
    case 1:
      capvals = capvals_a;
      nvals   = 3;
      capfval = CAP_CLEAR;
      break;
    case 2:
      capvals = capvals_a;
      nvals   = 3;
      capfval = CAP_SET;
      break;
    case 3:
      capvals = capvals_b;
      nvals   = 2;
      capfval = CAP_CLEAR;
      break;
    case 4:
      capvals = capvals_b;
      nvals   = 2;
      capfval = CAP_SET;
      break;
    default:
      return (0);
  }

  if (0 != cap_set_flag(caps, capflag, nvals, capvals, capfval))
    {
      error = errno;
      cap_free(caps);
      return error;
    }
  if (0 != cap_set_proc(caps))
    {
      error = errno;
      cap_free(caps);
      return error;
    }
#if defined(SL_DEBUG)
  captext = cap_to_text(caps, NULL);
  TPT(( 0, FIL__, __LINE__, _("msg=<cap_int %d: %s>\n"), what, captext));
  cap_free(captext);
#endif
  cap_free(caps);
  return 0;
}

int sl_drop_cap_sub()  { return sl_drop_cap_int(1); }
int sl_get_cap_sub()   { return sl_drop_cap_int(2); }
int sl_drop_cap_qdel() { return sl_drop_cap_int(3); }
int sl_get_cap_qdel()  { return sl_drop_cap_int(4); }

#else
int sl_drop_cap ()     { return 0; }
int sl_drop_cap_sub()  { return 0; }
int sl_get_cap_sub()   { return 0; }
int sl_drop_cap_qdel() { return 0; }
int sl_get_cap_qdel()  { return 0; }
#endif

/* ---------------------------------------------------------------- 
 *
 *    String handling routines
 *
 * ---------------------------------------------------------------- */
  
/*
 * Have memset in a different translation unit (i.e. this) to prevent 
 * it to get optimized away
 */
void *sl_memset(void *s, int c, size_t n)
{
  return memset(s, c,n);
}


#if !defined (VA_COPY)
#if defined (__GNUC__) && defined (__PPC__) && (defined (_CALL_SYSV) || defined (_WIN32))
#define VA_COPY(ap1, ap2)     (*(ap1) = *(ap2))
#elif defined (VA_COPY_AS_ARRAY)
#define VA_COPY(ap1, ap2)     memmove ((ap1), (ap2), sizeof (va_list))
#else /* va_list is a pointer */
#define VA_COPY(ap1, ap2)     ((ap1) = (ap2))
#endif
#endif 

#if !defined(HAVE_VSNPRINTF) || defined(HAVE_BROKEN_VSNPRINTF)
static
size_t sl_printf_count (const char * fmt, va_list  vl)
{
  size_t  length       = 1;
  int  fini         = 0;
  int  islong       = 0;
  int  islonglong   = 0;
  int  islongdouble = 0;
  char * string_arg;

  SL_ENTER(_("sl_printf_count"));

  if (fmt == NULL)
    SL_IRETURN(SL_ENULL, _("sl_printf_count"));

  while (*fmt) {

    if ( (*fmt) == '%' ) { /* a format specifier */

      fmt++;        /* point to first char after '%' */

      fini = 0;
      islong = 0;
      islongdouble = 0;

      while (*fmt && (fini == 0) ) {
	
	switch (*fmt) {

	case '*':      /* field width supplied by an integer */
	  length = length + va_arg (vl, int);
	  ++fmt;
	  break;
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	  length = length + strtol (fmt, (char**) &fmt, 10);
	  /* strtol makes FastForward to first invalid char */
	  break;

	case 'l':   /* 'long' modifier */
	  if (islong == 0)
	    islong = 1;
	  else
	    {
	      islonglong = 1;
	      islong = 0;
	    }
	  ++fmt;
	  break;

	case 'L':  /* 'long double' modifier */ 
#ifdef HAVE_LONG_DOUBLE	  
	  islongdouble = 1;
#else
	  islong = 1;
#endif
	  ++fmt;
	  break;

	case 'd':
	case 'i': 
	case 'o':
	case 'u':
	case 'x':
	case 'X':
	  if (islonglong == 1)
#ifdef HAVE_LONG_LONG
	    (void) va_arg (vl, long long);
#else
	    (void) va_arg (vl, long);
#endif
	  else if (islong == 1)
	    (void) va_arg (vl, long);
	  else
	    (void) va_arg (vl, int);
	  islong = 0;
	  islonglong = 0;
	  length = length + 24;
	  ++fmt;
	  fini = 1;
	  break;

	case 'D':
	case 'O':
	case 'U':
	  (void) va_arg (vl, long);
	  length = length + 24;
	  fmt++;
	  fini = 1;
	  break;

	case 'e':
	case 'E':
	case 'f':
	case 'g':
#ifdef HAVE_LONG_DOUBLE	  
	  if (islongdouble == 1) {
	    (void) va_arg (vl, long double);
	    islongdouble = 0;
	    length = length + 20;
	    }
	  else
#endif
	    (void) va_arg (vl, double);
	  length = length + 20;
	  fini = 1;
	  ++fmt;
	  break;

	case 's':
	  string_arg = va_arg (vl, char *);
	  if (string_arg != NULL)
	    length = length + sl_strlen (string_arg);
	  else
	    length = length + 16;
	  fini = 1;
	  ++fmt;
	  break;

	case 'c':
	  (void) va_arg (vl, int);
	  length = length + 1;
	  fini = 1;
	  ++fmt;
	  break;

	case 'p':
	case 'n':
	  (void) va_arg (vl, void * );
	  length = length + 32;
	  fini = 1;
	  ++fmt;
	  break;

	case '%':            /* %% will print '%' */
	  length = length + 1;
	  fini = 1;
	  ++fmt;
	  break;

	default:
	  length = length + 1;
	  ++fmt;
	  break;

	}  /* end switch */
      }    
      /* end parsing a single format specifier */
    } else {
      length = length + 1;
      fmt++;
    }
  }
  SL_IRETURN(length, _("sl_printf_count"));
}
#endif  /* #ifndef  HAVE_VSNPRINTF */

/*
 * An implementation of vsnprintf. va_start/va_end are in the caller
 * function.
 * Returns C99 (#bytes that would heve been written) on success.
 */
int sl_vsnprintf(char *str, size_t n,
		 const char *format, va_list vl )
{
  int len = 0;
#if !defined(HAVE_VSNPRINTF) || defined(HAVE_BROKEN_VSNPRINTF)
  size_t         total;
  va_list       vl2;
#endif

  SL_ENTER(_("sl_vsnprintf"));
  if (str == NULL || format == NULL)
    SL_IRETURN(0, _("sl_vsnprintf"));

#if defined(HAVE_VSNPRINTF) && !defined(HAVE_BROKEN_VSNPRINTF)
  len = vsnprintf (str, n, format, vl);                /* flawfinder: ignore */
  str[n-1] = '\0';
#else
  VA_COPY (vl2, vl);                     /* save the argument list           */
  total = sl_printf_count (format, vl);
  len = (int) total;
  if (total < n) 
    {
      /* flawfinder: ignore */
      vsprintf (str, format, vl2);       /* program has checked that it fits */
      str[n-1] = '\0';
    }
  else 
    {
      sl_strlcpy (str, format, n);
      va_end(vl2);
      SL_IRETURN(len, _("sl_vsnprintf"));
    }
  va_end(vl2);
#endif
  SL_IRETURN(len, _("sl_vsnprintf"));
}

/*
 * An implementation of snprintf.
 * Returns SL_ENONE on success.
 * ENULL:  src || format == NULL
 * ERANGE: n out of range
 * ETRUNC: truncated (unimplemented)
 */
int sl_snprintf(char *str, size_t n,
		const char *format, ... )
{
  va_list       vl;
#if !defined(HAVE_VSNPRINTF) || defined(HAVE_BROKEN_VSNPRINTF)
  size_t          total = 0;
  va_list       vl2;
#endif

  SL_ENTER(_("sl_snprintf"));
  if (str == NULL || format == NULL)
    SL_IRETURN(SL_ENULL, _("sl_snprintf"));
  
  va_start (vl, format);
#if defined(HAVE_VSNPRINTF) && !defined(HAVE_BROKEN_VSNPRINTF)
  /* flawfinder: ignore */
  vsnprintf (str, n, format, vl);
  str[n-1] = '\0';
#else
  VA_COPY (vl2, vl);                   /* save the argument list           */
  total = sl_printf_count (format, vl);
  if (total < n) 
    {
      /* flawfinder: ignore */
      vsprintf (str, format, vl2);     /* program has checked that it fits */
      str[n-1] = '\0';
    }
  else 
    {
      sl_strlcpy (str, format, n);
      va_end(vl2);
      va_end(vl);
      SL_IRETURN(SL_ETRUNC, _("sl_snprintf"));
    }
  va_end(vl2);
#endif  
  va_end(vl);
  SL_IRETURN(SL_ENONE, _("sl_snprintf"));
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns SL_NONE on success, errcode on failure.
 *
 * ENULL:  dst == NULL
 * ERANGE: siz out of range
 * ETRUNC: src truncated
 */
int sl_strlcat(char * dst, /*@null@*/const char *src, size_t siz)
{
  register size_t dst_end;
  register size_t dst_free;

  register char       * p;
  register const char * q;

  if (!(dst == NULL || src == NULL || *src == '\0'))
    {
      if (siz > 0) 
	{

	  /* How much free space do we have ?
	   */
	  dst_end  = strlen(dst);
	  dst_free = siz - dst_end - 1;
	  
	  p = &dst[dst_end];
	  q = src;
	  
	  while (dst_free > 0 && *q != '\0')
	    {
	      *p++ = *q++;
	      --dst_free;
	    }
	
	  /* NULL terminate dst.
	   */
	  *p = '\0';
	
	  if (*q == '\0')
	    return SL_ENONE;
	  else
	    return SL_ETRUNC;
	}
    }
  return SL_ENONE;
}

/*
 * An alternative implementation of the OpenBSD strlcpy() function.
 *
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns SL_NONE on success, errcode on failure.
 *
 * ENULL:  dst == NULL
 * ERANGE: siz out of range
 * ETRUNC: src truncated
 */
int sl_strlcpy(char * dst, /*@null@*/const char * src, size_t siz)
{
  /* SL_ENTER(_("sl_strlcpy")); */

  if (!((dst == NULL) || (src == NULL))) 
    {
      if (siz > 0) {
	/* copy siz-1 characters 
	 */
	(void) strncpy(dst, src, siz-1);

	/* NULL terminate
	 */
	dst[siz-1] = '\0';
      }
      return SL_ENONE;
    }
  else if (src == NULL)
    {
      if (dst && siz > 0) 
	dst[0] = '\0';
      return SL_ENONE;
    }
  else
    {
      return SL_ENULL;
    } 
}

/*
 * A robust drop-in replacement of strncpy. strlcpy is preferable.
 */
char * sl_strncpy(char *dst, const char *src, size_t size)
{

#ifdef SL_FAIL_ON_ERROR
  SL_REQUIRE(dst != NULL, _("dst != NULL"));
  SL_REQUIRE(src != NULL, _("src != NULL"));
  SL_REQUIRE(size > 0, _("size > 0"));
#endif

  if (dst == NULL)
    {
      sl_errno = SL_ENULL;
      return (NULL);
    }
  if (size < 1)
    {
      sl_errno = SL_ERANGE;
      return (dst);
    }
  if (!src)
    {
      sl_errno = SL_ENULL;
      dst[0] = '\0';
    }
  else if (src[0] == '\0')
    dst[0] = '\0';
  else
    strncpy(dst, src, size);

  if (sl_strlen(src) >= size)
    {
      errno = ENOSPC;
      dst[size-1] = '\0';
    }
  return (dst);
}

/*
 * A robust drop-in replacement of strncat. strlcat is preferable.
 */
char * sl_strncat(char *dst, const char *src, size_t n)
{
#ifdef SL_FAIL_ON_ERROR
  SL_REQUIRE(dst != NULL, _("dst != NULL"));
  SL_REQUIRE(src != NULL, _("src != NULL"));
  SL_REQUIRE(n > 0, _("n > 0"));
#endif

  if (dst == NULL)
    {
      sl_errno = SL_ENULL;
      return (NULL);
    }
  if (n < 1)
    {
      sl_errno = SL_ERANGE;
      return (dst);
    }
  if (!src)
    {
      sl_errno = SL_ENULL;
      return (dst);
    }
  else if (src[0] == '\0')
    dst[0] = '\0';
  else
    strncat(dst, src, n);

  return (dst);
}

#include <ctype.h>
int sl_strcasecmp(const char * one, const char * two)
{
#ifdef SL_FAIL_ON_ERROR
  SL_REQUIRE (one != NULL, _("one != NULL"));
  SL_REQUIRE (two != NULL, _("two != NULL"));
#endif

  if (one && two)
    {
      do {
	if (*one && *two)
	  {
	    if (tolower((int) *one) == tolower((int) *two))
	      {
		++one; ++two;
	      }
	    else if (tolower((int) *one) < tolower((int) *two))
	      return -1;
	    else
	      return 1;
	  }
	else if (*one == '\0' && *two == '\0')
	  return 0;
	else if (*one == '\0')
	  return -1;
	else
	  return 1;
      } while (1 == 1);
    }
  else if (one == NULL && two != NULL)
    return -1;
  else if (one != NULL && two == NULL)
    return 1;
  else
    return -7; /* default to not equal */
}

int sl_strcmp(const char * a, const char * b)
{
#ifdef SL_FAIL_ON_ERROR
  SL_REQUIRE (a != NULL, _("a != NULL"));
  SL_REQUIRE (b != NULL, _("b != NULL"));
#endif

  if (a != NULL && b != NULL)
    return (strcmp(a, b));
  else if (a == NULL && b != NULL)
    return (-1);
  else if (a != NULL && b == NULL)
    return (1);
  else
    return (-7); /* default to not equal */
}

int sl_strncmp(const char * a, const char * b, size_t n)
{
#ifdef SL_FAIL_ON_ERROR
  SL_REQUIRE (a != NULL, _("a != NULL"));
  SL_REQUIRE (b != NULL, _("b != NULL"));
  SL_REQUIRE (n > 0, _("n > 0"));
#endif

  if (a != NULL && b != NULL)
    return (strncmp(a, b, n));
  else if (a == NULL && b != NULL)
    return (-1);
  else if (a != NULL && b == NULL)
    return (1);
  else
    return (-7); /* default to not equal */
}

int sl_strncasecmp(const char * a, const char * b, size_t n)
{
#ifdef SL_FAIL_ON_ERROR
  SL_REQUIRE (a != NULL, _("a != NULL"));
  SL_REQUIRE (b != NULL, _("b != NULL"));
  SL_REQUIRE (n > 0, _("n > 0"));
#endif

  if (a != NULL && b != NULL)
    return (strncasecmp(a, b, n));
  else if (a == NULL && b != NULL)
    return (-1);
  else if (a != NULL && b == NULL)
    return (1);
  else
    return (-7); /* default to not equal */
}

/* string searching
 */

char * sl_strstr (const char * haystack, const char * needle) 
{
#ifndef HAVE_STRSTR
  unsigned int    i;
  size_t          needle_len;
  size_t          haystack_len;
#endif
  
  if (haystack == NULL || needle == NULL)
    return NULL;
  if (*needle == '\0' || *haystack == '\0')
    return NULL;

#if defined(HAVE_STRSTR)
  return (strstr(haystack, needle));
#else
  needle_len   = strlen(needle);
  haystack_len = strlen(haystack);

  for (i = 0; i <= (haystack_len-needle_len); ++i)
    if (0 == sl_strncmp(&haystack[i], needle, needle_len))
      return (needle);
  return NULL;
#endif
}


/* ---------------------------------------------------------------- 
 *
 *    Privilege handling routines
 *
 * ---------------------------------------------------------------- */

  

static   uid_t   euid;
static   uid_t   ruid;
static   uid_t   ruid_orig;
static   gid_t   egid;
static   gid_t   rgid;
static   gid_t   rgid_orig;

static   int     uids_are_stored = S_FALSE;
static   int     suid_is_set     = S_TRUE;

#ifdef HAVE_SETRESUID
extern       int setresuid (uid_t truid, uid_t teuid, uid_t tsuid);
extern       int setresgid (gid_t trgid, gid_t tegid, gid_t tsgid);
#endif


/*
 * This function returns true if the program is SUID.
 * It calls abort() if the uid's are not saved already.
 */
int sl_is_suid()
{
  if (uids_are_stored == S_FALSE)
    {
      if (getuid() == geteuid() && getgid() == getegid())
	return (0);     /* FALSE */
      else
	return (1);     /* TRUE  */
    }
  else
    {
      if (euid == ruid && egid == rgid)
	return (0);     /* FALSE */
      else
	return (1);     /* TRUE  */
    }
}

/*
 * This function returns the saved euid.
 * It calls abort() if the uid's are not saved already.
 */
int sl_get_euid(uid_t * ret)
{
  SL_ENTER(_("sl_get_euid"));
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    *ret = euid;
  else
    *ret = geteuid();
  SL_IRETURN (SL_ENONE, _("sl_get_euid"));
}

uid_t sl_ret_euid()
{
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    return (euid);
  else
    return (geteuid());
}

/*
 * This function returns the saved egid.
 * It calls abort() if the uid's are not saved already.
 */
int sl_get_egid(gid_t * ret)
{
  SL_ENTER(_("sl_get_egid"));
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    *ret = egid;
  else
    *ret = getegid();
  SL_IRETURN (SL_ENONE, _("sl_get_egid"));
}

/*
 * This function returns the saved ruid.
 * It calls abort() if the uid's are not saved already.
 */
int sl_get_ruid(uid_t * ret)
{
  SL_ENTER(_("sl_get_ruid"));
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    *ret = ruid;
  else
    *ret = getuid();
  SL_IRETURN (SL_ENONE, _("sl_get_ruid"));
}

/*
 * This function returns the saved rgid.
 * It calls abort() if the uid's are not saved already.
 */
int sl_get_rgid(gid_t * ret)
{
  SL_ENTER(_("sl_get_rgid"));
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    *ret = rgid;
  else
    *ret = getgid();
  SL_IRETURN (SL_ENONE, _("sl_get_rgid"));
}

/*
 * This function returns the saved original ruid.
 * It calls abort() if the uid's are not saved already.
 */
int sl_get_ruid_orig(uid_t * ret)
{
  SL_ENTER(_("sl_get_ruid_orig"));
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    *ret = ruid_orig;
  else
    *ret = getuid();
  SL_IRETURN (SL_ENONE, _("sl_get_ruid_orig"));
}

/*
 * This function returns the saved original rgid.
 * It calls abort() if the uid's are not saved already.
 */
int sl_get_rgid_orig(gid_t * ret)
{
  SL_ENTER(_("sl_get_rgid_orig"));
  /* SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));*/
  if (uids_are_stored == S_TRUE)
    *ret = rgid_orig;
  else
    *ret = getgid();
  SL_IRETURN (SL_ENONE, _("sl_get_rgid_orig"));
}

static int suid_warn_flag = 1;
static void suid_warn(int a)
{
  fprintf(stderr, _("ERROR:  open set/unset suid !!! %d\n"), a);
  return;
}

/*
 * This function sets the effective uid 
 * to the saved effective uid.
 * It will abort on failure.
 */
int sl_set_suid ()
{
  int retval;

  SL_ENTER(_("sl_set_suid"));

  if (uids_are_stored == S_FALSE)
    {
      SL_IRETURN(SL_ENONE, _("sl_set_suid"));
    }

  SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));  

  if (ruid == euid && rgid == egid) 
    {
      suid_is_set = S_TRUE;
      SL_IRETURN(SL_ENONE, _("sl_set_suid"));
    }  
  SL_REQUIRE(suid_is_set     == S_FALSE, _("suid_is_set == S_FALSE"));  

#if defined(HAVE_SETRESUID)
  retval = setresuid (sh_uid_neg, euid, sh_uid_neg);
  if (retval == 0) 
    retval = setresgid (sh_gid_neg, egid, sh_gid_neg);

#elif defined(HAVE_SETEUID)
  retval = seteuid (egid);
  if (retval == 0) 
    retval = setegid (euid);

  /* on AIX, setreuid does not behave well for non-root users.
   */
#elif defined(HAVE_SETREUID)
  retval = setreuid (ruid, euid);
  if (retval == 0) 
    retval = setregid (rgid, egid);

#else
  retval = setuid (euid);
  if (retval == 0) 
    retval = setgid (egid);
#endif
  if (suid_warn_flag == 1)
    suid_warn(1);
  suid_warn_flag = 1;

  SL_REQUIRE(retval == 0, _("retval == 0"));
  suid_is_set = S_TRUE;
  SL_IRETURN(SL_ENONE, _("sl_set_suid"));
}

/*
 * This function sets the effective uid to the real uid.
 * It will abort on failure.
 */
int sl_unset_suid ()
{
  register int retval;

  SL_ENTER(_("sl_unset_suid"));

  if (uids_are_stored == S_FALSE)
    {
      SL_IRETURN(SL_ENONE, _("sl_unset_suid"));
    }

  SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));

  if (ruid == euid && rgid == egid)
    {
      suid_is_set = S_FALSE;
      SL_IRETURN(SL_ENONE, _("sl_unset_suid"));
    }  
  SL_REQUIRE(suid_is_set     == S_TRUE, _("suid_is_set == S_TRUE"));  

#if defined(HAVE_SETRESUID)
  retval = setresgid (sh_gid_neg, rgid, sh_gid_neg);
  if (retval == 0) 
    retval = setresuid (sh_uid_neg, ruid, sh_uid_neg);

#elif defined(HAVE_SETEUID)
  retval = setegid (rgid);
  if (retval == 0) 
    retval = seteuid (ruid);

#elif defined(HAVE_SETREUID)
  retval = setregid (egid, rgid);
  if (retval == 0) 
    retval = setreuid (euid, ruid);

#else
  retval = setgid (rgid);
  if (retval == 0) 
    retval = setuid (ruid);
#endif

  if (suid_warn_flag == 0)
    suid_warn(0);
  suid_warn_flag = 0;

  SL_REQUIRE(retval == 0, _("retval == 0"));
  suid_is_set = S_FALSE;
  SL_IRETURN(SL_ENONE, _("sl_unset_suid"));
}


/*
 * This function saves the uid's.
 */
int sl_save_uids()
{
  SL_ENTER(_("sl_save_uids"));
  if (uids_are_stored == S_TRUE) 
    SL_IRETURN(SL_EREPEAT, _("sl_save_uids"));

  ruid_orig = getuid();
  rgid_orig = getgid();
  egid = getegid();
  euid = geteuid();
  ruid = ruid_orig;
  rgid = rgid_orig;
  uids_are_stored = S_TRUE;

  SL_IRETURN(SL_ENONE, _("sl_save_uids"));
}

/* 
 * This function drops SUID privileges irrevocably.
 * It set the effective uid to the original real uid.
 */
extern int  sh_unix_initgroups2 (uid_t in_pid, gid_t in_gid);
int sl_drop_privileges()
{
  SL_ENTER(_("sl_drop_privileges"));
  SL_REQUIRE(uids_are_stored == S_TRUE, _("uids_are_stored == S_TRUE"));

  SL_REQUIRE(setgid(rgid_orig) == 0, _("setgid(rgid_orig) == 0"));
  SL_REQUIRE(sh_unix_initgroups2(ruid_orig, rgid_orig) == 0, _("sh_unix_initgroups2(ruid_orig,rgid_orig) == 0"));
  SL_REQUIRE(setuid(ruid_orig) == 0, _("setuid(ruid_orig) == 0"));

  /* make sure that setuid(0) fails
   */
  SL_REQUIRE(setuid(0) < 0, _("setuid(0) < 0"));

  euid = ruid_orig;
  egid = rgid_orig;
  ruid = ruid_orig;
  rgid = rgid_orig;

  SL_IRETURN(SL_ENONE, _("sl_drop_privileges"));
}

/* 
 * Define a policy: Stay root.
 * Do nothing if not SUID.
 */
int sl_policy_get_root()
{
  SL_ENTER(_("sl_policy_get_root"));
  SL_REQUIRE(uids_are_stored == S_FALSE, _("uids_are_stored == S_FALSE"));

  SL_REQUIRE (sl_save_uids() == SL_ENONE, _("sl_save_uids() == SL_ENONE"));

  if (euid != ruid || egid != rgid)
    {
      SL_REQUIRE(setgid(egid) == 0, _("setgid(egid) == 0"));
      SL_REQUIRE(setuid(euid) == 0, _("setuid(euid) == 0"));
      SL_REQUIRE(ruid == getuid() && rgid == getgid(),
		 _("ruid == getuid() && rgid == getgid()"));
      ruid = euid;
      rgid = egid;
    }
  suid_is_set = S_TRUE;
  if (euid == 0)
    {
      SL_REQUIRE(sh_unix_initgroups2(euid, egid) == 0, _("sh_unix_initgroups2(euid,egid) == 0"));
    }
  SL_IRETURN(SL_ENONE, _("sl_policy_get_root"));
}

#include <pwd.h>

/* 
 * Define a policy: Get real (irrevocably).
 * This function drops SUID privileges irrevocably.
 * Do nothing if not SUID (? not true - drops if root).
 */

int sl_policy_get_real(char * user)
{
  SL_ENTER(_("sl_policy_get_real"));
  SL_REQUIRE(uids_are_stored == S_FALSE, _("uids_are_stored == S_FALSE"));
  SL_REQUIRE (sl_save_uids() == SL_ENONE, _("sl_save_uids() == SL_ENONE"));

  if (euid == 0 || ruid == 0)
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      struct passwd    pwd;
      char          *  buffer;
      struct passwd *  tempres;
      buffer = calloc(1,SH_PWBUF_SIZE);
      SL_REQUIRE (buffer != NULL, _("buffer != NULL"));
      sh_getpwnam_r(user, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
      struct passwd * tempres = sh_getpwnam(user);
#endif

      SL_REQUIRE (NULL != tempres, _("tempres != NULL"));
  
      rgid_orig = tempres->pw_gid;
      ruid_orig = tempres->pw_uid;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      free(buffer);
#endif
    }
  else
    {
      rgid_orig = rgid;
      ruid_orig = ruid;
    }

  SL_REQUIRE (sl_drop_privileges() == SL_ENONE,
	      _("sl_drop_privileges() == SL_ENONE"));

  suid_is_set = S_TRUE;
  SL_IRETURN(SL_ENONE, _("sl_policy_get_real"));
}


/* 
 * Define a policy: Get user.
 * Drops privileges.
 * Do nothing if not SUID.
 */
int sl_policy_get_user(const char * user)
{
  SL_ENTER(_("sl_policy_get_user"));

  SL_REQUIRE(user != NULL, _("user != NULL"));
  SL_REQUIRE(uids_are_stored == S_FALSE, _("uids_are_stored == S_FALSE"));
  SL_REQUIRE (sl_save_uids() == SL_ENONE, _("sl_save_uids() == SL_ENONE"));

#ifndef SH_ALLOW_SUID
  if (euid != ruid || egid != rgid)
    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      struct passwd    pwd;
      char          *  buffer;
      struct passwd *  tempres;
      buffer = calloc(1,SH_PWBUF_SIZE);
      SL_REQUIRE (buffer != NULL, _("buffer != NULL"));
      sh_getpwnam_r(user, &pwd, buffer, SH_PWBUF_SIZE, &tempres);
#else
      struct passwd * tempres = sh_getpwnam(user);
#endif

      SL_REQUIRE (NULL != tempres, _("tempres != NULL"));

      SL_REQUIRE (sl_drop_privileges() == SL_ENONE,
		  _("sl_drop_privileges() == SL_ENONE"));
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_GETPWNAM_R)
      free(buffer);
#endif
    }
#endif
  SL_IRETURN(SL_ENONE, _("sl_policy_get_user"));
}



/* ---------------------------------------------------------------- 
 *
 *    File access routines
 *
 * ---------------------------------------------------------------- */

#define TOFFSET 0x1234

/* this would prevent opening files if the first 16 fds are open :( */ 
/* #define MAXFD   FOPEN_MAX                                        */

#define MAXFD   1024

typedef struct openfiles {
  SL_TICKET ticket;          /* The unique  ID.      */ 
  int fd;                    /* The file descriptor. */
  FILE * stream;             /* The file descriptor. */
  char * path;               /* The file path.       */
  int flush;                 /* Whether we want to flush the cache */
  char ofile[SL_OFILE_SIZE]; /* origin file */
  int  oline;                /* origin line */
  sh_string * content;       /* The file content     */
} SL_OFILE; 

static SL_OFILE * ofiles[MAXFD]; 

static char stale_orig_file[64] = { '\0' };
static int  stale_orig_line = -1;
static char stale_orig_mesg[128];

static char badfd_orig_file[64] = { '\0' };
static int  badfd_orig_line = -1;
static char badfd_orig_mesg[128];


char * sl_check_stale()
{
  if (stale_orig_line == -1)
    return NULL;
  sl_snprintf(stale_orig_mesg, sizeof(stale_orig_mesg), 
	      _("stale handle, %s, %d"), stale_orig_file, stale_orig_line);
  stale_orig_file[0] = '\0';
  stale_orig_line    = -1;
  return stale_orig_mesg;
}

char * sl_check_badfd()
{
  if (badfd_orig_line == -1)
    return NULL;
  sl_snprintf(badfd_orig_mesg, sizeof(badfd_orig_mesg), 
	      _("close on file descriptor with allocated handle, %s, %d"), 
	      badfd_orig_file, badfd_orig_line);
  badfd_orig_file[0] = '\0';
  badfd_orig_line    = -1;
  return badfd_orig_mesg;
}

typedef struct { volatile unsigned int atom; } atomic_t;
static atomic_t nonce_counter = { TOFFSET };

#if defined(__GNUC__) && (defined(__i486__) || defined(__x86_64__))
/* from linux/include/asm-i386/atomic.h */
static unsigned int atomic_add ( unsigned int i, atomic_t *var)
{
  unsigned int j = i;

  __asm__ __volatile__ ("lock; xaddl %0, %1"
			: "+r" (i), "+m" (var->atom)
			: : "memory");
  return j+i; 
}
#else
SH_MUTEX_STATIC(mutex_ticket, PTHREAD_MUTEX_INITIALIZER);

static unsigned int atomic_add ( unsigned int i, atomic_t *var)
{
  volatile unsigned int j;

  SH_MUTEX_LOCK_UNSAFE(mutex_ticket);
  var->atom += i;
  j = var->atom;
  SH_MUTEX_UNLOCK_UNSAFE(mutex_ticket);

  return j;
}
#endif

static
SL_TICKET sl_create_ticket (unsigned int myindex) 
{
  unsigned int high; /* index */ 
  unsigned int low;  /* nonce */
  SL_TICKET    retval = SL_EINTERNAL;
  unsigned int nonce;/* nonce */

  SL_ENTER(_("sl_create_ticket"));

  if (myindex >= MAXFD)
    {
      retval = SL_EINTERNAL01;
      goto out_ticket;
    }

  /* mask out the high bit and check that it is not used
   * -> verify that it fits into 16 bits as positive
   */
  high = (myindex + TOFFSET) & 0x7fff; 

  if (high != myindex + TOFFSET)
    {
      retval = SL_EINTERNAL02;
      goto out_ticket;
    }

  nonce = atomic_add(1, &nonce_counter);

  /* Wrap around the nonce counter.
   * This is a dirty trick.
   */
  if (nonce > 0x7fff)
    {
      nonce_counter.atom = TOFFSET;
      nonce = atomic_add(1, &nonce_counter);
    }

  low = nonce & 0xffff;

  /* Overflow -> nonce too big.
   */
  if ((low != nonce) || low == 0)
    {
      retval = SL_EINTERNAL03;
      goto out_ticket;
    }

  retval = (SL_TICKET) ((high << 16) | low);

 out_ticket:
  SL_RETURN (retval, _("sl_create_ticket")); 
}

static 
int sl_read_ticket (SL_TICKET fno) 
{
  register unsigned myindex; 
  register SL_OFILE *of; 

  myindex = ((fno >> 16) & 0xffff) - TOFFSET;
  if (myindex >= MAXFD)
    return (SL_ETICKET);

  if (ofiles[myindex] == NULL)
    return (SL_ETICKET);

  if (ofiles[myindex]->ticket != fno)
    return (SL_ETICKET);

  if ((of = ofiles[myindex])->fd < 0 || of->fd >= MAXFD )
    return (SL_EINTERNAL04);

  if (((of->ticket) & 0xffff) == 0)
    return (SL_EINTERNAL05); 

  return (myindex); 
}

SL_TICKET sl_make_ticket (const char * ofile, int oline,
			  int fd, const char * filename, FILE * stream)
{
  size_t    len;
  SL_TICKET ticket;
  SL_ENTER(_("sl_make_ticket"));
  /* Make entry.
   */
  /* cppcheck-suppress arrayIndexOutOfBoundsCond */
  if (fd >= MAXFD || fd < 0)
     {
	SL_IRETURN(SL_TOOMANY, _("sl_make_ticket"));
     }

  if (ofiles[fd] != NULL) /* stale entry */
    {
      /* SL_IRETURN(SL_EINTERNAL06, _("sl_make_ticket")); */
      sl_strlcpy(stale_orig_file, ofiles[fd]->ofile, sizeof(stale_orig_file));
      stale_orig_line = ofiles[fd]->oline;

      if (ofiles[fd]->content)
	sh_string_destroy(&(ofiles[fd]->content));
      (void) free (ofiles[fd]->path);
      (void) free (ofiles[fd]);
      ofiles[fd] = NULL;
    }

  if ( (ofiles[fd] = calloc(1,sizeof(SL_OFILE))) == NULL)
    {
      SL_IRETURN(SL_EMEM, _("sl_make_ticket"));
    }

  len = sl_strlen(filename)+1;

  if ( (ofiles[fd]->path = calloc(1,len) ) == NULL)
    {
      free (ofiles[fd]);
      ofiles[fd] = NULL;
      SL_IRETURN(SL_EMEM, _("sl_make_ticket"));
    }

  /* Get a ticket.
   */
  ticket = sl_create_ticket((unsigned int)fd);

  if (SL_ISERROR(ticket))
    {
      (void) free (ofiles[fd]->path);
      (void) free (ofiles[fd]);
      ofiles[fd] = NULL;
      SL_IRETURN(ticket, _("sl_make_ticket"));
    }

  sl_strlcpy (ofiles[fd]->path, filename, len);
  ofiles[fd]->ticket  = ticket;
  ofiles[fd]->fd      = fd;
  ofiles[fd]->content = NULL;
  ofiles[fd]->stream  = stream;
  ofiles[fd]->flush   = S_FALSE;

  sl_strlcpy(ofiles[fd]->ofile, ofile, SL_OFILE_SIZE);
  ofiles[fd]->oline = oline;

  SL_IRETURN(ticket, _("sl_make_ticket"));
}

#define SL_OPEN_MIN          113
#define SL_OPEN_FOR_READ     113
#define SL_OPEN_FOR_WRITE    114
#define SL_OPEN_FOR_RDWR     115
#define SL_OPEN_FOR_WTRUNC   116
#define SL_OPEN_FOR_RWTRUNC  117
#define SL_OPEN_SAFE_RDWR    118
#define SL_OPEN_FOR_FASTREAD 119
#define SL_OPEN_MAX          119

#if !defined(O_NOATIME)
#if defined(__linux__) && (defined(__i386__) || defined(__x86_64__) || defined(__PPC__))
#define O_NOATIME 01000000
#else
  /* 
   * bitwise 'or' with zero does not modify any bit 
   */
#define O_NOATIME 0
#endif
#endif

static int     o_noatime = O_NOATIME;
static mode_t  open_mode = (S_IWUSR|S_IRUSR|S_IRGRP);


static
int sl_open_file (const char * ofile, int oline,
		  const char *filename, int mode, int priv)
{
  struct stat   lbuf;
  struct stat   buf;
  int           errval = 0;
  int           lstat_return;
  int           stat_return;
  int           fd;
  int           sflags;
  size_t        len;
  SL_TICKET     ticket;
 
#if !defined(O_NONBLOCK)
#if defined(O_NDELAY)
#define O_NONBLOCK  O_NDELAY
#else
#define O_NONBLOCK  0
#endif
#endif

  SL_ENTER(_("sl_open_file"));

  if (filename == NULL)
    SL_IRETURN(SL_ENULL, _("sl_open_file"));
  if (mode < SL_OPEN_MIN || mode > SL_OPEN_MAX)
    SL_IRETURN(SL_EINTERNAL07, _("sl_open_file"));
    
  /* "This system call always succeeds and the previous value of
   * the mask is returned." 
   */
  (void) umask (0);

  if (mode == SL_OPEN_FOR_FASTREAD)
    {
      fd = aud_open_noatime (FIL__, __LINE__, priv, filename, 
			     O_RDONLY|O_NONBLOCK, 0, &o_noatime);
      /*
      if (fd >= 0) {
	sflags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags & ~O_NONBLOCK);
      }
      */
      if (fd < 0)
	SL_IRETURN(SL_EBADFILE, _("sl_open_file"));
      goto createTicket;
    }

#ifdef USE_SUID
  if (priv == SL_YESPRIV)
    sl_set_suid();
#endif
  if (mode == SL_OPEN_FOR_READ)
    lstat_return = retry_stat (FIL__, __LINE__, filename, &lbuf);
  else
    lstat_return = retry_lstat(FIL__, __LINE__, filename, &lbuf);
  errval = errno;
#ifdef USE_SUID
  if (priv == SL_YESPRIV)
    sl_unset_suid();
#endif

  if (lstat_return == -1)
    {
      lstat_return = ENOENT;
      if ( (mode == SL_OPEN_FOR_READ && lstat_return == ENOENT) ||
	   (errval != ENOENT))
	{
	  TPT(( 0, FIL__, __LINE__, _("msg=<lstat: %s> errno=<%d>\n"), 
	    filename, errval));
	  errno = errval;
	  SL_IRETURN(SL_ESTAT, _("sl_open_file"));
	}
    }
  
  if ( (mode != SL_OPEN_FOR_READ) && (lstat_return != ENOENT) &&
       ( S_ISDIR(lbuf.st_mode) || (S_IWOTH & lbuf.st_mode) ) 
      )
    {
      int retval = S_ISDIR(lbuf.st_mode) ? SL_EISDIR : SL_EBADOTH;
      errno = 0;
      SL_IRETURN(retval, _("sl_open_file"));
    }
    
  /* O_NOATIME has an effect for read(). But write() ?.
   */
  switch (mode)
    {
    case SL_OPEN_FOR_READ:
      fd = aud_open_noatime (FIL__, __LINE__, priv, filename, 
			     O_RDONLY|O_NONBLOCK, 0, &o_noatime);
      errval = errno;
      if (fd >= 0) {
	sflags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
	retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags & ~O_NONBLOCK);
      }
      break;
    case SL_OPEN_FOR_WRITE:
      if (lstat_return == ENOENT)
      	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_WRONLY|O_CREAT|O_EXCL,    open_mode);
      else
	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_WRONLY,                   open_mode);
      errval = errno;
      break;
    case SL_OPEN_SAFE_RDWR:
      if (lstat_return == ENOENT)
	{
	  fd = aud_open (FIL__, __LINE__, priv, filename, 
			 O_RDWR|O_CREAT|O_EXCL,      open_mode);
	  errval = errno;
	}
      else
	{
	  errno = errval;
	  SL_IRETURN(SL_EBADFILE, _("sl_open_file"));
	}
      break;
    case SL_OPEN_FOR_RDWR:
      if (lstat_return == ENOENT)
	fd = aud_open (FIL__, __LINE__, priv, filename, 
			 O_RDWR|O_CREAT|O_EXCL,      open_mode);
      else
	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_RDWR,                     open_mode);
      errval = errno;
      break;
    case SL_OPEN_FOR_WTRUNC:
      if (lstat_return == ENOENT)
      	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_WRONLY|O_CREAT|O_EXCL,    open_mode);
      else
	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_WRONLY|O_TRUNC,           open_mode);
      errval = errno;
      break;
    case SL_OPEN_FOR_RWTRUNC:
      if (lstat_return == ENOENT)
      	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_RDWR|O_CREAT|O_EXCL,      open_mode);
      else
	fd = aud_open (FIL__, __LINE__, priv, filename, 
		       O_RDWR|O_TRUNC,             open_mode);
      errval = errno;
      break;
    default:
      errno = 0;
      SL_IRETURN(SL_EINTERNAL08, _("sl_open_file"));
    }

  if (fd < 0)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<Error opening: %s> errno=<%d>\n"), 
	    filename, errval));
      errno = errval;
      SL_IRETURN(SL_EBADFILE, _("sl_open_file"));
    }

#ifdef USE_SUID
  if (priv == SL_YESPRIV)
    sl_set_suid();
#endif
  stat_return = retry_fstat(FIL__, __LINE__, fd, &buf);
  errval = errno;
#ifdef USE_SUID
  if (priv == SL_YESPRIV)
    sl_unset_suid();
#endif

  if (stat_return < 0)
    {
      sl_close_fd (FIL__, __LINE__, fd);
      errno = errval;
      SL_IRETURN(SL_EFSTAT, _("sl_open_file"));
    }

  errno = 0;

  if (lstat_return != ENOENT && buf.st_ino != lbuf.st_ino)
    {
      sl_close_fd (FIL__, __LINE__, fd);
      SL_IRETURN(SL_EBOGUS, _("sl_open_file"));
    }

 createTicket:

  /* Make entry.
   */
  /* cppcheck-suppress arrayIndexOutOfBoundsCond */
  if (fd >= MAXFD)
     {
	sl_close_fd(FIL__, __LINE__, fd);
	SL_IRETURN(SL_TOOMANY, _("sl_open_file"));
     }

  if (ofiles[fd] != NULL) /* stale entry */
    {
      /*
      sl_close_fd(FIL__, __LINE__, fd);
      SL_IRETURN(SL_EINTERNAL09, _("sl_open_file"));
      */
      sl_strlcpy(stale_orig_file, ofiles[fd]->ofile, sizeof(stale_orig_file));
      stale_orig_line = ofiles[fd]->oline;

      if (ofiles[fd]->content)
	sh_string_destroy(&(ofiles[fd]->content));
      (void) free (ofiles[fd]->path);
      (void) free (ofiles[fd]);
      ofiles[fd] = NULL;
    }

  if ( (ofiles[fd] = calloc(1,sizeof(SL_OFILE))) == NULL)
    {
      sl_close_fd(FIL__, __LINE__, fd);
      SL_IRETURN(SL_EMEM, _("sl_open_file"));
    }

  len = sl_strlen(filename)+1;

  if ( (ofiles[fd]->path = calloc(1,len) ) == NULL)
    {
      free (ofiles[fd]);
      ofiles[fd] = NULL;
      sl_close_fd(FIL__, __LINE__, fd);
      SL_IRETURN(SL_EMEM, _("sl_open_file"));
    }

  /* Get a ticket.
   */
  ticket = sl_create_ticket(fd);

  if (SL_ISERROR(ticket))
    {
      (void) free (ofiles[fd]->path);
      (void) free (ofiles[fd]);
      ofiles[fd] = NULL;
      sl_close_fd(FIL__, __LINE__, fd);
      SL_IRETURN(ticket, _("sl_open_file"));
    }

  sl_strlcpy (ofiles[fd]->path, filename, len);
  ofiles[fd]->ticket  = ticket;
  ofiles[fd]->fd      = fd;
  ofiles[fd]->content = NULL;
  ofiles[fd]->stream  = NULL;
  ofiles[fd]->flush   = S_FALSE;

  sl_strlcpy(ofiles[fd]->ofile, ofile, SL_OFILE_SIZE);
  ofiles[fd]->oline = oline;

  SL_IRETURN(ticket, _("sl_open_file"));
}

FILE * sl_stream (SL_TICKET ticket, char * mode)
{
  int    fd;

  if (SL_ISERROR(fd = sl_read_ticket(ticket)))
    return (NULL);

  if (ofiles[fd] == NULL || fd != ofiles[fd]->fd || 
      ticket != ofiles[fd]->ticket || fd < 0)
    return (NULL);

  if (!ofiles[fd]->stream)
    ofiles[fd]->stream = fdopen(fd, mode);

  return ofiles[fd]->stream;
}

int get_the_fd (SL_TICKET ticket)
{
  int fd;

  if (SL_ISERROR(fd = sl_read_ticket(ticket)))
    return (fd);

  if (ofiles[fd] == NULL || fd != ofiles[fd]->fd || 
      ticket != ofiles[fd]->ticket || fd < 0)
    return (SL_EINTERNAL10);

  return (fd);
}

static
int check_fname_priv (const char * fname, int priv)
{
  SL_ENTER(_("check_fname_priv"));
  if (fname == NULL)
    SL_IRETURN(SL_ENULL, _("check_fname_priv"));
  if (priv != SL_YESPRIV && priv != SL_NOPRIV)
    SL_IRETURN(SL_EINTERNAL11, _("check_fname_priv"));
  SL_IRETURN(SL_ENONE, _("check_fname_priv"));
}
  
SL_TICKET sl_open_write (const char * ofile, int oline,
			 const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_write"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    SL_IRETURN(status, _("sl_open_write"));

  status = sl_open_file(ofile, oline, fname, SL_OPEN_FOR_WRITE, priv);
  SL_IRETURN(status, _("sl_open_write"));
}

SL_TICKET sl_open_read (const char * ofile, int oline,
			const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_read"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    {
      TPT(( 0, FIL__, __LINE__, 
	    _("msg=<Error in check_fname_priv.> status=<%ld>\n"), 
	    status));
      SL_IRETURN(status, _("sl_open_read"));
    }

  status = sl_open_file(ofile, oline, fname, SL_OPEN_FOR_READ, priv);
  SL_IRETURN(status, _("sl_open_read"));
}

#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_MINCORE) && defined(POSIX_FADV_DONTNEED)
static int sl_check_mincore(int fd)
{
  /* Idea from Tobias Oetiker (http://insights.oetiker.ch/linux/fadvise.html)
   */
  struct stat fbuf;
  int retval = -1;

  if (0 == fstat(fd, &fbuf))
    {
      void *f_map;
      
      f_map = mmap((void *)0, fbuf.st_size, PROT_NONE, MAP_SHARED, fd, 0);
      if (MAP_FAILED != f_map)
	{
	  extern int sh_unix_pagesize(void);
	  size_t i;
	  size_t page_size    = sh_unix_pagesize();
	  size_t vec_size     = (fbuf.st_size+page_size-1)/page_size;
	  unsigned char * vec = calloc(1, vec_size);

	  if (vec)
	    {
	      mincore(f_map, fbuf.st_size, vec);
	      /* imax = fbuf.st_size/page_size; */
	      for (i = 0; i <= vec_size; ++i)
		{
		  if (vec[i]&1)
		    {
		      goto incore;
		    }
		}
	      retval = 0;
	    incore:
	      free(vec);
	    }
	  munmap(f_map, fbuf.st_size);
	}
    }
  return retval;
}
#endif

static int sl_drop_cache = S_FALSE;

int sl_set_drop_cache(const char * str)
{
  extern int sh_util_flagval(const char * c, int * fval);
  return sh_util_flagval(str, &sl_drop_cache);
}

SL_TICKET sl_open_fastread (const char * ofile, int oline,
			    const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_fastread"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    SL_IRETURN(status, _("sl_open_read"));

  status = sl_open_file(ofile, oline, fname, SL_OPEN_FOR_FASTREAD, priv);

#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_MINCORE) && defined(POSIX_FADV_DONTNEED)

  if (S_FALSE != sl_drop_cache && !SL_ISERROR(status))
    {
      int fd = get_the_fd(status);
      if (fd >= 0)
	{
	  if (0 == sl_check_mincore(fd))
	    ofiles[fd]->flush = S_TRUE;
	}
    }

#endif

  SL_IRETURN(status, _("sl_open_fastread"));
}

SL_TICKET sl_open_rdwr (const char * ofile, int oline,
			const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_rdwr"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    SL_IRETURN(status, _("sl_open_rdwr"));

  status = sl_open_file(ofile, oline, fname, SL_OPEN_FOR_RDWR, priv);
  SL_IRETURN(status, _("sl_open_rdwr"));
}

SL_TICKET sl_open_safe_rdwr (const char * ofile, int oline,
			     const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_safe_rdwr"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    SL_IRETURN(status, _("sl_open_safe_rdwr"));

  status = sl_open_file(ofile, oline, fname, SL_OPEN_SAFE_RDWR, priv);
  SL_IRETURN(status, _("sl_open_safe_rdwr"));
}

SL_TICKET sl_open_write_trunc (const char * ofile, int oline,
			       const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_write_trunc"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    SL_IRETURN(status, _("sl_open_write_trunc"));

  status = sl_open_file(ofile, oline, fname, SL_OPEN_FOR_WTRUNC, priv);
  SL_IRETURN(status, _("sl_open_write_trunc"));
}

SL_TICKET sl_open_rdwr_trunc (const char * ofile, int oline,
			      const char * fname, int priv)
{
  long status;
  SL_ENTER(_("sl_open_rdwr_trunc"));

  if (SL_ENONE != (status = check_fname_priv (fname, priv)))
    SL_IRETURN(status, _("sl_open_rdwr_trunc"));

  status = sl_open_file(ofile, oline, fname, SL_OPEN_FOR_RWTRUNC, priv);
  SL_IRETURN(status, _("sl_open_rdwr_trunc"));
}


int sl_init_content (SL_TICKET ticket, size_t size)
{
  int fd;

  if (SL_ISERROR(fd = sl_read_ticket(ticket)))
    return (fd);

  if (ofiles[fd] == NULL || fd != ofiles[fd]->fd || 
      ticket != ofiles[fd]->ticket || fd < 0)
    return (SL_EINTERNAL12);

  if (ofiles[fd]->content)
    sh_string_destroy(&(ofiles[fd]->content));
  ofiles[fd]->content = sh_string_new(size);

  return SL_ENONE;
}

sh_string * sl_get_content (SL_TICKET ticket)
{
  int fd;

  if (SL_ISERROR(fd = sl_read_ticket(ticket)))
    return (NULL);

  if (ofiles[fd] == NULL || fd != ofiles[fd]->fd || 
      ticket != ofiles[fd]->ticket || fd < 0)
    return (NULL);

  return (ofiles[fd]->content);
}

int sl_lock (SL_TICKET ticket)
{
  int fd;
  struct flock lock;
  int retval;
 
  SL_ENTER(_("sl_lock"));

  if (SL_ISERROR(fd = get_the_fd (ticket)))
    SL_IRETURN(fd, _("sl_lock"));

  lock.l_type   = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start  = 0;
  lock.l_len    = 0;

  /* F_SETLK returns if the lock cannot be obtained */
  do {
    retval = fcntl(fd, F_SETLK, &lock);
  } while (retval < 0 && errno == EINTR);

  if (retval < 0 && errno == EBADF)
    SL_IRETURN(SL_ETICKET, _("sl_lock"));
  else if (retval < 0)
    SL_IRETURN(SL_EBADFILE, _("sl_lock"));
  else
    SL_IRETURN(SL_ENONE, _("sl_lock"));
 }
 
int sl_close (SL_TICKET ticket) 
{
  register int fd;
  FILE * fp = NULL;

  SL_ENTER(_("sl_close"));

  if (SL_ISERROR(fd = get_the_fd (ticket)))
    SL_IRETURN(fd, _("sl_close"));

  if (ofiles[fd] != NULL)
    {
#if defined(HAVE_POSIX_FADVISE) && defined(HAVE_MINCORE) && defined(POSIX_FADV_DONTNEED)
      if (ofiles[fd]->flush == S_TRUE)
	{
	  posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	}
#endif
      if (ofiles[fd]->content)
	sh_string_destroy(&(ofiles[fd]->content));
      (void) free (ofiles[fd]->path);
      fp = ofiles[fd]->stream;
      (void) free (ofiles[fd]);
      ofiles[fd] = NULL;
    }

  /* This may fail, but what to do then ?
   */
  if (fp)
    {
      if (0 != fclose (fp)) /* within sl_close */
	{
	  TPT((0, FIL__, __LINE__, 
	       _("msg=<Error fclosing file.>, fd=<%d>, err=<%s>\n"), 
	       fd, strerror(errno)));
	}
    }
  else
    {
      if (0 != close(fd)) /* within sl_close */
	{
	  TPT((0, FIL__, __LINE__, 
	       _("msg=<Error closing file.>, fd=<%d>, err=<%s>\n"), 
	       fd, strerror(errno)));
	}
    }

  SL_IRETURN(SL_ENONE, _("sl_close")); 
}

int sl_close_fd (const char * file, int line, int fd)
{
  int ret = -1;

  SL_ENTER(_("sl_close_fd"));

  if (fd >= 0 && fd < MAXFD && ofiles[fd] != NULL) /* stale ofiles[fd] handle */
    {
      sl_strlcpy(badfd_orig_file, file, sizeof(badfd_orig_file));
      badfd_orig_line = line;
    }

  ret = close(fd); /* within sl_close_fd wrapper */

  SL_IRETURN(ret, _("sl_close_fd")); 
}

int sl_fclose (const char * file, int line, FILE * fp)
{
  int ret = -1;
  int fd;

  SL_ENTER(_("sl_fclose"));

  fd = fileno(fp);

  if (fd >= 0 && fd < MAXFD && ofiles[fd] != NULL) /* stale ofiles[fd] handle */
    {
      sl_strlcpy(badfd_orig_file, file, sizeof(badfd_orig_file));
      badfd_orig_line = line;
    }

  ret = fclose(fp); /* within sl_fclose wrapper */

  SL_IRETURN(ret, _("sl_fclose")); 
}

int sl_dropall(int fd, int except)
{
  while (fd < MAXFD)
    {
      if (ofiles[fd] != NULL && fd != except)
	{
	  if (ofiles[fd]->content)
	    sh_string_destroy(&(ofiles[fd]->content));
	  if (ofiles[fd]->path != NULL)
	    (void) free (ofiles[fd]->path);
	  (void) free (ofiles[fd]);
	  ofiles[fd] = NULL;
	}
      ++fd;
    }
  return 0;
}

int sl_dropall_dirty(int fd, int except)
{
  while (fd < MAXFD)
    {
      if (ofiles[fd] != NULL && fd != except)
	{
	  ofiles[fd] = NULL;
	}
      ++fd;
    }
  return 0;
}


int sl_unlink (SL_TICKET ticket) 
{
  register int fd;

  SL_ENTER(_("sl_unlink"));

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    SL_IRETURN(fd, _("sl_unlink"));

  if (retry_aud_unlink(FIL__, __LINE__, ofiles[fd]->path) < 0)
    SL_IRETURN(SL_EUNLINK, _("sl_unlink"));

  SL_IRETURN(SL_ENONE, _("sl_unlink")); 
}

  
int sl_seek (SL_TICKET ticket, off_t off_data) 
{
  register int fd;

  SL_ENTER(_("sl_seek"));

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    SL_IRETURN(fd, _("sl_seek"));

  if (lseek(fd, off_data, SEEK_SET) == (off_t)-1)
    SL_IRETURN(SL_EREWIND, _("sl_seek"));

  SL_IRETURN(SL_ENONE, _("sl_seek")); 
}
    
int sl_rewind (SL_TICKET ticket) 
{
  register int fd;

  SL_ENTER(_("sl_rewind"));

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    SL_IRETURN(fd, _("sl_rewind"));

  if (lseek (fd, 0L, SEEK_SET) == (off_t)-1)
    SL_IRETURN(SL_EREWIND, _("sl_rewind"));

  SL_IRETURN(SL_ENONE, _("sl_rewind")); 
}

int sl_forward (SL_TICKET ticket) 
{
  register int fd;

  SL_ENTER(_("sl_forward"));

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    SL_IRETURN(fd, _("sl_forward"));

  if (lseek (fd, 0L, SEEK_END) == (off_t)-1)
    SL_IRETURN(SL_EFORWARD, _("sl_forward"));

  SL_IRETURN(SL_ENONE, _("sl_forward")); 
}


int sl_sync (SL_TICKET ticket) 
{
  register int fd;

  SL_ENTER(_("sl_sync"));

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    SL_IRETURN(fd, _("sl_sync"));

  if (fsync (fd) == -1)
    SL_IRETURN(SL_ESYNC, _("sl_sync"));

  SL_IRETURN(SL_ENONE, _("sl_sync")); 
}

int sl_read_timeout_prep (SL_TICKET ticket)
{
  int fd;
  int sflags;

  SL_ENTER(_("sl_read_timeout_prep"));

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<ticket error> errno=<%d>"), fd));
      SL_IRETURN(fd, _("sl_read_timeout_prep"));
    }

  /* set to non-blocking mode 
   */
  sflags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
  retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags | O_NONBLOCK);

  SL_IRETURN(SL_ENONE, _("sl_read_timeout_prep"));
}


int sl_read_timeout_fd (int fd, void * buf_in, size_t count, 
			int timeout, int is_nonblocking)
{
  int sflags = 0;
  fd_set readfds;
  struct timeval tv;
  /* int sflags; */
  int retval;
  int error;

  int    byteread = 0;
  int    bytes    = 0;
  char * buf;

  time_t tnow;
  time_t tstart;
  time_t tdiff;
  extern volatile int sig_termfast;
 
  if (is_nonblocking == S_FALSE)
    {
      /* set to non-blocking mode 
       */
      sflags = retry_fcntl(FIL__, __LINE__, fd, F_GETFL, 0);
      retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags | O_NONBLOCK);
    }

  buf = (char *) buf_in;

  tstart = time(NULL);
  tdiff  = 0;

  while (count > 0)
    {
      FD_ZERO(&readfds);
      FD_SET(fd, &readfds);

      tv.tv_sec  = timeout - tdiff;
      tv.tv_usec = 0;
      
      retval = select (fd+1, &readfds, NULL, NULL, &tv);
      
      if (retval > 0)
	{
	  byteread = read (fd, buf, count);

	  if (byteread > 0) 
	    {
	      bytes += byteread; count -= byteread;
	      buf += byteread;
	      if (count == 0)
		break;
	    }  
	  else if (byteread == 0)
	    {
	      /* zero indicates end of file */
	      break;
	    }
	  else
	    {
	      if (errno == EINTR || errno == EAGAIN)
		{
		  retry_msleep(1, 0);
		  tnow  = time(NULL);
		  tdiff = tnow - tstart;
		  continue;
		}
	      else
		{
		  error = errno;
		  if (is_nonblocking == S_FALSE)
		      retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags);
		  TPT(( 0, FIL__, __LINE__, _("msg=<read error>")));
		  errno = error;
		  return (SL_EREAD);
		}
	    }
	}
      else if ((retval == -1) && (errno == EINTR || errno == EAGAIN))
	{
	  retry_msleep(1, 0);
	  tnow  = time(NULL);
	  tdiff = tnow - tstart;
	  continue;
	}
      else if (retval == 0)
	{
	  if (is_nonblocking == S_FALSE)
	      retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags);
	  TPT(( 0, FIL__, __LINE__, _("msg=<timeout>")));
	  errno = 0;
	  if (bytes > 0)
	    return ((int) bytes); 
	  return (SL_TIMEOUT);
	}
      else
	{
	  error = errno;
	  if (is_nonblocking == S_FALSE)
	      retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags);
	  TPT(( 0, FIL__, __LINE__, _("msg=<timeout>")));
	  errno = error;
	  return (SL_EREAD);
	}

      if (sig_termfast == 1) 
	{
	  if (is_nonblocking == S_FALSE)
	      retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags);
	  TPT(( 0, FIL__, __LINE__, _("msg=<terminated>")));
	  errno = 0;
	  return (SL_EREAD);
	}
	  
      tnow  = time(NULL);
      tdiff = tnow - tstart;

      if (tdiff > timeout)
	{
	  if (is_nonblocking == S_FALSE)
	      retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags);
	  TPT(( 0, FIL__, __LINE__, _("msg=<timeout>")));
	  errno = 0;
	  if (bytes > 0)
	    return ((int) bytes);
	  return (SL_TIMEOUT);
	}
    }

  if (is_nonblocking == S_FALSE)
    retry_fcntl(FIL__, __LINE__, fd, F_SETFL, sflags);
  return ((int) bytes);
}

int sl_read_timeout (SL_TICKET ticket, void * buf_in, size_t count, 
		     int timeout, int is_nonblocking)
{
  int    fd, retval;
 
  SL_ENTER(_("sl_read_timeout"));

  if (buf_in == NULL || SL_ISERROR(fd = get_the_fd(ticket)))
    {
      if (buf_in == NULL)
	{
	  TPT(( 0, FIL__, __LINE__, _("msg=<null buffer>")));
	  SL_IRETURN((SL_ENULL), _("sl_read_timeout"));
	}
      if (SL_ISERROR(fd = get_the_fd(ticket)))
	{
	  TPT(( 0, FIL__, __LINE__, _("msg=<ticket error> errno=<%d>"), fd));
	  SL_IRETURN((fd),  _("sl_read_timeout"));
	}
    }

  retval = sl_read_timeout_fd (fd, buf_in, count, timeout, is_nonblocking);
  SL_IRETURN((retval), _("sl_read_timeout"));
}


int sl_read (SL_TICKET ticket, void * buf_in, size_t count)
{
  int fd;
  int byteread = 0;
  int bytes    = 0;

  char * buf;

  SL_ENTER(_("sl_read"));

  if (count < 1)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<range error>")));
      SL_IRETURN((SL_ERANGE), _("sl_read"));
    }
  if (buf_in == NULL)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<null buffer>")));
      SL_IRETURN((SL_ENULL), _("sl_read"));
    }

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<ticket error> errno=<%d>"), fd));
      SL_IRETURN((fd), _("sl_read"));
    }

  buf = (char *) buf_in;

  do 
    {
      byteread = read (fd, buf, count);
      if (byteread > 0) 
	{
	  bytes += byteread; count -= byteread;
	  buf += byteread;
	}  
    } while ( byteread > 0 || 
	      ( byteread == -1 && (errno == EINTR || errno == EAGAIN)) 
	      );

 
  if (byteread == (-1))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<read error> errno=<%d>\n"), errno));
      SL_IRETURN((SL_EREAD), _("sl_read"));
    }
  SL_IRETURN((bytes), _("sl_read"));
}

int sl_read_fast (SL_TICKET ticket, void * buf_in, size_t count)
{
  int fd;
  int byteread = 0;

  char * buf;

  SL_ENTER(_("sl_read_fast"));

  if (count < 1)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<range error>")));
      SL_IRETURN((SL_ERANGE), _("sl_read_fast"));
    }
  if (buf_in == NULL)
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<null buffer>")));
      SL_IRETURN((SL_ENULL), _("sl_read_fast"));
    }

  if (SL_ISERROR(fd = get_the_fd(ticket)))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<ticket error> errno=<%d>"), fd));
      SL_IRETURN((fd), _("sl_read_fast"));
    }

  buf = (char *) buf_in;

  do 
    {
      byteread = read (fd, buf, count);
      if (byteread >= 0) 
	{
	  SL_IRETURN((byteread), _("sl_read_fast"));
	}  
    } while ( byteread == -1 && (errno == EINTR || errno == EAGAIN));

 
  if (byteread == (-1))
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<read error> errno=<%d>\n"), errno));
      SL_IRETURN((SL_EREAD), _("sl_read_fast"));
    }
  SL_IRETURN((0), _("sl_read_fast"));
}


int sl_write (SL_TICKET ticket, const void * msg_in, long nbytes)
{
  long bytewritten;
  long bytecount;
  int  fd;

  const char * msg; 

  SL_ENTER(_("sl_write"));

  if (nbytes < 1)
    SL_IRETURN(SL_ERANGE, _("sl_write"));
  if (msg_in == NULL)
    SL_IRETURN(SL_ENULL, _("sl_write"));
  if (SL_ISERROR(fd = get_the_fd(ticket)))
    SL_IRETURN(fd, _("sl_write"));

  msg = (const char *) msg_in;

  /* write
   */
  bytecount    = 0;

  while (bytecount < nbytes) 
    {    
      bytewritten = write (fd, msg, nbytes-bytecount);

      if (bytewritten > 0) 
	{
	  bytecount += bytewritten;
	  msg       += bytewritten;    /* move buffer pointer forward */
	}
      else if (bytewritten <= 0)
	{
	  if ( errno == EINTR || errno == EAGAIN) /* try again */
	      continue;
	  else 
	    SL_IRETURN(SL_EWRITE, _("sl_write"));
	}
    }
  SL_IRETURN(SL_ENONE, _("sl_write"));
}

int sl_write_line (SL_TICKET ticket, const void * msg, long nbytes)
{
  int  status;

  SL_ENTER(_("sl_write_line"));

  status = sl_write(ticket,  msg, nbytes); 
  if (!SL_ISERROR(status))
    status = sl_write(ticket,  "\n", 1);

  SL_IRETURN(status, _("sl_write_line"));
}

int sl_write_line_fast (SL_TICKET ticket, void * msg, long nbytes)
{
  int  status;
  char * p = (char *) msg;

  SL_ENTER(_("sl_write_line_fast"));

  /* Here nbytes is strlen(msg), so p[nbytes] is the terminating '\0'
   * Overwrite the terminator, write out, then write back the terminator.
   */
  p[nbytes] = '\n';
  status = sl_write(ticket,  msg, nbytes+1);
  p[nbytes] = '\0';

  SL_IRETURN(status, _("sl_write_line_fast"));
}


/* ---------------------------------------------------------------- 
 *
 *    Trustfile interface
 *
 * ---------------------------------------------------------------- */

extern uid_t rootonly[];
extern unsigned int   EUIDSLOT;
extern unsigned int   ORIG_EUIDSLOT;

extern char  tf_path[MAXFILENAME];	/* Error path for trust function. */
extern uid_t tf_euid;	                /* Space for EUID of process.     */

char * sl_error_string(int errorcode)
{

  switch (errorcode)
    {
    case SL_EBOGUS: 
      return _("Bogus file, modified during access");
    case SL_EWRITE: 
      return _("Write error");
    case SL_EREAD: 
      return _("Read error");
    case SL_ESYNC: 
      return _("Error in fsync()");
    case SL_EFORWARD: 
      return _("Error in lseek()");
    case SL_EREWIND: 
      return _("Error in lseek()");
    case SL_EUNLINK: 
      return _("Error in unlink()");
    case SL_EMEM: 
      return _("Out of memory");
    case SL_EINTERNAL: 
      return _("Internal error");
    case SL_EINTERNAL01: 
      return _("Internal error 01");
    case SL_EINTERNAL02: 
      return _("Internal error 02");
    case SL_EINTERNAL03: 
      return _("Internal error 03");
    case SL_EINTERNAL04: 
      return _("Internal error 04");
    case SL_EINTERNAL05: 
      return _("Internal error 05");
    case SL_EINTERNAL06: 
      return _("Internal error 06");
    case SL_EINTERNAL07: 
      return _("Internal error 07");
    case SL_EINTERNAL08: 
      return _("Internal error 08");
    case SL_EINTERNAL09: 
      return _("Internal error 09");
    case SL_EINTERNAL10: 
      return _("Internal error 10");
    case SL_EINTERNAL11: 
      return _("Internal error 11");
    case SL_EINTERNAL12: 
      return _("Internal error 12");
    case SL_ETICKET:
      return _("Bad ticket");
    case SL_EREPEAT: 
      return _("Illegal repeated use of function");
    case SL_ERANGE: 
      return _("Argument out of range");
    case SL_ENULL: 
      return _("Dereferenced NULL pointer");

    case SL_EBADUID: 
      return _("Owner not trustworthy");
    case SL_EBADGID:
      return _("Group writeable and member not trustworthy");
    case SL_EBADOTH:
      return _("World writeable");
    case SL_EISDIR:
      return _("Is a directory");
    case SL_EBADFILE:
      return _("File access error");
    case SL_EBADNAME:
      return _("Invalid filename (prob. too long or null)");

    case SL_ETRUNC:
      return _("Truncation occured");
    case SL_ESTAT:
      return _("stat() failed");
    case SL_EFSTAT:
      return _("fstat() failed");
    default:
      return _("Unknown error");
    }
}



char * sl_trust_errfile(void)
{
  return &tf_path[0];
}

extern uid_t tf_baduid;
uid_t   sl_trust_baduid(void)
{
  return tf_baduid;
}

extern gid_t tf_badgid;
gid_t   sl_trust_badgid(void)
{
  return tf_badgid;
}


static int trust_count = 0;

int  sl_trust_purge_user (void)
{
  unsigned int i;

  EUIDSLOT = ORIG_EUIDSLOT;
  trust_count = 0;

  for (i = EUIDSLOT; i < (EUIDSLOT + 15); ++i) 
    rootonly[i] = sh_uid_neg;
  return 0;
}

int  sl_trust_add_user (uid_t pwid)
{
  SL_ENTER(_("sl_trust_add_user"));

  if (trust_count == 15)
    SL_IRETURN(SL_ERANGE, _("sl_trust_add_user"));
  
  rootonly[EUIDSLOT] = pwid;
  ++EUIDSLOT;
  ++trust_count;

  SL_IRETURN(SL_ENONE, _("sl_trust_add_user"));
}

#include "sh_mem.h"
extern char * sh_util_strdup (const char * str);

struct sl_trustfile_store {
  char * filename;
  uid_t  teuid;
  struct sl_trustfile_store * next;
};

static struct sl_trustfile_store * sl_trusted_files = NULL;

static void sl_add_trusted_file(const char * filename, uid_t teuid)
{
  struct sl_trustfile_store *new = SH_ALLOC(sizeof(struct sl_trustfile_store));

  new->filename = sh_util_strdup (filename);
  new->teuid    = teuid;
  new->next     = sl_trusted_files;

  sl_trusted_files = new;
  return;
}

static const char * sl_check_trusted_file(const char * filename, uid_t teuid)
{
  struct sl_trustfile_store *new = sl_trusted_files;

  while (new)
    {
      if ((new->teuid == teuid) && (0 == strcmp(new->filename, filename)))
	return filename;
      new = new->next;
    }

  return NULL;
}

static void sl_clear_trusted_file(struct sl_trustfile_store * file)
{
  if (file)
    {
      if (file->next != NULL)
	sl_clear_trusted_file(file->next);
      SH_FREE(file->filename);
      SH_FREE(file);
    }
  return;
}

int sl_trustfile_euid(const char * filename, uid_t teuid)
{
  long          status;
  static size_t old = 0;
  static size_t now;

  SL_ENTER(_("sl_trustfile_euid"));

  tf_path[0] = '\0';
  if (filename == NULL || filename[0] == '\0')
    SL_IRETURN(SL_EBADNAME, _("sl_trustfile_euid"));

  now = time(NULL);

  if (now < (old + 300))
    {
      if (NULL != sl_check_trusted_file(filename, teuid))
	{
	  sl_strlcpy(tf_path, filename, sizeof(tf_path));
	  SL_IRETURN(SL_ENONE, _("sl_trustfile_euid"));
	}
    }
  else
    {
      sl_clear_trusted_file(sl_trusted_files);
      sl_trusted_files = NULL;
      old = now;
    }

  tf_euid = teuid;
  status = sl_trustfile(filename, NULL, NULL);
  if (status == SL_ENONE)
    sl_add_trusted_file(filename, teuid);
  SL_IRETURN(status, _("sl_trustfile_euid"));
}

/* ---------------------------------------------------------------- 
 *
 *    Overflow tests
 *
 * ---------------------------------------------------------------- */

#ifndef SIZE_MAX
#define SIZE_MAX              (4294967295U)
#endif

int sl_ok_muli (int a, int b) /* a*b */
{
  if ((b == 0) || (a >= (INT_MIN / b) && a <= (INT_MAX / b)))
    return S_TRUE; /* no overflow */
  return S_FALSE;
}

int sl_ok_muls (size_t a, size_t b) /* a*b */
{
  if ((b == 0) || (a <= (SIZE_MAX / b)))
    return S_TRUE; /* no overflow */
  return S_FALSE;
}

int sl_ok_divi (int a, int b) /* a/b */
{
  (void) a;
  if (b != 0)
    return S_TRUE; /* no overflow */
  return S_FALSE;
}

int sl_ok_addi (int a, int b) /* a+b */
{
  if (a >= 0 && b >= 0)
    {
      if (a <= (INT_MAX - b))
	return S_TRUE; /* no overflow */
      else
	return S_FALSE;
    }
  else if (a < 0 && b < 0)
    {
      if (a >= (INT_MIN - b))
	return S_TRUE; /* no overflow */
      else
	return S_FALSE;
    }
  return S_TRUE;
}

int sl_ok_adds (size_t a, size_t b) /* a+b */
{
  if (a <= (SIZE_MAX - b))
    return S_TRUE; /* no overflow */
  else
    return S_FALSE;
}

int sl_ok_subi (int a, int b) /* a-b */
{
  if (a >= 0 && b < 0)
    {
      if (a <= (INT_MAX + b))
	return S_TRUE; /* no overflow */
      else
	return S_FALSE;
    }
  else if (a < 0 && b >= 0)
    {
      if (a >= (INT_MIN + b))
	return S_TRUE; /* no overflow */
      else
	return S_FALSE;
    }
  return S_TRUE;
}
