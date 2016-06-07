/* --------------------------------------------------------------
 * 
 * The developement of this library has been stimulated by reading 
 * a paper on 'Robust Programming' by Matt Bishop, although
 * not all of his ideas might be implemented in the same 
 * strictness as discussed in the paper.
 *
 * --------------------------------------------------------------
 */

#ifndef SL_SLIB_H
#define SL_SLIB_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

#include "config_xor.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sh_string.h"

/****************

		 -- Defined in config.h. --

		 #ifndef _(string)
		 #define _(string) string
		 #endif
		 
		 #ifndef N_(string)
		 #define N_(string) string
		 #endif

*****************/


/* --------------------------------------------------------------
 * 
 * Typedefs, global variables, macros.
 *
 * --------------------------------------------------------------
 */

extern  long int sl_errno;              /* Global error variable.         */


/* The ticketing system; used to hide internals from the
 * programmer.
 */
typedef long int SL_TICKET;             /* Unique ID for opened files.    */


/*
 * TRUE, FALSE
 */
#if !defined(S_TRUE)
#define S_TRUE  1
#define S_FALSE 0
#endif

#define SH_GRBUF_SIZE   4096
#define SH_PWBUF_SIZE  32768


#if defined(__GNUC__) && (__GNUC__ >= 3)
#undef  SL_GNUC_CONST
#define SL_GNUC_CONST   __attribute__((const))
#else
#undef  SL_GNUC_CONST
#define SL_GNUC_CONST
#endif

/*
 *  The following macros are provided:
 *  
 *  SL_ISERROR(x)       TRUE if return status of 'x' is an error code.
 *  SL_REQUIRE(x, xstr) Abort if 'x' is false.
 *  SL_ENTER(s)         Trace entry in    function 's'.
 *  SL_RETURN(x, s)     Trace return from function 's'.
 */


/*
 * The error codes.
 */
#define SL_ENONE         0

#define SL_ENULL     -1024     /* Invalid use of NULL pointer.         */
#define SL_ERANGE    -1025     /* Argument out of range.               */
#define SL_ETRUNC    -1026     /* Result truncated.                    */
#define SL_EREPEAT   -1027     /* Illegal repeated use of function.    */

#define SL_EINTERNAL -1028     /* Internal error.                      */
#define SL_ETICKET   -1029     /* Bad ticket.                          */
#define SL_EBADFILE  -1030     /* File access error. Check errno.      */
#define SL_EBOGUS    -1031     /* Bogus file.                          */
#define SL_EMEM      -1032     /* Out of memory.                       */
#define SL_EUNLINK   -1033     /* Unlink error. Check errno.           */
#define SL_EREWIND   -1034     /* Rewind error. Check errno.           */
#define SL_EFORWARD  -1035     /* Forward error. Check errno.          */
#define SL_EREAD     -1036     /* Read error. Check errno.             */
#define SL_EWRITE    -1037     /* Write error. Check errno.            */
#define SL_ESYNC     -1038     /* Write error. Check errno.            */

#define SL_EBADNAME  -1040     /* Invalid name.                        */
#define SL_ESTAT     -1041     /* stat of file failed. Check errno.    */
#define SL_EFSTAT    -1042     /* fstat of file failed. Check errno.   */

#define SL_EBADUID   -1050	/* Owner not trustworthy.              */
#define SL_EBADGID   -1051	/* Group writeable and not trustworthy.*/
#define SL_EBADOTH   -1052	/* World writeable.                    */

#define SL_TOOMANY   -1053      /* Too many open files                 */
#define SL_TIMEOUT   -1054      /* Timeout in read                     */

#define SL_EISDIR    -1055      /* Is a directory                      */

#define SL_EINTERNAL01 -1061    /* Internal error.                      */
#define SL_EINTERNAL02 -1062    /* Internal error.                      */
#define SL_EINTERNAL03 -1063    /* Internal error.                      */
#define SL_EINTERNAL04 -1064    /* Internal error.                      */
#define SL_EINTERNAL05 -1065    /* Internal error.                      */
#define SL_EINTERNAL06 -1066    /* Internal error.                      */
#define SL_EINTERNAL07 -1067    /* Internal error.                      */
#define SL_EINTERNAL08 -1068    /* Internal error.                      */
#define SL_EINTERNAL09 -1069    /* Internal error.                      */
#define SL_EINTERNAL10 -1070    /* Internal error.                      */
#define SL_EINTERNAL11 -1071    /* Internal error.                      */
#define SL_EINTERNAL12 -1072    /* Internal error.                      */

/*
 * All int functions return SL_NONE on success.
 */

#ifdef  __cplusplus
extern "C" {
#endif

  int dlog (int flag, const char * file, int line, const char *fmt, ...);

  char * sl_get_errmsg(void);

  /* ---------------------------------------------------------------- 
   *
   *    Heap consistency routines
   *
   * ---------------------------------------------------------------- */

  int sl_test_heap(void);

  /* ---------------------------------------------------------------- 
   *
   *    Capability routines
   *
   * ---------------------------------------------------------------- */

  extern int sl_useCaps;

  int sl_drop_cap (void);
  int sl_drop_cap_sub(void);
  int sl_get_cap_sub(void);
  int sl_drop_cap_qdel(void);
  int sl_get_cap_qdel(void);

  /* ---------------------------------------------------------------- 
   *
   *    String handling routines
   *
   * ---------------------------------------------------------------- */

  /*
   * A memset that does not get optimized away
   */
  void *sl_memset(void *s, int c, size_t n);
#if !defined(SH_REAL_SET)
#undef  memset
#define memset sl_memset
#endif

  /* 
   * Copy src to dst. siz is the length of dst.
   */
  int sl_strlcpy(char * dst, /*@null@*/const char * src, size_t siz);

  /* 
   * Append src to dst. siz is the length of dst.
   */
  int sl_strlcat(char * dst, /*@null@*/const char *src,  size_t siz);

  /*
   * An implementation of vsnprintf. va_start/va_end are in the caller
   * function.
   */
  int sl_vsnprintf(char *str, size_t n,
		   const char *format, va_list vl );

  /*
   * An implementation of snprintf.
   */
  int sl_snprintf(char *str, size_t n,
		  const char *format, ... );
  
  /*
   * A robust drop-in replacement of strncpy. strlcpy is preferable.
   */
  char * sl_strncpy(/*@out@*/char *dst, const char *src, size_t size);

  /*
   * Robust strncat.
   */
  char * sl_strncat(char *dst, const char *src, size_t n);

  /*
   * strstr
   */
  char * sl_strstr (const char * haystack, const char * needle); 

  /*
   * robust strn[case]cmp replacement
   */
  int sl_strncmp(const char * a, const char * b, size_t n);

  int sl_strncasecmp(const char * a, const char * b, size_t n);

  /*
   * robust strcmp replacement
   */
  int sl_strcmp(const char * a, const char * b);

  /*
   * robust strcasecmp replacement
   */
  int sl_strcasecmp(const char * one, const char * two);

  /*
   * robust strlen replacement
   */
#define sl_strlen(arg) ((arg == NULL) ? 0 : (strlen(arg)))

  /* ---------------------------------------------------------------- 
   *
   *    Privilege handling routines
   *
   * ---------------------------------------------------------------- */

  /*
   * ONE OF THE FOLLOWING THREE FUNCTIONS
   * SHOULD BE CALLED BEFORE ANY OTHER OF THE 
   * UID HANDLING FUNCTIONS.
   */
  int sl_policy_get_user(const char *username);  /* drop SUID to <username>  */ 
  int sl_policy_get_real(char *username);  /* drop privs to <username> */
  int sl_policy_get_root(void);            /* drop SUID to root        */

  /*
   * If not using one of the above, use this function, 
   * and then call sh_unset_suid().
   * This function saves the uid's.
   * It calls abort() on error.
   */
  int sl_save_uids(void);

  /*
   * This function returns the saved euid.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_get_euid(/*@out@*/uid_t * ret);
  uid_t sl_ret_euid(void);

  /*
   * This function returns the saved egid.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_get_egid(/*@out@*/gid_t * ret);

  /*
   * This function returns the saved current ruid.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_get_ruid(/*@out@*/uid_t * ret);
  
  /*
   * This function returns the saved current rgid.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_get_rgid(gid_t * ret);

  /*
   * This function returns the saved original ruid.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_get_ruid_orig(uid_t * ret);

  /*
   * This function returns the saved original rgid.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_get_rgid_orig(gid_t * ret);

  /*
   * This function returns true if the program is SUID.
   * It calls abort() if the uid's are not saved already.
   */
  int sl_is_suid(void);

  /*
   * This function sets the effective uid 
   * to the saved effective uid.
   */
  int sl_set_suid (void);

  /*
   * This function sets the effective uid to the real uid.
   */
  int sl_unset_suid (void);

  /* 
   * This function drops SUID privileges irrevocably.
   */
  int sl_drop_privileges(void);

  /* ---------------------------------------------------------------- 
   *
   *    File handling routines
   *
   * ---------------------------------------------------------------- */

#define SL_OFILE_SIZE 32

  char * sl_check_badfd();
  char * sl_check_stale();

  /* Create a file record for an open file
   */
  SL_TICKET sl_make_ticket (const char * ofile, int oline,
			    int fd, const char * filename, FILE * stream);
 
  /* Get the pointer to a stream. If none exists yet, open it
   */
  FILE * sl_stream (SL_TICKET ticket, char * mode);

  /* Open for writing.
   */
  SL_TICKET  sl_open_write       (const char * ofile, int oline,
				  const char * fname, int priviledge_mode);

  /* Open for reading.
   */
  SL_TICKET  sl_open_read        (const char * ofile, int oline,
				  const char * fname, int priviledge_mode);

  /* Drop from cach when closing
   */
  int sl_set_drop_cache(const char * str);

  /* Open for reading w/minimum checking.
   */
  SL_TICKET  sl_open_fastread    (const char * ofile, int oline,
				  const char * fname, int priviledge_mode);

  /* Open for read and write.
   */
  SL_TICKET  sl_open_rdwr        (const char * ofile, int oline,
				  const char * fname, int priviledge_mode);

  /* Open for read and write, fail if file exists.
   */
  SL_TICKET sl_open_safe_rdwr    (const char * ofile, int oline,
				  const char * fname, int priv);

  /* Open for write, truncate.
   */
  SL_TICKET  sl_open_write_trunc (const char * ofile, int oline,
				  const char * fname, int priviledge_mode);

  /* Open for read and write, truncate.
   */
  SL_TICKET  sl_open_rdwr_trunc  (const char * ofile, int oline,
				  const char * fname, int priviledge_mode);

  /* Initialize the content sh_string.
   */
  int sl_init_content (SL_TICKET ticket, size_t size);

  /* Get the (pointer to) the content sh_string.
   */
  sh_string * sl_get_content (SL_TICKET ticket);

  /* Lock file (uses fcntl F_SETLK).
   */
  int sl_lock (SL_TICKET ticket);

  /* Close file.
   */
  int sl_close (SL_TICKET ticket);

  /* Close file descriptor.
   */
  int sl_close_fd (const char * file, int line, int fd);

  /* Close stream.
   */
  int sl_fclose (const char * file, int line, FILE * fp);

  /* Unlink file.
   */
  int sl_unlink (SL_TICKET ticket);

  /* Rewind file.
   */
  int sl_rewind (SL_TICKET ticket);

  /* Seek file.
   */
  int sl_seek (SL_TICKET ticket, off_t off_data);
 
  /* Forward file.
   */
  int sl_forward (SL_TICKET ticket);

  /* Sync file.
   */
  int sl_sync (SL_TICKET ticket);

  /* Read file.
   */
  int sl_read (SL_TICKET ticket, void * buf, size_t count);

  int sl_read_timeout_prep (SL_TICKET ticket);

  int sl_read_timeout_fd (int fd, void * buf, 
			  size_t count, int timeout, int is_nonblocking);

  int sl_read_timeout (SL_TICKET ticket, void * buf, 
		       size_t count, int timeout, int is_nonblocking);

  int sl_read_fast (SL_TICKET ticket, void * buf_in, size_t count);

  /* Write file.
   */
  int sl_write (SL_TICKET ticket, const void * msg, long nbytes);

  /* Write file, terminate with newline.
   */
  int sl_write_line (SL_TICKET ticket, const void * msg, long nbytes);

  /* As above, but only for non-constant strings.
   */
  int sl_write_line_fast (SL_TICKET ticket, void * msg, long nbytes);

  /* Drop all metadata for file descriptors >= fd.
   */
  int sl_dropall(int fd, int except);
  int sl_dropall_dirty(int fd, int except); /* don't deallocate */

  /* Check whether file is trustworthy.
   */
  int sl_trustfile(const char * path, uid_t * ok, uid_t * bad);

  /* Check whether file is trustworthy.
   */
  int sl_trustfile_euid(const char * filename, uid_t euid);

  /* purge list of trusted users
   */
  int  sl_trust_purge_user (void);

  /* Add a trusted user.
   */
  int  sl_trust_add_user (uid_t pwid);

  /* Get error string.
   */
  char * sl_error_string(int errorcode);

  /* Get error file.
   */
  char * sl_trust_errfile(void);

  /* Overflow tests
   */
  int sl_ok_muli (int a, int b) SL_GNUC_CONST;
  int sl_ok_divi (int a, int b) SL_GNUC_CONST;
  int sl_ok_addi (int a, int b) SL_GNUC_CONST;
  int sl_ok_subi (int a, int b) SL_GNUC_CONST;

  int sl_ok_muls (size_t a, size_t b) SL_GNUC_CONST;
  int sl_ok_adds (size_t a, size_t b) SL_GNUC_CONST;


#ifdef  __cplusplus
}
#endif

/* Privilege modes for file access.
 */
#define SL_YESPRIV 0x33
#define SL_NOPRIV  0x34

/* Suitable for Linux
 */
#define MAXFILENAME	4096


/*
 * This macro is TRUE if (x) < 0.
 */
#define SL_ISERROR(x) ((long)(x) < 0)

#if defined(WITH_TPT) 
#define TPT(arg) dlog arg ;
#else
#define TPT(arg)
#endif


/*
 * The 'require' macro.
 */
#define SL_REQUIRE(assertion, astext)                  \
do {                                                   \
    /*@i@*/ if (assertion) ;                           \
    else {                                             \
        dlog(0, FIL__, __LINE__, SDG_AFAIL,            \
                 FIL__, __LINE__, astext);             \
        _exit(EXIT_FAILURE);                           \
    }                                                  \
} while (0)


/*
 * The enter macro. Prints the trace if TRACE is on.
 */
extern int slib_do_trace;
extern int slib_trace_fd;

#if defined(SL_DEBUG)
#define SL_ENTER(s)  sl_stack_push(s, FIL__, __LINE__);
#else
#define SL_ENTER(s)  if (slib_do_trace != 0) sl_trace_in(s, FIL__, __LINE__);
#endif

/*
 * The return macro.
 */
#if defined(SL_DEBUG)
#ifndef S_SPLINT_S
#define SL_RETURN(x, s)   \
do {                      \
   sl_stack_pop(s, FIL__, __LINE__);       \
   return(x);      \
} while(0)
#else
/*@notfunction@*/
#define SL_RETURN(x, s) return(x);
#endif  /* S_SPLINT_S */
#else
#ifndef S_SPLINT_S
#define SL_RETURN(x, s)   \
do {                      \
   if (slib_do_trace != 0)     \
     sl_trace_out(s, FIL__, __LINE__);     \
   return(x);      \
} while(0)
#else
/*@notfunction@*/
#define SL_RETURN(x, s) return(x);
#endif  /* S_SPLINT_S */
#endif  /* SL_RETURN macro */

#if defined(SL_DEBUG)
#define SL_RET0(s)      \
do {                    \
      sl_stack_pop(s, FIL__, __LINE__);  \
      return;    \
} while(0)
#else
#ifndef S_SPLINT_S
#define SL_RET0(s)      \
do {                    \
   if (slib_do_trace != 0)   \
     sl_trace_out(s, FIL__, __LINE__);   \
   return;       \
} while(0)
#else
/*@notfunction@*/
#define SL_RET0(s) return;
#endif  /* S_SPLINT_S */
#endif  /* SL_RETURN macro */

#if defined(SL_DEBUG)
void sl_stack_push(char * c, char * file, int line);
void sl_stack_pop(char * c, char * file, int line);
void sl_stack_print(void);
#endif
void sl_trace_in   (const char * str, const char * file, int line);
void sl_trace_out  (const char * str, const char * file, int line);
int  sl_trace_file (const char * str);
int  sl_trace_use  (const char * str);




/*
 * The internal return macro. Sets sl_errno to the return value.
 */

#if defined(SL_DEBUG)
#define SL_IRETURN(x, s)                                            \
do {                                                                \
   if((long)(x) < 0) {                                              \
      TPT((0,    FIL__, __LINE__, SDG_ERROR, (long)(x)))            \
      sl_errno=(x);                                                 \
    }                                                               \
   sl_stack_pop(s, FIL__, __LINE__);                              \
   if (1) return(x);                                                \
} while(0)
#else
#define SL_IRETURN(x, s)             \
do {                                 \
   if ((long)(x) < 0) sl_errno=(x);  \
   if (slib_do_trace)                \
     sl_trace_out(s, FIL__, __LINE__);   \
   if (1) return(x);                 \
} while(0)

#endif  /* SL_IRETURN macro */



/* slib.h */
#endif 




