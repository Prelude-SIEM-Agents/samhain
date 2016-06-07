/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2015 Rainer Wichmann                                      */
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "samhain.h"
#include "sh_utils.h"
#include "sh_dbIO_int.h"
#include "sh_hash.h"
#include "sh_dbIO.h"
#include "sh_gpg.h"
#include "sh_tiger.h"
#include "sh_xfer.h"
#include "sh_pthread.h"
#include "sh_socket.h"
#include "sh_files.h"

#undef  FIL__
#define FIL__  _("sh_dbIO.c")

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) 

/* external prototypes                                                     */

extern int get_the_fd (SL_TICKET ticket);

SH_MUTEX_EXTERN(mutex_hash);

/******************************************************************
 *
 * Get a single line
 *
 ******************************************************************/
static FILE * sh_fin_fd = NULL;

int sh_dbIO_getline (FILE * fd, char * line, const size_t sizeofline)
{
  size_t  n = 0;

  SL_REQUIRE(sizeofline >= SH_MINIBUF, _("sizeofline >= SH_MINIBUF"));

  if (NULL != fgets(line, sizeofline, fd))
    {
      n = strlen(line);
      if (n > 0 && line[n-1] == '\n') {
	n--; line[n] = '\0';
      }
    } 
  else {
    line[0] = '\0';
    return -1;
  }

  return n;
}

/******************************************************************
 *
 * Fast forward to start of data
 *
 ******************************************************************/

static void reopen_fin_fd(SL_TICKET fd)
{
  if (sh_fin_fd != NULL)
    {
      sl_fclose (FIL__, __LINE__, sh_fin_fd);
      sh_fin_fd = NULL;
    }

  sh_fin_fd = fdopen(dup(get_the_fd(fd)), "rb");
  return;
}


static int seek_sof(FILE * fd, char * line, int size, const char * file)
{
  long i;

  while (1) 
    {
      i =  sh_dbIO_getline (fd, line, size);
      if (i < 0 ) 
	{
	  SH_FREE(line);
	  dlog(1, FIL__, __LINE__, 
	       _("The file signature database: %s does not\ncontain any data, or the start-of-file marker is missing (unlikely,\nunless modified by hand).\n"),
	       (NULL == file) ? _("(null)") : file);
	       
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
			   ( (NULL == file) ? _("(null)") : file)
			   );
	  return -1;
	}

#if defined(SH_STEALTH)
      if (0 == sl_strncmp (line, N_("[SOF]"), 5)) 
#else
      if (0 == sl_strncmp (line, _("[SOF]"),  5)) 
#endif
	break;
    }
  fflush(fd);
  return 0;
}

static int sh_dbIO_setdataent (SL_TICKET fd, char * line, int size, 
			       const char * file)
{
  int retval;

  SL_ENTER(_("sh_dbIO_setdataent"));

  sl_rewind (fd);
  reopen_fin_fd(fd);

  if (!sh_fin_fd)
    {
      dlog(1, FIL__, __LINE__, 
	   _("The file signature database: %s is not readable.\n"),
	   (NULL == file) ? _("(null)") : file);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_P_NODATA,
		       ( (NULL == file) ? _("(null)") : file)
		       );
      SL_RETURN( -1, _("sh_dbIO_setdataent"));
    }

  retval = seek_sof(sh_fin_fd, line, size, file);
  SL_RETURN( retval, _("sh_dbIO_setdataent"));
}

static int sh_dbIO_setdataent_old (SL_TICKET fd, char * line, int size, 
				   const char * file)
{
  FILE * fdp;
  
  SL_ENTER(_("sh_dbIO_setdataent_old"));

  sl_rewind (fd);
  fdp = sl_stream(fd, "r+");
  if (0 != seek_sof(fdp, line, size, file))
    SL_RETURN( SL_EREAD, _("sh_dbIO_setdataent_old"));

  lseek(fileno(fdp), ftello(fdp), SEEK_SET);

  if (0 != ftruncate(fileno(fdp), ftello(fdp)))
    {
      char ebuf[SH_ERRBUF_SIZE];
      int errnum = errno;
      sh_error_message(errnum, ebuf, sizeof(ebuf));
      sh_error_handle ((-1), FIL__, __LINE__, errnum, MSG_E_SUBGEN,
		       ebuf, _("sh_dbIO_setdataent_old") );
      SL_RETURN( SL_EWRITE, _("sh_dbIO_setdataent_old"));
    }
  SL_RETURN( 0, _("sh_dbIO_setdataent_old"));
}

/******************************************************************
 *
 * IO helper functions
 *
 ******************************************************************/


static UINT32 * swap_32 (UINT32 * iptr)
{
#ifdef WORDS_BIGENDIAN
  unsigned char swap;
  unsigned char * ii = (unsigned char *) iptr;
  swap = ii[0]; ii[0] = ii[3]; ii[3] = swap;
  swap = ii[1]; ii[1] = ii[2]; ii[2] = swap;
  return iptr;
#else
  return iptr;
#endif
}

static UINT64 *  swap_64 (UINT64 * iptr)
{
#ifdef WORDS_BIGENDIAN
#ifdef UINT64_IS_32
  swap_32 ((UINT32*) iptr);
#else
  unsigned char swap;
  unsigned char * ii = (unsigned char *) iptr;
  swap = ii[0]; ii[0] = ii[7]; ii[7] = swap;
  swap = ii[1]; ii[1] = ii[6]; ii[6] = swap;
  swap = ii[2]; ii[2] = ii[5]; ii[5] = swap;
  swap = ii[3]; ii[3] = ii[4]; ii[4] = swap;
#endif
  return iptr;
#else
  return iptr;
#endif
}

static unsigned short *  swap_short (unsigned short * iptr)
{
#ifdef WORDS_BIGENDIAN
  if (sizeof(short) == 4)
    swap_32 ((UINT32*) iptr);
  else
    {
      /* alignment problem */
      unsigned char swap;
      static unsigned short ooop;
      unsigned char * ii;
      ooop = *iptr;
      ii = (unsigned char *) &ooop;
      swap = ii[0]; ii[0] = ii[1]; ii[1] = swap;
      return &ooop;
    }
  return iptr;
#else
  return iptr;
#endif
}

static void swap_data(sh_filestore_t * ft)
{
  swap_32(&(ft->mode));
  swap_32(&(ft->linkmode));
  swap_64(&(ft->dev));
  swap_64(&(ft->rdev));
  swap_32(&(ft->hardlinks));
  swap_32(&(ft->ino));
  swap_64(&(ft->size));
  swap_64(&(ft->atime));
  swap_64(&(ft->mtime));
  swap_64(&(ft->ctime));
  swap_32(&(ft->owner));
  swap_32(&(ft->group));
  swap_32(&(ft->checkflags));
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  swap_32(&(ft->attributes));
#endif
  ft->mark = *(swap_short(&(ft->mark)));
  return;
}

#define QUOTE_CHAR '='

char * unquote_string (const char * str, size_t len)
{
  int    i = 0, t1, t2;
  char * tmp = NULL;
  size_t l2, j, k = 0;

  SL_ENTER(_("unquote_string"));

  if (str != NULL)
    {
      l2  = len - 2;
      tmp = SH_ALLOC(len + 1);

      for (j = 0; j <= len; ++j)
	{
	  if (str[j] != QUOTE_CHAR)
	    {
	      tmp[k] = str[j];
	    }
	  else if (str[j] == QUOTE_CHAR && j < l2)
	    {
	      t1 = sh_util_hexchar(str[j+1]);
	      t2 = sh_util_hexchar(str[j+2]);
	      if ((t1|t2) >= 0)
		{
		  i = 16 * t1 + t2;
		  tmp[k] = i; 
		  j += 2;
		}
	      else
		{
		  tmp[k] = str[j];
		}
	    }
	  else
	    tmp[k] = str[j];
	  ++k;
	}
    }
  SL_RETURN(tmp, _("unquote_string"));
}

static char * int2hex (unsigned char i, char * i2h)
{
  static char hexchars[] = "0123456789ABCDEF";

  i2h[0] = hexchars[(((i) & 0xF0) >> 4)]; /* high */
  i2h[1] = hexchars[((i) & 0x0F)];        /* low  */

  return i2h;
}

char * quote_string (const char * str, size_t len)
{
  char * tmp;
  char * tmp2;
  size_t l2, j, i = 0, k = 0;
  char   i2h[2];

  SL_ENTER(_("quote_string"));

  if (str == NULL)
    {
      SL_RETURN(NULL, _("quote_string"));
    }

  for (j = 0; j < len; ++j)
    if (str[j] == '\n' || str[j] == QUOTE_CHAR) ++i;

  l2 = len + 1;
  if (sl_ok_muls(3, i) && sl_ok_adds(l2, (3*i)))
    {
      tmp = SH_ALLOC(len + 1 + 3*i);
    }
  else
    {
      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_E_SUBGEN,
		      _("integer overflow"), 
		      _("quote_string"));
      SL_RETURN(NULL, _("quote_string"));
    }

  for (j = 0; j <= len; ++j)
    {
      if (str[j] == '\n')
	{
	  tmp2 = int2hex((unsigned char) '\n', i2h);
	  tmp[k] = QUOTE_CHAR; ++k;
	  tmp[k] = tmp2[0];    ++k;
	  tmp[k] = tmp2[1];
	}
      else if (str[j] == QUOTE_CHAR)
	{
	  tmp2 = int2hex((unsigned char) QUOTE_CHAR, i2h);
	  tmp[k] = QUOTE_CHAR; ++k;
	  tmp[k] = tmp2[0];    ++k;
	  tmp[k] = tmp2[1];
	}
      else
	{
	  tmp[k] = str[j];
	}
      ++k;
    }
  SL_RETURN(tmp, _("quote_string"));
}

static char * unquote_path(char * line, long i)
{
  char * tmp  = unquote_string (line, i);
  size_t len  = sl_strlen(tmp)+1;
  char * path = SH_ALLOC(len);

  (void) sl_strlcpy (path, tmp, len);
  if (tmp)
    SH_FREE(tmp);
  if (len > 1) {
    if (path[len-2] == '\n')
      path[len-2] = '\0';
  }
  return path;
}

/******************************************************************
 *
 * Read next record and return it
 *
 ******************************************************************/

static void corrupt_record(char * file, int line, const char * filepath)
{
  dlog(1, file, line, 
       _("There is a corrupt record in the file signature database: %s\n"),
       (NULL == filepath)? _("(null)") : filepath);
  sh_error_handle ((-1), file, line, 0, MSG_E_SUBGPATH,
		   _("Corrupt record in file signature database"), 
		   _("sh_dbIO_getdataent"),
		   ( (NULL == filepath) ? _("(null)") : filepath) );
  return;
}

static void wrong_version(char * file, int line, const char * filepath)
{
  dlog(1, file, line, 
       _("There is a record with a bad version number in the file signature database: %s\n"),
       (NULL == filepath) ? _("(null)") : filepath);
  sh_error_handle((-1), file, line, 0, MSG_E_SUBGPATH,
		  _("Record with bad version number in file signature database"), 
		  _("sh_dbIO_getdataent"),
		  (NULL == filepath) ? _("(null)") : filepath);
  return;
}

static void hexdump(unsigned char * data, size_t size)
{
  unsigned int count =0;
  char ith[3];

  do {
    int2hex(data[count], ith); ith[2] = '\0';
    printf("%2s", ith);
    ++count;
    if (count % 40 == 0) putc('\n', stdout);
  } while (count < size);
}

static size_t dbIO_fread_struct (sh_filestore_t * ptr, FILE *stream, 
				 const char * path, int * errflag)
{
  sh_filestore_old_t old_struct;
  fpos_t position;
  static int oldflag = -1;

 start:
  if (oldflag != -1) /* 'initialized' case first */
    {
      if (oldflag == 0)
	return fread (ptr, sizeof(sh_filestore_t), 1, stream);

      else
	{
	  unsigned short mark;
	  if (1 != fread (&old_struct, sizeof(old_struct), 1, stream))
	    return 0;

	  /* set mark to current version */
	  mark = old_struct.mark;
	  mark = *(swap_short(&(mark)));
	  if ((mark & ~REC_FLAGS_MASK) != OLD_REC_MAGIC)
	    {
	      sh_filestore_old_t try_struct;
	      char try[5];

	      if (1 == 0)
		hexdump((unsigned char *)&old_struct, sizeof(old_struct));
	      memset(&try_struct, '\0', sizeof(try_struct));
	      if (!memcmp(&old_struct, &try_struct, sizeof(try_struct)))
		return 0; /* NULL read */
	      if (1 != fread (try, sizeof(try), 1, stream))
		return 0;
	      if (feof(stream))
		return 0;

	      wrong_version(FIL__, __LINE__, path);
	      *errflag = -1;
	      return 0;
	    }
	  if ((mark & REC_FLAGS_ATTR) != 0)
	    mark = REC_MAGIC|REC_FLAGS_ATTR;
	  else
	    mark = REC_MAGIC;
	  mark = *(swap_short(&(mark)));
	  old_struct.mark = mark;

	  /* copy into current struct version */
	  memcpy(ptr, &old_struct, sizeof(old_struct));
	  ptr->checkflags = 0;
	  return 1;
	}
    }
  else /* not initialized yet, test DB version */
    {
      if (0 == fgetpos(stream, &position))
	{
	  unsigned short mark;

	  if (1 != fread (&old_struct, sizeof(old_struct), 1, stream))
	    return 0;

	  mark = old_struct.mark;
	  mark = *(swap_short(&(mark)));
	  if ((mark & ~REC_FLAGS_MASK) == REC_MAGIC)
	    oldflag = 0;
	  else if ((mark & ~REC_FLAGS_MASK) == OLD_REC_MAGIC)
	    oldflag = 1;
	  else
	    {
	      wrong_version(FIL__, __LINE__, path);
	      *errflag = -1;
	      return 0;
	    }

	  /* return to previous position and read data */
	  if (0 != fsetpos(stream, &position))
	    return 0;
	  goto start;
	}
      return 0;
    }
}

int sig_end_detected (void * ft)
{
  char * str = (char *) ft;
  char cmp[SH_MINIBUF];

  sl_strlcpy(cmp, _("-----BEGIN PGP SIGNATURE-----"), sizeof(cmp));

  if ( 0 == memcmp(str, cmp, strlen(cmp)) ) 
    return S_TRUE;
  return S_FALSE;
}

static sh_file_t *  sh_dbIO_getdataent (char * line, int size, 
					const char * filepath, int * errflag)
{
  sh_file_t * p;
  sh_filestore_t ft;
  long i;
  char * fullpath;
  char * linkpath;
  char * attr_string = NULL;

  SL_ENTER(_("sh_dbIO_getdataent"));

  *errflag = 0;

  p = SH_ALLOC(sizeof(sh_file_t));

  /* Read next record -- Part One 
   */
  if (1 != dbIO_fread_struct (&ft, sh_fin_fd, filepath, errflag))
    {
      SH_FREE(p);
      SL_RETURN( NULL, _("sh_dbIO_getdataent"));
    }

  ft.mark = *(swap_short(&(ft.mark)));

  if ((ft.mark & ~REC_FLAGS_MASK) != REC_MAGIC)
    {
      if (sig_end_detected(&ft))
	{
	  SH_FREE(p);
	  SL_RETURN( NULL, _("sh_dbIO_getdataent"));
	}
      SH_FREE(p);
      wrong_version(FIL__, __LINE__, filepath);
      *errflag = -1;
      SL_RETURN( NULL, _("sh_dbIO_getdataent"));
    }

  ft.mark = *(swap_short(&(ft.mark)));
  swap_data(&ft);

  /* Read next record -- Part Two -- Fullpath
   */
  i = sh_dbIO_getline (sh_fin_fd, line, size);

  if (i <= 0 ) 
    {
      SH_FREE(p);
      corrupt_record(FIL__, __LINE__, filepath);
      *errflag = -1;
      SL_RETURN( NULL, _("sh_dbIO_getdataent"));
    }

  fullpath = unquote_path(line, i);

  /* Read next record -- Part Three -- Linkpath
   */
  i =  sh_dbIO_getline (sh_fin_fd, line, size);

  if (i <= 0 ) 
    {
      SH_FREE(fullpath); SH_FREE(p);
      corrupt_record(FIL__, __LINE__, filepath);
      *errflag = -1;
      SL_RETURN( NULL, _("sh_dbIO_getdataent"));
    }

  linkpath = unquote_path(line, i);

  /* Read next record -- Part Four -- attr_string
   */
  if ((ft.mark & REC_FLAGS_ATTR) != 0)
    {
      i =  sh_dbIO_getline (sh_fin_fd, line, size);
      if (i <= 0 ) 
	{
	  SH_FREE(fullpath); SH_FREE(linkpath); SH_FREE(p);
	  corrupt_record(FIL__, __LINE__, filepath);
	  *errflag = -1;
	  SL_RETURN( NULL, _("sh_dbIO_getdataent"));
	}

      attr_string = unquote_path(line, i);
    }

  /* Read next record -- Part Four -- Decode
   */
#if defined(SH_STEALTH)
  sh_do_decode(fullpath,    sl_strlen(fullpath));
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sh_do_decode(ft.c_attributes,   sl_strlen(ft.c_attributes));
#endif
  sh_do_decode(ft.c_mode,   sl_strlen(ft.c_mode));
  sh_do_decode(ft.c_owner,  sl_strlen(ft.c_owner));
  sh_do_decode(ft.c_group,  sl_strlen(ft.c_group));
  sh_do_decode(ft.checksum, sl_strlen(ft.checksum));  
  /* 
   * TXT entries are c_mode[0] != 'l' and do not get decoded 
   */
  if (ft.c_mode[0] == 'l' && linkpath[0] != '-')
    {  
      sh_do_decode(linkpath, sl_strlen(linkpath));
    }
  if ((ft.mark & REC_FLAGS_ATTR) != 0)
    {  
      sh_do_decode(attr_string, sl_strlen(attr_string));
    }
#endif

  memcpy( &(*p).theFile, &ft, sizeof(sh_filestore_t) );

  /* init fflags, such that suid files in 
   * database are recognized as such 
   */
  {
    mode_t mode = (mode_t) ft.mode;

    if (S_ISREG(mode) &&
	(0 !=(S_ISUID & mode) ||
#if defined(HOST_IS_LINUX)
	 (0 !=(S_ISGID & mode) && 
	  0 !=(S_IXGRP & mode)) 
#else  
	 0 !=(S_ISGID & mode)
#endif
	 )
	)
      p->fflags = SH_FFLAG_SUIDCHK;

    else
      p->fflags = 0;
  }

  p->modi_mask   = ft.checkflags;
  if (MODI_ISSET(ft.checkflags, MODI_ALLIGNORE))
    SET_SH_FFLAG_ALLIGNORE(p->fflags);
  p->fullpath    = fullpath;
  p->linkpath    = linkpath;
  p->attr_string = attr_string;

  /* set to an invalid value 
   */
  ft.mark = (REC_MAGIC + 5);

  SL_REQUIRE((*errflag == 0), _("errflag not set correctly"));
  SL_RETURN( p, _("sh_dbIO_getdataent"));
}

/******************************************************************
 *
 * Data loading routines
 *
 ******************************************************************/
static SL_TICKET load_data_from_server(const char * uuid)
{
  SL_TICKET fd = -1;

#if defined(SH_WITH_CLIENT)
  char hashbuf[KEYBUF_SIZE];

  /* Data file from Server
   */
  if (0 != sl_strcmp(file_path('D', 'R'), _("REQ_FROM_SERVER")))
    return -1;

  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_D_DSTART);
  fd = sh_xfer_request_file((!uuid) ? _("DATA") : uuid);

  if (SL_ISERROR(fd))
    {
      if (!uuid)
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FBAD);
	  dlog(1, FIL__, __LINE__, 
	       _("Could not retrieve the file signature database from the server(errnum = %ld).\nPossible reasons include:\n - the server is not running,\n - session key negotiation failed (see the manual for proper setup), or\n - the server cannot access the file.\n"), fd);  
	}
      else
	sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_TCP_FBAD);
      return fd;
    }
  sl_rewind (fd);

  if (!uuid)
    {
      sl_strlcpy (sh.data.hash, 
		  sh_tiger_hash (file_path('D', 'R'),  
				 fd, TIGER_NOLIM, hashbuf, sizeof(hashbuf)),
		  KEY_LEN+1);
      sl_rewind (fd);
    }
#else
  (void) uuid;
#endif
  return fd;
}

static SL_TICKET load_data_from_disk(const char * filepath)
{
  char hashbuf[KEYBUF_SIZE];
  SL_TICKET fd = -1;

  /* Local data file
   */
  if ( SL_ISERROR(fd = sl_open_read(FIL__, __LINE__, filepath, SL_YESPRIV)) )
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<Error opening: %s>\n"), filepath));
      dlog(1, FIL__, __LINE__, 
    _("Could not open the local file signature database for reading because\nof the following error: %s (errnum = %ld)\nIf this is a permission problem, you need to change file permissions\nto make the file readable for the effective UID: %d\n"), 
	   sl_get_errmsg(), fd, (int) sl_ret_euid());
      sh_error_handle ((-1), FIL__, __LINE__, fd, MSG_EXIT_ABORT1, 
		       sh.prg_name);
      return -1;
    }
  
  TPT(( 0, FIL__, __LINE__, _("msg=<Opened database: %s>\n"), 
	filepath));

  if (sh.data.hash[0] == '\0')
    {
      char hashbuf[KEYBUF_SIZE];
      sl_strlcpy(sh.data.hash, 
		 sh_tiger_hash (filepath, TIGER_FILE, TIGER_NOLIM, hashbuf, sizeof(hashbuf)), 
		 KEY_LEN+1);
    }
  else
    {
      if (0 != sl_strncmp(sh.data.hash, 
			  sh_tiger_hash (filepath, fd, TIGER_NOLIM, 
					 hashbuf, sizeof(hashbuf)),
			  KEY_LEN)
	  && sh.flag.checkSum != SH_CHECK_INIT) 
	{
	  dlog(1, FIL__, __LINE__, 
	       _("The checksum of the file signature database has changed since startup: %s -> %s\n"),
	       sh.data.hash, sh_tiger_hash (filepath, fd, TIGER_NOLIM, 
					    hashbuf, sizeof(hashbuf)));
	  sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_E_AUTH,
			   ( (NULL == filepath) ? _("(null)") :
			     filepath )
			   );
	}
    }
  sl_rewind (fd);
  return fd;
}

static SL_TICKET verify_data (SL_TICKET fd)
{
#if defined(WITH_GPG) || defined(WITH_PGP)
  SL_TICKET fdTmp;

  /* extract the data and copy to temporary file
   */
  fdTmp = sh_gpg_extract_signed(fd);

  if (sig_termfast == 1)  /* SIGTERM */
    {
      TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
      --sig_raised; --sig_urgent;
      return -1;
    }

  sl_close(fd);
  fd = fdTmp;

  /* Validate signature of open file.
   */
  if (0 != sh_gpg_check_sign (fd, SIG_DATA))
    {
      sl_close(fd);
      return -1;
    }
  sl_rewind (fd);
#endif

  return fd;
}

static int read_data(SL_TICKET fd, sh_file_t * tab[TABSIZE], 
		     const char * filepath)
{
  sh_file_t * p;
  int count = 0;
  int errflag = 0;
  char * line = SH_ALLOC(MAX_PATH_STORE+2);

  /* fast forward to start of data
   */
  if (0 != sh_dbIO_setdataent(fd, line, MAX_PATH_STORE+1, filepath))
    return -1;

  while (1) 
    {
      if (sig_termfast == 1)  /* SIGTERM */
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
	  --sig_raised; --sig_urgent;
	  SH_FREE(line);
	  return -1;
	}

      p = sh_dbIO_getdataent (line, MAX_PATH_STORE+1, filepath, &errflag);
      if (p != NULL)
	{
	  if (!sh_hash_is_null_record(&(p->theFile)))
	    hashinsert (tab, p);
	  else
	    sh_hash_remove_unconditional (p->fullpath);
	  ++count;
	}
      else
	break;
    }

  if (line != NULL)
    SH_FREE(line);

  /* Always keep db in memory, so we have no open file
   */
  sl_close (fd);

  sl_fclose (FIL__, __LINE__, sh_fin_fd);
  sh_fin_fd = NULL;

  return errflag;
}


static int sh_dbIO_load_db_int(sh_file_t * tab[TABSIZE], 
			       const char * filepath, const char * uuid)
{
#define FGETS_BUF 16384

  SL_TICKET fd = -1;

  if (uuid)
    {
      fd = load_data_from_server(uuid);
      if (SL_ISERROR(fd))
	return -1;
    }
  else if (!filepath)
    {
      char * dbpath = file_path('D', 'R');

      fd = load_data_from_server(NULL);

      if (SL_ISERROR(fd))
	{
	  if (*dbpath == '/')
	    fd = load_data_from_disk(dbpath);
	}
    }
  else
    {
      fd = load_data_from_disk(filepath);
    }

  if (SL_ISERROR(fd))
    return -1;

  if (sig_termfast == 1)  /* SIGTERM */
    {
      TPT((0, FIL__, __LINE__, _("msg=<Terminate.>\n")));
      --sig_raised; --sig_urgent;
      aud_exit (FIL__, __LINE__, EXIT_SUCCESS);
    }

  fd = verify_data(fd);
  if (SL_ISERROR(fd))
    return -1;

  if (!uuid) { int i; for (i = 0; i < TABSIZE; ++i) tab[i] = NULL; }

  return read_data (fd, tab, filepath);
}


int sh_dbIO_load_db(sh_file_t * tab[TABSIZE])
{
  return sh_dbIO_load_db_int(tab, NULL, NULL);
}
int sh_dbIO_load_db_file(sh_file_t * tab[TABSIZE], const char * filepath)
{
  return sh_dbIO_load_db_int(tab, filepath, NULL);
}

int sh_dbIO_load_delta()
{
  int    status = 0;
#if defined(SH_WITH_CLIENT)
  sh_file_t ** mtab = get_default_data_table();
  int errflag = 0;
  unsigned int count;
  time_t last;

  if ( sh.flag.checkSum != SH_CHECK_INIT )
    {
      if (sh_hash_get_initialized() != 0)
	{
	  char * uuid = sh_socket_get_uuid(&errflag, &count, &last);

	  if (!uuid) 
	    return errflag;

	  if (count > 0)
	    sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, count, MSG_E_SUBGEN,
			  _("Retrying download of delta DB"), 
			  _("sh_dbIO_load_delta"));

	  status = sh_dbIO_load_db_int(mtab, NULL, uuid);
	  if (status < 0)
	    {
	      /* Return status < 0 indicates that max_try is exceeded
	       */
	      if (sh_socket_return_uuid(uuid, count, last) < 0)
		sh_error_handle((-1), FIL__, __LINE__, -1, MSG_D_DELTAFAIL, uuid);
	    }
	  else
	    {
	      sh_error_handle((-1), FIL__, __LINE__, -1, MSG_D_DELTAOK, uuid);
	    }
	  SH_FREE(uuid);
	}
      else
	{
	  /* not initialized yet */
	  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, -1, MSG_E_SUBGEN,
			  _("Download of delta DB skipped, not initialized yet"), 
			  _("sh_dbIO_load_delta"));
	  return -1;
	}
    }
#endif
  return status;
}

/******************************************************************
 *
 * Writing out a file to the database.
 *
 ******************************************************************/ 
static int       pushdata_isfirst =  1;
static SL_TICKET pushdata_fd      = -1;

static int       pushdata_stdout  =  S_FALSE;

static char * sh_db_version_string = NULL;

int sh_dbIO_writeout_stdout (const char * str)
{
  if (!str)
    { pushdata_stdout  =  S_TRUE; return 0; }
  return -1;
}

int sh_dbIO_version_string(const char * str)
{
  if (str)
    {
      if (sh_db_version_string != NULL) {
	SH_FREE(sh_db_version_string);
      }
      if (0 == sl_strncmp(str, _("NULL"), 4))
	{
	  sh_db_version_string = NULL;
	  return 0;
	}
      sh_db_version_string = sh_util_strdup(str);
      return 0;
    }
  return -1;
}

void do_writeout_checks(const char * outpath)
{
  if ((pushdata_stdout == S_TRUE) && (sh.flag.update == S_TRUE))
    {
      dlog(1, FIL__, __LINE__, 
	   _("You cannot write the database to stdout when you use update rather than init.\n"));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORTS,
		      _("Writing database to stdout with update"), 
		      sh.prg_name, 
		      _("sh_dbIO_data_write_int"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  if ((pushdata_stdout == S_TRUE) && (sl_is_suid()))
    {
      dlog(1, FIL__, __LINE__, 
	   _("You cannot write the database to stdout when running with suid privileges.\n"));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORTS,
		      _("Writing database to stdout when suid"), 
		      sh.prg_name, 
		      _("sh_dbIO_data_write_int"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }


  if ( (pushdata_isfirst == 1) && (pushdata_stdout == S_FALSE) && 
       ( (NULL == outpath) || (0 == sl_strcmp(outpath, _("REQ_FROM_SERVER"))) ) )
    {
      dlog(1, FIL__, __LINE__, 
	   _("You need to configure a local path for initializing the database\nlike ./configure --with-data-file=REQ_FROM_SERVER/some/local/path\n"));
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORTS,
		      _("No local path for database specified"), 
		      sh.prg_name, 
		      _("sh_dbIO_data_write_int"));
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  if ((pushdata_isfirst == 1) && (pushdata_stdout == S_FALSE))  
    {
      /* Warn that file already exists; file_path != NULL here because
       * checked above
       */
      struct stat sbuf;

      if (0 == retry_lstat(FIL__, __LINE__, outpath, &sbuf))
	{
	  if (sh.flag.update == S_FALSE)
	    {
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_FI_DBEX,
			      file_path('D', 'W'));
	    }
	}
    }

  return;
}

static SL_TICKET open_writeout_data_truncate(const char * path)
{
  int status;
  SL_TICKET fd;

  if ( SL_ISERROR(fd = sl_open_rdwr_trunc(FIL__, __LINE__, path, SL_YESPRIV))) 
    {
      sh_error_handle((-1), FIL__, __LINE__, fd, MSG_E_ACCESS,
		      geteuid(), path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  if (SL_ISERROR(status = sl_lock (fd)))
    {
      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGPATH,
		      _("Failed to lock baseline database"), _("sh_dbIO_data_write_int"),
		      path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }
  return fd;
}

static SL_TICKET open_writeout_data(const char * path)
{
  int status;
  SL_TICKET fd;

  if ( SL_ISERROR(fd = sl_open_rdwr(FIL__, __LINE__, path, SL_YESPRIV))) 
    {
      sh_error_handle((-1), FIL__, __LINE__, fd, MSG_E_ACCESS,
		      geteuid(), path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }

  if (SL_ISERROR(status = sl_lock (fd)))
    {
      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGPATH,
		      _("Failed to lock baseline database"), _("sh_dbIO_data_write_int"),
		      path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }
  return fd;
}

static void seek_writeout_data(SL_TICKET fd, const char * path)
{
  int status;

  if ( SL_ISERROR(status = sl_forward(fd))) 
    {
      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGPATH,
		      _("Failed to seek to end of baseline database"),
		      _("seek_writeout_data"),
		      path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }
  return;
}

static int seek_writeout_data_old(SL_TICKET fd, const char * path)
{
  char * line = SH_ALLOC(MAX_PATH_STORE+1);

  if (SL_ISERROR(sh_dbIO_setdataent_old (fd, line, MAX_PATH_STORE, path)))
    {
      SH_FREE(line);
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGPATH,
		      _("Failed to seek to end of baseline database"),
		      _("seek_writeout_data_old"),
		      path);
      aud_exit(FIL__, __LINE__, EXIT_FAILURE);
    }
  SH_FREE(line);
  return 0;
}

char * prep_path(char * path, int flag)
{
  size_t old_len = sl_strlen(path);
  char * tmp;
  size_t tmp_len;
  size_t path_len;
  char * outpath = NULL;
#if !defined(SH_STEALTH)
  (void) flag;
#endif

#if defined(SH_STEALTH)
  if (flag == S_TRUE)
    sh_do_encode(path, old_len);
#endif
  tmp = quote_string(path, old_len);
  tmp_len = sl_strlen(tmp);
#if defined(SH_STEALTH)
  if (flag == S_TRUE)
    sh_do_decode(path, old_len);
#endif

  if (tmp && tmp_len <= MAX_PATH_STORE) 
    {
      outpath = sh_util_strdup(path);
    } 
  else 
    {
      char hashbuf[KEYBUF_SIZE];
      
      outpath = sh_util_strdup(sh_tiger_hash (path,
					      TIGER_DATA, old_len, 
					      hashbuf, sizeof(hashbuf)));
    }
  if (tmp) 
    SH_FREE(tmp);

  path_len = sl_strlen(outpath);
#if defined(SH_STEALTH)
  if (flag == S_TRUE)
    sh_do_encode(outpath, path_len);
#endif
  
  tmp = quote_string(outpath, path_len);
  if (tmp) {
    SH_FREE(outpath);
    outpath = tmp;
  }
  return outpath;
}

static char * prep_attr(char * attr_str)
{
  char * tmp;
  char * outstr = NULL;
  size_t old_len = sl_strlen(attr_str);

#if defined(SH_STEALTH)
  sh_do_encode(attr_str, old_len);
#endif

  tmp = quote_string(attr_str, old_len);
  if (tmp)
    {
      outstr = tmp;
    }

#if defined(SH_STEALTH)
  sh_do_decode(attr_str, old_len);
#endif
  return outstr;
}

static void prep_encode(sh_filestore_t * p)
{
#if defined(SH_STEALTH)
  sh_do_encode(p->c_mode,   sl_strlen(p->c_mode));
  sh_do_encode(p->c_owner,  sl_strlen(p->c_owner));
  sh_do_encode(p->c_group,  sl_strlen(p->c_group));
  sh_do_encode(p->checksum, sl_strlen(p->checksum));
  sh_do_encode(p->c_attributes,   sl_strlen(p->c_attributes));
#else
  (void) p;
#endif
  return;
}

static void prep_struct(sh_filestore_t * p, file_type * buf, char * fileHash)
{
#if !defined(__linux__) && !defined(HAVE_STAT_FLAGS)
  int    i;
#endif
  p->mark = REC_MAGIC;
  sl_strlcpy(p->c_mode,   buf->c_mode,   CMODE_SIZE);
  sl_strlcpy(p->c_group,  buf->c_group,  GROUP_MAX+1);
  sl_strlcpy(p->c_owner,  buf->c_owner,  USER_MAX+1);
  if (fileHash) {
    sl_strlcpy(p->checksum, fileHash,      KEY_LEN+1);
  }
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  sl_strlcpy(p->c_attributes, buf->c_attributes, ATTRBUF_SIZE);
#else
  for (i = 0; i < ATTRBUF_USED; ++i) p->c_attributes[i] = '-';
  p->c_attributes[ATTRBUF_USED] = '\0';
#endif
 
  prep_encode(p);
  
#if defined(__linux__) || defined(HAVE_STAT_FLAGS)
  p->attributes  = (UINT32) buf->attributes;
#else
  p->attributes  = 0;
#endif
  p->linkmode    = (UINT32) buf->linkmode;
  p->hardlinks   = (UINT32) buf->hardlinks;
  p->dev   = (UINT64) buf->dev;
  p->rdev  = (UINT64) buf->rdev;
  p->mode  = (UINT32) buf->mode;
  p->ino   = (UINT32) buf->ino;
  p->size  = (UINT64) buf->size;
  p->mtime = (UINT64) buf->mtime;
  p->atime = (UINT64) buf->atime;
  p->ctime = (UINT64) buf->ctime;
  p->owner = (UINT32) buf->owner;
  p->group = (UINT32) buf->group;

  p->checkflags = (UINT32) buf->check_flags; 
  
  return;
}


static void write_start_header(SL_TICKET fd)
{
  char   timestring[81];

  if (pushdata_stdout == S_FALSE)
    {
      sl_write (fd, _("\n#Host "), 7);
      sl_write (fd, sh.host.name, 
		sl_strlen(sh.host.name));
      sl_write (fd, _(" Version "), 9);
      sl_write (fd, sh_db_version_string, 
		sl_strlen(sh_db_version_string));
      sl_write (fd, _(" Date "), 6);
      (void) sh_unix_time(0, timestring, sizeof(timestring));
      sl_write (fd, timestring, strlen(timestring));
      sl_write (fd,        "\n", 1);
    } 
  else 
    {
      printf ("%s",_("\n#Host "));
      printf ("%s", sh.host.name);
      printf ("%s",_(" Version "));
      printf ("%s", sh_db_version_string);
      printf ("%s",_(" Date "));
      (void) sh_unix_time(0, timestring, sizeof(timestring));
      printf ("%s\n", timestring);
    }
}

static void write_start_marker(SL_TICKET fd)
{
  if (sh_db_version_string != NULL)
    {
      write_start_header(fd);
    }
  
  if (pushdata_stdout == S_FALSE)
    {
#if defined(SH_STEALTH)
      sl_write      (fd,        "\n", 1);
      sl_write_line (fd, N_("[SOF]"), 5);
#else
      sl_write_line (fd, _("\n[SOF]"),  6);
#endif
    }
  else 
    {
#if defined(SH_STEALTH)
      puts (N_("[SOF]"));
#else
      puts (_("\n[SOF]"));
#endif
    }
}

static void   write_record(SL_TICKET fd, sh_filestore_t * p, 
			   char * fullpath, char * linkpath, char * attr_string)
{
  static char ll[2] = { '-', '\0' };
  char * lpath;

  if (!linkpath || 0 == sl_strlen(linkpath))
    lpath = ll;
  else
    lpath = linkpath;

  if (pushdata_stdout == S_FALSE)
    {
      if (SL_ENONE != sl_write (fd,        p, sizeof(sh_filestore_t)))
	{
	  char * tmp = sh_util_safe_name(fullpath);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGPATH,
			  _("Failed to write record to baseline database"),
			  _("write_record"),
			  tmp);
	  SH_FREE(tmp);
	  aud_exit(FIL__, __LINE__,  EXIT_FAILURE );
	}
      if (SL_ENONE != sl_write_line_fast (fd, fullpath, sl_strlen(fullpath)))
	{
	  char * tmp = sh_util_safe_name(fullpath);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGPATH,
			  _("Failed to write path to baseline database"),
			  _("write_record"),
			  tmp);
	  SH_FREE(tmp);
	  aud_exit(FIL__, __LINE__,  EXIT_FAILURE );
	}
      if (SL_ENONE != sl_write_line_fast (fd,    lpath, sl_strlen(lpath)))
	{
	  char * tmp = sh_util_safe_name(fullpath);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGPATH,
			  _("Failed to write lpath to baseline database"),
			  _("write_record"),
			  tmp);
	  SH_FREE(tmp);
	  aud_exit(FIL__, __LINE__,  EXIT_FAILURE );
	}
      if (attr_string)
	sl_write_line_fast (fd, attr_string, sl_strlen(attr_string));
    } 
  else 
    {
      if (fwrite (p, sizeof(sh_filestore_t), 1, stdout))
	{
	  puts (fullpath);
	  puts (lpath);
	  if (attr_string)
	    puts (attr_string);
	}
      else
	{
	  perror(_("Error writing database"));
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
    }

  SH_FREE(fullpath);
  if (linkpath)
    SH_FREE(linkpath);
  if (attr_string)
    SH_FREE(attr_string);

  return;
}

static void sh_dbIO_data_write_int (file_type * buf, char * fileHash, 
				    const char * outpath, int truncate)
{
  static long p_count = 0;
  sh_filestore_t p;
  char *  fullpath = NULL;
  char *  linkpath = NULL;
  char *  attr_string = NULL;

  SL_ENTER(_("sh_dbIO_data_write_int"));

  do_writeout_checks(outpath);

  if (sh.flag.update == S_FALSE)
    {
      if (pushdata_stdout == S_FALSE && pushdata_fd == -1)
	{
	  if (truncate == S_TRUE)
	    pushdata_fd = open_writeout_data_truncate(outpath);
	  else
	    {
	      pushdata_fd = open_writeout_data(outpath);
	      seek_writeout_data(pushdata_fd, outpath);
	    }
	}
    }
  else /* update == TRUE */
    {
      if (pushdata_isfirst == 1)
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Update.>\n")));
	  pushdata_fd = open_writeout_data(outpath);
	  seek_writeout_data_old(pushdata_fd, outpath);
 	}
    }
	 
  if (!buf) {
    memset(&p, '\0', sizeof(sh_filestore_t));
  }

  if (buf != NULL) 
    {
      fullpath = prep_path(buf->fullpath, S_TRUE);
    }

  /* NOTE: TXT entries are c_mode[0] != 'l' and do not get decoded 
   */
  if (buf != NULL /* && buf->c_mode[0] == 'l' */ && buf->link_path != NULL) 
    {  
      if (buf->c_mode[0] == 'l')
	linkpath = prep_path(buf->link_path, S_TRUE);
      else
	linkpath = prep_path(buf->link_path, S_FALSE);
    }

  if (buf != NULL && buf->attr_string != NULL) 
    {
      attr_string = prep_attr(buf->attr_string);
    }

  if (buf != NULL) 
    {
      prep_struct(&p, buf, fileHash);
      if (attr_string)
	p.mark |= REC_FLAGS_ATTR;
      swap_data(&p);
    }

  /* write the start marker 
   */
  if (pushdata_isfirst == 1) 
    {
      if (sh.flag.update == S_FALSE)
	write_start_marker(pushdata_fd);
      pushdata_isfirst = 0;
    }

  if (buf && fullpath)
    {
      write_record(pushdata_fd, &p, fullpath, linkpath, attr_string);
      ++p_count;
    }

  if ((sh.flag.update != S_TRUE) && (pushdata_stdout == S_FALSE))
    {
      if (sh.flag.checkSum != SH_CHECK_INIT || (buf == NULL && fileHash == NULL))
	{
	  sl_close (pushdata_fd);
	  pushdata_fd = -1;
	}
    }

  SL_RET0(_("sh_dbIO_data_write_int"));
}

SH_MUTEX_STATIC(mutex_writeout,PTHREAD_MUTEX_INITIALIZER);

void sh_dbIO_data_write (file_type * buf, char * fileHash)
{
  SH_MUTEX_LOCK(mutex_writeout); 
  sh_dbIO_data_write_int (buf, fileHash, file_path('D', 'W'), S_FALSE);
  SH_MUTEX_UNLOCK(mutex_writeout); 
  return;
}


static int dbIO_writeout(sh_file_t * mtab[TABSIZE], const char * outpath, int truncate)
{
  sh_file_t * p;
  int         i;
  file_type * f;
  char   fileHash[KEY_LEN + 1];

  SL_ENTER(_("dbIO_writeout"));

  SH_MUTEX_LOCK(mutex_writeout); 
  if (!SL_ISERROR(pushdata_fd))
    {
      sl_close(pushdata_fd);
      pushdata_fd = -1;
    }
  pushdata_isfirst =  1;


  SH_MUTEX_LOCK(mutex_hash);
  for (i = 0; i < TABSIZE; ++i)
    {
      for (p = mtab[i]; p; p = p->next)
	{
	  f = sh_hash_create_ft (p, fileHash);
	  sh_dbIO_data_write_int (f, fileHash, outpath, (i == 0) ? truncate : S_FALSE);
	  if (f->attr_string) SH_FREE(f->attr_string);
	  if (f->link_path)   SH_FREE(f->link_path);
	  SH_FREE(f);
	}
    }
  SH_MUTEX_UNLOCK(mutex_hash);

  if (!SL_ISERROR(pushdata_fd))
    {
      sl_close(pushdata_fd);
      pushdata_fd = -1;
    }
  pushdata_isfirst =  1;
  SH_MUTEX_UNLOCK(mutex_writeout); 

  SL_RETURN (0, _("dbIO_writeout"));
}

int sh_dbIO_writeout_update()
{
  sh_file_t ** mtab = get_default_data_table();

  if (S_TRUE == file_is_remote())
    {
      sh_error_handle((-1), FIL__, __LINE__, S_FALSE, MSG_E_SUBGEN, 
		      _("Baseline database is remote"), _("sh_dbIO_writeout"));
      SL_RETURN (1, _("sh_dbIO_writeout_update"));
    }

  return dbIO_writeout(mtab, file_path('D', 'W'), S_FALSE);
}

int sh_dbIO_writeout_to_path(const char * path)
{
  sh_file_t ** mtab = get_default_data_table();
  return dbIO_writeout(mtab, path, S_TRUE);
}

static void dbIO_write_record(sh_file_t * record, SL_TICKET fd)
{
  sh_filestore_t * p = &(record->theFile);
  char * fullpath    = NULL;
  char * linkpath    = NULL;
  char * attr_string = NULL;

  fullpath = prep_path(record->fullpath, S_TRUE);

  /* NOTE: TXT entries are c_mode[0] != 'l' and do not get decoded 
   */
  if (record->linkpath != NULL && 0 != strcmp("-", record->linkpath)) 
    {  
      if (p->c_mode[0] == 'l')
	linkpath = prep_path(record->linkpath, S_TRUE);
      else
	linkpath = prep_path(record->linkpath, S_FALSE);
    }

  if (record->attr_string != NULL) 
    attr_string = prep_attr(record->attr_string);

  prep_encode(p);
  swap_data(p);

  write_record(fd, p, fullpath, linkpath, attr_string);
  return;
}

static void dbIO_write_entry(sh_file_t * p)
{
  static int is_first = 1;

  if (is_first)
    {
      pushdata_isfirst =  1;
      if (!sh.outpath || sh.outpath[0] == '\0') 
	pushdata_stdout  =  S_TRUE;
      else
	pushdata_fd = open_writeout_data_truncate(sh.outpath);
      write_start_marker(pushdata_fd);
      pushdata_isfirst = 0;
      is_first = 0;
    }

  dbIO_write_record(p, pushdata_fd);

}


/******************************************************************
 *
 * Listing the database.
 *
 ******************************************************************/ 

static int ListBinary = S_FALSE;
static char * ListFilter = NULL;

int sh_dbIO_list_binary (const char * c)
{
  (void) c;
  ListBinary = S_TRUE;
  return 0;
}
int sh_dbIO_list_filter (const char * c)
{
  ListFilter = sh_util_strdup(c);
  return 0;
}

#include "zAVLTree.h"

static zAVLTree * filter_list = NULL;
extern char * rtrim (char * str);

#include <ctype.h>
static void read_filter()
{
  int    i, n = 0;
  size_t len;
  char * key;
  char * str;
  char * line = SH_ALLOC(SH_MAXBUF);
  FILE * fd   = fopen(ListFilter, "r");
  
  if (!fd)
    {
      perror(_("read_filter: fopen:"));
      _exit(EXIT_FAILURE);
    }
  do {
    i = sh_dbIO_getline (fd, line, SH_MAXBUF);
    str = rtrim(line);
    while (isspace((int)*str)) ++str;

    key = sh_files_parse_input(str, &len);

    if (key && *key == '/')
      {
	zAVL_string_set(&filter_list, key);
	++n;
      }
  } while (i >= 0);

  fclose(fd);
  SH_FREE(line);

  if (n == 0)
    {
      fprintf(stderr, _("read_filter: empty file <%s>\n"), ListFilter);
      _exit (EXIT_FAILURE);
    }
  return;
}

static int check_filter(char * path)
{
  if (NULL == zAVL_string_get(filter_list, path))
    return S_FALSE;
  return S_TRUE;
}

int sh_dbIO_list_db (const char * db_file)
{
  sh_file_t * p;
  SL_TICKET fd;
  char * line;
  int  errflag = 0;
  int  flag = 0;
  char * ListFile = get_list_file();

  if (!db_file)
    {
      fputs(_("ERROR: no database file given\n"), stderr);
      _exit(EXIT_FAILURE);
      return -1; 
    }
  if (sl_is_suid())
    {
      fputs(_("ERROR: insufficient privilege\n"), stderr);
      _exit (EXIT_FAILURE);
      return -1; /* for Mac OSX compiler */
    }
  if (0 == strcmp(db_file, _("default")))
    db_file = file_path('D', 'W');
  if (!db_file)
    {
      fputs(_("ERROR: no filename\n"), stderr);
      _exit(EXIT_FAILURE);
      return -1; 
    }

  if (ListFilter) 
    read_filter();

  line = SH_ALLOC(MAX_PATH_STORE+2);

  if ( SL_ISERROR(fd = sl_open_read(FIL__, __LINE__, db_file, SL_YESPRIV))) 
    {
      fprintf(stderr, _("ERROR: can't open %s for read (errnum = %ld)\n"), 
	      db_file, fd);
      _exit(EXIT_FAILURE);
      return -1; 
    }

  /* fast forward to start of data
   */
  if (0 != sh_dbIO_setdataent(fd, line, MAX_PATH_STORE+1, db_file))
    {
      fprintf(stderr, _("ERROR: can't find start marker in %s\n"), 
	      db_file);
      _exit(EXIT_FAILURE);
      return -1; 
    }

  while (1) 
    {
      p = sh_dbIO_getdataent (line, MAX_PATH_STORE+1, db_file, &errflag);
      if ((p != NULL) && (p->fullpath[0] == '/'))
	{
	  if (!ListFile)
	    {
	      flag = 1;
	      if (ListFilter && S_FALSE == check_filter(p->fullpath))
		continue;
	      if (ListBinary)
		dbIO_write_entry (p);
	      else
		sh_hash_list_db_entry (p); 
	    }
	  else
	    {
	      if (0 != sl_strcmp(ListFile, p->fullpath))
		{
		  continue;
		}
	      flag = 1;
	      if ('l' != p->theFile.c_mode[0])
		{
		  if (sh_hash_printcontent(p->linkpath) < 0)
		    {
		      fputs(_("Error listing file content\n"), stderr);
		      _exit(EXIT_FAILURE);
		      return -1;
		    }
		}
	      else
		{
		  fputs(_("File is a link\n"), stderr);
		  _exit(EXIT_FAILURE);
		  return -1;
		}
	      break;
	    }
	}
      else if (p == NULL)
	{
	  break;
	}
    }

  if (line != NULL)
    SH_FREE(line);
  sl_close (fd);

  fflush(NULL);

  if (flag == 0)
    {
      fputs(_("File not found.\n"), stderr);
      _exit(EXIT_FAILURE);
    }
  else if (errflag < 0)
    {
      fputs(_("Error while reading file.\n"), stderr);
      _exit(EXIT_FAILURE);
    }
      
  _exit(EXIT_SUCCESS);
  return 0; 
}

/* if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE) */
#endif
