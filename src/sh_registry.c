/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2010       Rainer Wichmann                                */
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

/***************************************************************************
 *
 * This file provides a module for samhain to check the MS Windows registry.
 *
 */

#include "config_xor.h"

#ifdef USE_REGISTRY_CHECK

#include <windows.h>
#include <stdio.h>
#include <time.h>

#define FIL__  _("sh_registry.c")

/* We don't want to build this into yule 
 */
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)

#include <sys/types.h>
#include <regex.h>

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_modules.h"
#include "sh_hash.h"
#include "sh_tiger.h"

static int check_key (char * name, int isSingle);

static int sh_reg_set_active  (const char *s);
static int sh_reg_set_interval (const char * c);
static int sh_reg_set_severity (const char *s);
static int sh_reg_add_key (const char *s);
static int sh_reg_add_hierarchy (const char *s);
static int sh_reg_add_stop (const char *s);
static int sh_reg_add_ign (const char *s);
static int sh_reg_ign_time (const char *s);

#define STOP_FALSE  0
#define STOP_CHECK  1
#define STOP_IGN    2

sh_rconf sh_reg_check_table[] = {
    {
        N_("severitychange"),
        sh_reg_set_severity,
    },
    {
        N_("registrycheckactive"),
        sh_reg_set_active,
    },
    {
        N_("registrycheckinterval"),
        sh_reg_set_interval,
    },
    {
        N_("ignoretimestamponly"),
        sh_reg_ign_time,
    },
    {
        N_("singlekey"),
        sh_reg_add_key,
    },
    {
        N_("hierarchy"),
        sh_reg_add_hierarchy,
    },
    {
        N_("stopatkey"),
        sh_reg_add_stop,
    },
    {
        N_("ignorekey"),
        sh_reg_add_ign,
    },
    {
        NULL,
        NULL
    }
};

/* Runtime configuration */

#define SH_REGISTRY_INTERVAL 300

static int      ShRegCheckActive      = S_FALSE;
static time_t   sh_reg_check_interval = SH_REGISTRY_INTERVAL;
static int      sh_reg_check_severity = SH_ERR_SEVERE;
static int      ShRegIgnTime          = S_FALSE;

struct regkeylist {
  char        * name;
  int           stop;
  int           single;
#ifdef HAVE_REGEX_H
  regex_t       preg;
#endif

  struct regkeylist *next;
};

static struct regkeylist * keylist = NULL;

static int sh_reg_set_active(const char *s) 
{
  int value;
    
  SL_ENTER(_("sh_reg_set_active"));

  value = sh_util_flagval(s, &ShRegCheckActive);

  SL_RETURN((value), _("sh_reg_set_active"));
}

static int sh_reg_ign_time(const char *s) 
{
  int value;
    
  SL_ENTER(_("sh_reg_ign_time"));

  value = sh_util_flagval(s, &ShRegIgnTime);

  SL_RETURN((value), _("sh_reg_ign_time"));
}

static int sh_reg_set_interval (const char * c)
{
  int retval = 0;
  long val;

  SL_ENTER(_("sh_reg_set_interval"));
  val = strtol (c, (char **)NULL, 10);
  if (val <= 0)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle ((-1), FIL__, __LINE__, EINVAL, MSG_EINVALS,
		       _("registry check interval"), c);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);
      retval = -1;
    }

  sh_reg_check_interval = (time_t) val;
  SL_RETURN(0, _("sh_reg_set_interval"));
}

static int sh_reg_set_severity (const char *s)
{
  char tmp[32];
  tmp[0] = '='; tmp[1] = '\0';
  sl_strlcat (tmp, s, 32);
  return sh_error_set_level (tmp, &sh_reg_check_severity);
}

static int sh_reg_add_key_int (const char *s, int isSingle, int isStop)
{
  struct regkeylist * newkey;
  size_t len = sl_strlen(s);

  if (len > 0)
    {
      newkey = SH_ALLOC(sizeof(struct regkeylist));
      newkey->single = isSingle;
      newkey->stop   = isStop;
      newkey->name = NULL;

      if (STOP_FALSE == isStop)
	{
	  newkey->name = SH_ALLOC(len + 1);
	  sl_strlcpy(newkey->name, s, len+1);
	}
      else
	{
#ifdef HAVE_REGEX_H
	  int status = regcomp(&(newkey->preg), s, REG_NOSUB|REG_EXTENDED);
	  if (status != 0)
	    {
	      char  errbuf[512];
	      char  *p;
	      regerror(status, &(newkey->preg), errbuf, sizeof(errbuf));

	      sl_strlcat(errbuf, ": ", sizeof(errbuf));
	      p = sh_util_safe_name_keepspace(s);
	      sl_strlcat(errbuf, p, sizeof(errbuf));
	      SH_FREE(p);

	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN, 
			      errbuf, _("sh_reg_add_key_int"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      SH_FREE(newkey);
	      return -1;
	    }
#else
	  newkey->name = SH_ALLOC(len + 1);
	  sl_strlcpy(newkey->name, s, len+1);
#endif
	}
      newkey->next = keylist;
      keylist      = newkey;
      return 0;
    }
  return -1;
}

static int sh_reg_add_key (const char *s)
{
  return sh_reg_add_key_int (s, S_TRUE, STOP_FALSE);
}
static int sh_reg_add_hierarchy (const char *s)
{
  return sh_reg_add_key_int (s, S_FALSE, STOP_FALSE);
}
static int sh_reg_add_stop (const char *s)
{
  return sh_reg_add_key_int (s, S_FALSE, STOP_CHECK);
}
static int sh_reg_add_ign (const char *s)
{
  return sh_reg_add_key_int (s, S_FALSE, STOP_IGN);
}

/* Module functions      */

int sh_reg_check_init(struct mod_type * arg)
{
#ifndef HAVE_PTHREAD
  (void) arg;
#endif

  if (ShRegCheckActive == S_FALSE)
    return SH_MOD_FAILED;
#ifdef HAVE_PTHREAD
  if (arg != NULL && arg->initval < 0 &&
      (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      if (0 == sh_pthread_create(sh_threaded_module_run, (void *)arg))
	return SH_MOD_THREAD;
      else
	return SH_MOD_FAILED;
    }
  else if (arg != NULL && arg->initval == SH_MOD_THREAD &&
	   (sh.flag.isdaemon == S_TRUE || sh.flag.loop == S_TRUE))
    {
      return SH_MOD_THREAD;
    }
#endif
  return 0;
}

int sh_reg_check_timer(time_t tcurrent)
{
  static time_t lastcheck = 0;

  SL_ENTER(_("sh_reg_check_timer"));
  if ((time_t) (tcurrent - lastcheck) >= sh_reg_check_interval)
    {
      lastcheck  = tcurrent;
      SL_RETURN((-1), _("sh_reg_check_timer"));
    }
  SL_RETURN(0, _("sh_reg_check_timer"));
}

#define SH_REGFORM_NEW 1
#define SH_REGFORM_OLD 2

static char * format_changes(int flag, char * buf, size_t len,
			     time_t time_old, unsigned long size_old, 
			     unsigned long keys_old, unsigned long values_old,
			     char * hash_old,
			     time_t time_new, unsigned long size_new, 
			     unsigned long keys_new, unsigned long values_new,
			     char * hash_new)
{
  char timestr1[32];
  char timestr2[32];
  char timestr3[32];

  char buf_old[512] = "";
  char buf_new[512] = "";

  if ((0 != (flag & SH_REGFORM_NEW)) && (NULL != hash_new))
    {
      (void) sh_unix_gmttime (time_new,   timestr1,  sizeof(timestr1));
      (void) sh_unix_gmttime (keys_new,   timestr2,  sizeof(timestr2));
      (void) sh_unix_gmttime (values_new, timestr3,  sizeof(timestr3));

#ifdef SH_USE_XML
      sl_snprintf(buf_new, sizeof(buf_new), 
		  "size_new=\"%lu\" mtime_new=\"%s\" ctime_new=\"%s\" atime_new=\"%s\" chksum_new=\"%s\"",
		  size_new, timestr1, timestr2, timestr3, hash_new);
#else
      sl_snprintf(buf_new, sizeof(buf_new), 
		  "size_new=<%lu>, mtime_new=<%s>, ctime_new=<%s>, atime_new=<%s>, chksum_new=<%s>",
		  size_new, timestr1, timestr2, timestr3, hash_new);
#endif
    }

  if ((0 != (flag & SH_REGFORM_OLD)) && (NULL != hash_old))
    {
      (void) sh_unix_gmttime (time_old,   timestr1,  sizeof(timestr1));
      (void) sh_unix_gmttime (keys_old,   timestr2,  sizeof(timestr2));
      (void) sh_unix_gmttime (values_old, timestr3,  sizeof(timestr3));

#ifdef SH_USE_XML
      sl_snprintf(buf_old, sizeof(buf_old), 
		  " size_old=\"%lu\" mtime_old=\"%s\" ctime_old=\"%s\" atime_old=\"%s\" chksum_old=\"%s\"",
		  size_old, timestr1, timestr2, timestr3, hash_old);
#else
      sl_snprintf(buf_old, sizeof(buf_old), 
		  " size_old=<%lu>, mtime_old=<%s>, ctime_old=<%s>, atime_old=<%s>, chksum_old=<%s>",
		  size_old, timestr1, timestr2, timestr3, hash_old);
#endif
    }

  sl_strlcpy(buf, buf_new, len);
  sl_strlcat(buf, buf_old, len);

  return buf;
}

static void report_missing_entry(const char * path)
{
  char  * infobuf  = SH_ALLOC(1024);
  char  * errbuf   = SH_ALLOC(1024);
  char  * tmp      = sh_util_safe_name (path);
  char timestr[32];
  struct store2db save;

  memset(&save, '\0', sizeof(struct store2db));
  sh_hash_db2pop (path, &save);
    
  (void) sh_unix_gmttime (save.val1, timestr,  sizeof(timestr));
  
  sl_snprintf(infobuf, 1024, _("mtime=%s size=%lu subkeys=%lu values=%lu"),
	      timestr, 
	      (unsigned long) save.val0, 
	      (unsigned long) save.val2, 
	      (unsigned long) save.val3);

  (void) format_changes (SH_REGFORM_OLD, errbuf, 1024, 
			 save.val1, save.val0, save.val2, save.val3, save.checksum,
			 0, 0, 0, 0, NULL);
  
  SH_MUTEX_LOCK(mutex_thread_nolog);
  sh_error_handle(sh_reg_check_severity, FIL__, __LINE__, 0, MSG_REG_MISS, 
		  infobuf, tmp, errbuf);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  
  SH_FREE(tmp);
  SH_FREE(errbuf);
  SH_FREE(infobuf);
  return;
}

int sh_reg_check_run(void)
{
  struct regkeylist *this = keylist;

  if (this)
    {
      SH_MUTEX_LOCK(mutex_thread_nolog);
      sh_error_handle(SH_ERR_INFO, FIL__, __LINE__, 0, MSG_E_SUBGEN, 
		      _("Checking the registry"),
		      _("sh_reg_check_run"));
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      while (this)
	{
	  if (STOP_FALSE == this->stop)
	    {
	      /* 
	       *  -- Check key -- 
	       */
	      check_key (this->name, this->single);
	    }
	  this = this->next;
	}
    }
  sh_hash_unvisited_custom ('H', report_missing_entry);

  return 0;
}

int sh_reg_check_reconf(void)
{
  struct regkeylist *this;

  while (keylist)
    {
      this    = keylist;
      keylist = keylist->next;

      if (this->name)
	SH_FREE(this->name);
#ifdef HAVE_REGEX_H
      if (STOP_FALSE != this->stop)
	regfree(&(this->preg));
#endif
      SH_FREE(this);
    }

  sh_reg_check_interval = SH_REGISTRY_INTERVAL;

  return 0;
}

int sh_reg_check_cleanup(void)
{
  sh_reg_check_reconf();
  return 0;
}

/* >>>>>>>>>>>> Main check function <<<<<<<<<<<< */


#include <windows.h>

#define MAX_KEY_LENGTH (2*256)
#define MAX_VALUE_NAME (2*16384)

CHAR  achValue[MAX_VALUE_NAME];

unsigned long nKeys = 0;
unsigned long nVals = 0;

static int CheckThisSubkey (HKEY key, char * subkey, char * path, 
			    int isSingle, int view);

static time_t convertTime(FILETIME * ft)
{
  time_t result;

  /* Shift high part up by 2^32
   */
  UINT64 date = ((UINT64)ft->dwHighDateTime) << 32; 

  /* Add low part 
   */
  date |= (UINT64)ft->dwLowDateTime;

  /* Subtract difference between Jan 1, 1601 and Jan 1, 1970
   */
  date -= ((UINT64)116444736) * ((UINT64)100) * ((UINT64)10000000);

  /* Divide by number of 100-nanosecond intervals per second
   */
  date /= ((UINT64)10000000);

  /* Convert to a time_t 
   */
  result = (time_t) date;

  return result;
}

#if !defined(KEY_WOW64_64KEY)
#define KEY_WOW64_64KEY 0x0100;
#endif
#if !defined(KEY_WOW64_32KEY)
#define KEY_WOW64_32KEY 0x0200;
#endif


#define SH_KEY_NULL _("000000000000000000000000000000000000000000000000")

int QueryKey(HKEY hKey, char * path, size_t pathlen, int isSingle) 
{ 
  CHAR     achKey[MAX_KEY_LENGTH];   /* buffer for subkey name */
  DWORD    cbName;                   /* size of name string */
  /* CHAR     achClass[MAX_PATH] = "";  *//* buffer for class name */
  /* DWORD    cchClassName = MAX_PATH/2;*//* size of class string */
  DWORD    cSubKeys=0;               /* number of subkeys */
  DWORD    cbMaxSubKey;              /* longest subkey size */
  DWORD    cchMaxClass;              /* longest class string */
  DWORD    cValues;              /* number of values for key */
  DWORD    cchMaxValue;          /* longest value name */
  DWORD    cbMaxValueData;       /* longest value data */
  DWORD    cbSecurityDescriptor; /* size of security descriptor */
  FILETIME ftLastWriteTime;      /* last write time */
  DWORD    lpType;               /* type of data stored in value */
  BYTE     lpData[256];          /* buffer for data in value */
  DWORD    lpcbData;             /* size of lpData buffer */
  DWORD    i, retCode; 
  DWORD    cchValue = MAX_VALUE_NAME/2;

  char hashbuf[KEYBUF_SIZE];
  unsigned long totalSize = 0;
  time_t fTime = 0;

  char * tPath = NULL;
  int    doUpdate = S_FALSE;

  retCode = RegQueryInfoKey(
			    hKey,                    /* key handle */
			    NULL /* achClass */,     /* buffer for class name */
			    NULL /* &cchClassName */,/* size of class string */
			    NULL,                    /* reserved */
			    &cSubKeys,               /* number of subkeys */
			    &cbMaxSubKey,            /* longest subkey size */
			    &cchMaxClass,            /* longest class string */
			    &cValues,                /* number of values for this key */
			    &cchMaxValue,            /* longest value name */
			    &cbMaxValueData,         /* longest value data */
			    &cbSecurityDescriptor,   /* security descriptor */
			    &ftLastWriteTime);       /* last write time */
  
  if (retCode != ERROR_SUCCESS)
    {
      return -1;
    }

  ++nKeys;

  fTime = convertTime (&ftLastWriteTime);

  /* Enumerate the subkeys, until RegEnumKeyEx fails. */
  
  if (cSubKeys)
    {
      /*
       * printf( "\nNumber of subkeys: %lu\n", (unsigned long) cSubKeys);
       */

      for (i=0; i<cSubKeys; i++) 
	{ 
	  cbName = MAX_KEY_LENGTH/2;
	  retCode = RegEnumKeyEx(hKey, i,
				 achKey, 
				 &cbName, 
				 NULL, 
				 NULL, 
				 NULL, 
				 &ftLastWriteTime);
 
	  if (retCode == ERROR_SUCCESS && S_TRUE != isSingle) 
	    {
	      /*
	       * _tprintf(TEXT("(%lu) %s\\%s\n"), (unsigned long) i+1, 
	       * path, achKey);
	       */
	      CheckThisSubkey (hKey, achKey, path, isSingle, 0); 
	    }
	}
    } 
  
  /* Enumerate the key values. */

  if (cValues) 
    {
      char hashtmp[3][KEYBUF_SIZE];

      memset(hashbuf, '0', sizeof(hashbuf));

      /* Loop over values and build checksum */

      for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
	{ 
	  LPBYTE lpDataAlloc = NULL;

	  cchValue = MAX_VALUE_NAME/2; 
	  achValue[0] = '\0';
	  lpcbData = sizeof(lpData);
	  retCode = RegEnumValue(hKey, i, 
				 achValue, 
				 &cchValue, 
				 NULL, 
				 &lpType,
				 lpData,
				 &lpcbData);
	  
	  if (retCode == ERROR_MORE_DATA)
	    {
	      lpDataAlloc = SH_ALLOC(lpcbData);

	      retCode = RegEnumValue(hKey, i, 
				     achValue, 
				     &cchValue, 
				     NULL, 
				     &lpType,
				     lpDataAlloc,
				     &lpcbData);
	    }

	  if (retCode == ERROR_SUCCESS)
	    {
	      totalSize += lpcbData;

	      /* checksum(valuename) */
	      sh_tiger_hash (achValue, TIGER_DATA, cchValue, 
			     hashtmp[0], KEYBUF_SIZE);

	      /* checksum(valuedata) */
	      if (NULL == lpDataAlloc)
		{
		  sh_tiger_hash ((char*) lpData,      TIGER_DATA, lpcbData, 
				 hashtmp[1], KEYBUF_SIZE);
		}
	      else
		{
		  sh_tiger_hash ((char*) lpDataAlloc, TIGER_DATA, lpcbData, 
				 hashtmp[1], KEYBUF_SIZE);
		}

	      /* old_checksum */
	      memcpy(hashtmp[2], hashbuf, KEYBUF_SIZE);

	      /* hash(hash(valuename)+hash(valuedata)+old_hash) */
	      sh_tiger_hash ((char*) hashtmp, TIGER_DATA, 
			     sizeof(hashtmp), hashbuf, sizeof(hashbuf));

	      ++nVals;
	    }

	  if (lpDataAlloc)
	    {
	      SH_FREE(lpDataAlloc);
	    }
	}
    }
  else
    {
      /* no values */
      sl_strlcpy(hashbuf, SH_KEY_NULL, sizeof(hashbuf));
    }

  /* Here we have:
   *  hashbuf       [checksum over values], 
   *  fTime         [last write time], 
   *  totalSize     [size of all value data],
   *  cSubKeys      [number of subkeys],
   *  cValues       [number of values],
   *  path, pathlen [which may be up to 131072 (256*512) bytes] 
   */

  if (pathlen > (PATH_MAX-1))
    {
      char hashbuf2[KEYBUF_SIZE];
      char * p = strchr(path, '\\');

      if (p)
	{
	  char *q = p;

	  ++p;
	  
	  tPath = SH_ALLOC(256 + KEYBUF_SIZE);
	  *q = '\0';
	  sl_strlcpy(tPath, path, 256); /* truncates */
	  *q = '\\';
	  sl_strlcat(tPath, "\\", 257);
	  (void) sh_tiger_hash(p, TIGER_DATA, sl_strlen(p), 
			       hashbuf2, sizeof(hashbuf2));
	  sl_strlcat(tPath, hashbuf2, 256 + KEYBUF_SIZE);
	}
    }
 
  if (sh.flag.checkSum == SH_CHECK_CHECK || sh.flag.update == S_TRUE)
    {
      struct store2db save;

      memset(&save, '\0', sizeof(struct store2db));

      if (tPath)
	{
	  sh_hash_db2pop (tPath, &save);
	}
      else
	{
	  sh_hash_db2pop (path, &save);
	}

      if (save.size == -1)
	{
	  /* Not in database */

	  char  * infobuf  = SH_ALLOC(1024);
	  char  * errbuf   = SH_ALLOC(1024);
	  char  * tmp      = sh_util_safe_name ((tPath == NULL) ? path : tPath);
	  char timestr[32];
      
	  (void) sh_unix_gmttime (fTime, timestr,  sizeof(timestr));

	  sl_snprintf(infobuf, 1024, 
		      _("mtime=%s size=%lu subkeys=%lu values=%lu"), 
		      timestr, 
		      (unsigned long) totalSize, 
		      (unsigned long) cSubKeys, 
		      (unsigned long) cValues);

	  (void) format_changes (SH_REGFORM_NEW, errbuf, 1024, 
				 0, 0, 0, 0, NULL,
				 fTime, totalSize, cSubKeys, cValues, hashbuf);
      
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_reg_check_severity, FIL__, __LINE__, 
			  0, MSG_REG_NEW, 
			  infobuf, tmp, errbuf);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  
	  SH_FREE(tmp);
	  SH_FREE(errbuf);
	  SH_FREE(infobuf);

	  doUpdate = S_TRUE;
	}
      else if (save.val0 != totalSize ||  
	       save.val2 != cSubKeys ||
	       save.val3 != cValues ||
	       0 != strcmp(save.checksum, hashbuf) || 
	       ( (((time_t) save.val1) != fTime) && (ShRegIgnTime == S_FALSE)) )
	{
	  /* Change detected */
	  char  * infobuf  = SH_ALLOC(1024);
	  char  * errbuf   = SH_ALLOC(1024);
	  char  * tmp      = sh_util_safe_name ((tPath == NULL) ? path : tPath);
 	  char timestr_new[32];
      
	  (void) sh_unix_gmttime (fTime,     timestr_new,  sizeof(timestr_new));

	  sl_snprintf(infobuf, 1024, 
		      _("mtime=%s size %lu->%lu subkeys %lu->%lu values %lu->%lu checksum %s"), 
		      timestr_new, 
		      (unsigned long) save.val0, (unsigned long) totalSize, 
		      (unsigned long) save.val2, (unsigned long) cSubKeys, 
		      (unsigned long) save.val3, (unsigned long) cValues, 
		      (0 == strcmp(save.checksum, hashbuf)) ? _("good") : _("bad"));

	  (void) format_changes (SH_REGFORM_OLD|SH_REGFORM_NEW, errbuf, 1024, 
				 save.val1, save.val0, 
				 save.val2, save.val3, save.checksum,
				 fTime, totalSize, 
				 cSubKeys, cValues, hashbuf);
      
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle(sh_reg_check_severity, FIL__, __LINE__, 
			  0, MSG_REG_CHANGE, 
			  infobuf, tmp, errbuf);
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  
	  SH_FREE(tmp);
	  SH_FREE(errbuf);
	  SH_FREE(infobuf);

	  doUpdate = S_TRUE;
	}

    }
 
  if ( sh.flag.checkSum == SH_CHECK_INIT || doUpdate == S_TRUE /* change detected */ )
    {
      struct store2db save;

      memset(&save, '\0', sizeof(struct store2db));
      
      save.val0 = totalSize;
      save.val1 = fTime;
      save.val2 = cSubKeys;
      save.val3 = cValues;
      sl_strlcpy(save.checksum, hashbuf, KEY_LEN+1);

      if (tPath)
	{
	  sh_hash_push2db (tPath, &save);
	}
      else
	{
	  sh_hash_push2db (path, &save);
	}
    }

  /* Without this, freshly updated entries would get deleted
   * as 'not seen'.
   */
  if (sh.flag.checkSum != SH_CHECK_INIT)
    {
      if (tPath)
	sh_hash_set_visited (tPath);
      else
	sh_hash_set_visited (path);
    }

  if (tPath)
    {
      SH_FREE(tPath);
    }

  return 0;
}

static int check_for_stop (char * name)
{
  struct regkeylist *this = keylist;

  while (this)
    {
      if (STOP_FALSE != this->stop)
	{
#ifdef HAVE_REGEX_H
	  if (0 == regexec(&(this->preg), name, 0, NULL, 0))
	    return this->stop;
#else
	  if (0 == strcmp(this->name, name))
	    return this->stop;
#endif
	}
      this = this->next;
    }
  return STOP_FALSE;
}


int CheckThisSubkey (HKEY key, char * subkey, char * path, int isSingle,
		     int view)
{
  HKEY hTestKey;
  LONG qError;
  char * newpath;
  size_t len;
  int    retval = -1;
  
  len = strlen(path) + 1 + strlen(subkey) + 1;
  newpath = SH_ALLOC(len);
  snprintf(newpath, len, "%s\\%s", path, subkey);
  
  /* Check for stop condition, if not single key. 
   * Set flag to isSingle = S_TRUE if we should stop here. 
   */
  if (S_TRUE != isSingle)
    {
      int isStop = check_for_stop(newpath);

      if (STOP_CHECK == isStop)
	{
	  isSingle = S_TRUE;
	}
      else if (STOP_IGN == isStop)
	{
	  SH_FREE(newpath);
	  return 0;
	}
    }

  len = strlen(path) + 1 + strlen(subkey) + 1;
  newpath = SH_ALLOC(len);
  snprintf(newpath, len, "%s\\%s", path, subkey);
  
  qError = RegOpenKeyEx( key,
			 subkey,
			 0,
			 (KEY_READ | view),
			 &hTestKey);


  if (qError == ERROR_SUCCESS)
    {
      QueryKey(hTestKey, newpath, len-1, isSingle);
      RegCloseKey(hTestKey);
      retval = 0;
    }
  else
    {
      /* Error message */
      LPVOID lpMsgBuf;
  
      char  * tmp     = sh_util_safe_name (newpath);
      size_t  tlen    = sl_strlen(tmp);

      if (S_TRUE == sl_ok_adds(64, tlen))
	{
	  char * errbuf;
	  size_t elen;

	  tlen += 64;

	  elen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			       FORMAT_MESSAGE_FROM_SYSTEM |
			       FORMAT_MESSAGE_IGNORE_INSERTS,
			       NULL,
			       qError,
			       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			       (LPTSTR) &lpMsgBuf,
			       0, NULL );

	  if (elen > 0 && S_TRUE == sl_ok_adds(elen, tlen))
	    {
	      tlen += elen;

	      errbuf = SH_ALLOC(elen + tlen);
	      sl_snprintf(errbuf, 64+tlen, _("Failed to open key %s: %s"), 
			  tmp, lpMsgBuf);
	      LocalFree(lpMsgBuf);

	      SH_MUTEX_LOCK(mutex_thread_nolog);
	      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			      errbuf, _("CheckThisSubkey"));
	      SH_MUTEX_UNLOCK(mutex_thread_nolog);
	      
	      SH_FREE(errbuf);
	    }
	}
      sh_reg_add_ign (newpath);
      SH_FREE(tmp);
    }
  
  SH_FREE(newpath);
  return retval;
}


int check_key (char * key, int isSingle)
{
  HKEY topKey;
  char * subkey;
  char path[20] = "";
  int pos = 0;
  
  if      (0 == strncmp(key, _("HKEY_CLASSES_ROOT"), 17))
    {
      topKey = HKEY_CLASSES_ROOT;
      pos = 17;
      strncpy(path, _("HKEY_CLASSES_ROOT"), sizeof(path));
    }
  else if (0 == strncmp(key, _("HKEY_CURRENT_USER"), 17))
    {
      topKey = HKEY_CURRENT_USER;
      pos = 17;
      strncpy(path, _("HKEY_CURRENT_USER"), sizeof(path));
    }
  else if (0 == strncmp(key, _("HKEY_LOCAL_MACHINE"), 18))
    {
      topKey = HKEY_LOCAL_MACHINE;
      pos = 18;
      strncpy(path, _("HKEY_LOCAL_MACHINE"), sizeof(path));
    }
  else if (0 == strncmp(key, _("HKEY_USERS"), 10))
    {
      topKey = HKEY_USERS;
      pos = 10;
      strncpy(path, _("HKEY_USERS"), sizeof(path));
    }


  if (pos > 0)
    {
      if (key[pos] == '\\')
	{
	  ++pos;
	  subkey = &key[pos];
	}
    }
  else
    {

      char * tmp = sh_util_safe_name_keepspace(key);
      size_t tlen = sl_strlen(tmp);

      if (S_TRUE == sl_ok_adds(64, tlen))
	{
	  char * errbuf = SH_ALLOC(64 + tlen);
	  
	  sl_snprintf(errbuf, 64+tlen, _("Invalid key %s"), tmp);
	  
	  SH_MUTEX_LOCK(mutex_thread_nolog);
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			  errbuf, _("check_key"));
	  SH_MUTEX_UNLOCK(mutex_thread_nolog);
	  
	  SH_FREE(errbuf);
	}
      SH_FREE(tmp);
      return -1;
    }

  /************************  
  if (ShCheckBothViews)
    {
      CheckThisSubkey (topKey, subkey, path, isSingle, KEY_WOW64_32KEY);
      return CheckThisSubkey (topKey, subkey, path, isSingle, KEY_WOW64_64KEY);
    }
  *************************/

  return CheckThisSubkey (topKey, subkey, path, isSingle, 0);
}

/* #if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) */
#endif

/* #ifdef USE_REGISTRY_CHECK */
#endif

