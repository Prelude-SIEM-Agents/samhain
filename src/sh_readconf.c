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
#include <ctype.h>


#include "samhain.h"
#include "sh_calls.h"
#include "sh_error.h"
#include "sh_extern.h"
#include "sh_unix.h"
#include "sh_files.h"
#include "sh_xfer.h"
#include "sh_gpg.h"
#include "sh_hash.h"
#include "sh_dbIO.h"
#include "sh_ignore.h"
#include "sh_database.h"
#include "sh_mail.h"
#include "sh_modules.h"
#include "sh_nmail.h"
#include "sh_prelink.h"
#ifdef HAVE_LIBPRELUDE
#include "sh_prelude.h"
#endif
#include "sh_tiger.h"
#include "sh_tools.h"
#include "sh_utils.h"
#include "sh_restrict.h"
#include "sh_socket.h"

extern int set_reverse_lookup (const char * c);

#undef  FIL__
#define FIL__  _("sh_readconf.c")

typedef enum {
  SH_SECTION_NONE,
  SH_SECTION_LOG,
  SH_SECTION_MISC,
  SH_SECTION_ATTRIBUTES,
  SH_SECTION_READONLY,
  SH_SECTION_LOGFILES,
  SH_SECTION_LOGGROW,
  SH_SECTION_NOIGNORE,
  SH_SECTION_ALLIGNORE,
  SH_SECTION_USER0,
  SH_SECTION_USER1,
  SH_SECTION_USER2,
  SH_SECTION_USER3,
  SH_SECTION_USER4,
  SH_SECTION_PRELINK,
#if defined (SH_WITH_MAIL) 
  SH_SECTION_MAIL,
#endif
#if defined (SH_WITH_CLIENT) 
  SH_SECTION_CLT,
#endif
#ifdef WITH_EXTERNAL
  SH_SECTION_EXTERNAL,
#endif
#ifdef WITH_DATABASE
  SH_SECTION_DATABASE,
#endif
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  SH_SECTION_OTHER,
#endif
#ifdef SH_WITH_SERVER
  SH_SECTION_CLIENTS,
  SH_SECTION_SRV,
#endif
  SH_SECTION_THRESHOLD
} ShSectionType;

typedef struct str_ListSections {
  const char * name;
  int    type;
} sh_str_ListSections;

struct str_ListSections tab_ListSections[] = {
  { N_("[Log]"),              SH_SECTION_LOG},
  { N_("[Misc]"),             SH_SECTION_MISC},
  { N_("[Attributes]"),       SH_SECTION_ATTRIBUTES},
  { N_("[ReadOnly]"),         SH_SECTION_READONLY},
  { N_("[LogFiles]"),         SH_SECTION_LOGFILES},
  { N_("[GrowingLogFiles]"),  SH_SECTION_LOGGROW},
  { N_("[IgnoreAll]"),        SH_SECTION_ALLIGNORE},
  { N_("[IgnoreNone]"),       SH_SECTION_NOIGNORE},
  { N_("[User0]"),            SH_SECTION_USER0},
  { N_("[User1]"),            SH_SECTION_USER1},
  { N_("[User2]"),            SH_SECTION_USER2},
  { N_("[User3]"),            SH_SECTION_USER3},
  { N_("[User4]"),            SH_SECTION_USER4},
  { N_("[Prelink]"),          SH_SECTION_PRELINK},
#ifdef WITH_EXTERNAL
  { N_("[External]"),         SH_SECTION_EXTERNAL}, 
#endif
#ifdef WITH_DATABASE
  { N_("[Database]"),         SH_SECTION_DATABASE}, 
#endif
  { N_("[EventSeverity]"),    SH_SECTION_THRESHOLD},
#ifdef SH_WITH_SERVER
  { N_("[Clients]"),          SH_SECTION_CLIENTS},
  { N_("[Server]"),           SH_SECTION_SRV},
#endif
#if defined (SH_WITH_CLIENT) 
  { N_("[Client]"),           SH_SECTION_CLT},
#endif
#if defined (SH_WITH_MAIL) 
  { N_("[Mail]"),             SH_SECTION_MAIL},
#endif
  { NULL,                     SH_SECTION_NONE}
};

static char * sh_readconf_expand_value (const char * str)
{
#ifdef SH_EVAL_SHELL
  char * tmp = sh_util_strdup(str);
  char * out;
  char * tmp_orig = tmp;

  while (tmp && isspace((int)*tmp)) ++tmp;
  
  if (tmp && tmp[0] == '$' && tmp[1] == '(')
    {
      size_t len = strlen(tmp);
      while (isspace((int) tmp[len-1])) { tmp[len-1] = '\0'; --len; }
      if (tmp[len-1] == ')')
	{
	  tmp[len-1] = '\0';
	  out = sh_ext_popen_str(&tmp[2]);
	  SH_FREE(tmp_orig);
	  return out;
	}
    }
  SH_FREE(tmp_orig);
#endif
  return sh_util_strdup(str);
}

enum {
  SH_RC_ANY        = 0, 
  SH_RC_HOST       = 1, 
  SH_RC_SYSTEM     = 2,
  SH_RC_FILE       = 3,
  SH_RC_IFACE      = 4,
#ifdef SH_EVAL_SHELL
  SH_RC_CMD        = 5
#endif
};


static int sh_readconf_cond_match(char * str, int line)
{
  int    match  = 0;
  int    negate = 1;
  int    cond_type = SH_RC_ANY;
  char   myident[3*SH_MINIBUF+3];
  struct stat buf;

  char * p = str;

  if (*p == '!') { negate = 0; ++p; }
  if (*p == '$') { 
    cond_type = SH_RC_SYSTEM; ++p; /* [!]$system */ 
  }
  else { /* *p == '@' */

    ++p; while (isspace((int)*p)) ++p;

    if (0 != strncasecmp(p, _("if "),   3)) {
      cond_type = SH_RC_HOST; /* [!]$host */
    }

    else {

      p += 3; while (isspace((int)*p)) ++p; /* skip the 'if\s+' */

      if (0 == strncasecmp(p, _("not "), 4))
	{
	  p += 4; while (isspace((int)*p)) ++p;
	  negate = 0;
	  match  = 1;
	}
      else if (0 == strncmp(p, _("!"), 1))
	{
	  ++p; while (isspace((int)*p)) ++p;
	  negate = 0;
	  match  = 1;
	}
  
      if (0 == strncasecmp(p, _("file_exists "), 12))
	{
	  p += 12; cond_type = SH_RC_FILE;
	}
      else if (0 == strncasecmp(p, _("interface_exists "), 17))
	{
	  p += 17; cond_type = SH_RC_IFACE;
	}
      else if (0 == strncasecmp(p, _("hostname_matches "), 17))
	{
	  p += 17; cond_type = SH_RC_HOST;
	}
      else if (0 == strncasecmp(p, _("system_matches "), 15))
	{
	  p += 15; cond_type = SH_RC_SYSTEM;
	}
#ifdef SH_EVAL_SHELL
      else if (0 == strncasecmp(p, _("command_succeeds "), 17))
	{
	  p += 17; cond_type = SH_RC_CMD;
	}
#endif
      else
	{
	  char errbuf[SH_ERRBUF_SIZE];
	  sl_snprintf(errbuf, sizeof(errbuf), 
		      _("Unsupported test at line %d of configuration file"),
		      line);
	  sh_error_handle(SH_ERR_ERR, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  errbuf,
			  _("sh_readconf_cond_match"));
	  return 0;
	}
    }
  }

  while (isspace((int)*p)) ++p;

  switch (cond_type)
    {
    case SH_RC_HOST:
      if  (sl_strncmp (p,  sh.host.name, strlen(sh.host.name)) == 0
#ifdef HAVE_REGEX_H
	   || sh_util_regcmp (p, sh.host.name) == 0
#endif
	   )
	match = negate;
      break;
    case SH_RC_SYSTEM:
      /*
       * The system type, release, and machine.
       */
      sl_snprintf(myident, sizeof(myident), _("%s:%s:%s"),  
		  sh.host.system, /* flawfinder: ignore */ 
		  sh.host.release, sh.host.machine);
      
      if  (sl_strncmp (p,  myident, strlen(myident)) == 0
#ifdef HAVE_REGEX_H
	   || sh_util_regcmp (p, myident) == 0
#endif
	   )
	match = negate;
      break;
    case SH_RC_FILE:
      if (0 == retry_lstat(FIL__, __LINE__, p, &buf))
	match = negate;
      break;
    case SH_RC_IFACE:
      if (sh_tools_iface_is_present(p))
	match = negate;
      break;
#ifdef SH_EVAL_SHELL
    case SH_RC_CMD:
      if (0 == sh_unix_run_command(p))
	match = negate;
      break;
#endif
    default:
      /* do nothing */;
    }
  return match;
}

static int sh_readconf_is_end (char * str)
{
  int retval = 0;

  if (str[0] == '@' || str[0] == '$')
    {
      char * p = str;
      ++p; while (isspace((int)*p)) ++p;
      if ( 
	  (0 == strncasecmp (p, _("end"), 3) && (p[3] == '\0' || isspace((int)p[3]))) ||
	  (0 == strncasecmp (p, _("fi"),  2) && (p[2] == '\0' || isspace((int)p[2])))
	   )
	{
	  return 1;
	}
    }
  return retval;
}
   
static int sh_readconf_is_else (char * str)
{
  int retval = 0;

  if (str[0] == '@')
    {
      char * p = str;
      ++p; while (isspace((int)*p)) ++p;
      if ( 0 == strncasecmp (p, _("else"), 4) && (p[4] == '\0' || isspace((int)p[4])) )
	{
	  return 1;
	}
    }
  return retval;
}
   
static int sh_readconfig_line (char * line);

static ShSectionType read_mode = SH_SECTION_NONE;

static int conf_line = 0;

/* --- Read the configuration file. ---
 */
int sh_readconf_read (void)
{
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  /* This is for modules. 
   */
  int    modnum;
#endif

  int i;

  SL_TICKET    fd    = -1;
#if defined(SH_STEALTH) && !defined(SH_STEALTH_MICRO)
  SL_TICKET    fdTmp = -1;
#endif
#if defined(WITH_GPG) || defined(WITH_PGP)
  SL_TICKET    fdGpg = -1;
#endif
  char * tmp;

#define SH_LINE_IN 16384
  char * line_in;
  char * line;

  /* This is for nested conditionals.
   */
  int    cond_depth  = 0;
  int    cond_excl   = 0;
  
  int    local_file = 1;
  char   local_flag = 'R';

#if defined(WITH_GPG) || defined(WITH_PGP)
  int    signed_content = S_FALSE;
  int    true_content   = S_FALSE;
#endif
#if defined(SH_STEALTH) && !defined(SH_STEALTH_MICRO)
  int    hidden_count = 0;
#endif
  uid_t  euid;
  char hashbuf[KEYBUF_SIZE];

  SL_ENTER(_("sh_readconf_read"));

  /* --- Open config file, exit on failure. ---
   */
#if defined(SH_WITH_CLIENT)
  if (0 == sl_strcmp(file_path('C', 'R'), _("REQ_FROM_SERVER")))
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_D_START);

      fd = sh_xfer_request_file(_("CONF"));

      if (!SL_ISERROR(fd))
	{
	  local_file = 0;
	}
      else if (sh.flag.checkSum != SH_CHECK_INIT)
	{
	  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_TCP_FBAD);
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
      else
	{
	  sh_error_handle(SH_ERR_WARN, FIL__, __LINE__, 0, MSG_TCP_FBAD);
	  sh_error_handle ((-1), FIL__, __LINE__, fd, MSG_D_FAIL);
	  local_file = 1;
	  local_flag = 'I';
	}
    }
#endif

  /* Use a local configuration file.
   */
  if (local_file == 1)
    {
      if (0 != tf_trust_check (file_path('C', local_flag), SL_YESPRIV))
	{
	  sl_get_euid(&euid);
	  dlog(1, FIL__, __LINE__, 
	       _("The configuration file: %s is untrusted, i.e. an\nuntrusted user owns or can write to some directory in the path.\n"), 
	       ( (NULL == file_path('C', local_flag)) 
			     ? _("(null)") : file_path('C', local_flag) ));
	  sh_error_handle ((-1), FIL__, __LINE__, EACCES, MSG_TRUST, 
			   (long) euid, 
			   ( (NULL == file_path('C', local_flag)) 
			     ? _("(null)") : file_path('C', local_flag) )
			   );
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
      if (SL_ISERROR(fd = sl_open_read(FIL__, __LINE__, 
				       file_path('C',local_flag),SL_YESPRIV)))
	{
	  sl_get_euid(&euid);
	  dlog(1, FIL__, __LINE__, 
	       _("Could not open the local configuration file for reading because\nof the following error: %s (errnum = %ld)\nIf this is a permission problem, you need to change file permissions\nto make the file readable for the effective UID: %d\n"), 
	       sl_get_errmsg(), fd, (int) euid);
	  sh_error_handle ((-1), FIL__, __LINE__, fd, MSG_NOACCESS, 
			   (long) euid, 
			   ( (NULL == file_path('C', local_flag)) 
			     ? _("(null)") : file_path('C', local_flag) )
			   );
	  aud_exit (FIL__, __LINE__, EXIT_FAILURE);
	}
    }

  /* Compute the checksum of the open file.
   */
  sl_strlcpy(sh.conf.hash, 
	     sh_tiger_hash(file_path('C',local_flag), fd, TIGER_NOLIM, 
			   hashbuf, sizeof(hashbuf)),
	     KEY_LEN+1);
  sl_rewind (fd);

  line_in = SH_ALLOC(SH_LINE_IN);

#if defined(SH_STEALTH) && !defined(SH_STEALTH_MICRO)
    /* extract the data and copy to temporary file
     */
  fdTmp = open_tmp(); 

  sh_unix_getline_stealth (0, NULL, 0); /* initialize */

  while ( sh_unix_getline_stealth (fd, line_in, SH_LINE_IN-2) > 0) {
    hidden_count++;
    if (line_in[0] == '\n')
      {
	sl_write(fdTmp, line_in, 1);
      }
    else
      {
	sl_write_line(fdTmp, line_in, sl_strlen(line_in));
      }
#if defined(WITH_GPG) || defined(WITH_PGP)
    if (0 == sl_strncmp(line_in, _("-----END PGP SIGNATURE-----"), 25))
      break;
#else
    if (0 == sl_strncmp(line_in, _("[EOF]"), 5))
      break;
#endif
    if (hidden_count > 1048576)  /* arbitrary safeguard, 1024*1024 */
      break;
  }
  sl_close(fd);
  fd = fdTmp;
  sl_rewind (fd);
#endif

#if defined(WITH_GPG) || defined(WITH_PGP)

  /* extract the data and copy to temporary file
   */
  fdGpg = sh_gpg_extract_signed(fd);

  sl_close(fd);
  fd = fdGpg;

  /* Validate signature of open file.
   */
  if (0 != sh_gpg_check_sign (fd, SIG_CONF))
    {
      SH_FREE(line_in);
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1, sh.prg_name);
      aud_exit (FIL__, __LINE__, EXIT_FAILURE);
    }
  sl_rewind (fd);
#endif


  /* ---  Start reading lines.  ---
   */
  conf_line = 0;

  while ( sh_unix_getline (fd, line_in, SH_LINE_IN-2) > 0) {

    ++conf_line;

    line = &(line_in[0]);

    /* fprintf(stderr, "<%s>\n", line); */

    /* Sun May 27 18:40:05 CEST 2001
     */
#if defined(WITH_GPG) || defined(WITH_PGP)
    if (signed_content == S_FALSE)
      { 
	if (0 == sl_strcmp(line, _("-----BEGIN PGP SIGNED MESSAGE-----")))
	  signed_content = S_TRUE;
	else 
	  continue;
      }
    else if (true_content == S_FALSE)
      {
	if (line[0] == '\n')
	  true_content = S_TRUE;
	else
	  continue;
      }
    else if (signed_content == S_TRUE)
      { 
	if (0 == sl_strcmp(line, _("-----BEGIN PGP SIGNATURE-----")))
	  break;
	else if (0 == sl_strcmp(line, _("-----BEGIN PGP SIGNED MESSAGE-----")))
	  {
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    _("second signed message in file"),
			    _("sh_readconf_read"));
	    dlog(1, FIL__, __LINE__, 
		 _("There seems to be more than one signed message in the configuration\nfile. Please make sure there is only one signed message.\n"));
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EXIT_ABORT1,
			     sh.prg_name);
	    SH_FREE(line_in);
	    aud_exit (FIL__, __LINE__,EXIT_FAILURE);
	  }
      }
#endif

    /* Skip leading white space.
     */
    while (isspace((int)*line)) ++line;


    /* Skip header etc. 
     */
    if (line[0] == '#' || line[0] == '\0' || line[0] == ';' || 
	(line[0] == '/' && line[1] == '/'))
      continue; 
  
    /* Clip off trailing white space.                 
     */
    tmp = line + sl_strlen( line ); --tmp;
    while( isspace((int) *tmp ) && tmp >= line ) *tmp-- = '\0';


    /* ---  an @host/@if/$system directive -------------- */

    if (line[0] == '@' || (line[0] == '!' && line[1] == '@') || 
	line[0] == '$' || (line[0] == '!' && line[1] == '$'))
      {
	if (sh_readconf_is_end(line))
	  {
	    if (0 == cond_depth) {
	      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALD,
			       _("config file"), 
			       (long) conf_line);
	    }
	    else {
	      if (cond_excl == cond_depth)
		cond_excl = 0;
	      --cond_depth;
	    }
	  }
	else if (sh_readconf_is_else(line))
	  {
	    if (0 == cond_depth) {
	      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALD,
			       _("config file"), 
			       (long) conf_line);
	    }
	    else if (cond_excl == cond_depth) {
	      cond_excl = 0;
	    }
	    else if (cond_excl == 0) {
	      cond_excl = cond_depth;
	    }
	  }
	else
	  {
	    if (sh_readconf_cond_match(line, conf_line)) {
	      ++cond_depth;
	    }
	    else {
	      ++cond_depth;
	      if (cond_excl == 0)
		cond_excl = cond_depth;
	    }
	  }
	continue;
      }

    /* fprintf(stderr, "%d %s\n", cond_excl, line); */

    /****************************************************
     *
     * Only carry on if this section is intended for us
     *
     ****************************************************/
    
    if (cond_excl != 0) {
      continue;
    }

    /* -------  starts a section  ------------  */
    
    else if (line[0] == '[')
      { 
	read_mode = SH_SECTION_NONE;

	if (0 == sl_strncasecmp (line,  _("[EOF]"), 5)) {
	  goto nopel;
	}

	i = 0;

	while (tab_ListSections[i].name != 0)
	  {
	    if (sl_strncasecmp (line, _(tab_ListSections[i].name), 
				sl_strlen(tab_ListSections[i].name)) == 0)
	      { 
		read_mode = tab_ListSections[i].type;
		break;
	      }
	    ++i;
	  }

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
	if (read_mode == SH_SECTION_NONE)
	  {
	    for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
	      {
		if (0 == sl_strncasecmp (line, _(modList[modnum].conf_section),
					 sl_strlen(modList[modnum].conf_section)) )
		  read_mode = SH_SECTION_OTHER;
	      }
	  }
#endif
	if (read_mode == SH_SECTION_NONE)
	  {
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALHEAD,
			     (long) conf_line);
	  }
      } 

    /* ---  an %schedule directive ------------ */

    else if (line[0] == '%' || (line[0] == '!' && line[1] == '%')) 
      {
#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
	if (line[0] == '!' && 0 == sl_strcasecmp(&(line[2]), _("SCHEDULE_TWO")))
	  set_dirList(1);
	else if (0 == sl_strcasecmp(&(line[1]), _("SCHEDULE_TWO")))
	  set_dirList(2);
#else
	;
#endif
      }

    /* ------  no new section -------------- */


    else if (read_mode != SH_SECTION_NONE)
      { 
	if (0 != sh_readconfig_line (line))
	  {
	    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALCONF,
			     (long) conf_line);
	  }
      }
  } /* while getline() */

 nopel:
	   
  if (0 != cond_depth)
    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALDD,
		     _("config file"), 
		     (long) conf_line);

  sl_close (fd);

  sh_error_fixup();

  read_mode = SH_SECTION_NONE; /* reset b/o sighup reload */

  SH_FREE(line_in);
  SL_RETURN( 0, _("sh_readconf_read"));
}

int sh_readconf_set_path (char * which, const char * what)
{
  int len;
  SL_ENTER( _("sh_readconf_set_path"));

  if (which == NULL || what == NULL)
    {
      TPT((0, FIL__, __LINE__ , _("msg=<Input error>\n")));
      SL_RETURN( -1, _("sh_readconf_set_path"));
    }

  if (0 == sl_strcmp(what, _("AUTO")))
    {
      len = sl_strlen(which);
      if ( (len + sl_strlen(sh.host.name) + 2) > SH_PATHBUF)
	{
	  TPT((0, FIL__, __LINE__ , _("msg=<Path too large: %s:%s>\n"), 
	       which, sh.host.name));
	  SL_RETURN( -1, _("sh_readconf_set_path"));
	}
      else
	{
	  which[len] = ':'; which[len+1] = '\0';
	  sl_strlcat(which, sh.host.name, SH_PATHBUF);
	}
    }
  else  /* not auto */
    {
      if (sl_strlen(what) > (SH_PATHBUF-1))
	{
	  TPT((0, FIL__, __LINE__ , _("msg=<Path too large: %s>\n"), what));
	  SL_RETURN( -1, _("sh_readconf_set_path"));
	}
      else
	{
	  sl_strlcpy(which, what, SH_PATHBUF);
	}
    }
  SL_RETURN( 0, _("sh_readconf_set_path"));
}

int sh_readconf_set_database_path (const char * what)
{
  return (sh_readconf_set_path(sh.data.path, what));
}

int sh_readconf_set_logfile_path (const char * what)
{
  return (sh_readconf_set_path(sh.srvlog.name, what));
}

int sh_readconf_set_lockfile_path (const char * what)
{
  return( sh_readconf_set_path(sh.srvlog.alt, what));
}




typedef enum {
  SET_MAILTIME,
  SET_FILETIME 
} ShTimerItem;
 
    
int sh_readconf_setTime (const char * str, ShTimerItem what)
{
  unsigned long i = atoi (str);

  SL_ENTER( _("sh_readconf_setTime"));

  if (i < LONG_MAX) 
    {
      if      (what == SET_MAILTIME)
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Set mail timer to %ld>\n"), i));
	  sh.mailTime.alarm_interval = i;
	}
      else if (what == SET_FILETIME)
	{
	  TPT((0, FIL__, __LINE__, _("msg=<Set filecheck timer to %ld>\n"),i));
	  sh.fileCheck.alarm_interval  = i;
	}

      SL_RETURN( 0, _("sh_readconf_setTime"));
    } 
  else 
    {
      sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALL,
		     _("set timer"), (long) i);
      SL_RETURN( (-1), _("sh_readconf_setTime"));
    }
}

int sh_readconf_setMailtime (const char * c)
{
  return sh_readconf_setTime (c, SET_MAILTIME);
}

int sh_readconf_setFiletime (const char * c)
{
  return sh_readconf_setTime (c, SET_FILETIME);
}

int sh_readconf_set_nice (const char * c)
{
  long val;

  SL_ENTER(_("sh_readconf_set_nice"));

  val = strtol (c, (char **)NULL, 10);
  if (val < -20 || val > 20)
    {
      SL_RETURN((-1), _("sh_readconf_set_nice"));
    }

  val = (val < -19 ? -19 : val);
  val = (val >  19 ?  19 : val);

  sh.flag.nice =  val;
  SL_RETURN((0), _("sh_readconf_set_nice"));
}


#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
static int sh_readconf_set_delay (const char * c)
{
  unsigned long i = atol (c);

  if (i  > INT_MAX)
    return -i;
  sh.delayload = (int) i;
  return 0;
}
#endif

#ifdef FANCY_LIBCAP
int sh_readconf_setCaps(const char * c)
{
  int i;
  SL_ENTER(_("sh_readconf_setCaps"));

  i = sh_util_flagval(c, &sl_useCaps);
  SL_RETURN((i), _("sh_readconf_setCaps"));
}
#endif

typedef struct _cfg_options {
  const char * optname;
  ShSectionType   section;
  ShSectionType   alt_section;
  int (*func)(const char * opt);
} cfg_options;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
extern int sh_set_schedule_one(const char * str);
extern int sh_set_schedule_two(const char * str);
extern int sh_set_silent_full (const char * str);
#endif
#if defined (SH_WITH_SERVER)
extern int sh_socket_use (const char * c);
extern int sh_socket_uid (const char * c);
extern int sh_socket_password (const char * c);
#endif

cfg_options ext_table[] = {
#if defined(WITH_EXTERNAL)
  { N_("opencommand"),     SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_setcommand },
  { N_("closecommand"),    SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_close_command },
  { N_("setcommandline"),  SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_add_argv },
  { N_("setchecksum"),     SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_checksum },
  { N_("setdefault"),      SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_add_default },
  { N_("setenviron"),      SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_add_environ },
  { N_("setdeadtime"),     SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_deadtime },
  { N_("settype"),         SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_type },
  { N_("setcredentials"),  SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_priv },
  { N_("setfilternot"),    SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_add_not },
  { N_("setfilterand"),    SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_add_and },
  { N_("setfilteror"),     SH_SECTION_EXTERNAL, SH_SECTION_NONE,  
    sh_ext_add_or },
  { N_("externalseverity"),SH_SECTION_LOG,      SH_SECTION_EXTERNAL,  
    sh_error_set_external },
  { N_("externalclass"),   SH_SECTION_LOG,      SH_SECTION_EXTERNAL,  
    sh_error_external_mask },
#endif

#if defined(WITH_DATABASE)
  { N_("usepersistent"),   SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_use_persistent },
  { N_("setdbname"),       SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_set_database },
  { N_("setdbtable"),      SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_set_table },
  { N_("setdbhost"),       SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_set_host },
  { N_("setdbuser"),       SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_set_user },
  { N_("setdbpassword"),   SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_set_password },
  { N_("addtodbhash"),     SH_SECTION_DATABASE, SH_SECTION_NONE,  
    sh_database_add_to_hash },
  { N_("databaseseverity"),SH_SECTION_LOG,      SH_SECTION_DATABASE,  
    sh_error_set_database },
  { N_("databaseclass"),   SH_SECTION_LOG,      SH_SECTION_DATABASE,  
    sh_error_database_mask },
  { N_("setdbservertstamp"), SH_SECTION_DATABASE,      SH_SECTION_NONE,  
    set_enter_wrapper },
#endif


#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE)
  { N_("dir"),            SH_SECTION_ATTRIBUTES, SH_SECTION_NONE, 
    sh_files_pushdir_attr },
  { N_("file"),           SH_SECTION_ATTRIBUTES, SH_SECTION_NONE, 
    sh_files_pushfile_attr },
  { N_("dir"),            SH_SECTION_READONLY,   SH_SECTION_NONE, 
    sh_files_pushdir_ro },
  { N_("file"),           SH_SECTION_READONLY,   SH_SECTION_NONE, 
    sh_files_pushfile_ro },
  { N_("dir"),            SH_SECTION_LOGFILES,   SH_SECTION_NONE, 
    sh_files_pushdir_log },
  { N_("file"),           SH_SECTION_LOGFILES,   SH_SECTION_NONE, 
    sh_files_pushfile_log },
  { N_("dir"),            SH_SECTION_LOGGROW,    SH_SECTION_NONE, 
    sh_files_pushdir_glog },
  { N_("file"),           SH_SECTION_LOGGROW,    SH_SECTION_NONE, 
    sh_files_pushfile_glog },
  { N_("dir"),            SH_SECTION_NOIGNORE,   SH_SECTION_NONE, 
    sh_files_pushdir_noig },
  { N_("file"),           SH_SECTION_NOIGNORE,   SH_SECTION_NONE, 
    sh_files_pushfile_noig },
  { N_("dir"),            SH_SECTION_ALLIGNORE,  SH_SECTION_NONE, 
    sh_files_pushdir_allig },
  { N_("file"),           SH_SECTION_ALLIGNORE,  SH_SECTION_NONE, 
    sh_files_pushfile_allig },

  { N_("dir"),            SH_SECTION_USER0,      SH_SECTION_NONE, 
    sh_files_pushdir_user0 },
  { N_("file"),           SH_SECTION_USER0,      SH_SECTION_NONE, 
    sh_files_pushfile_user0 },
  { N_("dir"),            SH_SECTION_USER1,      SH_SECTION_NONE, 
    sh_files_pushdir_user1 },
  { N_("file"),           SH_SECTION_USER1,      SH_SECTION_NONE, 
    sh_files_pushfile_user1 },
  { N_("dir"),            SH_SECTION_USER2,      SH_SECTION_NONE, 
    sh_files_pushdir_user2 },
  { N_("file"),           SH_SECTION_USER2,      SH_SECTION_NONE, 
    sh_files_pushfile_user2 },
  { N_("dir"),            SH_SECTION_USER3,      SH_SECTION_NONE, 
    sh_files_pushdir_user3 },
  { N_("file"),           SH_SECTION_USER3,      SH_SECTION_NONE, 
    sh_files_pushfile_user3 },
  { N_("dir"),            SH_SECTION_USER4,      SH_SECTION_NONE, 
    sh_files_pushdir_user4 },
  { N_("file"),           SH_SECTION_USER4,      SH_SECTION_NONE, 
    sh_files_pushfile_user4 },
  { N_("dir"),            SH_SECTION_PRELINK,    SH_SECTION_NONE, 
    sh_files_pushdir_prelink },
  { N_("file"),           SH_SECTION_PRELINK,    SH_SECTION_NONE, 
    sh_files_pushfile_prelink },

  { N_("ignoreadded"),          SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_ignore_add_new },
  { N_("ignoremissing"),        SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_ignore_add_del },
  { N_("ignoremodified"),       SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_ignore_add_mod },

  { N_("skipchecksum"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_restrict_define },
  { N_("filetype"),             SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_restrict_add_ftype },


  { N_("filecheckscheduleone"), SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_set_schedule_one },
  { N_("filecheckscheduletwo"), SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_set_schedule_two },

  { N_("usehardlinkcheck"),     SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_check_hardlinks },
  { N_("usersrccheck"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_use_rsrc },
  { N_("hardlinkoffset"),       SH_SECTION_MISC,   SH_SECTION_NONE,
    sh_files_hle_reg },
#if defined(USE_XATTR)
  { N_("useselinuxcheck"),      SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_unix_setcheckselinux },
#endif
#if defined(USE_ACL)
  { N_("useaclcheck"),          SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_unix_setcheckacl },
#endif
  { N_("loosedircheck"),        SH_SECTION_MISC,   SH_SECTION_NONE,
    sh_hash_loosedircheck },
  { N_("addokchars"),           SH_SECTION_MISC,   SH_SECTION_NONE,
    sh_util_obscure_ok },
  { N_("filenamesareutf8"),     SH_SECTION_MISC,   SH_SECTION_NONE,
    sh_util_obscure_utf8 },
  { N_("setrecursionlevel"),    SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_setrecursion },
  { N_("checksumtest"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_util_setchecksum },
  { N_("reportonlyonce"),       SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_reportonce },
  { N_("reportfulldetail"),     SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_fulldetail },
  { N_("uselocaltime"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_unix_uselocaltime },

  { N_("setnicelevel"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_readconf_set_nice },

  { N_("startuploaddelay"),     SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_readconf_set_delay },

#if defined(FANCY_LIBCAP)
  { N_("usecaps"),              SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_readconf_setCaps },
#endif

  { N_("reportcheckflags"),     SH_SECTION_MISC,   SH_SECTION_NONE, 
    set_report_checkflags },

  { N_("setdropcache"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sl_set_drop_cache },

  { N_("setiolimit"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_unix_set_io_limit },

  { N_("versionstring"),        SH_SECTION_MISC,   SH_SECTION_NONE,
    sh_dbIO_version_string },

  { N_("digestalgo"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_tiger_hashtype },

  { N_("redefreadonly"),        SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_readonly },

  { N_("redeflogfiles"),        SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_logfiles },

  { N_("redefgrowinglogfiles"), SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_loggrow },

  { N_("redefattributes"),      SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_attributes },

  { N_("redefignorenone"),      SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_noignore },

  { N_("redefignoreall"),       SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_allignore },

  { N_("redefuser0"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_user0 },

  { N_("redefuser1"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_user1 },

  { N_("redefuser2"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_user2 },

  { N_("redefuser3"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_user3 },

  { N_("redefuser4"),           SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_user4 },

  { N_("redefprelink"),         SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_files_redef_prelink },


  { N_("setprelinkpath"),       SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_prelink_set_path },
  { N_("setprelinkchecksum"),   SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_prelink_set_hash },

  { N_("setfullsilent"),        SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_set_silent_full },

  /* client or standalone
   */
#endif

#ifdef SH_WITH_SERVER
#ifdef INET_SYSLOG
  { N_("setudpactive"),        SH_SECTION_SRV,  SH_SECTION_MISC, 
    set_syslog_active },
#endif
  { N_("setusesocket"),        SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_socket_use },
  { N_("setsocketallowuid"),   SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_socket_uid },
  { N_("setsocketpassword"),   SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_socket_password },
  { N_("setstripdomain"),      SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_xfer_set_strip },
  { N_("useseparatelogs"),     SH_SECTION_SRV,  SH_SECTION_MISC, 
    set_flag_sep_log },
  { N_("setchrootdir"),        SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_unix_set_chroot },
  { N_("setclienttimelimit"),  SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_xfer_set_time_limit },
  { N_("setconnectiontimeout"),SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_xfer_set_timeout },
  { N_("useclientseverity"),   SH_SECTION_SRV,  SH_SECTION_MISC, 
  sh_xfer_use_clt_sev },
  { N_("useclientclass"),      SH_SECTION_SRV,  SH_SECTION_MISC, 
  sh_xfer_use_clt_class },
  { N_("severitylookup"),      SH_SECTION_SRV,  SH_SECTION_MISC, 
  sh_xfer_lookup_level },
  { N_("setclientfromaccept"), SH_SECTION_SRV,  SH_SECTION_MISC, 
    set_socket_peer },
  { N_("setserverport"),       SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_xfer_set_port },
  { N_("setserverinterface"),  SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_xfer_set_interface },
  { N_("client"),              SH_SECTION_CLIENTS,           SH_SECTION_NONE, 
    sh_xfer_register_client },
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
  { N_("exportseverity"),      SH_SECTION_LOG,  SH_SECTION_NONE, 
    sh_error_setexport },
  { N_("exportclass"),         SH_SECTION_LOG,  SH_SECTION_NONE, 
    sh_error_export_mask },
#if defined(SH_WITH_SERVER)
  { N_("setlogserver"),        SH_SECTION_SRV,  SH_SECTION_MISC, 
    sh_xfer_set_logserver },
#else
  { N_("setlogserver"),        SH_SECTION_CLT,  SH_SECTION_MISC, 
    sh_xfer_set_logserver },
  { N_("setthrottle"),         SH_SECTION_CLT,  SH_SECTION_MISC, 
    sh_xfer_set_throttle_delay},
  { N_("setdeltaretrycount"),   SH_SECTION_CLT,  SH_SECTION_MISC, 
    set_delta_retry_count},
  { N_("setdeltaretryinterval"),SH_SECTION_CLT,  SH_SECTION_MISC, 
    set_delta_retry_interval},
#endif
#endif
  { N_("setfilechecktime"),  SH_SECTION_MISC,   SH_SECTION_NONE, 
    sh_readconf_setFiletime },
  { N_("setlooptime"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_util_setlooptime },

#ifdef SH_WITH_MAIL
  { N_("mailseverity"),      SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_setseverity },
  { N_("mailclass"),         SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_mail_mask },
  { N_("setmailtime"),       SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_readconf_setMailtime },
  { N_("setmailnum"),        SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_mail_setNum },
  { N_("setmailrelay"),      SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_mail_set_relay },
  { N_("setmailport"),       SH_SECTION_MAIL,  SH_SECTION_MISC,
    sh_mail_set_port },
  { N_("mailsingle"),        SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_mail_setFlag },
  { N_("mailsubject"),       SH_SECTION_MAIL,  SH_SECTION_MISC, 
    set_mail_subject },
  { N_("setmailsender"),     SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_mail_set_sender },
  { N_("setmailalias"),       SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_nmail_add_alias },
  { N_("setmailaddress"),    SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_nmail_add_recipient },
  { N_("closeaddress"),      SH_SECTION_MAIL,  SH_SECTION_MISC, 
    sh_nmail_close_recipient },
  { N_("setaddrseverity"),   SH_SECTION_MAIL,  SH_SECTION_MISC,
    sh_nmail_set_severity },
  { N_("setmailfilternot"),  SH_SECTION_MAIL,  SH_SECTION_MISC,
    sh_nmail_add_not },
  { N_("setmailfilterand"),  SH_SECTION_MAIL,  SH_SECTION_MISC,
    sh_nmail_add_and },
  { N_("setmailfilteror"),   SH_SECTION_MAIL,  SH_SECTION_MISC,
    sh_nmail_add_or },
#endif
  { N_("setbindaddress"),    SH_SECTION_MISC,  SH_SECTION_NONE,
    sh_calls_set_bind_addr },
  { N_("daemon"),            SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_unix_setdeamon },
  { N_("samhainpath"),       SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_unix_self_hash },
  { N_("trusteduser"),       SH_SECTION_MISC,  SH_SECTION_NONE, 
    tf_add_trusted_user },
  { N_("settimeserver"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_unix_settimeserver },

  { N_("printseverity"),     SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_setprint },
  { N_("printclass"),        SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_print_mask },

  { N_("logseverity"),       SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_setlog },
  { N_("logclass"),          SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_log_mask },

  { N_("syslogseverity"),    SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_set_syslog },
  { N_("syslogclass"),       SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_syslog_mask },
#ifdef HAVE_LIBPRELUDE
  { N_("preludeseverity"),   SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_set_prelude },
  { N_("preludeclass"),      SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_error_prelude_mask },
  { N_("preludeprofile"),    SH_SECTION_MISC,  SH_SECTION_NONE,
    sh_prelude_set_profile },
  { N_("preludemaptoinfo"),    SH_SECTION_MISC,  SH_SECTION_NONE,
    sh_prelude_map_info },
  { N_("preludemaptolow"),     SH_SECTION_MISC,  SH_SECTION_NONE,
    sh_prelude_map_low },
  { N_("preludemaptomedium"),  SH_SECTION_MISC,  SH_SECTION_NONE,
    sh_prelude_map_medium },
  { N_("preludemaptohigh"),    SH_SECTION_MISC,  SH_SECTION_NONE,
    sh_prelude_map_high },
#endif

  { N_("logcalls"),          SH_SECTION_LOG,   SH_SECTION_NONE, 
    sh_aud_set_functions },

  { N_("messageheader"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_error_ehead },

  { N_("setconsole"),        SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_log_set_console },

  { N_("setreportfile"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_efile_path },
  { N_("setreportgroup"),    SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_efile_group },

#ifdef WITH_MESSAGE_QUEUE
  { N_("messagequeueactive"),SH_SECTION_MISC,  SH_SECTION_NONE, 
    enable_msgq },
#endif

  { N_("setreverselookup"),    SH_SECTION_MISC,  SH_SECTION_NONE, 
    set_reverse_lookup },

  { N_("setdatabasepath"),    SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_readconf_set_database_path },

  { N_("setlogfilepath"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_readconf_set_logfile_path },

  { N_("setlockfilepath"),    SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_readconf_set_lockfile_path },

  { N_("hidesetup"),         SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_util_hidesetup },

  { N_("syslogfacility"),    SH_SECTION_LOG,   SH_SECTION_MISC, 
    sh_log_set_facility },

  { N_("syslogmapstampto"),    SH_SECTION_LOG,   SH_SECTION_MISC, 
    sh_log_set_stamp_priority },

  { N_("mactype"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_util_sigtype },

  { N_("avoidblock"),     SH_SECTION_MISC,  SH_SECTION_NONE, 
    sh_calls_set_sub },

#ifdef SCREW_IT_UP
  { N_("setsigtrapmaxduration"),        SH_SECTION_MISC,  SH_SECTION_MISC, 
    sh_sigtrap_max_duration_set },
#endif

  { NULL,    0,   0,  NULL}
};




static int sh_readconfig_line (char * line)
{
  char * key;
  const char * value;
  char * value_dup;
  char * tmp;
  int    i;
  int    good_opt = -1;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  int    modnum, modkey;
#endif

  static const char  *dummy = N_("dummy");

  static const char  *closing[] = {
    N_("closecommand"),
    N_("closeaddress"),
    N_("logmonendgroup"),
    N_("logmonendhost"),
    NULL
  };

  static const char  *ident[] = {
    N_("severityreadonly"),
    N_("severitylogfiles"),
    N_("severitygrowinglogs"),
    N_("severityignorenone"),
    N_("severityignoreall"),
    N_("severityattributes"),
    N_("severitydirs"),
    N_("severityfiles"),
    N_("severitynames"),
    N_("severityuser0"),
    N_("severityuser1"),
    N_("severityuser2"),
    N_("severityuser3"),
    N_("severityuser4"),
    N_("severityprelink"),
    NULL
  };

  static int      identnum[] = { 
    SH_ERR_T_RO,    
    SH_ERR_T_LOGS,  
    SH_ERR_T_GLOG,  
    SH_ERR_T_NOIG,  
    SH_ERR_T_ALLIG, 
    SH_ERR_T_ATTR, 
    SH_ERR_T_DIR,   
    SH_ERR_T_FILE, 
    SH_ERR_T_NAME,       
    SH_ERR_T_USER0,       
    SH_ERR_T_USER1,       
    SH_ERR_T_USER2,       
    SH_ERR_T_USER3,       
    SH_ERR_T_USER4,       
    SH_ERR_T_PRELINK,       
  };
    
  SL_ENTER(_("sh_readconf_line"));

  /* convert to lowercase                              */

  tmp = line;
  while (*tmp != '=' && *tmp != '\0')
    {
      *tmp = tolower( (int) *tmp);
      ++tmp;
    }

  key = line;

  /* interpret line                                    */

  value = strchr(line, '=');

  if (value == NULL || (*value) == '\0')
    {
      if (key != NULL)
	{
	  i = 0;
	  while (closing[i] != NULL) 
	    {
	      if (sl_strncmp(key,_(closing[i]),sl_strlen(closing[i])-1) == 0)
		{
		  value = dummy;
		  goto ok_novalue;
		}
	      ++i;
	    }

	  TPT(( 0, FIL__, __LINE__, _("msg=<ConfigFile: not key=value: %s>\n"),
		line));
	}
      SL_RETURN(good_opt, _("sh_readconf_line"));
    }
  else
    ++value;

  /* skip leading whitespace
   */
  while ((*value) == ' ' || (*value) == '\t')
    ++value;

  if ((*value) == '\0')     /* no value                    */
    {
      if (key != NULL)
	{
	  TPT(( 0, FIL__, __LINE__, _("msg=<ConfigFile: not key=value: %s>\n"),
		line));
	}
      SL_RETURN(good_opt, _("sh_readconf_line"));
    }

 ok_novalue:

  if (!sl_is_suid())
    {
      TPT(( 0, FIL__, __LINE__, _("msg=<ConfigFile: %s>\n"), line));
    }

  /* Expand shell expressions. This return allocated memory which we must free.
   * If !defined(SH_EVAL_SHELL), this will reduce to a strdup.
   */
  value_dup = sh_readconf_expand_value(value);

  if (!value_dup || (*value_dup) == '\0')
    {
      TPT(( 0, FIL__, __LINE__, 
	    _("msg=<ConfigFile: empty after shell expansion: %s>\n"),
	    line));
      SL_RETURN(good_opt, _("sh_readconf_line"));
    }

  value = value_dup;

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 
  if      (read_mode == SH_SECTION_OTHER) 
    {
      for (modnum = 0; modList[modnum].name != NULL; ++modnum) 
	{
	  for (modkey = 0; modList[modnum].conf_table[modkey].the_opt != NULL; 
	       ++modkey) 
	    {
	      if (sl_strncmp (key,
			      _(modList[modnum].conf_table[modkey].the_opt),
			      sl_strlen(modList[modnum].conf_table[modkey].the_opt) ) == 0)
		{
		  good_opt = 0;
		  if (0 != modList[modnum].conf_table[modkey].func(value))
		    sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALS,
				     _(modList[modnum].conf_table[modkey].the_opt), value);
		  if (!sl_is_suid())
		    {
		      TPT(( 0, FIL__, __LINE__, 
			    _("msg=<line = %s, option = %s>\n"), line,
			    _(modList[modnum].conf_table[modkey].the_opt)));
		    }
		  goto outburst;
		}
	    }
	}
    }
  outburst:
#endif


  if (read_mode == SH_SECTION_THRESHOLD) 
    {
      i = 0;
      while (ident[i] != NULL) {
	if (sl_strncmp (key, _(ident[i]), sl_strlen(ident[i])) == 0)
	  {
	    good_opt = 0;
	    sh_error_set_iv (identnum[i], value);
	    break;
	  }
	++i;
      }
    }
  else  
    {
      i = 0;
      while (ext_table[i].optname != NULL)
	{
	  if ((ext_table[i].section == read_mode || 
	       ext_table[i].alt_section == read_mode) &&
	      sl_strncmp (key, _(ext_table[i].optname), 
			  sl_strlen(ext_table[i].optname)) == 0)
	    {
	      good_opt = 0;
	      if (0 != ext_table[i].func (value))
		sh_error_handle ((-1), FIL__, __LINE__, 0, MSG_EINVALS,
				 _(ext_table[i].optname), value);
	      break;
	    }
	  ++i;
	}
    }

  SH_FREE(value_dup);

  SL_RETURN(good_opt, _("sh_readconf_line"));
}

    
