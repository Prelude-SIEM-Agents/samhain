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


/* Public interface for error routines
 */
#ifndef SH_ERROR_H
#define SH_ERROR_H

#include "sh_error_min.h"


enum {
  SH_ERR_T_START  = 0,

  /* 1-13 = SH_LEVEL_XXX */

  SH_ERR_T_RO      = SH_LEVEL_READONLY,
  SH_ERR_T_LOGS    = SH_LEVEL_LOGFILES,
  SH_ERR_T_GLOG    = SH_LEVEL_LOGGROW,
  SH_ERR_T_NOIG    = SH_LEVEL_NOIGNORE,
  SH_ERR_T_ALLIG   = SH_LEVEL_ALLIGNORE,
  SH_ERR_T_ATTR    = SH_LEVEL_ATTRIBUTES,  
  SH_ERR_T_USER0   = SH_LEVEL_USER0,  
  SH_ERR_T_USER1   = SH_LEVEL_USER1,  
  SH_ERR_T_USER2   = SH_LEVEL_USER2,  
  SH_ERR_T_USER3   = SH_LEVEL_USER3,  
  SH_ERR_T_USER4   = SH_LEVEL_USER4,  
  SH_ERR_T_PRELINK = SH_LEVEL_PRELINK,  

  SH_ERR_T_DIR    = 13,
  SH_ERR_T_FILE   = 14,
  SH_ERR_T_NAME   = 15,

  SH_ERR_T_END    = 16
};


typedef struct  _errFlags {
  int           debug;
  int           HaveLog;

  int           loglevel;
  int           loglevel_temp;
  int           printlevel;
  int           maillevel;
  int           exportlevel;
  int           sysloglevel;
  int           externallevel;
  int           databaselevel;

  int           log_class;
  int           print_class;
  int           mail_class;
  int           export_class;
  int           syslog_class;
  int           external_class;
  int           database_class;

  /* HAVE_LIBPRELUDE */
  int           preludelevel;
  int           prelude_class;

} blurb_errFlags;

extern int  ShDFLevel[SH_ERR_T_END];

/* set mask for message class
 */
int sh_error_log_mask (const char * c);
int sh_error_print_mask (const char * c);
int sh_error_mail_mask (const char * c);
int sh_error_export_mask (const char * c);
int sh_error_syslog_mask (const char * c);
int sh_error_external_mask (const char * c);
int sh_error_database_mask (const char * c);
int sh_error_prelude_mask (const char * c);


int sh_error_verify (const char * s);
int sh_error_logverify_mod (const char * s); /* just list, don't verify */
int sh_error_logverify (const char * s);

void sh_error_dbg_switch(void);

#ifdef SH_WITH_SERVER

void sh_error_set_peer(const char * str);
#ifdef HAVE_LIBPRELUDE
void sh_error_set_peer_ip(const char * str);
#endif
int  set_flag_sep_log (const char * str);
#endif

/* init or re-init log facilities that need it
 */
void sh_error_fixup(void);

/* only to stderr (GOOD/BAD)
 */
void sh_error_only_stderr (int flag);

/* facilities unsafe for closeall()
 */
void sh_error_enable_unsafe (int flag);

/* set syslog facility 
 */
int  sh_log_set_facility (const char * c);

/* map heartbeat messages 
 */
int sh_log_set_stamp_priority (const char * c);

/* define message header
 */
int sh_error_ehead (/*@null@*/const char * s);

/* set level for error logging 
 */
int sh_error_setlog(const char * str_s);

/* set severity levels
 */
int sh_error_set_iv (int iv, const char *  severity_s);

/* set priorities
 */
int sh_error_set_level(const char * str_s, int *facility);

/* set level for TCP export
 */
int sh_error_setexport(const char *  str_s);

/* set level for syslog
 */
int sh_error_set_syslog (const char * flag_s);

/* set level for printing
 */
int sh_error_setprint(const char *  flag_s);

/* set severity for external
 */
int sh_error_set_external (const char * str_s);

/* set severity for external
 */
int sh_error_set_database (const char * str_s);

/* set severity for external
 */
int sh_error_set_prelude (const char * str_s);


/* set level for mailing
 */
int sh_error_setseverity (const char * flag);

/* set debug level
 */
int sh_error_setdebug (char * debug_s);

/* switch on/off log to file temporarily
 */
void sh_error_logoff(void);
void sh_error_logrestore(void);

/* short errfile
 */
void sh_efile_report();
int sh_efile_path(const char * str);
int sh_efile_group(const char * str);

/* (re)set the console device(s)
 */
int sh_log_set_console (const char * address);
void reset_count_dev_console(void);

/* close the message queue [no-op if !defined(WITH_MESSAGE_QUEUE)]
 */
void close_ipc (void);

#ifdef WITH_MESSAGE_QUEUE
/* enable message queue
 */
int enable_msgq(const char * foo);
#endif
 
#endif
