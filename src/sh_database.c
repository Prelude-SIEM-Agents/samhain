/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2001 Rainer Wichmann                                      */
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
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#ifdef WITH_DATABASE

/* define this if you want to debug the Oracle database support */
/* #define DB_DEBUG  */

#define SH_REAL_SET

#include "samhain.h"

#include "sh_cat.h"
#include "sh_error.h"
#include "sh_utils.h"

#undef  FIL__
#define FIL__  _("sh_database.c")

typedef struct my_attr_ 
{
  char * attr;
  char * attr_o;
  int    inHash;
  int    val;
  int    size;
  int    alen;
  size_t off;
} my_attr;

typedef struct dbins_ {
  struct dbins_ * next;
  char            host[64];
  char            time[20];
  char            msg[1024];
  char            sev[8];
  char            path[MAX_PATH_STORE+1];
  char            user[9];
  char            group[9];
  char            program[8];
  char            subroutine[16];
  char            status[12];
  char            hash[50];
  char            path_data[1024];
  char            hash_data[50];
  char            key_uid[64];
  char            key_uid_data[64];
  char            key_id[16];
  char            module[8];
  char            syscall[16];
  char            ip[SH_IP_BUF];     
  char            tty[16];    
  char            peer[64];
  char            fromhost[64];
  char            obj[1024];   
  char            interface[64];   
  char            ltime[64];   
  char            dir[MAX_PATH_STORE+1];   
  char            linked_path[MAX_PATH_STORE+1]; 
  char            service[64];   
  char            facility[32];   
  char            priority[32];   
  char            syslog_msg[1024];

  char            mode_old[16];
  char            mode_new[16];
  char            attr_old[16];
  char            attr_new[16];
  char            device_old[16];
  char            device_new[16];
  char            owner_old[9];
  char            owner_new[9];
  char            group_old[9];
  char            group_new[9];
  char            ctime_old[20];
  char            ctime_new[20];
  char            atime_old[20];
  char            atime_new[20];
  char            mtime_old[20];
  char            mtime_new[20];
  char            chksum_old[50];
  char            chksum_new[50];
  char            link_old[MAX_PATH_STORE+1];
  char            link_new[MAX_PATH_STORE+1];
  char            acl_old[1024];
  char            acl_new[1024];

  unsigned long   ulong_data[20];

  /*
  long            size_old;
  long            size_new;
  long            hardlinks_old;
  long            hardlinks_new;
  long            inode_old;
  long            inode_new;
  */

} dbins;

static my_attr * attr_tab_srch = NULL;
static int       attr_tab_srch_siz = 0;

static my_attr attr_tab[] = {
  { NULL, N_("sev"),         0,   1,    8, 0, offsetof(struct dbins_, sev) },
  { NULL, N_("tstamp"),      0,   2,   16, 0, offsetof(struct dbins_, time) },
  { NULL, N_("remote_host"), 0,   3,   64, 0, offsetof(struct dbins_, host) },
  { NULL, N_("msg"),         0,   4, 1024, 0, offsetof(struct dbins_, msg) },

  { NULL, N_("path"),        0,   5,MAX_PATH_STORE+1, 0, offsetof(struct dbins_, path)  },
  /* username -> userid; replace (long) 'userid' - below - by 'dummy' */ 
  { NULL, N_("userid"),      0,   6,    9, 0, offsetof(struct dbins_, user)  },
  { NULL, N_("group"),       0,   7,    9, 0, offsetof(struct dbins_, group)  },
  { NULL, N_("program"),     0,   8,    8, 0, offsetof(struct dbins_, program)  },
  { NULL, N_("subroutine"),  0,   9,   16, 0, offsetof(struct dbins_, subroutine)},
  { NULL, N_("status"),      0,  10,   12, 0, offsetof(struct dbins_, status)  },
  { NULL, N_("hash"),        0,  11,   50, 0, offsetof(struct dbins_, hash)  },
  { NULL, N_("path_data"),   0,  12, 1024, 0, offsetof(struct dbins_, path_data)  },
  { NULL, N_("hash_data"),   0,  13,   50, 0, offsetof(struct dbins_, hash_data)  },
  { NULL, N_("key_uid"),     0,  14,   64, 0, offsetof(struct dbins_, key_uid)  },
  { NULL, N_("key_uid_data"),0,  15,   64, 0, offsetof(struct dbins_, key_uid_data)},
  { NULL, N_("key_id"),      0,  16,   16, 0, offsetof(struct dbins_, key_id)  },
  { NULL, N_("module"),      0,  17,    8, 0, offsetof(struct dbins_, module)  },
  { NULL, N_("syscall"),     0,  19,   16, 0, offsetof(struct dbins_, syscall)  },
  { NULL, N_("ip"),          0,  20,SH_IP_BUF, 0, offsetof(struct dbins_, ip)  },
  { NULL, N_("tty"),         0,  21,   16, 0, offsetof(struct dbins_, tty)  },
  { NULL, N_("peer"),        0,  22,   64, 0, offsetof(struct dbins_, peer)  },
  { NULL, N_("obj"),         0,  23, 1024, 0, offsetof(struct dbins_, obj)  },
  { NULL, N_("interface"),   0,  24,   64, 0, offsetof(struct dbins_, interface)},
  { NULL, N_("time"),        0,  25,   64, 0, offsetof(struct dbins_, ltime)  },
  { NULL, N_("dir"),         0,  26, MAX_PATH_STORE+1, 0, offsetof(struct dbins_, dir)  },
  { NULL, N_("linked_path"), 0,  27, MAX_PATH_STORE+1, 0, offsetof(struct dbins_, linked_path)},
  { NULL, N_("service"),     0,  29,   64, 0, offsetof(struct dbins_, service)},
  { NULL, N_("facility"),    0,  30,   32, 0, offsetof(struct dbins_, facility) },
  { NULL, N_("priority"),    0,  31,   32, 0, offsetof(struct dbins_, priority) },
  { NULL, N_("syslog_msg"),  0,  32, 1024, 0, offsetof(struct dbins_, syslog_msg)  },

  { NULL, N_("mode_old"),    0,  33,   16, 0, offsetof(struct dbins_, mode_old) },
  { NULL, N_("mode_new"),    0,  34,   16, 0, offsetof(struct dbins_, mode_new) },
  { NULL, N_("device_old"),  0,  35,   16, 0, offsetof(struct dbins_, device_old)}, 
  { NULL, N_("device_new"),  0,  36,   16, 0, offsetof(struct dbins_, device_new)},
  { NULL, N_("owner_old"),   0,  37,    9, 0, offsetof(struct dbins_, owner_old)},
  { NULL, N_("owner_new"),   0,  38,    9, 0, offsetof(struct dbins_, owner_new)},
  { NULL, N_("group_old"),   0,  39,    9, 0, offsetof(struct dbins_, group_old)},
  { NULL, N_("group_new"),   0,  40,    9, 0, offsetof(struct dbins_, group_new)},
  { NULL, N_("ctime_old"),   0,  41,   20, 0, offsetof(struct dbins_, ctime_old)},
  { NULL, N_("ctime_new"),   0,  42,   20, 0, offsetof(struct dbins_, ctime_new)},
  { NULL, N_("atime_old"),   0,  43,   20, 0, offsetof(struct dbins_, atime_old)},
  { NULL, N_("atime_new"),   0,  44,   20, 0, offsetof(struct dbins_, atime_new)},
  { NULL, N_("mtime_old"),   0,  45,   20, 0, offsetof(struct dbins_, mtime_old)},
  { NULL, N_("mtime_new"),   0,  46,   20, 0, offsetof(struct dbins_, mtime_new)},
  { NULL, N_("chksum_old"),  0,  47,   50, 0, offsetof(struct dbins_, chksum_old)},
  { NULL, N_("chksum_new"),  0,  48,   50, 0, offsetof(struct dbins_, chksum_new)},
  { NULL, N_("link_old"),    0,  49, MAX_PATH_STORE+1, 0, offsetof(struct dbins_, link_old)},
  { NULL, N_("link_new"),    0,  50, MAX_PATH_STORE+1, 0, offsetof(struct dbins_, link_new)},

  /* These go into  dbins.ulong_data[n - START_SEC_LONGS] */             				    
  { NULL, N_("size_old"),     0,  51,    0, 0, 0  },
  { NULL, N_("size_new"),     0,  52,    0, 0, 0  },
  { NULL, N_("hardlinks_old"),0,  53,    0, 0, 0  },
  { NULL, N_("hardlinks_new"),0,  54,    0, 0, 0  },
  { NULL, N_("inode_old"),    0,  55,    0, 0, 0  }, 
  { NULL, N_("inode_new"),    0,  56,    0, 0, 0  }, 
					    
  { NULL, N_("imode_old"),    0,  57,    0, 0, 0  },
  { NULL, N_("imode_new"),    0,  58,    0, 0, 0  },
  { NULL, N_("iattr_old"),    0,  59,    0, 0, 0  },
  { NULL, N_("iattr_new"),    0,  60,    0, 0, 0  },
  { NULL, N_("idevice_old"),  0,  61,    0, 0, 0  }, 
  { NULL, N_("idevice_new"),  0,  62,    0, 0, 0  }, 
  { NULL, N_("iowner_old"),   0,  63,    0, 0, 0  },
  { NULL, N_("iowner_new"),   0,  64,    0, 0, 0  },
  { NULL, N_("igroup_old"),   0,  65,    0, 0, 0  },
  { NULL, N_("igroup_new"),   0,  66,    0, 0, 0  },

  { NULL, N_("port"),         0,  67,    0, 0, 0  },
  { NULL, N_("return_code"),  0,  68,    0, 0, 0  },

  { NULL, N_("checkflags_old"), 0,  69,    0, 0, 0  },
  { NULL, N_("checkflags_new"), 0,  70,    0, 0, 0  },

  /* END_SEC_LONGS                                         */

  { NULL, N_("host"),         0,  71,   64, 0, offsetof(struct dbins_, fromhost)},
  { NULL, N_("attr_old"),     0,  72,   16, 0, offsetof(struct dbins_, attr_old)},
  { NULL, N_("attr_new"),     0,  73,   16, 0, offsetof(struct dbins_, attr_new)},
  { NULL, N_("acl_old"),      0,  74, 1024, 0, offsetof(struct dbins_, acl_old)},
  { NULL, N_("acl_new"),      0,  75, 1024, 0, offsetof(struct dbins_, acl_new)},

  { NULL, NULL,      0,  0, 0, 0, 0 }
};

#define SH_SLOT_CHECKFLAGS 69

/* need special attention b/o reserved SQL words    */
#define SH_SLOT_HOST    71
#define SH_SLOT_GROUP    7

/* these go into dbins.ulong_data[n-START_SEC_LONGS */
#define START_SEC_LONGS 51
#define END_SEC_LONGS   70

#if defined(HAVE_INT_32)
typedef unsigned int uint32;
#elif defined(HAVE_LONG_32)
typedef unsigned long uint32;
#elif defined(HAVE_SHORT_32)
typedef unsigned short uint32;
#else
#error No 32 byte type found !
#endif

typedef unsigned char uint8;

typedef struct md5_ctx
{
  uint32 A;
  uint32 B;
  uint32 C;
  uint32 D;

  uint32 total[2];
  uint32 buflen;
  char buffer[128];
} md5Param;


typedef unsigned char        sh_byte;


extern int md5Reset(register md5Param* p);
extern int md5Update(md5Param* p, const sh_byte* data, int size);
extern int md5Digest(md5Param* p, uint32* data);

static char db_name[64]     = ""; 
static char db_table[64]    = ""; 
static char db_host[64]     = ""; 
static char db_user[64]     = ""; 
static char db_password[64] = "";

static int  sh_persistent_dbconn = S_TRUE;

int sh_database_use_persistent (const char * str)
{
  return sh_util_flagval (str, &sh_persistent_dbconn);
}

static int insert_value (char * ptr, const char * str)
{
  if (!ptr || !str)
    return -1;
  if (strlen(str) > 63)
    return -1;
  (void) sl_strlcpy(ptr, str, 64);
  return 0;
}

static void init_db_entry (dbins * ptr)
{
  memset (ptr, (int) '\0', sizeof(dbins));
  ptr->next = NULL;
  return;
}
  

int sh_database_set_database (const char * str)
{
  return insert_value (db_name, str);
}
int sh_database_set_table (const char * str)
{
  return insert_value (db_table, str);
}
int sh_database_set_host (const char * str)
{
  return insert_value (db_host, str);
}
int sh_database_set_user (const char * str)
{
  return insert_value (db_user, str);
}
int sh_database_set_password (const char * str)
{
  return insert_value (db_password, str);
}

/******************************************************************
 *
 *  Oracle and unixODBC stuff, only Oracle tested untested
 *
 *  Based on the code in the snort output plugin (spo_database.c).
 *  Copyright/license statement in spo_database.c:
 *
 * Portions Copyright (C) 2000,2001,2002 Carnegie Mellon University
 * Copyright (C) 2001 Jed Pickel <jed@pickel.net>
 * Portions Copyright (C) 2001 Andrew R. Baker <andrewb@farm9.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ******************************************************************/
#ifdef WITH_ODBC

#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>

static    SQLHENV     u_handle;
static    SQLHDBC     u_connection;
static    SQLHSTMT    u_statement;
static    SQLINTEGER  u_col;
static    SQLINTEGER  u_rows;

void sh_database_reset()
{
  return;
}

static
int sh_database_query (char  * query, /*@out@*/ long * id)
{
  static int fatal_error = 0;
  int result = 0;
  char         row_query[128];
  long result_call;

  SL_ENTER(_("sh_database_query"));

  *id = 0;

  if (fatal_error == 1)
    {
      SL_RETURN((-1), _("sh_database_query"));
    }

  /* Connect
   */
  if (db_name[0]     == '\0')
    sl_strlcpy(db_name,  _("samhain"),   64);

  if (db_user[0]     == '\0')
    sl_strlcpy(db_user,  _("samhain"),   64);

  result_call = SQLAllocEnv(&u_handle);
  if ((result_call != SQL_SUCCESS) && (result_call != SQL_SUCCESS_WITH_INFO))
    {
      sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, result_call, 
		      MSG_E_SUBGEN,
		      _("Error in SQLAllocEnv when connecting to ODBC data source"), 
		      _("sh_database_query"));
      fatal_error = 1;
      SL_RETURN((-1), _("sh_database_query"));
    }
  result_call = SQLAllocConnect(u_handle, &u_connection);
  if ((result_call != SQL_SUCCESS) && (result_call != SQL_SUCCESS_WITH_INFO))
    {
      sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, result_call,
		      MSG_E_SUBGEN,
		      _("Error in SQLAllocEnv when connecting to ODBC data source"), 
		      _("sh_database_query"));
      fatal_error = 1;
      SL_RETURN((-1), _("sh_database_query"));
    }
  result_call = SQLConnect(u_connection, db_name, SQL_NTS, 
			   db_user, SQL_NTS, db_password, SQL_NTS);
  if ((result_call != SQL_SUCCESS) && (result_call != SQL_SUCCESS_WITH_INFO))
    {
      sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, result_call, 
		      MSG_E_SUBGEN,
		      _("Error in SQLAllocEnv when connecting to ODBC data source"), 
		      _("sh_database_query"));
      fatal_error = 1;
      SL_RETURN((-1), _("sh_database_query"));
    }

  /* Insert
   */
  result_call = SQLAllocStmt(u_connection, &u_statement);
  if ((result_call == SQL_SUCCESS) || (result_call == SQL_SUCCESS_WITH_INFO))
    {
      result_call = SQLPrepare(u_statement, query, SQL_NTS);
      if ((result_call == SQL_SUCCESS) || 
	  (result_call == SQL_SUCCESS_WITH_INFO))
	{
	  result_call = SQLExecute(u_statement);
	  if((result_call == SQL_SUCCESS) || 
	     (result_call == SQL_SUCCESS_WITH_INFO))
	    {
	      result = 1;
	    }
	}
    }

  if (result == 0)
    {
      sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("Error inserting into ODBC data source"), 
		      _("sh_database_query"));
      goto odbc_disconnect;
    }

  /* Select
   */
  result = 0;

  sl_strlcpy (row_query, _("SELECT MAX(log_index) FROM "), 128);
  sl_strlcat (row_query, db_table, 128);

  result_call = SQLAllocStmt(u_connection, &u_statement);
  if ((result_call == SQL_SUCCESS) ||
      (result_call == SQL_SUCCESS_WITH_INFO))
    {
      result_call = SQLPrepare(u_statement, row_query, SQL_NTS);
      if ((result_call == SQL_SUCCESS) ||
	  (result_call == SQL_SUCCESS_WITH_INFO))
	{
	  result_call = SQLExecute(u_statement);
	  if ((result_call == SQL_SUCCESS) ||
	      (result_call == SQL_SUCCESS_WITH_INFO))
	    {
	      result_call = SQLRowCount(u_statement, &u_rows);
	      if ((result_call == SQL_SUCCESS) ||
		  (result_call == SQL_SUCCESS_WITH_INFO))
		{
		  if((u_rows) && (u_rows == 1))
		    {
		      result_call = SQLFetch(u_statement);
		      if ((result_call == SQL_SUCCESS) ||
			  (result_call == SQL_SUCCESS_WITH_INFO))
			{
			  result_call = SQLGetData(u_statement, 1, 
						   SQL_INTEGER, &u_col,
						   sizeof(u_col), NULL);
			  if ((result_call == SQL_SUCCESS) ||
			      (result_call == SQL_SUCCESS_WITH_INFO))
			    {
			      *id = (long int) u_col;
			      result = 1;
			    }
			}
		    }
		}
	    }
	}
    }

  if (result == 0)
    {
      sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("Error selecting MAX(log_index) from ODBC data source"), 
		      _("sh_database_query"));
    }

 odbc_disconnect:
  SQLFreeHandle(SQL_HANDLE_STMT, u_statement);
  SQLDisconnect(u_connection); 
  SQLFreeHandle(SQL_HANDLE_DBC, u_connection);
  SQLFreeHandle(SQL_HANDLE_ENV, u_handle);

  SL_RETURN(((result == 0) ? -1 : 0), _("sh_database_query"));
  
}

/* #ifdef WITH_ODBC */
#endif

#ifdef WITH_ORACLE

#include <oci.h>

static    OCIDefine * o_define;
static    OCIEnv    * o_environment;
static    OCISvcCtx * o_servicecontext;
static    OCIError  * o_error = NULL;
static    OCIStmt   * o_statement;
static    OCIBind   * o_bind = (OCIBind *) 0;
static    text        o_errormsg[512];
static    sb4         o_errorcode;

static  int  connected = 0;

void sh_database_reset()
{
  if (connected == 1) 
    {
      OCILogoff(o_servicecontext, o_error);
      OCIHandleFree((dvoid *) o_statement,      OCI_HTYPE_STMT);
      OCIHandleFree((dvoid *) o_servicecontext, OCI_HTYPE_SVCCTX);
      OCIHandleFree((dvoid *) o_error,          OCI_HTYPE_ERROR);
      o_error = NULL;
    }
  connected = 0;
  return;
}

static char * sh_stripnl (char * str)
{
  size_t len = sl_strlen(str);
  if (len > 0)
    {
      if (str[len-1] == '\n')
	str[len-1] = '\0';
    }
  return str;
}

static
int sh_database_query (char  * query, /*@out@*/ long * id)
{
  static  int  bad_init  = 0;
  int          result    = 0;
  char         row_query[128];
  int          retry     = 0;
  static SH_TIMEOUT sh_timer = { 0, 3600, S_TRUE };


  SL_ENTER(_("sh_database_query"));

  *id = 0;

  if (bad_init == 1) {
    SL_RETURN(-1, _("sh_database_query"));
  }
  else if (connected == 1) {
    goto oracle_connected;
  }

  /* 
   * Connect
   */
#define PRINT_ORACLE_ERR(func_name) \
     do { \
         OCIErrorGet(o_error, 1, NULL, &o_errorcode, \
                     o_errormsg, sizeof(o_errormsg), \
                     OCI_HTYPE_ERROR); \
         sh_stripnl (o_errormsg); \
         sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN, \
		     o_errormsg, _("sh_database_query")); \
         sl_snprintf(row_query, 127, \
		     _("%s: Connection to database '%s' failed"), \
                     func_name, db_name); \
         sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN, \
		     row_query, _("sh_database_query")); \
         bad_init = 1; \
         SL_RETURN(-1, _("sh_database_query")); \
     } while (1 == 0)

 oracle_doconnect:

  if (!getenv("ORACLE_HOME")) /* flawfinder: ignore */
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("ORACLE_HOME environment variable not set"), 
		      _("sh_database_query"));
    }
  if (db_name[0]     == '\0')
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("database name not set, using default 'samhain'"), 
		      _("sh_database_query"));
      sl_strlcpy(db_name,  _("samhain"),   64);
    }
  if (db_user[0]     == '\0')
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("database user not set, using default 'samhain'"), 
		      _("sh_database_query"));
      sl_strlcpy(db_user,  _("samhain"),   64);
    }
  if (db_password[0] == '\0')
    {
      sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("database password not set, cannot proceed"), 
		      _("sh_database_query"));
      bad_init = 1;
      SL_RETURN(-1, _("sh_database_query"));
    }


#ifdef DB_DEBUG
  sl_snprintf(row_query, 127, 
	      _("Conncting to oracle database '%s'"), 
	      db_name); 
  sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  row_query, 
		  _("sh_database_query"));
#endif

  /* a) Oracle says use OCIEnvCreate instead of OCIInitialize/OCIEnvcreate
   * b) why two times OCIEnvInit() ???
   */
  if (OCIInitialize(OCI_DEFAULT, NULL, NULL, NULL, NULL)) 
    PRINT_ORACLE_ERR("OCIInitialize");
  
  if (OCIEnvInit(&o_environment, OCI_DEFAULT, 0, NULL)) 
    PRINT_ORACLE_ERR("OCIEnvInit");
  
  if (OCIEnvInit(&o_environment, OCI_DEFAULT, 0, NULL)) 
    PRINT_ORACLE_ERR("OCIEnvInit (2)");

  /* allocate and initialize the error handle 
   */
  if (OCIHandleAlloc(o_environment, (dvoid **)&o_error, 
		     OCI_HTYPE_ERROR, (size_t) 0, NULL))
    PRINT_ORACLE_ERR("OCIHandleAlloc");

  /* logon and allocate the service context handle 
   */
  if (OCILogon(o_environment, o_error, &o_servicecontext,
	       (OraText*) db_user,     sl_strlen(db_user), 
	       (OraText*) db_password, sl_strlen(db_password), 
	       (OraText*) db_name,     sl_strlen(db_name))) 
      {
   
	connected = 0;

	sh_timer.flag_ok = S_FALSE;

	if (S_TRUE == sh_util_timeout_check(&sh_timer))
	  {
	    OCIErrorGet(o_error, 1, NULL, &o_errorcode, 
			o_errormsg, sizeof(o_errormsg), OCI_HTYPE_ERROR);
	    sh_stripnl (o_errormsg);
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    o_errormsg, 
			    _("sh_database_query"));
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    _("check database is listed in tnsnames.ora"), 
			    _("sh_database_query"));
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    _("check tnsnames.ora readable"), 
			    _("sh_database_query"));
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
			    _("check database accessible with sqlplus"), 
			    _("sh_database_query"));
	    sl_snprintf(row_query, 127, 
			_("OCILogon: Connection to database '%s' failed"), 
			db_name); 
	    sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN, 
			    row_query, _("sh_database_query")); 

	    goto err_out;
	  }
	else
	  {
	    SL_RETURN(0, _("sh_database_query"));
	  }
      }
 
  if (OCIHandleAlloc(o_environment, (dvoid **)&o_statement, 
		     OCI_HTYPE_STMT, 0, NULL))
    PRINT_ORACLE_ERR("OCIHandleAlloc (2)");

  /* Flag connection status
   */
  connected = 1;

 oracle_connected:

  /* Get row index
   */
  sl_strlcpy (row_query, _("SELECT log_log_index_seq.NEXTVAL FROM dual"), 128);

#ifdef DB_DEBUG
  sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  row_query, 
		  _("sh_database_query"));
#endif

  if (OCIStmtPrepare(o_statement, o_error, 
		     (OraText*) row_query, sl_strlen(row_query), 
		     OCI_NTV_SYNTAX, OCI_DEFAULT))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	  { 
	    ++retry; sh_database_reset(); goto oracle_doconnect; 
	  }
      goto err_out;
    }

  if (OCIStmtExecute(o_servicecontext, o_statement, o_error, 
		     0, 0, NULL, NULL, OCI_DEFAULT))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	  { 
	    ++retry; sh_database_reset(); goto oracle_doconnect; 
	  }
      goto err_out;
    }

  if (OCIDefineByPos (o_statement, &o_define, o_error, 1, 
		      &result, sizeof(result), 
		      SQLT_INT, 0, 0, 0, OCI_DEFAULT))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	  { 
	    ++retry; sh_database_reset(); goto oracle_doconnect; 
	  }
      goto err_out;
    }
  if (OCIStmtFetch (o_statement, o_error, 1, OCI_FETCH_NEXT, OCI_DEFAULT))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	  { 
	    ++retry; sh_database_reset(); goto oracle_doconnect; 
	  }
      goto err_out;
    }
  
#ifdef DB_DEBUG
  sl_snprintf(row_query, 127, _("Returned value: %d"), result); 
  sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  row_query, 
		  _("sh_database_query"));
#endif

  *id = result;

  /* do the insert
   */
#ifdef DB_DEBUG
  sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  query, 
		  _("sh_database_query"));
#endif

  if (OCIStmtPrepare(o_statement, o_error, 
		     (OraText*) query, sl_strlen(query), 
		     OCI_NTV_SYNTAX, OCI_DEFAULT))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	{ 
	  ++retry; sh_database_reset(); goto oracle_doconnect; 
	}
      goto err_out;
    }
 
  if (OCIBindByPos(o_statement, &o_bind, o_error, 1,
		   (dvoid *) &result, (sword) sizeof(result), SQLT_INT, 
		   (dvoid *) 0, (ub2 *) 0, (ub2 *) 0, (ub4) 0, (ub4 *) 0, OCI_DEFAULT))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	  { 
	    ++retry; sh_database_reset(); goto oracle_doconnect; 
	  }
      goto err_out;
    }

   if (OCIStmtExecute(o_servicecontext, 
		      o_statement, o_error, 1,  0, 
		      NULL, NULL, OCI_COMMIT_ON_SUCCESS))
    {
      OCIErrorGet(o_error, 1, NULL, 
		  &o_errorcode, o_errormsg, sizeof(o_errormsg), 
		  OCI_HTYPE_ERROR);
      sh_stripnl (o_errormsg);
      sh_error_handle((-1), FIL__, __LINE__, (long) o_errorcode, MSG_E_SUBGEN,
		      o_errormsg, 
		      _("sh_database_query"));
      if (retry == 0 && 
	  (3114 == o_errorcode || 0 == strncmp(o_errormsg, _("ORA-03114"), 9))) 
	  { 
	    ++retry; sh_database_reset(); goto oracle_doconnect; 
	  }
      goto err_out;
    }

#ifdef DB_DEBUG
  sh_error_handle(SH_ERR_NOTICE, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  _("No error on insert"), 
		  _("sh_database_query"));
#endif

  if (sh_persistent_dbconn == S_FALSE)
    {
      OCILogoff(o_servicecontext, o_error);
      OCIHandleFree((dvoid *) o_statement,      OCI_HTYPE_STMT);
      OCIHandleFree((dvoid *) o_servicecontext, OCI_HTYPE_SVCCTX);
      OCIHandleFree((dvoid *) o_error,          OCI_HTYPE_ERROR);
      o_error = NULL;
      connected = 0;
    }
  SL_RETURN(0, _("sh_database_query"));

 err_out:
  /* 
   * Error
   */
  sh_database_reset();

  SL_RETURN(-1, _("sh_database_query"));
}

/* #ifdef WITH_ORACLE */
#endif

#ifdef WITH_POSTGRES
/******************************************************************
 *
 *  Postgresql stuff, tested
 *
 ******************************************************************/

#if defined(HAVE_PGSQL_LIBPQ_FE_H)
#include <pgsql/libpq-fe.h>
#elif defined(HAVE_POSTGRESQL_LIBPQ_FE_H)
#include <postgresql/libpq-fe.h>
#else
#if !defined(USE_UNO)
#include <libpq-fe.h>
#else
#include <postgresql/libpq-fe.h>
#endif
#endif

static int        connection_status = S_FALSE;

void sh_database_reset()
{
  connection_status = S_FALSE;
  return;
}

static
int sh_database_query (char  * query, /*@out@*/ long * id)
{
  char              conninfo[256];
  char            * p;
  static PGconn   * conn = NULL;
  PGresult        * res;
  unsigned int      i;
  const char      * params[1];
  char              id_param[32];
  static SH_TIMEOUT sh_timer = { 0, 3600, S_TRUE };

  SL_ENTER(_("sh_database_query"));

  *id       = 0; 

  p = &conninfo[0]; 

  if (db_host[0]     == '\0')
    sl_strlcpy(db_host,  _("localhost"), 64);
  if (db_name[0]     == '\0')
    sl_strlcpy(db_name,  _("samhain"),   64);
  if (db_user[0]     == '\0')
    sl_strlcpy(db_user,  _("samhain"),   64);

  if (db_host[0]     != '\0' && NULL != strchr(db_host, '.')) 
    {
      sl_snprintf(p, 255, "hostaddr=%s ", db_host);
      p = &conninfo[strlen(conninfo)];
    }
  if (db_name[0]     != '\0') 
    {
      sl_snprintf(p, 255 - strlen(conninfo), "dbname=%s ", db_name);
      p = &conninfo[strlen(conninfo)];
    }

  if (db_user[0]     != '\0') 
    {
      sl_snprintf(p, 255 - strlen(conninfo), "user=%s ", db_user);
      p = &conninfo[strlen(conninfo)];
    }

  if (db_password[0] != '\0') 
    {
      sl_snprintf(p, 255 - strlen(conninfo), "password=%s ", db_password);
    }

  if (connection_status == S_FALSE)
    {
      if (conn)
	PQfinish(conn);
      conn = NULL;
      conn = PQconnectdb(conninfo);
    }
  else
    {
      if (PQstatus(conn) == CONNECTION_BAD) 
	PQreset(conn);
    }

  if ((conn == NULL) || (PQstatus(conn) == CONNECTION_BAD))
    {
      connection_status = S_FALSE;

      sh_timer.flag_ok = S_FALSE;
      if (S_TRUE == sh_util_timeout_check(&sh_timer))
	{
	  goto err_out;
	}
      else
	{
	  if (conn)
	    PQfinish(conn);
	  conn = NULL;
	  SL_RETURN(0, _("sh_database_query"));
	}
    }
  connection_status = S_TRUE;


  /* get the unique row index
   */
  res = PQexec(conn, _("SELECT NEXTVAL('log_log_index_seq')"));
  if (PQresultStatus(res) != PGRES_TUPLES_OK) 
    {
      PQclear(res);
      goto err_out;
    }

  *id = atoi (PQgetvalue(res, 0, 0)); 
  PQclear(res);

  sl_snprintf(id_param, 32, "%ld", *id);
  params[0] = id_param;

  /* do the insert
   */
  res = PQexecParams(conn, query, 1, NULL, params, NULL, NULL, 1);
  if (PQresultStatus(res) != PGRES_COMMAND_OK) 
    {
      PQclear(res);
      goto err_out;
    }
  PQclear(res);

  if (S_FALSE == sh_persistent_dbconn)
    {
      if (conn)
	PQfinish(conn);
      conn = NULL;
      connection_status = S_FALSE;
    }
  SL_RETURN(0, _("sh_database_query"));


 err_out:
  if (conn)
    {
      p = PQerrorMessage(conn);
      for (i = 0; i < sl_strlen(p); ++i)
	if (p[i] == '\n') p[i] = ' ';
    }
  else
    {
      p = NULL;
    }
  sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
		  (p == NULL ? _("(null)") : p), 
		  _("sh_database_query"));
  if (conn)
    PQfinish(conn);
  conn = NULL;
  connection_status = S_FALSE;
  SL_RETURN(-1, _("sh_database_query"));
}
#endif 


#ifdef WITH_MYSQL 

#ifdef HAVE_MYSQL_MYSQL_H
#include <mysql/mysql.h>
#else
#include <mysql.h>
#endif 

extern int flag_err_debug;

static int        connection_status = S_FALSE;

void sh_database_reset(void)
{
  connection_status = S_FALSE;
  return;
}

static
int sh_database_query (char  * query, /*@out@*/ long * id)
{
  int               status = 0;
  const char      * p;
  static MYSQL    * db_conn = NULL;
  static SH_TIMEOUT sh_timer = { 0, 3600, S_TRUE };

  SL_ENTER(_("sh_database_query"));

  *id = 0;

  if (query == NULL)
    {
      sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
		      _("NULL query"), 
		      _("sh_database_query"));
      SL_RETURN(0, _("sh_database_query"));
    }

  if (db_host[0]     == '\0')
    (void) sl_strlcpy(db_host,  _("localhost"), 64);
  if (db_name[0]     == '\0')
    (void) sl_strlcpy(db_name,  _("samhain"),   64);
  if (db_user[0]     == '\0')
    (void) sl_strlcpy(db_user,  _("samhain"),   64);

  if ((db_conn == NULL) || (connection_status == S_FALSE))
    {
      if (db_conn)
	{
	  mysql_close(db_conn);
	  db_conn = NULL;
	}
      connection_status = S_FALSE;

      db_conn = mysql_init(NULL);
      if (NULL == db_conn)
	{
	  p = NULL; status = 0;
	  sh_timer.flag_ok = S_FALSE;
	  if (S_TRUE == sh_util_timeout_check(&sh_timer))
	    {
	      goto alt_out;
	    }
	  else
	    {
	      SL_RETURN(0, _("sh_database_query"));
	    }
	}

      /* Read in defaults from /etc/my.cnf and associated files,
       * suggested by arjones at simultan dyndns org
       * see: - http://dev.mysql.com/doc/refman/5.0/en/option-files.html
       *        for the my.cnf format,
       *      - http://dev.mysql.com/doc/refman/5.0/en/mysql-options.html
       *        for possible options
       * We don't check the return value because it's useless (failure due 
       * to lack of access permission is not reported).
       */
#if !defined(__x86_64__)
      /* 
       *   libmysql segfaults on x86-64 if this is used
       */
      mysql_options(db_conn, MYSQL_READ_DEFAULT_GROUP, _("samhain"));
#endif

      status = 0;
  
      if (NULL == mysql_real_connect(db_conn, 
				     db_host[0] == '\0'     ? NULL : db_host, 
				     db_user[0] == '\0'     ? NULL : db_user, 
				     db_password[0] == '\0' ? NULL : db_password,
				     db_name[0] == '\0'     ? NULL : db_name, 
				     0, NULL, 0))
	{
	  sh_timer.flag_ok = S_FALSE;
	  if (S_TRUE == sh_util_timeout_check(&sh_timer))
	    {
	      goto err_out;
	    }
	  else
	    {
	      SL_RETURN(0, _("sh_database_query"));
	    }
	}
      connection_status = S_TRUE;
    }
  else
    {
      if (0 != mysql_ping(db_conn))
	{
	  connection_status = S_FALSE;
	  sh_timer.flag_ok = S_FALSE;
	  if (S_TRUE == sh_util_timeout_check(&sh_timer))
	    {
	      goto err_out;
	    }
	  else
	    {
	      SL_RETURN(0, _("sh_database_query"));
	    }
	}
    }
  
  if (0 != mysql_query(db_conn, query))
    {
      goto err_out;
    }

  if (flag_err_debug == S_TRUE)
    {
      p = mysql_info (db_conn);
      if (p != NULL)
	{
	  sh_error_handle(SH_ERR_ALL, FIL__, __LINE__, 0, MSG_E_SUBGEN,
			  p, 
			  _("sh_database_query"));
	}
    }

  *id = (long) mysql_insert_id(db_conn);
  if (S_FALSE == sh_persistent_dbconn)
    {
      if (db_conn)
	mysql_close(db_conn);
      db_conn = NULL;
      connection_status = S_FALSE;
    }
  SL_RETURN(0, _("sh_database_query"));

 err_out:

  if (db_conn)
    {
      p      = mysql_error (db_conn);
      status = (int) mysql_errno (db_conn);
    }
  else
    {
      p = NULL; p = 0;
    }

 alt_out:

  *id = 0;
  sh_error_handle((-1), FIL__, __LINE__, status, MSG_E_SUBGEN,
		  (p == NULL ? _("(null)") : p), 
		  _("sh_database_query"));
  if (db_conn)
    mysql_close(db_conn);
  db_conn = NULL;
  connection_status = S_FALSE;
  SL_RETURN(status, _("sh_database_query"));
}
#endif

static
char * null_or_val (char * end,   char * val,   int * size, int flag)
{
  long len;

  if (!((end == NULL) || (val == NULL) || (size == NULL)))
    {
      if (val[0] != '\0')
	{
	  if (*size > 1)
	    {
	      *end = ','; ++end; (*size) -= 1;
	      if (flag == 1) { *end = '\''; ++end; (*size) -= 1; }
	      *end = '\0';
	    }
	  len = (long) strlen(val);
	  if ((long) *size > (len+1))
	    {
	      (void) sl_strlcat(end, val, (size_t) *size);
	      end   += len; (*size) -= len;
	      if (flag == 1) { *end = '\''; ++end;  (*size) -= 1; }
	      *end = '\0'; 
	    }
	}
    }
  
  return end;
}

#define SH_QUERY_MAX SH_MSG_BUF
/* define SH_QUERY_MAX 16383 */

static
long sh_database_entry (dbins * db_entry, long id)
{
  /* This does not need to be re-entrant
   */
  char * query;
  static char   columns[1024];
  char * values;

  long   the_id;
  int    size;
  char * end;
  int    c_size;
  char * c_end;
  char * p;
  int    i;
  char   num[64];

  md5Param crc;
  unsigned char md5buffer[16];
  char md5out[33];
  int  cnt;

  size_t len_val;
  size_t len_col;

  SL_ENTER(_("sh_database_entry"));

  query  = SH_ALLOC(SH_QUERY_MAX+1);
  values = SH_ALLOC(SH_QUERY_MAX+1);

  (void) md5Reset(&crc);

  if (db_entry->host[0] == '\0')
    {
      if (sh.host.name[0] == '\0')
	(void) strcpy (db_entry->host, _("localhost"));  /* known to fit  */
      else
	(void) sl_strlcpy (db_entry->host, sh.host.name, 64); 
    }

  /*@-bufferoverflowhigh@*/
  if (id >= 0)
    sprintf(num, "%ld", id);                       /* known to fit  */
  /*@+bufferoverflowhigh@*/

#if defined(WITH_ORACLE)
  /* Oracle needs some help for the time format (fix by Michael Somers)
   */
  (void)
  sl_snprintf (values, SH_QUERY_MAX,  
	       _("(:1,%s,%c%s%c,to_date(%c%s%c,'YYYY-MM-DD HH24:MI:SS'),%c%s%c,%c%s%c"),
               id >= 0 ? num : _("NULL"),
               '\'', db_entry->host,'\'', 
               '\'', db_entry->time,'\'', 
               '\'', db_entry->sev, '\'',
               '\'', 
               (db_entry->msg[0] == '\0' ? _("NULL") : db_entry->msg),
               '\'');
  (void) sl_snprintf (columns, 1023, 
		      _("(log_index,log_ref,log_host,log_time,log_sev,log_msg"));
#elif defined(WITH_POSTGRES)
  /* Prepare query for PQexecParams
   */
  (void)
  sl_snprintf (values, SH_QUERY_MAX, 
	       _("($1,%s,%c%s%c,%c%s%c,%c%s%c,%c%s%c"),
	       id >= 0 ? num : _("NULL"),
	       '\'', db_entry->host,'\'', 
	       '\'', db_entry->time,'\'', 
	       '\'', db_entry->sev, '\'',
	       '\'', 
	       (db_entry->msg[0] == '\0' ? _("NULL") : db_entry->msg), 
	       '\'');
  (void) sl_snprintf (columns, 1023, 
		      _("(log_index,log_ref,log_host,log_time,log_sev,log_msg"));
#else
  (void)
  sl_snprintf (values, SH_QUERY_MAX, _("(%s,%c%s%c,%c%s%c,%c%s%c,%c%s%c"),
	       id >= 0 ? num : _("NULL"),
	       '\'', db_entry->host,'\'', 
	       '\'', db_entry->time,'\'', 
	       '\'', db_entry->sev, '\'',
	       '\'', 
	       (db_entry->msg[0] == '\0' ? _("NULL") : db_entry->msg), 
	       '\'');
  (void) sl_snprintf (columns, 1023, 
		      _("(log_ref,log_host,log_time,log_sev,log_msg"));
#endif


  /*@-type@*//* byte* versus char[..] */
  if (attr_tab[0].inHash == 1) 
    (void) md5Update(&crc, (sh_byte*) db_entry->sev,  
		     (int) strlen(db_entry->sev));
  if (attr_tab[1].inHash == 1) 
    (void) md5Update(&crc, (sh_byte*) db_entry->time, 
		     (int) strlen(db_entry->time));
  if (attr_tab[2].inHash == 1) 
    (void) md5Update(&crc, (sh_byte*) db_entry->host, 
		     (int) strlen(db_entry->host));
  if (attr_tab[3].inHash == 1 && db_entry->msg[0] != '\0') 
    (void) md5Update(&crc, (sh_byte*) db_entry->msg,  
		     (int) strlen(db_entry->sev));
  /*@+type@*/

  len_val = strlen(values);
  size    =  (int) (SH_QUERY_MAX - len_val);
  end     =  values + len_val;

  len_col = strlen(columns);
  c_size  =  1023   - (int) len_col; /* sizeof(colums) == 1024 */
  c_end   =  columns + len_col;

  i = 4;

  while (attr_tab[i].attr != NULL)
    {
      if (SH_SLOT_CHECKFLAGS == attr_tab[i].val) {
	if (db_entry->ulong_data[attr_tab[i].val-START_SEC_LONGS] == 0 &&
	    db_entry->ulong_data[attr_tab[i+1].val-START_SEC_LONGS] == 0)
	  { i+= 2; continue; } 
      }

      if (attr_tab[i].size != 0)
	{
	  if (attr_tab[i].val > 40 && attr_tab[i].val < 47)
	    {
	      /* remove the 'T' between date and time 
	       */
	      p = (char *)(db_entry)+attr_tab[i].off;
	      p = strchr(p, 'T');
	      if (p) *p = ' ';
	    }
	  p = end;
	  end = null_or_val(end,((char *)(db_entry)+attr_tab[i].off),&size,1);
	  if (p != end)
	    {
	      if ((attr_tab[i].val != SH_SLOT_HOST) &&
		  (attr_tab[i].val != SH_SLOT_GROUP))
		{
		  c_end = null_or_val (c_end, attr_tab[i].attr, &c_size,0);
		}
	      else
		{
		  /* 
		   * 'host' is a reserved word in SQL
		   */
		  if (attr_tab[i].val == SH_SLOT_HOST)
		    c_end = null_or_val (c_end, _("fromhost"), &c_size,0);
		  /* 
		   * 'group' is a reserved word in SQL
		   */
		  else /* if (attr_tab[i].val == SH_SLOT_GROUP) */
		    c_end = null_or_val (c_end, _("grp"), &c_size,0);
		}
	    }
	  /*@-type@*//* byte* versus char[..] */
	  if (attr_tab[i].inHash == 1 && 
	      ((char *)(db_entry)+attr_tab[i].off) != '\0')
	    {
	      (void)md5Update(&crc, 
			      (sh_byte*) ((char *)(db_entry)+attr_tab[i].off), 
			      (int)strlen((char *)(db_entry)+attr_tab[i].off));
	    }
	  /*@+type@*/
	}
      else if (attr_tab[i].val >= START_SEC_LONGS &&
	       attr_tab[i].val <= END_SEC_LONGS)
	{
	  (void)
	  sl_snprintf(end, (size_t)(size-1), _(",\'%lu\'"), 
		      db_entry->ulong_data[attr_tab[i].val-START_SEC_LONGS]);
	  while (*end != '\0') { ++end; --size; }
	  (void) sl_snprintf(c_end, (size_t)(c_size-1), 
			     _(",%s"), attr_tab[i].attr);
	  while (*c_end != '\0') { ++c_end; --c_size; }
	  if (attr_tab[i].inHash == 1) 
	    {
	      /*@-type@*//* byte* versus char[..] */
	      (void)
	      md5Update(&crc,
			(sh_byte *) db_entry->ulong_data[attr_tab[i].val-START_SEC_LONGS], 
			sizeof(long));
	      /*@+type@*/
	    }
	}

      ++i;
    }

  (void) md5Digest(&crc, (uint32 *) md5buffer);
  /*@-bufferoverflowhigh -usedef@*/
  for (cnt = 0; cnt < 16; ++cnt)
    sprintf (&md5out[cnt*2], _("%02X"),            /* known to fit  */
	     (unsigned int) md5buffer[cnt]); 
  /*@+bufferoverflowhigh +usedef@*/
  md5out[32] = '\0';

  (void) sl_snprintf(end, (size_t) (size-1), _(",%c%s%c"), '\'', md5out, '\'');
  while (*end != '\0') { ++end; --size; }
  (void) sl_snprintf(c_end, (size_t) (c_size-1),_(",log_hash"));
  while (*c_end != '\0') { ++c_end; --c_size; }


  if (size > 1)   { *end   = ')'; ++end;   *end   = '\0'; }
  if (c_size > 1) { *c_end = ')'; ++c_end; *c_end = '\0'; }

  if (db_table[0]    == '\0')
    (void) sl_strlcpy(db_table, _("log"),       64);

  (void) sl_snprintf (query, SH_QUERY_MAX,
		      _("INSERT INTO %s %s VALUES %s"),
		      db_table, columns, values);

  sh_database_query (query, &the_id);

  /*@-usedef@*//* no, 'values' is allocated here */
  SH_FREE(values);
  /*@+usedef@*/
  SH_FREE(query);
  
  SL_RETURN(the_id, _("sh_database_entry"));
}
 
static int sh_database_comp_attr (const void *m1, const void *m2) 
{
  const my_attr *mi1 = (const my_attr *) m1;
  const my_attr *mi2 = (const my_attr *) m2;
  return strcmp(mi1->attr, mi2->attr);
}


static void init_attr_table(void)
{
  static  int first = S_TRUE;
  int         i, j;

#ifdef SH_STEALTH
  int     k;

  if (first == S_FALSE)
    return;

  i = 0;
  while (attr_tab[i].attr_o != NULL)
    {
      j = strlen(attr_tab[i].attr_o);
      attr_tab[i].attr = calloc(1, j+1); /* only once */
      if (NULL == attr_tab[i].attr)
	return;
      for (k = 0; k < j; ++k)
	attr_tab[i].attr[k] = attr_tab[i].attr_o[k] ^ XOR_CODE;
      attr_tab[i].attr[j] = '\0';
      attr_tab[i].alen = strlen(attr_tab[i].attr_o);
      ++i;
    }
  first = S_FALSE;

#else

  if (first == S_FALSE)
    return;

  i = 0;
  while (attr_tab[i].attr_o != NULL)
    {
      attr_tab[i].attr = attr_tab[i].attr_o;
      attr_tab[i].alen = strlen(attr_tab[i].attr_o);
      ++i;
    }
  first = S_FALSE;

#endif

  /* create a sorted table for binary search
   */
  attr_tab_srch = SH_ALLOC(i * sizeof(my_attr));
  for (j=0; j<i; ++j)
    memcpy(&attr_tab_srch[j], &attr_tab[j], sizeof(my_attr));
  qsort(attr_tab_srch, i, sizeof(my_attr), sh_database_comp_attr);
  attr_tab_srch_siz = i;

  return;
}

int sh_database_add_to_hash  (const char * str)
{
  int i;

  if (!str)
    return -1;
  init_attr_table();
  if (0 == strcmp(str, _("log_msg")))  { attr_tab[3].inHash = 1; return 0;}
  if (0 == strcmp(str, _("log_sev")))  { attr_tab[0].inHash = 1; return 0;}
  if (0 == strcmp(str, _("log_time"))) { attr_tab[1].inHash = 1; return 0;}
  if (0 == strcmp(str, _("log_host"))) { attr_tab[2].inHash = 1; return 0;}
  i = 4;
  while (attr_tab[i].attr != NULL)
    {
      if (0 == strcmp(str, attr_tab[i].attr))  
	{ attr_tab[i].inHash = 1; return 0; }
      ++i;
    }
  return -1;
}

static int is_escaped(char * p_in) {

  int    escp = 0;
  int    retv = S_TRUE;
  unsigned char * p = (unsigned char *) p_in;

  if (*p != '\0')
    {
      do 
	{
	  if (*p <=  126 && *p >= 32)
	    {
	      if (escp == 0)
		{
		  if      (!((*p == '\'') || (*p == '\"') || (*p == '\\'))) 
		    /* do nothing */;
		  else if (*p == '\\') 
		    {
#ifndef WITH_MYSQL
		      if (p[1] == '\'')
			{
			  *p = '\'';
			}
#endif
		      escp = 1;
		    }
		  else  
		    retv = S_FALSE; /* (*p == '\'' || *p == '\"') */
		}
	      else /* escp == 1 */
		{
		  escp = 0;
		}
	    }
	  else /* *p > 126 || *p < 32 */
	    {
	      retv = S_FALSE;
	    }
	  
	  ++p;
	  
	} 
      while (*p != '\0');
    }

  if (escp == 0)
    return retv;
  else
    return S_FALSE;
}

/* this is not a real XML parser, but it copes with the XML format of
 * the log messages provided by sh_error_handle()
 */
static
char *  sh_database_parse (char * message, dbins * db_entry)
{
  static  int first = S_TRUE;
  char  * p;
  char  * q;
  char  * z;
  dbins * new;
  int     i;
  size_t  j;
  my_attr * res;
  my_attr key;
  char    key_str[64];

  SL_ENTER(_("sh_database_parse"));

  if (!message || *message == '\0')
    SL_RETURN (NULL, _("sh_database_parse"));

  if (first == S_TRUE)
    {
      init_attr_table();
      first = S_FALSE;
    }

  p = strchr (message, '<');
  if (!p)
    SL_RETURN (NULL, _("sh_database_parse"));

  while ((*p != '\0') && (*p != '>'))
    {
      if (p[0] == 'l' && p[1] == 'o' && p[2] == 'g' &&
	  (p[3] == ' ' || p[3] == '>'))
	{
	  p = &p[4];
	  goto parse;
	}
      else if (p[0] == '/' && p[1] == '>')
	SL_RETURN (&p[2], _("sh_database_parse"));
      else if (p[0] == '/' && p[1] == 'l' && p[2] == 'o' && 
	  p[3] == 'g' && p[4] == '>')
	SL_RETURN (&p[5], _("sh_database_parse"));
      ++p;
    }
  SL_RETURN(NULL, _("sh_database_parse")); 

 parse:

  while (*p == ' ' || *p == '>')
    ++p;

  if (*p == '\0')
    SL_RETURN(NULL, _("sh_database_parse"));

  if (*p != '<' && *p != '/')
    goto par2;

  if (p[0] == '<' && p[1] == 'l' &&
      p[2] == 'o' && p[3] == 'g')
    {
      /* 
       * recursive call 
       */
      new       = SH_ALLOC(sizeof(dbins));
      init_db_entry(new);
      db_entry->next = new;
      p = sh_database_parse (p, new);
    }

  if (p[0] == '/' && p[1] == '>')
    SL_RETURN (&p[1], _("sh_database_parse"));
  
  if (p[0] == '<' && p[1] == '/' && p[2] == 'l' &&
      p[3] == 'o' && p[4] == 'g' && p[5] == '>')
    SL_RETURN (&p[5], _("sh_database_parse"));

 par2:

  /* non-whitespace 
   */
  for (i=0; i < 64; ++i)
    {
      if (p[i] != '=')
	{
	  key_str[i] = p[i];
	}
      else
	{
	  key_str[i] = '\0';
	  break;
	}
    }
  key_str[63] = '\0';
  key.attr = &key_str[0];

  res = bsearch(&key, attr_tab_srch, attr_tab_srch_siz,
		sizeof(my_attr), sh_database_comp_attr);

  if (res != NULL)
    {
      j = res->alen; /* strlen(attr_tab[i].attr); */
      if (p[j] == '=' && p[j+1] == '"')
	{
	  q = strchr(&p[j+2], '"');
	  if (q)
	    {
	      *q = '\0';

	      if (S_TRUE == is_escaped(&p[j+2])) {

		if      (res->val == 1)
		  (void) sl_strlcpy(db_entry->sev, &p[j+2], 
				    (size_t)res->size);
		else if (res->val == 2)
		  {
		    z = strchr(&p[j+2], 'T');
		    if (z) *z = ' ';
		    (void) sl_strlcpy(db_entry->time, &p[j+2],  20);
		  }
		else if (res->val == 3)
		  (void) sl_strlcpy(db_entry->host, &p[j+2], 
				    (size_t) res->size);
		else if (res->val == 4)
		  (void) sl_strlcpy(db_entry->msg,  &p[j+2], 
				    (size_t) res->size);
		else if (res->size != 0)
		  {
		    (void) sl_strlcpy( (((char *)(db_entry))+ res->off),
				       &p[j+2], 
				       (size_t) res->size);
		  }
		else if (res->val >= START_SEC_LONGS && res->val <= END_SEC_LONGS)
		  {
		    db_entry->ulong_data[res->val-START_SEC_LONGS]
		      = strtoul(&p[j+2], (char **) NULL, 0);
		  }

		*q = '"';
		p  = q; 
		++p;

		goto parse;
	      }
	      else { /* S_FALSE == is_escaped(&p[j+2]) */
		sh_error_handle((-1), FIL__, __LINE__, 0, MSG_E_SUBGEN,
				_("Message not properly escaped"), 
				_("sh_database_parse"));
		SL_RETURN(NULL, _("sh_database_parse"));
	      }
	    }
	  else /* q == NULL */
	    {
	      SL_RETURN(NULL, _("sh_database_parse"));
	    }
	}
    }

  /* unknown attribute, skip
   */
  while ((p != NULL) && (*p != '\0') && (*p != ' '))
    ++p;

  goto parse;
}

static int enter_wrapper = 1;

int set_enter_wrapper (const char * str)
{
  return sh_util_flagval(str, &enter_wrapper);
}

/* recursively enter linked list of messages into database, last first
 * - last is client (if this is a client message received by client)
 */
long sh_database_insert_rec (dbins * curr, int depth, char * host)
{
  unsigned long    id = 0;

  SL_ENTER(_("sh_database_insert_rec"));

  if (curr->next)
    {
      /*
      prev = curr->next;
      sl_strlcpy(prev->host, curr->host, 64);
      id = sh_database_insert_rec (curr->next, (depth + 1));
      */
      ++depth;
      id = sh_database_insert_rec (curr->next, depth, curr->host);
    }

  if (host) 
    sl_strlcpy(curr->host, host, 64);

  if (id != 0)                       /* this is a server wrapper          */
    {
      if (enter_wrapper != 0)
	{
	  id = sh_database_entry (curr, id);
	}
    }
  else
    {
      /*
       * id = -1 is the client message; log_ref will be NULL 
       */
      if (depth > 0)                  /* this is a client message         */
	id = sh_database_entry (curr, -1);
      else                            /* this is a generic server message */
	id = sh_database_entry (curr, 0);
    }

  SH_FREE(curr);

  SL_RETURN(id, _("sh_database_insert_rec"));
}

int sh_database_insert (char * message)
{
  dbins * db_entry;

  SL_ENTER(_("sh_database_insert"));

  db_entry        = SH_ALLOC(sizeof(dbins));
  init_db_entry(db_entry);

  /* recursively parse the message into a linked list
   */
  (void) sh_database_parse (message, db_entry);

  /* recursively enter the linked list into the database
   */
  (void) sh_database_insert_rec (db_entry, 0, NULL);

  SL_RETURN(0, _("sh_database_insert"));
}

#endif
