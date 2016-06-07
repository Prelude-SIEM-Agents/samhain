#include "config_xor.h"

#include "samhain.h"
#include "sh_error.h"

#include "sh_cat.h"

/*@-nullassign@*/

const char * class_cat[] = {
  N_("AUD"),     /*  0 */
  N_("PANIC"),   /*  1 */
  N_("RUN_OLD"), /*  2 */
  N_("FIL_OLD"), /*  3 */
  N_("TCP"),     /*  4 */
  N_("ERR"),     /*  5 */
  N_("STAMP"),   /*  6 */
  N_("ENET"),    /*  7 */
  N_("EINPUT"),  /*  8 */

  /* new simplified classes */
  N_("EVENT"),   /*  9 */
  N_("START"),   /* 10 */
  N_("LOGKEY"),  /* 11 */
  N_("OTHER"),   /* 12 */
  /* end simplified classes */

  N_("RUN"),     /* 13 */
  N_("FIL"),     /* 14 */
  N_("ERROR"),   /* 15 */
  NULL
};


#ifdef SH_USE_XML

cat_entry msg_cat[] = {

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  { MSG_FI_CSUM,     SH_ERR_ALL,     FIL,   N_("msg=\"Checksum\" chk=\"%s\" path=\"%s\"")},
  { MSG_FI_DSUM,     SH_ERR_INFO,    FIL,   N_("msg=\"d: %3ld, -: %3ld, l: %3ld, |: %3ld, s: %3ld, c: %3ld, b: %3ld\"")},
  { MSG_FI_CHK,      SH_ERR_INFO,    FIL,   N_("msg=\"Checking %16s\" path=\"%s\"")},
#endif

  { MSG_EXIT_ABORTS, SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC %s\" program=\"%s\" subroutine=\"%s\"")},
  { MSG_START_SRV,   SH_ERR_STAMP,   START, N_("msg=\"Server up, simultaneous connections: %d\" socket_id=\"%d\"")}, 
 
  { MSG_EXIT_ABORT1, SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC Error initializing the application\" program=\"%s\"")},
  { MSG_EXIT_NORMAL, SH_ERR_FATAL,   START, N_("msg=\"EXIT\" program=\"%s\" status=\"%s\"")},
  { MSG_START_KEY_MAIL,   SH_ERR_FATAL, LOGKEY,   N_("msg=\"LOGKEY\" program=\"%s\" hash=\"%s\"\r\n-----BEGIN LOGKEY-----\r\n%s%s")},
  { MSG_START_KEY,   SH_ERR_FATAL,   LOGKEY,   N_("msg=\"LOGKEY\" program=\"%s\" hash=\"%s\"")},
  { MSG_START_0H,    SH_ERR_FATAL,   START, N_("msg=\"START\" program=\"%s\" userid=\"%ld\"")},
  { MSG_START_1H,    SH_ERR_FATAL,   START, N_("msg=\"START\" program=\"%s\" userid=\"%ld\" path=\"%s\" hash=\"%s\"")},
  { MSG_START_2H,    SH_ERR_FATAL,   START, N_("msg=\"START\" program=\"%s\" userid=\"%ld\" path=\"%s\" hash=\"%s\" path_data=\"%s\" hash_data=\"%s\"")},
  { MSG_START_GH,    SH_ERR_FATAL,   START, N_("msg=\"START\" program=\"%s\" userid=\"%ld\" path=\"%s\" key_uid=\"%s\" key_id=\"%s\"")},
  { MSG_START_GH2,   SH_ERR_FATAL,   START, N_("msg=\"EXIT\" program=\"%s\" userid=\"%ld\" path=\"%s\" key_uid=\"%s\" key_id=\"%s\" path_data=\"%s\" key_uid_data=\"%s\" key_id_data=\"%s\"")},
  { MSG_SUSPEND,     SH_ERR_STAMP,   START, N_("msg=\"SUSPEND\" program=\"%s\"")},


  { MSG_MLOCK,       SH_ERR_WARN,    RUN,   N_("msg=\"Using insecure memory\"")},
  { MSG_W_SIG,       SH_ERR_WARN,    RUN,   N_("interface=\"sigaction\" msg=\"%s\" sig=\"%ld\"")},
  { MSG_W_CHDIR,     SH_ERR_ERR,     RUN,   N_("interface=\"chdir\" msg=\"%s\" path=\"%s\"")},

  { MSG_MOD_FAIL,    SH_ERR_WARN,    RUN,   N_("msg=\"Module not initialized\" module=\"%s\" return_code=\"%ld\"")},
  { MSG_MOD_OK,      SH_ERR_INFO,    RUN,   N_("msg=\"Module initialized\" module=\"%s\"")},
  { MSG_MOD_EXEC,    SH_ERR_ERR,     RUN,   N_("msg=\"Module execution error\" module=\"%s\" return_code=\"%ld\"")},

  { MSG_RECONF,      SH_ERR_SEVERE,  START, N_("msg=\"Runtime configuration reloaded\"")},

  { MSG_CHECK_0,     SH_ERR_WARN,    RUN,   N_("msg=\"No files or directories defined for checking\"")},
  { MSG_CHECK_1,     SH_ERR_STAMP,   STAMP, N_("msg=\"File check completed.\" time=\"%ld\" kBps=\"%f\"")},
  { MSG_CHECK_2,     SH_ERR_STAMP,   STAMP, N_("msg=\"File check starting.\"")},
  { MSG_STAMP,       SH_ERR_STAMP,   STAMP, N_("msg=\"---- TIMESTAMP ----\"")},

  { MSG_D_START,     SH_ERR_INFO,    RUN,   N_("msg=\"Downloading configuration file\"")},
  { MSG_D_DSTART,    SH_ERR_INFO,    RUN,   N_("msg=\"Downloading database file\"")},
  { MSG_D_FAIL,      SH_ERR_INFO,    RUN,   N_("msg=\"No file from server, trying local file\"")},
  { MSG_D_DELTAOK,   SH_ERR_SEVERE,  RUN,   N_("msg=\"Delta database downloaded\", path=\"%s\"")},
  { MSG_D_DELTAFAIL, SH_ERR_SEVERE,  RUN,   N_("msg=\"Delta database download failed\", path=\"%s\"")},


#ifndef HAVE_URANDOM 
  { MSG_ENSTART,     SH_ERR_ALL,     RUN,   N_("msg=\"Found entropy source\" path=\"%s\"")},
  { MSG_ENEXEC,      SH_ERR_ALL,     RUN,   N_("msg=\"Execute entropy source\" path=\"%s\" rd_file_id=\"%ld\"")},
  { MSG_ENFAIL,      SH_ERR_ALL,     RUN,   N_("msg=\"Could not execute entropy source\" path=\"%s\"")},
  { MSG_ENTOUT,      SH_ERR_ALL,     RUN,   N_("msg=\"Timeout in entropy collector\" time=\"%ld\"")},
  { MSG_ENCLOS,      SH_ERR_ALL,     RUN,   N_("msg=\"End of data, closing entropy source\" rd_file_id=\"%ld\"")},
  { MSG_ENCLOS1,     SH_ERR_ALL,     RUN,   N_("msg=\"Close entropy source\" rd_file_id=\"%ld\"")},
  { MSG_ENREAD,      SH_ERR_ALL,     RUN,   N_("msg=\"Data from entropy source\" rd_file_id=\"%ld\" bytes=\"%ld\"")},
#endif

#ifdef SH_USE_SUIDCHK
  { MSG_SUID_POLICY, SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [SuidCheck]  %s\" path=\"%s\" %s") },
  { MSG_SUID_FOUND,  SH_ERR_INFO,    RUN,   N_("msg=\"Found suid/sgid file\" path=\"%s\"") },
  { MSG_SUID_SUMMARY,SH_ERR_INFO,    RUN,   N_("msg=\"Checked for SUID programs: %ld files, %ld seconds\"") },
  { MSG_SUID_QREPORT,SH_ERR_SEVERE,  EVENT, N_("msg=\"Quarantine report: %s\" path=\"%s\"") },
  { MSG_SUID_ERROR,  SH_ERR_SEVERE,  EVENT, N_("msg=\"Quarantine error: %s\"") },
#endif

#ifdef SH_USE_UTMP
  { MSG_UT_CHECK,    SH_ERR_INFO,    RUN,   N_("msg=\"Checking logins\"")},
  { MSG_UT_LG1X,     SH_ERR_INFO,    EVENT, N_("msg=\"Login\" userid=\"%s\" tty=\"%s\" host=\"%s\" ip=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG1A,     SH_ERR_INFO,    EVENT, N_("msg=\"Login\" userid=\"%s\" tty=\"%s\" host=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG1B,     SH_ERR_INFO,    EVENT, N_("msg=\"Login\" userid=\"%s\" tty=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG2X,     SH_ERR_INFO,    EVENT, N_("msg=\"Multiple login\" userid=\"%s\" tty=\"%s\" host=\"%s\" ip=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG2A,     SH_ERR_INFO,    EVENT, N_("msg=\"Multiple login\" userid=\"%s\" tty=\"%s\" host=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG2B,     SH_ERR_INFO,    EVENT, N_("msg=\"Multiple login\" userid=\"%s\" tty=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG3X,     SH_ERR_INFO,    EVENT, N_("msg=\"Logout\" userid=\"%s\" tty=\"%s\" host=\"%s\" ip=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG3A,     SH_ERR_INFO,    EVENT, N_("msg=\"Logout\" userid=\"%s\" tty=\"%s\" host=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG3B,     SH_ERR_INFO,    EVENT, N_("msg=\"Logout\" userid=\"%s\" tty=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_LG3C,     SH_ERR_INFO,    EVENT, N_("msg=\"Logout\" tty=\"%s\" time=\"%s\" status=\"%d\"")},
  { MSG_UT_ROT,      SH_ERR_WARN,    RUN,   N_("msg=\"Logfile size decreased\" path=\"%s\"")},

  { MSG_UT_BAD,      SH_ERR_SEVERE,  EVENT, N_("msg=\"Login at disallowed time\" userid=\"%s\" host=\"%s\" time=\"%s\"")},
  { MSG_UT_FIRST,    SH_ERR_SEVERE,  EVENT, N_("msg=\"First login from this host\" userid=\"%s\" host=\"%s\" time=\"%s\"")},
  { MSG_UT_OUTLIER,  SH_ERR_SEVERE,  EVENT, N_("msg=\"Login time outlier\" userid=\"%s\" host=\"%s\" time=\"%s\"")},

#endif

#ifdef SH_USE_PROCESSCHECK
  { MSG_PCK_CHECK,   SH_ERR_INFO,    RUN,   N_("msg=\"Checking processes in pid interval [%ld,%ld]\"")},
  { MSG_PCK_OK,      SH_ERR_ALL,     RUN,   N_("msg=\"PID %ld found with tests %s\"")},
  { MSG_PCK_P_HIDDEN,SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Process] Hidden pid: %ld tests: %s\" path=\"%s\" userid=\"%s\"")},
  { MSG_PCK_HIDDEN,  SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Process] Hidden pid: %ld tests: %s\"")},
  { MSG_PCK_FAKE,    SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Process] Fake pid: %ld tests: %s\"")},
  { MSG_PCK_MISS,    SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Process] Missing: %s\"")},
#endif

#ifdef SH_USE_PORTCHECK
  { MSG_PORT_MISS,   SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [ServiceMissing] %s\"")},
  { MSG_PORT_NEW,    SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [ServiceNew] %s\" path=\"%s\"  pid=\"%lu\" userid=\"%s\"")},
  { MSG_PORT_RESTART,SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [ServiceRestarted] %s\" path=\"%s\" pid=\"%lu\" userid=\"%s\"")},
  { MSG_PORT_NEWPORT,SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [ServicePortSwitch] %s\" path=\"%s\" pid=\"%lu\" userid=\"%s\"")},
#endif

#ifdef SH_USE_MOUNTS
  { MSG_MNT_CHECK,   SH_ERR_INFO,    RUN,   N_("msg=\"Checking mounts\"")},
  { MSG_MNT_MEMLIST, SH_ERR_ERR,     RUN,   N_("msg=\"Cannot read mount list from memory\"")},
  { MSG_MNT_MNTMISS, SH_ERR_WARN,    EVENT, N_("msg=\"POLICY [Mounts] Mount missing\" path=\"%s\"")},
  { MSG_MNT_OPTMISS, SH_ERR_WARN,    EVENT, N_("msg=\"POLICY [Mounts] Mount option missing\" path=\"%s\" option=\"%s\"")},
#endif

#ifdef SH_USE_USERFILES
  { MSG_USERFILES_SUMMARY,SH_ERR_INFO,    RUN,   N_("msg=\"Checked for users files\"") },
#endif

#ifdef USE_LOGFILE_MONITOR
  { MSG_LOGMON_CHKS, SH_ERR_INFO,    RUN,   N_("msg=\"Checking logfile %s\"") },
  { MSG_LOGMON_CHKE, SH_ERR_INFO,    RUN,   N_("msg=\"Finished logfile %s, %lu new records processed\"") },
  { MSG_LOGMON_MISS, SH_ERR_ERR,     RUN,   N_("msg=\"Missing logfile %s\"") },
  { MSG_LOGMON_EOPEN,SH_ERR_ERR,     RUN,   N_("msg=\"Cannot open logfile %s\"") },
  { MSG_LOGMON_EREAD,SH_ERR_ERR,     RUN,   N_("msg=\"Error while reading logfile %s\"") },
  { MSG_LOGMON_REP,  SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Logfile] %s\" time=\"%s\" host=\"%s\" path=\"%s\"") },
  { MSG_LOGMON_SUM,  SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Logfile] %s\" host=\"%s\" path=\"%s\"") },
  { MSG_LOGMON_COR,  SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Logfile] Correlation event %s occured %d time(s)\"") },
  { MSG_LOGMON_MARK, SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [Logfile] Event %s missing for %lu seconds\"") },
  { MSG_LOGMON_BURST, SH_ERR_SEVERE, EVENT, N_("msg=\"POLICY [Logfile] Repeated %d times: %s\" host=\"%s\"") },
#endif

#ifdef USE_REGISTRY_CHECK
  { MSG_REG_MISS,   SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [RegistryKeyMissing] %s\" path=\"%s\" %s")},
  { MSG_REG_NEW,    SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [RegistryKeyNew] %s\" path=\"%s\" %s")},
  { MSG_REG_CHANGE, SH_ERR_SEVERE,  EVENT, N_("msg=\"POLICY [RegistryKeyChanged] %s\" path=\"%s\" %s")},
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  
  { MSG_FI_TOOLATE,  SH_ERR_ERR,     FIL,   N_("msg=\"Large lstat/open overhead: %ld sec\" path=\"%s\"")},

#if 0
  { MSG_FI_CSUM,     SH_ERR_ALL,     FIL,   N_("msg=\"Checksum\" chk=\"%s\" path=\"%s\"")},
  { MSG_FI_DSUM,     SH_ERR_INFO,    FIL,   N_("msg=\"d: %3ld, -: %3ld, l: %3ld, |: %3ld, s: %3ld, c: %3ld, b: %3ld\"")},
  { MSG_FI_CHK,      SH_ERR_INFO,    FIL,   N_("msg=\"Checking %16s\" path=\"%s\"")},
#endif

  { MSG_FI_NULL,     SH_ERR_ERR,     FIL,   N_("msg=\"Path is NULL\"")},
  { MSG_FI_FAIL,     SH_ERR_ERR,     FIL,   N_("msg=\"Check failed\" path=\"%s\"")},
  { MSG_FI_GLOB,     SH_ERR_ERR,     FIL,   N_("interface=\"glob\" msg=\"%s\" path=\"%s\"")},
  { MSG_FI_COLL,     SH_ERR_WARN,    FIL,   N_("msg=\"Writeable file with timestamps of parent directory fixed\" dir=\"%s\" path=\"%s\"")},
  { MSG_FI_DOUBLE,   SH_ERR_WARN,    FIL,   N_("msg=\"File or directory appears twice in configuration\" path=\"%s\"")},
  { MSG_FI_2LONG,    SH_ERR_ERR,     FIL,   N_("msg=\"Filename too long\" path=\"%s\"")},
  { MSG_FI_2LONG2,   SH_ERR_ERR,     FIL,   N_("msg=\"Filename too long\" path=\"%s/%s\"")},
  { MSG_FI_NOPATH,   SH_ERR_ERR,     FIL,   N_("msg=\"Filename not an absolute path\" path=\"%s\"")},
  { MSG_FI_DLNK,     SH_ERR_INFO,    FIL,   N_("msg=\"Dangling link\" path=\"%s\" linked_path=\"%s\"")},
  { MSG_FI_RDLNK,    SH_ERR_ERR,     FIL,   N_("interface=\"readlink\" msg=\"%s\" path=\"%s\"")},
  { MSG_FI_NOGRP,    SH_ERR_ERR,     FIL,   N_("interface=\"getgrgid\" msg=\"No such group\" group=\"%ld\" path=\"%s\"")},
  { MSG_FI_NOUSR,    SH_ERR_ERR,     FIL,   N_("interface=\"getpwuid\" msg=\"No such user\" userid=\"%ld\" path=\"%s\"")},
  { MSG_FI_STAT,     SH_ERR_ERR,     FIL,   N_("interface=\"%s\" msg=\"%s\" userid=\"%ld\" path=\"%s\"")},
  { MSG_FI_OBSC,     SH_ERR_ERR,     FIL,   N_("msg=\"Weird filename\" path=\"%s\"")},
  { MSG_FI_OBSC2,    SH_ERR_ERR,     FIL,   N_("msg=\"Weird filename\" path=\"%s/%s\"")},
  { MSG_FI_LIST,     SH_ERR_ALL,     FIL,   N_("msg=\"%10s %2d %8s %8s %14ld %21s %s\"")},
  { MSG_FI_LLNK,     SH_ERR_ALL,     FIL,   N_("msg=\"   >>>  %10s  %s\"")},
  { MSG_FI_MISS,     SH_ERR_ERR,     EVENT, N_("msg=\"POLICY MISSING\" path=\"%s\"")},
  { MSG_FI_MISS2,    SH_ERR_ERR,     EVENT, N_("msg=\"POLICY MISSING\" path=\"%s\" %s")},
  { MSG_FI_ADD,      SH_ERR_ERR,     EVENT, N_("msg=\"POLICY ADDED\" path=\"%s\"")},
  { MSG_FI_ADD2,     SH_ERR_ERR,     EVENT, N_("msg=\"POLICY ADDED\" path=\"%s\" %s")},
  { MSG_FI_CHAN,     SH_ERR_ERR,     EVENT, N_("msg=\"POLICY %s %s\" path=\"%s\" %s")},
  { MSG_FI_NODIR,    SH_ERR_ERR,     EVENT, N_("msg=\"POLICY NODIRECTORY\" path=\"%s\"")},
  { MSG_FI_DBEX,     SH_ERR_WARN,    FIL,   N_("msg=\"Signature database exists\" path=\"%s\"")},
#endif

  { MSG_TCP_NETRP,   SH_ERR_ERR,     TCP,   N_("msg=\"Connection error: %s\" port=\"%ld\" subroutine=\"%s\"")},

#ifndef SH_STANDALONE

#ifdef INET_SYSLOG
  { MSG_INET_SYSLOG, SH_ERR_INET,    TCP,   N_("ip=\"%s\" facility=\"%s\" priority=\"%s\" syslog_msg=\"%s\"")},
  { MSG_ERR_SYSLOG,  SH_ERR_ERR,     TCP,   N_("msg=\"syslog socket: %s\" ip=\"%s\"")},
#endif
  { MSG_TCP_MISMATCH,SH_ERR_ERR,     TCP,   N_("msg=\"Protocol mismatch\"")},
  { MSG_TCP_MISENC,  SH_ERR_ERR,     TCP,   N_("msg=\"Encryption mismatch in %s: server: %s client: %s\"")},
  { MSG_TCP_NONAME,  SH_ERR_ERR,     TCP,   N_("msg=\"No server name known\"")},
  { MSG_TCP_UNEXP,   SH_ERR_ERR,     TCP,   N_("msg=\"Unexpected reply\"")},
  { MSG_TCP_EFIL,    SH_ERR_ERR,     TCP,   N_("msg=\"Could not open temporary file\"")},
  { MSG_TCP_NOCONF,  SH_ERR_ERR,     TCP,   N_("msg=\"Message delivery not confirmed\"")},
  { MSG_TCP_NOAUTH,  SH_ERR_ERR,     TCP,   N_("msg=\"Session key negotiation failed\"")},
  { MSG_TCP_CONF,    SH_ERR_ALL,     TCP,   N_("msg=\"Message delivery confirmed\"")},
  { MSG_TCP_AUTH,    SH_ERR_INFO,    TCP,   N_("msg=\"Session key negotiated\"")},
  { MSG_TCP_FOK,     SH_ERR_INFO,    TCP,   N_("msg=\"File download completed\"")},
  { MSG_TCP_FBAD,    SH_ERR_ERR,     TCP,   N_("msg=\"File download failed\"")},
  { MSG_TCP_ECONN,   SH_ERR_ERR,     TCP,   N_("msg=\"Connection error: %s\"")},
  { MSG_TCP_EZERO,   SH_ERR_ERR,     TCP,   N_("msg=\"Illegal zero reply\"")},
  { MSG_TCP_EBGN,    SH_ERR_ERR,     TCP,   N_("msg=\"Error in big integer library\"")},

  { MSG_TCP_CREG,    SH_ERR_ALL,     TCP,   N_("msg=\"Registered %s, salt %s, verifier %s\"")},
  { MSG_TCP_FAUTH,   SH_ERR_INFO,    TCP,   N_("msg=\"Force authentication\" host=\"%s\"")},

  { MSG_TCP_RESCLT,  SH_ERR_SEVERE,  TCP,   N_("msg=\"Cannot resolve client name\" host=\"%s\"")},
  { MSG_TCP_RESPEER, SH_ERR_SEVERE,  TCP,   N_("msg=\"Cannot resolve socket peer IP for client\" host=\"%s\" peer=\"%s\"")},
  { MSG_TCP_LOOKERS, SH_ERR_SEVERE,  TCP,   N_("msg=\"Reverse lookup of socket peer failed\" host=\"%s\" peer=\"%s\" obj=\"%s\"")},
  { MSG_TCP_LOOKUP,  SH_ERR_SEVERE,  TCP,   N_("msg=\"No socket peer alias matches client name\" host=\"%s\" peer=\"%s\"")},

  { MSG_TCP_TIMOUT,  SH_ERR_SEVERE,  TCP,   N_("msg=\"Connection timeout\" host=\"%s\"")},
  { MSG_TCP_TIMEXC,  SH_ERR_SEVERE,  TCP,   N_("msg=\"Time limit exceeded\" host=\"%s\"")},
  { MSG_TCP_NOCLT,   SH_ERR_SEVERE,  TCP,   N_("msg=\"Hostname is NULL\"")},
  { MSG_TCP_BADCONN, SH_ERR_SEVERE,  TCP,   N_("msg=\"Invalid connection attempt: %s\" host=\"%s\"")},
  { MSG_TCP_FFILE ,  SH_ERR_SEVERE,  TCP,   N_("msg=\"Unknown file request\" host=\"%s\" path=\"%s\"")},
  { MSG_TCP_NFILE ,  SH_ERR_SEVERE,  TCP,   N_("msg=\"Requested file not found\" host=\"%s\" path=\"%s\"")},
  { MSG_TCP_FINV ,   SH_ERR_SEVERE,  TCP,   N_("msg=\"Invalid request (%d) in pass %d\" host=\"%s\" request=\"%c%03o%c%03o%c%03o%c%03o\"")},
  { MSG_TCP_OKFILE,  SH_ERR_INFO,    TCP,   N_("msg=\"File transfer completed\" host=\"%s\"")},
  { MSG_TCP_OKMSG,   SH_ERR_ALL,     TCP,   N_("msg=\"Message transfer completed\" host=\"%s\"")},
  { MSG_TCP_MSG,     SH_ERR_INET,    TCP,   N_("remote_host=\"%s\" > %s </log>")},
  { MSG_TCP_NEW,     SH_ERR_NOTICE,  TCP,   N_("msg=\"NEW CLIENT\" host=\"%s\"")},
  { MSG_TCP_ILL,     SH_ERR_SEVERE,  TCP,   N_("msg=\"Restart without prior exit\" host=\"%s\"")},
  { MSG_TCP_SYNC,    SH_ERR_SEVERE,  TCP,   N_("msg=\"Out of sync\" host=\"%s\"")},
  { MSG_TCP_RESET,   SH_ERR_NOTICE,  TCP,   N_("msg=\"Connection reset by peer\" host=\"%s\"")},
  { MSG_TCP_CNEW,    SH_ERR_INFO,    TCP,   N_("msg=\"New connection\" socket_id=\"%d\"")},
  { MSG_E_HTML,      SH_ERR_ERR,     ERR,   N_("msg=\"Error writing HTML status\"")},
#endif

  
  { MSG_E_AUTH,      SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC - File modified\" path=\"%s\"")},
  { MSG_ACCESS,      SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC - Access violation\" userid=\"%ld\" path=\"%s\"")},
  { MSG_TRUST,       SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC - Untrusted path\" userid=\"%ld\" path=\"%s\"")},
  { MSG_NOACCESS,    SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC - File not accessible\" userid=\"%ld\" path=\"%s\"")},
  { MSG_P_NODATA,    SH_ERR_FATAL,   PANIC, N_("msg=\"PANIC - No data in file\" path=\"%s\"")},


#ifndef MEM_DEBUG
  { MSG_E_MNULL,     SH_ERR_ERR,     ERR,   N_("msg=\"Dereferenced NULL pointer\"")},
  { MSG_E_MMEM,      SH_ERR_ERR,     ERR,   N_("msg=\"Out of memory\"")},
#else
  { MSG_MSTAMP,      SH_ERR_STAMP,   STAMP, N_("msg=\"Memory used:  max.=%lu, current=%lu\"")},
  { MSG_MSTAMP2,     SH_ERR_STAMP,   STAMP, N_("msg=\"Blocks: %d allocated, %d freed, %d maximum\"")},
  { MSG_E_MNULL,     SH_ERR_ERR,     ERR,   N_("msg=\"Dereferenced NULL pointer allocated in %s, line %d\" source_file=\"%s\" source_line=\"%d\"")},
  { MSG_E_MMEM,      SH_ERR_ERR,     ERR,   N_("msg=\"Out of memory\" source_file=\"%s\" source_line=\"%d\"")},
  { MSG_E_MREC,      SH_ERR_ERR,     ERR,   N_("msg=\"Free() on unrecorded block\" source_file=\"%s\" source_line=\"%d\"")},
  { MSG_E_MOVER,     SH_ERR_ERR,     ERR,   N_("msg=\"Memory overrun on block allocated in %s, line %d\" source_file=\"%s\" source_line=\"%d\"")},
  { MSG_E_MUNDER,    SH_ERR_ERR,     ERR,   N_("msg=\"Memory underrun on block allocated in %s, line %d\" source_file=\"%s\" source_line=\"%d\"")},
  { MSG_E_NOTFREE,   SH_ERR_ERR,     ERR,   N_("msg=\"Block not deallocated\" size=\"%14ld\" source_file=\"%19s\" source_line=\"%d\"")},
#endif

  { MSG_E_TRUST,     SH_ERR_ERR,     ERR,   N_("msg=\"Untrusted path\" userid=\"%ld\" path=\"%s\"")},
  { MSG_E_HASH,      SH_ERR_ERR,     ERR,   N_("msg=\"Incorrect checksum\" path=\"%s\"")},
  { MSG_E_ACCESS,    SH_ERR_ERR,     ERR,   N_("msg=\"File not accessible\" userid=\"%ld\" path=\"%s\"")},
  { MSG_E_READ,      SH_ERR_ERR,     ERR,   N_("msg=\"Not accessible or not a regular file (%s / %s)\" path=\"%s\"")},
  { MSG_E_NOTREG,    SH_ERR_ERR,     ERR,   N_("msg=\"Not a regular file\" path=\"%s\"")},
  { MSG_E_TIMEOUT,   SH_ERR_ERR,     ERR,   N_("msg=\"Timeout (%d sec) while checksumming file\" path=\"%s\"")},
  { MSG_NODEV,       SH_ERR_ERR,     ERR,   N_("msg=\"Device not available or timeout during read attempt\" userid=\"%ld\" path=\"%s\"")},
  { MSG_LOCKED,      SH_ERR_ERR,     ERR,   N_("msg=\"File lock error\" userid=\"%ld\" path=\"%s\" obj=\"%s\"")},
  { MSG_PIDFILE,      SH_ERR_ERR,     ERR,   N_("msg=\"Could not write PID file\" userid=\"%ld\" path=\"%s\"")},
  { MSG_NOEXEC,      SH_ERR_ERR,     ERR,   N_("msg=\"Could not execute file\" userid=\"%ld\" path=\"%s\"")},

  { MSG_ES_ENT,      SH_ERR_ERR,     ERR,   N_("msg=\"No entropy collected\" subroutine=\"%s\"")},
  { MSG_ES_KEY1,     SH_ERR_ERR,     ERR,   N_("msg=\"Insecure key generation\" subroutine=\"%s\"")},
  { MSG_ES_KEY2,     SH_ERR_ERR,     ERR,   N_("msg=\"Error copying key\" subroutine=\"%s\"")},
  { MSG_E_GPG,       SH_ERR_ERR,     ERR,   N_("msg=\"Compiled-in gpg checksum does not match: need %s got %s\"")},
  { MSG_E_GPG_FP,    SH_ERR_ERR,     ERR,   N_("msg=\"Compiled-in fingerprint modified: one %s two %s\"")},
  { MSG_E_GPG_CHK,   SH_ERR_ERR,     ERR,   N_("msg=\"Compiled-in checksum modified: one %s two %s\"")},
  { MSG_E_SUBGEN,    SH_ERR_ERR,     ERR,   N_("msg=\"%s\" subroutine=\"%s\"")},
  { MSG_E_SUBGPATH,  SH_ERR_ERR,     ERR,   N_("msg=\"%s\" subroutine=\"%s\" path=\"%s\"")},
  { MSG_E_UNLNK,     SH_ERR_ERR,     FIL,   N_("interface=\"unlink\" msg=\"%s\" path=\"%s\"")},
  { MSG_E_REGEX,     SH_ERR_ERR,     ERR,   N_("interface=\"regcomp\" msg=\"%s\" obj=\"%s\"")},
  { MSG_E_OPENDIR,   SH_ERR_ERR,     FIL,   N_("interface=\"opendir\" msg=\"%s\" path=\"%s\"")},
  { MSG_E_TRUST1,    SH_ERR_ERR,     ERR,   N_("msg=\"%s\" subroutine=\"trustfile\" path=\"%s\"")},
  { MSG_E_TRUST2,    SH_ERR_ERR,     ERR,   N_("msg=\"%s\" subroutine=\"trustfile\" path=\"%s\" obj=\"%s\"")},
  { MSG_E_PWNULL,    SH_ERR_ERR,     ERR,   N_("msg=\"Empty password file entry: %s\" subroutine=\"%s\" userid=\"%ld\" obj=\"%s\"")},
  { MSG_E_PWLONG,    SH_ERR_ERR,     ERR,   N_("msg=\"Password file entry too long\" subroutine=\"%s\" userid=\"%ld\" obj=\"%s\"")},
  { MSG_E_GRNULL,    SH_ERR_ERR,     ERR,   N_("msg=\"Empty groups file entry: %s\" subroutine=\"%s\" group=\"%ld\" obj=\"%s\"")},

  { MSG_E_NET,       SH_ERR_ERR,     ENET,  N_("msg=\"%s\" subroutine=\"%s\" service=\"%s\" host=\"%s\"")},
  { MSG_E_NETST,     SH_ERR_ERR,     ENET,  N_("msg=\"Invalid connection state\" expect=\"%4s\" received=\"%4s\"")},
  { MSG_E_NETST1,    SH_ERR_ERR,     ENET,  N_("msg=\"Invalid connection state\" expect=\"%4s\" received=\"%4s\" host=\"%s\"")},
  { MSG_E_NLOST,     SH_ERR_ERR,     ENET,  N_("msg=\"Connection failure\" service=\"%s\" host=\"%s\"")},
  { MSG_E_NEST,      SH_ERR_ERR,     ENET,  N_("msg=\"Connection reestablished\" service=\"%s\" host=\"%s\"")},

  { MSG_EINVALHEAD,  SH_ERR_WARN,    EINPUT,N_("msg=\"Unrecognized section heading in line %ld of configuration file\"")},
  { MSG_EINVALCONF,  SH_ERR_WARN,    EINPUT,N_("msg=\"Invalid line %ld in configuration file: incorrect format, unrecognized option, or missing section header\"")},
  { MSG_EINVALS,     SH_ERR_WARN,    EINPUT,N_("msg=\"Invalid input\" option=\"%s\" obj=\"%s\"")},
  { MSG_EINVALL,     SH_ERR_WARN,    EINPUT,N_("msg=\"Invalid input\" option=\"%s\" obj=\"%ld\"")},
  { MSG_EINVALD,     SH_ERR_WARN,    EINPUT,N_("msg=\"Configuration file: unmatched @end\" option=\"%s\" obj=\"%ld\"")},
  { MSG_EINVALDD,    SH_ERR_WARN,    EINPUT,N_("msg=\"Configuration file: missing @end\" option=\"%s\" obj=\"%ld\"")},

  { MSG_SRV_FAIL,    SH_ERR_ERR,     ERR,   N_("msg=\"Service failure\" service=\"%s\" obj=\"%s\"")},
  { MSG_QUEUE_FULL,  SH_ERR_ERR,     ERR,   N_("msg=\"Queue full, messages may get lost\" service=\"%s\"")},

  { MSG_AUD_OPEN,    SH_ERR_NOTICE,  AUD,   N_("interface=\"open\" path=\"%s\" oflag=\"%ld\" mode=\"%ld\" return_id=\"%ld\"")},
  { MSG_AUD_DUP,     SH_ERR_NOTICE,  AUD,   N_("interface=\"dup\" file_id=\"%ld\" return_id=\"%ld\"")},
  { MSG_AUD_PIPE,    SH_ERR_NOTICE,  AUD,   N_("interface=\"pipe\" rd_file_id=\"%ld\" wr_file_id=\"%ld\"")},
  { MSG_AUD_FORK,    SH_ERR_NOTICE,  AUD,   N_("interface=\"fork\" return_id=\"%ld\"")},
  { MSG_AUD_EXIT,    SH_ERR_NOTICE,  AUD,   N_("interface=\"exit\" exit_code=\"%ld\"")},
  { MSG_AUD_SETUID,  SH_ERR_NOTICE,  AUD,   N_("interface=\"setuid\" uid=\"%ld\"")},
  { MSG_AUD_SETGID,  SH_ERR_NOTICE,  AUD,   N_("interface=\"setgid\" gid=\"%ld\"")},
  { MSG_AUD_UTIME,   SH_ERR_NOTICE,  AUD,   N_("interface=\"utime\" path=\"%s\" atime=\"%ld\" mtime=\"%ld\"")},
  { MSG_AUD_EXEC,    SH_ERR_NOTICE,  AUD,   N_("interface=\"exec\" path=\"%s\" uid=\"%ld\" gid=\"%ld\"")},
  { MSG_AUD_CHDIR,   SH_ERR_NOTICE,  AUD,   N_("interface=\"chdir\" path=\"%s\"")},
  { MSG_AUD_UNLINK,  SH_ERR_NOTICE,  AUD,   N_("interface=\"unlink\" path=\"%s\"")},
  { MSG_AUD_KILL,    SH_ERR_NOTICE,  AUD,   N_("interface=\"kill\" pid=\"%ld\" sig=\"%ld\"")},

  { MSG_ERR_OPEN,    SH_ERR_ALL,     ERR,   N_("interface=\"open\" msg=\"%s\" path=\"%s\" oflag=\"%ld\" mode=\"%ld\" return_id=\"%ld\"")},
  { MSG_ERR_DUP,     SH_ERR_ALL,     ERR,   N_("interface=\"dup\" msg=\"%s\" file_id=\"%ld\" return_id=\"%ld\"")},
  { MSG_ERR_PIPE,    SH_ERR_ALL,     ERR,   N_("interface=\"pipe\" msg=\"%s\" rd_file_id=\"%ld\" wr_file_id=\"%ld\"")},
  { MSG_ERR_FORK,    SH_ERR_ALL,     ERR,   N_("interface=\"fork\" msg=\"%s\" return_id=\"%ld\"")},
  { MSG_ERR_SETUID,  SH_ERR_ALL,     ERR,   N_("interface=\"setuid\" msg=\"%s\" uid=\"%ld\"")},
  { MSG_ERR_SETGID,  SH_ERR_ALL,     ERR,   N_("interface=\"setgid\" msg=\"%s\" gid=\"%ld\"")},
  { MSG_ERR_UTIME,   SH_ERR_ALL,     ERR,   N_("interface=\"utime\" msg=\"%s\" path=\"%s\" atime=\"%ld\" mtime=\"%ld\"")},
  { MSG_ERR_EXEC,    SH_ERR_ALL,     ERR,   N_("interface=\"exec\" msg=\"%s\" path=\"%s\" uid=\"%ld\" gid=\"%ld\"")},
  { MSG_ERR_CHDIR,   SH_ERR_ALL,     ERR,   N_("interface=\"chdir\" msg=\"%s\" path=\"%s\"")},
  { MSG_ERR_UNLINK,  SH_ERR_ALL,     ERR,   N_("interface=\"unlink\" msg=\"%s\" path=\"%s\"")},
  { MSG_ERR_KILL,    SH_ERR_ALL,     ERR,   N_("interface=\"kill\" msg=\"%s\" pid=\"%ld\" sig=\"%ld\"")},

  { MSG_ERR_SIGACT,  SH_ERR_ALL,     ERR,   N_("interface=\"sigaction\" msg=\"%s\" sig=\"%ld\"")},
  { MSG_ERR_CONNECT, SH_ERR_ALL,     ERR,   N_("interface=\"connect\" msg=\"%s\" socket_id=\"%ld\" port=\"%ld\" host=\"%s\"")},
  { MSG_ERR_ACCEPT,  SH_ERR_ALL,     ERR,   N_("interface=\"accept\" msg=\"%s\" socket_id=\"%ld\"")},
  { MSG_ERR_LSTAT,   SH_ERR_ALL,     ERR,   N_("interface=\"lstat\" msg=\"%s\" path=\"%s\"")},
  { MSG_ERR_STAT,    SH_ERR_ALL,     ERR,   N_("interface=\"stat\" msg=\"%s\" path=\"%s\"")},
  { MSG_ERR_FSTAT,   SH_ERR_ALL,     ERR,   N_("interface=\"fstat\" msg=\"%s\" file_id=\"%ld\"")},
  { MSG_ERR_FCNTL,   SH_ERR_ALL,     ERR,   N_("interface=\"fcntl\" msg=\"%s\" file_id=\"%ld\" cmd=\"%ld\" arg=\"%ld\"")},

  { 0, 0, 0, NULL}
};



/********************************************************************
 *
 *
 *         NO XML
 *
 *
 ********************************************************************/





/* #ifdef (SH_USE_XML) */
#else

cat_entry msg_cat[] = {
#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  { MSG_FI_CSUM,     SH_ERR_ALL,     FIL,   N_("msg=<Checksum>, chk=<%s>, path=<%s>")},
  { MSG_FI_DSUM,     SH_ERR_INFO,    FIL,   N_("msg=<d: %3ld, -: %3ld, l: %3ld, |: %3ld, s: %3ld, c: %3ld, b: %3ld>")},
  { MSG_FI_CHK,      SH_ERR_INFO,    FIL,   N_("msg=<Checking %16s>, path=<%s>")},
#endif

  { MSG_EXIT_ABORTS, SH_ERR_FATAL,   PANIC, N_("msg=<PANIC %s>, program=<%s>, subroutine=<%s>")},
  { MSG_START_SRV,   SH_ERR_STAMP,   START, N_("msg=<Server up, simultaneous connections: %d>, socket_id=<%d>")}, 
 
  { MSG_EXIT_ABORT1, SH_ERR_FATAL,   PANIC, N_("msg=<PANIC Error initializing the application>, program=<%s>")},
  { MSG_EXIT_NORMAL, SH_ERR_FATAL,   START, N_("msg=<EXIT>, program=<%s>, status=<%s>")},
  { MSG_START_KEY_MAIL,   SH_ERR_FATAL, LOGKEY,   N_("msg=<LOGKEY>, program=<%s>, hash=<%s>\r\n-----BEGIN LOGKEY-----\r\n%s%s")},
  { MSG_START_KEY,   SH_ERR_FATAL,   LOGKEY,   N_("msg=<LOGKEY>, program=<%s>, hash=<%s>")},
  { MSG_START_0H,    SH_ERR_FATAL,   START, N_("msg=<START>, program=<%s>, userid=<%ld>")},
  { MSG_START_1H,    SH_ERR_FATAL,   START, N_("msg=<START>, program=<%s>, userid=<%ld>, path=<%s>, hash=<%s>")},
  { MSG_START_2H,    SH_ERR_FATAL,   START, N_("msg=<START>, program=<%s>, userid=<%ld>, path=<%s>, hash=<%s>, path=<%s>, hash=<%s>")},
  { MSG_START_GH,    SH_ERR_FATAL,   START, N_("msg=<START>, program=<%s>, userid=<%ld>, path=<%s>, key_uid=<%s>, key_id=<%s>")},
  { MSG_START_GH2,   SH_ERR_FATAL,   START, N_("msg=<EXIT>, program=<%s>, userid=<%ld>, path=<%s>, key_uid=<%s>, key_id=<%s>, path=<%s>, key_uid=<%s>, key_id=<%s>")},
  { MSG_SUSPEND,     SH_ERR_STAMP,   START, N_("msg=<SUSPEND> program=<%s>")},


  { MSG_MLOCK,       SH_ERR_WARN,    RUN,   N_("msg=<Using insecure memory>")},
  { MSG_W_SIG,       SH_ERR_WARN,    RUN,   N_("msg=<%s>, interface=<sigaction>, signal=<%ld>")},
  { MSG_W_CHDIR,     SH_ERR_ERR,     RUN,   N_("msg=<%s>, interface=<chdir>, path=<%s>")},

  { MSG_MOD_FAIL,    SH_ERR_WARN,    RUN,   N_("msg=<Module not initialized>, module=<%s>, return_code=<%ld>")},
  { MSG_MOD_OK,      SH_ERR_INFO,    RUN,   N_("msg=<Module initialized>, module=<%s>")},
  { MSG_MOD_EXEC,    SH_ERR_ERR,     RUN,   N_("msg=<Module execution error>, module=<%s>, return_code=<%ld>")},

  { MSG_RECONF,      SH_ERR_SEVERE,  START, N_("msg=<Runtime configuration reloaded>")},
  { MSG_CHECK_0,     SH_ERR_WARN,    RUN,   N_("msg=<No files or directories defined for checking>")},
  { MSG_CHECK_1,     SH_ERR_STAMP,   STAMP, N_("msg=<File check completed.>, time=<%ld>, kBps=<%f>")},
  { MSG_CHECK_2,     SH_ERR_STAMP,   STAMP, N_("msg=<File check starting.>")},
  { MSG_STAMP,       SH_ERR_STAMP,   STAMP, N_("msg=<---- TIMESTAMP ---->")},

  { MSG_D_START,     SH_ERR_INFO,    RUN,   N_("msg=<Downloading configuration file>")},
  { MSG_D_DSTART,    SH_ERR_INFO,    RUN,   N_("msg=<Downloading database file>")},
  { MSG_D_FAIL,      SH_ERR_INFO,    RUN,   N_("msg=<No file from server, trying local file>")},
  { MSG_D_DELTAOK,   SH_ERR_SEVERE,  RUN,   N_("msg=<Delta database downloaded>, path=<%s>")},
  { MSG_D_DELTAFAIL, SH_ERR_SEVERE,  RUN,   N_("msg=<Delta database download failed>, path=<%s>")},


#ifndef HAVE_URANDOM 
  { MSG_ENSTART,     SH_ERR_ALL,     RUN,   N_("msg=<Found entropy source>, path=<%s>")},
  { MSG_ENEXEC,      SH_ERR_ALL,     RUN,   N_("msg=<Execute entropy source>, path=<%s>, rd_file_id=<%ld>")},
  { MSG_ENFAIL,      SH_ERR_ALL,     RUN,   N_("msg=<Could not execute entropy source>, path=<%s>")},
  { MSG_ENTOUT,      SH_ERR_ALL,     RUN,   N_("msg=<Timeout in entropy collector>, time=<%ld>")},
  { MSG_ENCLOS,      SH_ERR_ALL,     RUN,   N_("msg=<End of data, closing entropy source>, rd_file_id=<%ld>")},
  { MSG_ENCLOS1,     SH_ERR_ALL,     RUN,   N_("msg=<Close entropy source>, rd_file_id=<%ld>")},
  { MSG_ENREAD,      SH_ERR_ALL,     RUN,   N_("msg=<Data from entropy source>, rd_file_id=<%ld>, bytes=<%ld>")},
#endif

#ifdef SH_USE_SUIDCHK
  { MSG_SUID_POLICY, SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [SuidCheck]  %s>, path=<%s>, %s") },
  { MSG_SUID_FOUND,  SH_ERR_INFO,    RUN,   N_("msg=<Found suid/sgid file> path=<%s>") },
  { MSG_SUID_SUMMARY,SH_ERR_INFO,    RUN,   N_("msg=<Checked for SUID programs: %ld files, %ld seconds>") },
  { MSG_SUID_QREPORT,SH_ERR_SEVERE,  EVENT, N_("msg=<Quarantine report: %s>, path=<%s>") },
  { MSG_SUID_ERROR,  SH_ERR_SEVERE,  EVENT, N_("msg=<Quarantine error: %s>") },
#endif

#ifdef SH_USE_KERN
  { MSG_KERN_POLICY, SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Kernel] BSD syscall table: new: %#lx old: %#lx>, syscall=<%03d %s>") },
  { MSG_KERN_POL_CO, SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Kernel] BSD syscall code: new: %#x,%#x old: %#x,%#x>, syscall=<%03d %s>") },

  { MSG_KERN_SYSCALL,SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Kernel] SYSCALL modified> syscall=<%03d %s>, %s") },
  { MSG_KERN_PROC,   SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Kernel] PROC modified proc filesystem: %s>") },
  { MSG_KERN_IDT,    SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Kernel] IDT interrupt %03d: new: 0x%-8.8lx %-9s %3d %c old: 0x%-8.8lx %-9s %3d %c>, %s") },
  { MSG_KERN_GATE,   SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Kernel SYS_GATE code: new: %#x,%#x old: %#x,%#x> syscall=<%03d %s>, %s") },

#endif

#ifdef SH_USE_UTMP
  { MSG_UT_CHECK,    SH_ERR_INFO,    RUN,   N_("msg=<Checking logins>")},

  { MSG_UT_LG1X,     SH_ERR_INFO,    EVENT, N_("msg=<Login>, name=<%s>, tty=<%s>, host=<%s>, ip=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG1A,     SH_ERR_INFO,    EVENT, N_("msg=<Login>, name=<%s>, tty=<%s>, host=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG1B,     SH_ERR_INFO,    EVENT, N_("msg=<Login>, name=<%s>, tty=<%s>, time=<%s>, status=<%d>")},

  { MSG_UT_LG2X,     SH_ERR_INFO,    EVENT, N_("msg=<Multiple login>, name=<%s>, tty=<%s>, host=<%s>, ip=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG2A,     SH_ERR_INFO,    EVENT, N_("msg=<Multiple login>, name=<%s>, tty=<%s>, host=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG2B,     SH_ERR_INFO,    EVENT, N_("msg=<Multiple login>, name=<%s>, tty=<%s>, time=<%s>, status=<%d>")},

  { MSG_UT_LG3X,     SH_ERR_INFO,    EVENT, N_("msg=<Logout>, name=<%s>, tty=<%s>, host=<%s>, ip=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG3A,     SH_ERR_INFO,    EVENT, N_("msg=<Logout>, name=<%s>, tty=<%s>, host=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG3B,     SH_ERR_INFO,    EVENT, N_("msg=<Logout>, name=<%s>, tty=<%s>, time=<%s>, status=<%d>")},
  { MSG_UT_LG3C,     SH_ERR_INFO,    EVENT, N_("msg=<Logout>, tty=<%s>, time=<%s>")},
  { MSG_UT_ROT,      SH_ERR_WARN,    RUN,   N_("msg=<Logfile size decreased>, path=<%s>")},

  { MSG_UT_BAD,      SH_ERR_SEVERE,  EVENT, N_("msg=<Login at disallowed time> userid=<%s> host=<%s> time=<%s>")},
  { MSG_UT_FIRST,    SH_ERR_SEVERE,  EVENT, N_("msg=<First login from this host> userid=<%s> host=<%s> time=<%s>")},
  { MSG_UT_OUTLIER,  SH_ERR_SEVERE,  EVENT, N_("msg=<Login time outlier> userid=<%s> host=<%s> time=<%s>")},
#endif

#ifdef SH_USE_PROCESSCHECK
  { MSG_PCK_CHECK,   SH_ERR_INFO,    RUN,   N_("msg=<Checking processes in pid interval [%ld,%ld]>")},
  { MSG_PCK_OK,      SH_ERR_ALL,     RUN,   N_("msg=<PID %ld found with tests %s>")},
  { MSG_PCK_P_HIDDEN,SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Process] Hidden pid: %ld tests: %s> path=<%s> userid=<%s>")},
  { MSG_PCK_HIDDEN,  SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Process] Hidden pid: %ld tests: %s>")},
  { MSG_PCK_FAKE,    SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Process] Fake pid: %ld tests: %s>")},
  { MSG_PCK_MISS,    SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Process] Missing: %s>")},
#endif

#ifdef SH_USE_PORTCHECK
  { MSG_PORT_MISS,   SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [ServiceMissing] %s>")},
  { MSG_PORT_NEW,    SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [ServiceNew] %s> path=<%s> pid=<%lu> userid=<%s>")},
  { MSG_PORT_RESTART,SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [ServiceRestarted] %s> path=<%s> pid=<%lu> userid=<%s>")},
  { MSG_PORT_NEWPORT,SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [ServicePortSwitch] %s> path=<%s> pid=<%lu> userid=<%s>")},
#endif

#ifdef SH_USE_MOUNTS
  { MSG_MNT_CHECK,   SH_ERR_INFO,    RUN,   N_("msg=<Checking mounts>")},
  { MSG_MNT_MEMLIST, SH_ERR_ERR,     RUN,   N_("msg=<Cannot read mount list from memory>")},
  { MSG_MNT_MNTMISS, SH_ERR_WARN,    EVENT, N_("msg=<POLICY [Mounts] Mount missing>, path=<%s>")},
  { MSG_MNT_OPTMISS, SH_ERR_WARN,    EVENT, N_("msg=<POLICY [Mounts] Mount option missing>, path=<%s>, option=<%s>")},
#endif

#ifdef SH_USE_USERFILES
  { MSG_USERFILES_SUMMARY,SH_ERR_INFO,    RUN,   N_("msg=<Checked for users files>") },
#endif

#ifdef USE_LOGFILE_MONITOR
  { MSG_LOGMON_CHKS, SH_ERR_INFO,    RUN,   N_("msg=<Checking logfile %s>") },
  { MSG_LOGMON_CHKE, SH_ERR_INFO,    RUN,   N_("msg=<Finished logfile %s, %lu new records processed>") },
  { MSG_LOGMON_MISS, SH_ERR_ERR,     RUN,   N_("msg=<Missing logfile %s>") },
  { MSG_LOGMON_EOPEN,SH_ERR_ERR,     RUN,   N_("msg=<Cannot open logfile %s>") },
  { MSG_LOGMON_EREAD,SH_ERR_ERR,     RUN,   N_("msg=<Error while reading logfile %s>") },
  { MSG_LOGMON_REP,  SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Logfile] %s> time=<%s>, host=<%s>, path=<%s>") },
  { MSG_LOGMON_SUM,  SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Logfile] %s> host=<%s> path=<%s>") },
  { MSG_LOGMON_COR,  SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Logfile] Correlation event %s occured %d time(s)>") },
  { MSG_LOGMON_MARK, SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [Logfile] Event %s missing for %lu seconds>") },
  { MSG_LOGMON_BURST, SH_ERR_SEVERE, EVENT, N_("msg=<POLICY [Logfile] Repeated %d times: %s>, host=<%s> ") },
#endif

#ifdef USE_REGISTRY_CHECK
  { MSG_REG_MISS,   SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [RegistryKeyMissing] %s>, path=<%s>, %s")},
  { MSG_REG_NEW,    SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [RegistryKeyNew] %s>, path=<%s>, %s")},
  { MSG_REG_CHANGE, SH_ERR_SEVERE,  EVENT, N_("msg=<POLICY [RegistryKeyChanged] %s>, path=<%s>, %s")},
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  
  { MSG_FI_TOOLATE,  SH_ERR_ERR,     FIL,   N_("msg=<Large lstat/open overhead (%ld sec)>, path=<%s>")},

#if 0
  { MSG_FI_CSUM,     SH_ERR_ALL,     FIL,   N_("msg=<Checksum>, chk=<%s>, path=<%s>")},
  { MSG_FI_DSUM,     SH_ERR_INFO,    FIL,   N_("msg=<d: %3ld, -: %3ld, l: %3ld, |: %3ld, s: %3ld, c: %3ld, b: %3ld>")},
  { MSG_FI_CHK,      SH_ERR_INFO,    FIL,   N_("msg=<Checking %16s>, path=<%s>")},
#endif

  { MSG_FI_NULL,     SH_ERR_ERR,     FIL,   N_("msg=<Path is NULL>")},
  { MSG_FI_FAIL,     SH_ERR_ERR,     FIL,   N_("msg=<Check failed>, path=<%s>")},
  { MSG_FI_GLOB,     SH_ERR_ERR,     FIL,   N_("msg=<%s>, interface=<glob>, path=<%s>")},
  { MSG_FI_COLL,     SH_ERR_WARN,    FIL,   N_("msg=<Writeable file with timestamps of parent directory fixed>, dir=<%s>, path=<%s>")},
  { MSG_FI_DOUBLE,   SH_ERR_WARN,    FIL,   N_("msg=<File or directory appears twice in configuration>, path=<%s>")},
  { MSG_FI_2LONG,    SH_ERR_ERR,     FIL,   N_("msg=<Filename too long>, path=<%s>")},
  { MSG_FI_2LONG2,   SH_ERR_ERR,     FIL,   N_("msg=<Filename too long>, path=<%s/%s>")},
  { MSG_FI_NOPATH,   SH_ERR_ERR,     FIL,   N_("msg=<Filename not an absolute path>, path=<%s>")},
  { MSG_FI_DLNK,     SH_ERR_INFO,    FIL,   N_("msg=<Dangling link>, path=<%s>, linked_path=<%s>")},
  { MSG_FI_RDLNK,    SH_ERR_ERR,     FIL,   N_("msg=<%s>, interface=<readlink>, path=<%s>")},
  { MSG_FI_NOGRP,    SH_ERR_ERR,     FIL,   N_("msg=<No such group>, interface=<getgrgid>, group=<%ld>, path=<%s>")},
  { MSG_FI_NOUSR,    SH_ERR_ERR,     FIL,   N_("msg=<No such user>, interface=<getpwuid>, userid=<%ld>, path=<%s>")},
  { MSG_FI_STAT,     SH_ERR_ERR,     FIL,   N_("interface=<%s>, msg=<%s>, userid=<%ld>, path=<%s>")},
  { MSG_FI_OBSC,     SH_ERR_ERR,     FIL,   N_("msg=<Weird filename>, path=<%s>")},
  { MSG_FI_OBSC2,    SH_ERR_ERR,     FIL,   N_("msg=<Weird filename>, path=<%s/%s>")},
  { MSG_FI_LIST,     SH_ERR_ALL,     FIL,   N_("msg=<%10s %2d %8s %8s %14ld %21s %s>")},
  { MSG_FI_LLNK,     SH_ERR_ALL,     FIL,   N_("msg=<   >>>  %10s  %s>")},
  { MSG_FI_MISS,     SH_ERR_ERR,     EVENT, N_("msg=<POLICY MISSING>, path=<%s>")},
  { MSG_FI_MISS2,     SH_ERR_ERR,     EVENT, N_("msg=<POLICY MISSING>, path=<%s>, %s")},
  { MSG_FI_ADD,      SH_ERR_ERR,     EVENT, N_("msg=<POLICY ADDED>, path=<%s>")},
  { MSG_FI_ADD2,      SH_ERR_ERR,     EVENT, N_("msg=<POLICY ADDED>, path=<%s>, %s")},
  { MSG_FI_CHAN,     SH_ERR_ERR,     EVENT, N_("msg=<POLICY %s %s>, path=<%s>, %s")},
  { MSG_FI_NODIR,    SH_ERR_ERR,     EVENT, N_("msg=<POLICY NODIRECTORY>, path=<%s>")},
  { MSG_FI_DBEX,     SH_ERR_WARN,    FIL,   N_("msg=<Signature database exists>, path=<%s>")},
#endif

  { MSG_TCP_NETRP,   SH_ERR_ERR,     TCP,   N_("msg=<Connection error: %s>, port=<%ld>, subroutine=<%s>")},

#ifndef SH_STANDALONE
#ifdef INET_SYSLOG
  { MSG_INET_SYSLOG, SH_ERR_INET,    TCP,   N_("ip=<%s> facility=<%s> priority=<%s> syslog_msg=<%s>")},
  { MSG_ERR_SYSLOG,  SH_ERR_ERR,     TCP,   N_("msg=<syslog socket: %s>, ip=<%s>")},
#endif
  { MSG_TCP_MISMATCH,SH_ERR_ERR,     TCP,   N_("msg=<Protocol mismatch>")},
  { MSG_TCP_MISENC,  SH_ERR_ERR,     TCP,   N_("msg=<Encryption mismatch in %s: server: %s client: %s>")},
  { MSG_TCP_NONAME,  SH_ERR_ERR,     TCP,   N_("msg=<No server name known>")},
  { MSG_TCP_UNEXP,   SH_ERR_ERR,     TCP,   N_("msg=<Unexpected reply>")},
  { MSG_TCP_EFIL,    SH_ERR_ERR,     TCP,   N_("msg=<Could not open temporary file>")},
  { MSG_TCP_NOCONF,  SH_ERR_ERR,     TCP,   N_("msg=<Message delivery not confirmed>")},
  { MSG_TCP_NOAUTH,  SH_ERR_ERR,     TCP,   N_("msg=<Session key negotiation failed>")},
  { MSG_TCP_CONF,    SH_ERR_ALL,     TCP,   N_("msg=<Message delivery confirmed>")},
  { MSG_TCP_AUTH,    SH_ERR_INFO,    TCP,   N_("msg=<Session key negotiated>")},
  { MSG_TCP_FOK,     SH_ERR_INFO,    TCP,   N_("msg=<File download completed>")},
  { MSG_TCP_FBAD,    SH_ERR_ERR,     TCP,   N_("msg=<File download failed>")},
  { MSG_TCP_ECONN,   SH_ERR_ERR,     TCP,   N_("msg=<Connection error: %s>")},
  { MSG_TCP_EZERO,   SH_ERR_ERR,     TCP,   N_("msg=<Illegal zero reply>")},
  { MSG_TCP_EBGN,    SH_ERR_ERR,     TCP,   N_("msg=<Error in big integer library>")},

  { MSG_TCP_CREG,    SH_ERR_ALL,     TCP,   N_("msg=<Registered %s, salt %s, verifier %s>")},
  { MSG_TCP_FAUTH,   SH_ERR_INFO,    TCP,   N_("msg=<Force authentication>, client=<%s>")},

  { MSG_TCP_RESCLT,  SH_ERR_SEVERE,  TCP,   N_("msg=<Cannot resolve client name> host=<%s>")},
  { MSG_TCP_RESPEER, SH_ERR_SEVERE,  TCP,   N_("msg=<Cannot resolve socket peer IP for client> host=<%s> peer=<%s>")},
  { MSG_TCP_LOOKERS, SH_ERR_SEVERE,  TCP,   N_("msg=<Reverse lookup of socket peer failed> host=<%s> peer=<%s> obj=<%s>")},
  { MSG_TCP_LOOKUP,  SH_ERR_SEVERE,  TCP,   N_("msg=<No socket peer alias matches client name> host=<%s> peer=<%s>")},

  { MSG_TCP_TIMOUT,  SH_ERR_SEVERE,  TCP,   N_("msg=<Connection timeout>, client=<%s>")},
  { MSG_TCP_TIMEXC,  SH_ERR_SEVERE,  TCP,   N_("msg=<Time limit exceeded>, client=<%s>")},
  { MSG_TCP_NOCLT,   SH_ERR_SEVERE,  TCP,   N_("msg=<Hostname is NULL>")},
  { MSG_TCP_BADCONN, SH_ERR_SEVERE,  TCP,   N_("msg=<Invalid connection attempt: %s>, client=<%s>")},
  { MSG_TCP_FFILE ,  SH_ERR_SEVERE,  TCP,   N_("msg=<Unknown file request>, client=<%s>, path=<%s>")},
  { MSG_TCP_NFILE ,  SH_ERR_SEVERE,  TCP,   N_("msg=<Requested file not found>, client=<%s>, path=<%s>")},
  { MSG_TCP_FINV ,   SH_ERR_SEVERE,  TCP,   N_("msg=<Invalid request (%d) in pass %d>, client=<%s>, request=<%c%03o%c%03o%c%03o%c%03o>")},
  { MSG_TCP_OKFILE,  SH_ERR_INFO,    TCP,   N_("msg=<File transfer completed>, client=<%s>")},
  { MSG_TCP_OKMSG,   SH_ERR_ALL,     TCP,   N_("msg=<Message transfer completed>, client=<%s>")},
  { MSG_TCP_MSG,     SH_ERR_INET,    TCP,   N_("client=<%s>, msg=<%s>")},
  { MSG_TCP_NEW,     SH_ERR_NOTICE,  TCP,   N_("msg=<NEW CLIENT>, client=<%s>")},
  { MSG_TCP_ILL,     SH_ERR_SEVERE,  TCP,   N_("msg=<Restart without prior exit>, client=<%s>")},
  { MSG_TCP_SYNC,    SH_ERR_SEVERE,  TCP,   N_("msg=<Out of sync>, client=<%s>")},
  { MSG_TCP_RESET,   SH_ERR_NOTICE,  TCP,   N_("msg=<Connection reset by peer>, client=<%s>")},
  { MSG_TCP_CNEW,    SH_ERR_INFO,    TCP,   N_("msg=<New connection>, socket_id=<%d>")},
  { MSG_E_HTML,      SH_ERR_ERR,     ERR,   N_("msg=<Error writing HTML status>")},
#endif

  
  { MSG_E_AUTH,      SH_ERR_FATAL,   PANIC, N_("msg=<PANIC - File modified>, path=<%s>")},
  { MSG_ACCESS,      SH_ERR_FATAL,   PANIC, N_("msg=<PANIC - Access violation>, userid=<%ld>, path=<%s>")},
  { MSG_TRUST,       SH_ERR_FATAL,   PANIC, N_("msg=<PANIC - Untrusted path>, userid=<%ld>, path=<%s>")},
  { MSG_NOACCESS,    SH_ERR_FATAL,   PANIC, N_("msg=<PANIC - File not accessible>, userid=<%ld>, path=<%s>")},
  { MSG_P_NODATA,    SH_ERR_FATAL,   PANIC, N_("msg=<PANIC - No data in file>, path=<%s>")},


#ifndef MEM_DEBUG
  { MSG_E_MNULL,     SH_ERR_ERR,     ERR,   N_("msg=<Dereferenced NULL pointer>")},
  { MSG_E_MMEM,      SH_ERR_ERR,     ERR,   N_("msg=<Out of memory>")},
#else
  { MSG_MSTAMP,      SH_ERR_STAMP,   STAMP, N_("msg=<Memory used:  max.=%lu, current=%lu>")},
  { MSG_MSTAMP2,     SH_ERR_STAMP,   STAMP, N_("msg=<Blocks: %d allocated, %d freed, %d maximum>")},
  { MSG_E_MNULL,     SH_ERR_ERR,     ERR,   N_("msg=<Dereferenced NULL pointer>, source_file=<%s>, source_line=<%d>")},
  { MSG_E_MMEM,      SH_ERR_ERR,     ERR,   N_("msg=<Out of memory>, source_file=<%s>, source_line=<%d>")},
  { MSG_E_MREC,      SH_ERR_ERR,     ERR,   N_("msg=<Free() on unrecorded block>, source_file=<%s>, source_line=<%d>")},
  { MSG_E_MOVER,     SH_ERR_ERR,     ERR,   N_("msg=<Memory overrun on block allocated in %s, line %d>, source_file=<%s>, source_line=<%d>")},
  { MSG_E_MUNDER,    SH_ERR_ERR,     ERR,   N_("msg=<Memory underrun on block allocated in %s, line %d>, source_file=<%s>, source_line=<%d>")},
  { MSG_E_NOTFREE,   SH_ERR_ERR,     ERR,   N_("msg=<Not deallocated: size %14ld>, source_file=<%19s>, source_line=<%d>")},
#endif

  { MSG_E_TRUST,     SH_ERR_ERR,     ERR,   N_("msg=<Untrusted path>, userid=<%ld>, path=<%s>")},
  { MSG_E_HASH,      SH_ERR_ERR,     ERR,   N_("msg=<Incorrect checksum>, path=<%s>")},
  { MSG_E_ACCESS,    SH_ERR_ERR,     ERR,   N_("msg=<File not accessible>, userid=<%ld>, path=<%s>")},
  { MSG_E_READ,      SH_ERR_ERR,     ERR,   N_("msg=<Not accessible or not a regular file (%s / %s)>, path=<%s>")},
  { MSG_E_NOTREG,    SH_ERR_ERR,     ERR,   N_("msg=<Not a regular file>, path=<%s>")},
  { MSG_E_TIMEOUT,   SH_ERR_ERR,     ERR,   N_("msg=<Timeout (%d sec) while checksumming file>, path=<%s>")},
  { MSG_NODEV,       SH_ERR_ERR,     ERR,   N_("msg=<Device not available or timeout during read attempt>, userid=<%ld>, path=<%s>")},
  { MSG_LOCKED,      SH_ERR_ERR,     ERR,   N_("msg=<File lock error>, userid=<%ld>, path=<%s>, obj=<%s>")},
  { MSG_PIDFILE,      SH_ERR_ERR,     ERR,   N_("msg=<Could not write PID file>, userid=<%ld>, path=<%s>")},
  { MSG_NOEXEC,      SH_ERR_ERR,     ERR,   N_("msg=<Could not execute file>, userid=<%ld>, path=<%s>")},

  { MSG_ES_ENT,      SH_ERR_ERR,     ERR,   N_("msg=<No entropy collected>, subroutine=<%s>")},
  { MSG_ES_KEY1,     SH_ERR_ERR,     ERR,   N_("msg=<Insecure key generation>, subroutine=<%s>")},
  { MSG_ES_KEY2,     SH_ERR_ERR,     ERR,   N_("msg=<Error copying key>, subroutine=<%s>")},
  { MSG_E_GPG,       SH_ERR_ERR,     ERR,   N_("msg=<Compiled-in gpg checksum does not match: need %s got %s>")},
  { MSG_E_GPG_FP,    SH_ERR_ERR,     ERR,   N_("msg=<Compiled-in fingerprint modified: one %s two %s>")},
  { MSG_E_GPG_CHK,   SH_ERR_ERR,     ERR,   N_("msg=<Compiled-in checksum modified: one %s two %s>")},
  { MSG_E_SUBGEN,    SH_ERR_ERR,     ERR,   N_("msg=<%s>, subroutine=<%s>")},
  { MSG_E_SUBGPATH,  SH_ERR_ERR,     ERR,   N_("msg=<%s>, subroutine=<%s>, path=<%s>")},
  { MSG_E_UNLNK,     SH_ERR_ERR,     FIL,   N_("msg=<%s>, interface=<unlink>, path=<%s>")},
  { MSG_E_REGEX,     SH_ERR_ERR,     ERR,   N_("msg=<%s>, interface=<regcomp>, regexp=<%s>")},
  { MSG_E_OPENDIR,   SH_ERR_ERR,     FIL,   N_("msg=<%s>, interface=<opendir>, path=<%s>")},
  { MSG_E_TRUST1,    SH_ERR_ERR,     ERR,   N_("msg=<%s>, subroutine=<trustfile>, path=<%s>")},
  { MSG_E_TRUST2,    SH_ERR_ERR,     ERR,   N_("msg=<%s>, subroutine=<trustfile>, path=<%s>, obj=<%s>")},
  { MSG_E_PWNULL,    SH_ERR_ERR,     ERR,   N_("msg=<Empty password file entry: %s>, subroutine=<%s>, userid=<%ld>, obj=<%s>")},
  { MSG_E_PWLONG,    SH_ERR_ERR,     ERR,   N_("msg=<Password file entry too long>, subroutine=<%s>, userid=<%ld>, obj=<%s>")},
  { MSG_E_GRNULL,    SH_ERR_ERR,     ERR,   N_("msg=<Empty groups file entry: %s>, subroutine=<%s>, group=<%ld>, obj=<%s>")},

  { MSG_E_NET,       SH_ERR_ERR,     ENET,  N_("msg=<%s>, subroutine=<%s>, service=<%s>, host=<%s>")},
  { MSG_E_NETST,     SH_ERR_ERR,     ENET,  N_("msg=<Invalid connection state>, expect=<%4s>, received=<%4s>")},
  { MSG_E_NETST1,    SH_ERR_ERR,     ENET,  N_("msg=<Invalid connection state>, expect=<%4s>, received=<%4s>, host=<%s>")},
  { MSG_E_NLOST,     SH_ERR_ERR,     ENET,  N_("msg=<Connection failure>, service=<%s>, obj=<%s>")},
  { MSG_E_NEST,      SH_ERR_ERR,     ENET,  N_("msg=<Connection reestablished>, service=<%s>, obj=<%s>")},

  { MSG_EINVALHEAD,  SH_ERR_WARN,    EINPUT,N_("msg=<Unrecognized section heading in line %ld of configuration file>")},
  { MSG_EINVALCONF,  SH_ERR_WARN,    EINPUT,N_("msg=<Invalid line %ld in configuration file: incorrect format, unrecognized option, or missing section header>")},
  { MSG_EINVALS,     SH_ERR_WARN,    EINPUT,N_("msg=<Invalid input>, option=<%s>, obj=<%s>")},
  { MSG_EINVALL,     SH_ERR_WARN,    EINPUT,N_("msg=<Invalid input>, option=<%s>, obj=<%ld>")},
  { MSG_EINVALD,     SH_ERR_WARN,    EINPUT,N_("msg=<Configuration file: Unmatched @end>, option=<%s>, obj=<%ld>")},
  { MSG_EINVALDD,    SH_ERR_WARN,    EINPUT,N_("msg=<Configuration file: Missing @end>, option=<%s>, obj=<%ld>")},

  { MSG_SRV_FAIL,    SH_ERR_ERR,     ERR,   N_("msg=<Service failure>, service=<%s>, obj=<%s>")},
  { MSG_QUEUE_FULL,  SH_ERR_ERR,     ERR,   N_("msg=<Queue full, messages may get lost> service=<%s>")},

  { MSG_AUD_OPEN,    SH_ERR_NOTICE,  AUD,   N_("interface=<open>, pathname=<%s>, oflag=<%ld>, mode=<%ld>, return_id=<%ld>")},
  { MSG_AUD_DUP,     SH_ERR_NOTICE,  AUD,   N_("interface=<dup>, file_id=<%ld>, return_id=<%ld>")},
  { MSG_AUD_PIPE,    SH_ERR_NOTICE,  AUD,   N_("interface=<pipe>, rd_file_id=<%ld>, wr_file_id=<%ld>")},
  { MSG_AUD_FORK,    SH_ERR_NOTICE,  AUD,   N_("interface=<fork>, return_id=<%ld>")},
  { MSG_AUD_EXIT,    SH_ERR_NOTICE,  AUD,   N_("interface=<exit>, exit_code=<%ld>")},
  { MSG_AUD_SETUID,  SH_ERR_NOTICE,  AUD,   N_("interface=<setuid>, uid=<%ld>")},
  { MSG_AUD_SETGID,  SH_ERR_NOTICE,  AUD,   N_("interface=<setgid>, gid=<%ld>")},
  { MSG_AUD_UTIME,   SH_ERR_NOTICE,  AUD,   N_("interface=<utime>, pathname=<%s>, atime=<%ld>, mtime=<%ld>")},
  { MSG_AUD_EXEC,    SH_ERR_NOTICE,  AUD,   N_("interface=<exec>, pathname=<%s>, uid=<%ld>, gid=<%ld>")},
  { MSG_AUD_CHDIR,   SH_ERR_NOTICE,  AUD,   N_("interface=<chdir>, pathname=<%s>")},
  { MSG_AUD_UNLINK,  SH_ERR_NOTICE,  AUD,   N_("interface=<unlink>, pathname=<%s>")},
  { MSG_AUD_KILL,    SH_ERR_NOTICE,  AUD,   N_("interface=<kill>, pid=<%ld>, sig=<%ld>")},

  { MSG_ERR_OPEN,    SH_ERR_ALL,     ERR,   N_("interface=<open>, msg=<%s>, path=<%s>, oflag=<%ld>, mode=<%ld>, return_id=<%ld>")},
  { MSG_ERR_DUP,     SH_ERR_ALL,     ERR,   N_("interface=<dup>, msg=<%s>, file_id=<%ld>, return_id=<%ld>")},
  { MSG_ERR_PIPE,    SH_ERR_ALL,     ERR,   N_("interface=<pipe>, msg=<%s>, rd_file_id=<%ld>, wr_file_id=<%ld>")},
  { MSG_ERR_FORK,    SH_ERR_ALL,     ERR,   N_("interface=<fork>, msg=<%s>, return_id=<%ld>")},
  { MSG_ERR_SETUID,  SH_ERR_ALL,     ERR,   N_("interface=<setuid>, msg=<%s>, uid=<%ld>")},
  { MSG_ERR_SETGID,  SH_ERR_ALL,     ERR,   N_("interface=<setgid>, msg=<%s>, gid=<%ld>")},
  { MSG_ERR_UTIME,   SH_ERR_ALL,     ERR,   N_("interface=<utime>, msg=<%s>, path=<%s>, atime=<%ld>, mtime=<%ld>")},
  { MSG_ERR_EXEC,    SH_ERR_ALL,     ERR,   N_("interface=<exec>, msg=<%s>, path=<%s>, uid=<%ld>, gid=<%ld>")},
  { MSG_ERR_CHDIR,   SH_ERR_ALL,     ERR,   N_("interface=<chdir>, msg=<%s>, path=<%s>")},
  { MSG_ERR_UNLINK,  SH_ERR_ALL,     ERR,   N_("interface=<unlink>, msg=<%s>, path=<%s>")},
  { MSG_ERR_KILL,    SH_ERR_ALL,     ERR,   N_("interface=<kill>, msg=<%s>, pid=<%ld>, sig=<%ld>")},

  { MSG_ERR_SIGACT,  SH_ERR_ALL,     ERR,   N_("interface=<sigaction>, msg=<%s>, sig=<%ld>")},
  { MSG_ERR_CONNECT, SH_ERR_ALL,     ERR,   N_("interface=<connect>, msg=<%s>, socket_id=<%ld>, port=<%ld>, host=<%s>")},
  { MSG_ERR_ACCEPT,  SH_ERR_ALL,     ERR,   N_("interface=<accept>, msg=<%s>, socket_id=<%ld>")},
  { MSG_ERR_LSTAT,   SH_ERR_ALL,     ERR,   N_("interface=<lstat>, msg=<%s>, path=<%s>")},
  { MSG_ERR_STAT,    SH_ERR_ALL,     ERR,   N_("interface=<stat>, msg=<%s>, path=<%s>")},
  { MSG_ERR_FSTAT,   SH_ERR_ALL,     ERR,   N_("interface=<fstat>, msg=<%s>, file_id=<%ld>")},
  { MSG_ERR_FCNTL,   SH_ERR_ALL,     ERR,   N_("interface=<fcntl>, msg=<%s>, file_id=<%ld>, cmd=<%ld>, arg=<%ld>")},

  { 0, 0, 0, NULL}
};

/* #ifdef (SH_USE_XML) */
#endif





