
#ifndef SH_CAT_H
#define SH_CAT_H

typedef struct foo_cat_entry {
  unsigned long id;
  unsigned long priority;
  unsigned long class;
  const char *        format;
} cat_entry;

extern cat_entry msg_cat[];

extern const char * class_cat[];

#define  AUD      0
#define  PANIC    1
#define  RUN      2
#define  FIL      3
#define  TCP      4
#define  ERR      5
#define  STAMP    6
#define  ENET     7
#define  EINPUT   8
#define  EVENT    9
#define  START   10
#define  LOGKEY  11
#define  OTHER_CLA   ((1 << RUN)|(1 << FIL)|(1 << TCP))
#define  RUN_NEW     ((1 << RUN)|(1 << EVENT)|(1 << START)|(1 << LOGKEY))
#define  FIL_NEW     ((1 << FIL)|(1 << EVENT))
#define  ERROR_CLA   ((1 << ERR)|(1 << PANIC)|(1 << ENET)|(1 << EINPUT))

#define SH_CLA_RAW_MAX 12
#define SH_CLA_MAX     16


#if 0
enum {
  SH_CLA_AUD    = (1 << 0),
  SH_CLA_PANIC  = (1 << 1),
  SH_CLA_RUN    = (1 << 2),
  SH_CLA_FIL    = (1 << 3),
  SH_CLA_TCP    = (1 << 4),
  SH_CLA_ERR    = (1 << 5),
  SH_CLA_STAMP  = (1 << 6),
  SH_CLA_ENET   = (1 << 7),
  SH_CLA_EINPUT = (1 << 8)
};
#endif

enum {
 MSG_EXIT_ABORTS, 
 MSG_START_SRV,   
 		  
 MSG_EXIT_ABORT1, 
 MSG_EXIT_NORMAL, 
 MSG_START_KEY_MAIL,   
 MSG_START_KEY,   
 MSG_START_0H,    
 MSG_START_1H,    
 MSG_START_2H,    
 MSG_START_GH,    
 MSG_START_GH2,   
 MSG_SUSPEND,
 		  
 MSG_MLOCK,       
 MSG_W_SIG,       
 MSG_W_CHDIR,     
 		  
 MSG_MOD_FAIL,    
 MSG_MOD_OK,      
 MSG_MOD_EXEC,    
 		  
 MSG_RECONF,      
 MSG_CHECK_0,     
 MSG_CHECK_1,     
 MSG_CHECK_2,     
 MSG_STAMP,       
 		  
 MSG_D_START,     
 MSG_D_DSTART,    
 MSG_D_FAIL,      
 MSG_D_DELTAOK,
 MSG_D_DELTAFAIL,

#ifndef HAVE_URANDOM 
 MSG_ENSTART,     
 MSG_ENEXEC,      
 MSG_ENFAIL,      
 MSG_ENTOUT,      
 MSG_ENCLOS,      
 MSG_ENCLOS1,     
 MSG_ENREAD,      
#endif

#ifdef SH_USE_SUIDCHK
 MSG_SUID_POLICY,
 MSG_SUID_FOUND,
 MSG_SUID_SUMMARY,
 MSG_SUID_QREPORT,
 MSG_SUID_ERROR,
#endif

#ifdef SH_USE_UTMP
 MSG_UT_CHECK,

 MSG_UT_LG1X,
 MSG_UT_LG2X,
 MSG_UT_LG3X,

 MSG_UT_LG1A,     
 MSG_UT_LG1B,
     
 MSG_UT_LG2A,     
 MSG_UT_LG2B,

 MSG_UT_LG3A,     
 MSG_UT_LG3B,     
 MSG_UT_LG3C,     
 MSG_UT_ROT,      

 MSG_UT_BAD,
 MSG_UT_FIRST,
 MSG_UT_OUTLIER,
#endif

#ifdef SH_USE_PROCESSCHECK
 MSG_PCK_CHECK,  
 MSG_PCK_OK,     
 MSG_PCK_P_HIDDEN, 
 MSG_PCK_HIDDEN, 
 MSG_PCK_FAKE,   
 MSG_PCK_MISS,   
#endif

#ifdef SH_USE_PORTCHECK
 MSG_PORT_MISS,
 MSG_PORT_NEW,
 MSG_PORT_RESTART,
 MSG_PORT_NEWPORT,
#endif

#ifdef SH_USE_MOUNTS
 MSG_MNT_CHECK,
 MSG_MNT_MEMLIST,
 MSG_MNT_MNTMISS,
 MSG_MNT_OPTMISS,
#endif

#ifdef SH_USE_USERFILES
 MSG_USERFILES_SUMMARY,
#endif

#ifdef USE_LOGFILE_MONITOR
 MSG_LOGMON_CHKS,
 MSG_LOGMON_CHKE,
 MSG_LOGMON_MISS,
 MSG_LOGMON_EOPEN,
 MSG_LOGMON_EREAD,
 MSG_LOGMON_REP,
 MSG_LOGMON_SUM,
 MSG_LOGMON_COR,
 MSG_LOGMON_MARK,
 MSG_LOGMON_BURST,
#endif

#ifdef USE_REGISTRY_CHECK
 MSG_REG_MISS,
 MSG_REG_NEW,
 MSG_REG_CHANGE,
#endif

#if defined(SH_WITH_CLIENT) || defined(SH_STANDALONE)
  
 MSG_FI_TOOLATE,
 MSG_FI_CSUM,     
 MSG_FI_DSUM,     
 MSG_FI_CHK,      
 MSG_FI_NULL,     
 MSG_FI_FAIL,     
 MSG_FI_GLOB,
 MSG_FI_COLL,
 MSG_FI_DOUBLE,
 MSG_FI_2LONG,    
 MSG_FI_2LONG2,   
 MSG_FI_NOPATH,   
 MSG_FI_DLNK,     
 MSG_FI_RDLNK,    
 MSG_FI_NOGRP,    
 MSG_FI_NOUSR,    
 MSG_FI_STAT,    
 MSG_FI_OBSC,     
 MSG_FI_OBSC2,    
 MSG_FI_LIST,     
 MSG_FI_LLNK,     
 MSG_FI_MISS,     
 /* #ifdef SH_USE_XML */
 MSG_FI_MISS2,
 MSG_FI_ADD2,
 /* #endif */
 MSG_FI_ADD,
 MSG_FI_CHAN,     
 MSG_FI_NODIR,
 MSG_FI_DBEX,        
#endif

 MSG_TCP_NETRP,  

#ifndef SH_STANDALONE
#ifdef INET_SYSLOG
 MSG_INET_SYSLOG,
 MSG_ERR_SYSLOG,
#endif

 MSG_TCP_MISMATCH,
 MSG_TCP_MISENC,
 MSG_TCP_NONAME,  
 MSG_TCP_UNEXP,   
 MSG_TCP_EFIL,    
 MSG_TCP_NOCONF,  
 MSG_TCP_NOAUTH,  
 MSG_TCP_CONF,    
 MSG_TCP_AUTH,    
 MSG_TCP_FOK,     
 MSG_TCP_FBAD,    
 MSG_TCP_ECONN,
 MSG_TCP_EZERO,   
 MSG_TCP_EBGN,    
 		  
 MSG_TCP_CREG,    
 MSG_TCP_FAUTH,   
 MSG_TCP_TIMOUT,  

 MSG_TCP_RESCLT,
 MSG_TCP_RESPEER,
 MSG_TCP_LOOKERS,
 MSG_TCP_LOOKUP,

 MSG_TCP_TIMEXC,  
 MSG_TCP_NOCLT,   
 MSG_TCP_BADCONN, 
 MSG_TCP_FFILE ,  
 MSG_TCP_NFILE ,  
 MSG_TCP_FINV ,   
 MSG_TCP_OKFILE,  
 MSG_TCP_OKMSG,   
 MSG_TCP_MSG,     
 MSG_TCP_NEW,     
 MSG_TCP_ILL,     
 MSG_TCP_SYNC,    
 MSG_TCP_RESET,   
 MSG_TCP_CNEW,    
 MSG_E_HTML,      
#endif		  
		  
  		  
 MSG_E_AUTH,      
 MSG_ACCESS,      
 MSG_TRUST,       
 MSG_NOACCESS,    
 MSG_P_NODATA,         


#ifndef MEM_DEBUG
 MSG_E_MNULL,     
 MSG_E_MMEM,      
#else		  
 MSG_MSTAMP,      
 MSG_MSTAMP2,     
 MSG_E_MNULL,     
 MSG_E_MMEM,      
 MSG_E_MREC,      
 MSG_E_MOVER,     
 MSG_E_MUNDER,
 MSG_E_NOTFREE,    
#endif		  
		  
 MSG_E_TRUST,     
 MSG_E_HASH,      
 MSG_E_ACCESS,    
 MSG_E_READ,
 MSG_E_NOTREG,
 MSG_E_TIMEOUT,
 MSG_NODEV,       
 MSG_LOCKED,
 MSG_PIDFILE,
 MSG_NOEXEC,      
 MSG_ES_ENT,      
 MSG_ES_KEY1,     
 MSG_ES_KEY2,
 MSG_E_GPG,     
 MSG_E_GPG_FP,     
 MSG_E_GPG_CHK,     
 MSG_E_SUBGEN,    
 MSG_E_SUBGPATH,
 MSG_E_UNLNK,     
 MSG_E_REGEX,     
 MSG_E_OPENDIR,   
 MSG_E_TRUST1,    
 MSG_E_TRUST2,    
 MSG_E_PWNULL,    
 MSG_E_PWLONG,    
 MSG_E_GRNULL,    
  
 MSG_E_NET,       
 MSG_E_NETST,     
 MSG_E_NETST1,    
 MSG_E_NLOST,     
 MSG_E_NEST,      

 MSG_EINVALHEAD,
 MSG_EINVALCONF,
 MSG_EINVALS,     
 MSG_EINVALL,     
 MSG_EINVALD,     
 MSG_EINVALDD,    

 MSG_SRV_FAIL,
 MSG_QUEUE_FULL,

 MSG_AUD_OPEN,    
 MSG_AUD_DUP,     
 MSG_AUD_PIPE,    
 MSG_AUD_FORK,    
 MSG_AUD_EXIT,    
 MSG_AUD_SETUID,  
 MSG_AUD_SETGID,  
 MSG_AUD_UTIME,   
 MSG_AUD_EXEC,    
 MSG_AUD_CHDIR,   
 MSG_AUD_UNLINK,  
 MSG_AUD_KILL,

 MSG_ERR_OPEN,
 MSG_ERR_DUP,
 MSG_ERR_PIPE,
 MSG_ERR_FORK,
 MSG_ERR_SETUID,
 MSG_ERR_SETGID,
 MSG_ERR_UTIME,
 MSG_ERR_EXEC,
 MSG_ERR_CHDIR,
 MSG_ERR_UNLINK,
 MSG_ERR_KILL,

 MSG_ERR_SIGACT,
 MSG_ERR_CONNECT,
 MSG_ERR_ACCEPT,
 MSG_ERR_LSTAT,
 MSG_ERR_FSTAT,
 MSG_ERR_STAT,
 MSG_ERR_FCNTL
};

#endif
