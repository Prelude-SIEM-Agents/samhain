#include "config_xor.h"

#include <stdio.h>
#include <time.h>

#if defined (SH_WITH_CLIENT) || defined (SH_STANDALONE) 

#include "sh_modules.h"
#include "sh_pthread.h"

#include "sh_utmp.h"
#include "sh_mounts.h"
#include "sh_userfiles.h"
#include "sh_suidchk.h"
#include "sh_processcheck.h"
#include "sh_portcheck.h"
#include "sh_logmon.h"
#include "sh_registry.h"
#include "sh_fInotify.h"

sh_mtype modList[] = {
#ifdef SH_USE_UTMP
  {
    N_("UTMP"),
    -1,
    SH_MODFL_NOTIMER,
    sh_utmp_init,
    sh_utmp_timer,
    sh_utmp_check,
    sh_utmp_end,
    sh_utmp_reconf,

    N_("[Utmp]"),
    sh_utmp_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef SH_USE_MOUNTS
  {
    N_("MOUNTS"),
    -1,
    0,
    sh_mounts_init,
    sh_mounts_timer,
    sh_mounts_check,
    sh_mounts_cleanup,
    sh_mounts_reconf,

    N_("[Mounts]"),
    sh_mounts_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef SH_USE_USERFILES
  {
    N_("USERFILES"),
    -1,
    0,
    sh_userfiles_init,
    sh_userfiles_timer,
    sh_userfiles_check,
    sh_userfiles_cleanup,
    sh_userfiles_reconf,

    N_("[UserFiles]"),
    sh_userfiles_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef SH_USE_SUIDCHK
  {
    N_("SUIDCHECK"),
    -1,
    0,
    sh_suidchk_init,
    sh_suidchk_timer,
    sh_suidchk_check,
    sh_suidchk_end,
    sh_suidchk_reconf,

    N_("[SuidCheck]"),
    sh_suidchk_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef SH_USE_PROCESSCHECK
  {
    N_("PROCESSCHECK"),
    -1,
    0,
    sh_prochk_init,
    sh_prochk_timer,
    sh_prochk_check,
    sh_prochk_cleanup,
    sh_prochk_reconf,

    N_("[ProcessCheck]"),
    sh_prochk_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef SH_USE_PORTCHECK
  {
    N_("PORTCHECK"),
    -1,
    0,
    sh_portchk_init,
    sh_portchk_timer,
    sh_portchk_check,
    sh_portchk_cleanup,
    sh_portchk_reconf,

    N_("[PortCheck]"),
    sh_portchk_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef USE_LOGFILE_MONITOR
  {
    N_("LOGMON"),
    -1,
    0,
    sh_log_check_init,
    sh_log_check_timer,
    sh_log_check_check,
    sh_log_check_cleanup,
    sh_log_check_reconf,

    N_("[Logmon]"),
    sh_log_check_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#ifdef USE_REGISTRY_CHECK
  {
    N_("REGISTRY"),
    -1,
    0,
    sh_reg_check_init,
    sh_reg_check_timer,
    sh_reg_check_run,
    sh_reg_check_cleanup,
    sh_reg_check_reconf,

    N_("[Registry]"),
    sh_reg_check_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

#if defined(HAVE_SYS_INOTIFY_H)
  {
    N_("INOTIFY"),
    -1,
    SH_MODFL_NEEDPAUSED,
    sh_fInotify_init,
    sh_fInotify_timer,
    sh_fInotify_run,
    sh_fInotify_cleanup,
    sh_fInotify_reconf,

    N_("[Inotify]"),
    sh_fInotify_table,
    PTHREAD_MUTEX_INITIALIZER,
  },
#endif

  {
    NULL,
    -1,
    0,

    NULL,
    NULL,
    NULL,
    NULL,
    NULL,

    NULL,
    NULL,
    PTHREAD_MUTEX_INITIALIZER,
  },
};

#endif

