
#ifndef SH_SUIDCHK_H
#define SH_SUIDCHK_H

#include "sh_modules.h"

#ifdef SH_USE_SUIDCHK
int sh_suidchk_init   (struct mod_type * arg);
int sh_suidchk_timer  (time_t tcurrent);
int sh_suidchk_check  (void);
int sh_suidchk_end    (void);
int sh_suidchk_reconf (void);

int sh_suidchk_set_activate   (const char * c);
int sh_suidchk_set_severity   (const char * c);
int sh_suidchk_set_timer      (const char * c);
int sh_suidchk_set_schedule   (const char * c);
int sh_suidchk_set_exclude    (const char * c);
int sh_suidchk_set_fps        (const char * c);
int sh_suidchk_set_yield      (const char * c);
int sh_suidchk_set_nosuid     (const char * c);
int sh_suidchk_set_quarantine (const char * c);
int sh_suidchk_set_qmethod    (const char * c);
int sh_suidchk_set_qdelete    (const char * c);


extern sh_rconf sh_suidchk_table[];

/* Quarantine Methods
 */
typedef enum {

  SH_Q_DELETE = 0,     /* delete */
  SH_Q_CHANGEPERM = 1, /* remove suid/sgid permissions */
  SH_Q_MOVE = 2        /* move   */
 } ShQuarantineMethod;


#endif

/* #ifndef SH_SUIDCHK_H */
#endif
