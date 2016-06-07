
#ifndef SH_MODULE_H
#define SH_MODULE_H

#include "sh_pthread.h"

enum
  {
    SH_MODFL_NOTIMER    = (1 << 0),
    SH_MODFL_NEEDPAUSED = (1 << 1),
    SH_MODFL_ISPAUSED   = (1 << 2)
  };


typedef struct rconf
{
  char * the_opt;
  int (*func)(const char * opt);
} sh_rconf;

typedef struct mod_type
{
  /* The name of the module                                    */
  char * name;      

  /* Set by samhain to 1 on successful initialization, else 0  */
  int    initval; 

  /* Flags: SH_MOD_NOTIMER                                     */
  int    flags; 

  /* The initialization function. Return 0 on success.         */
  int (* mod_init)    (struct mod_type * arg);  
                             
  /* The timer function. Return 0 if NOT time to check.        */
  int (* mod_timer)   (time_t tcurrent); 

  /* The check function. Return 0 on success.                  */
  /* Return nonzero on fatal error or if module is disabled.   */
  int (* mod_check)   (void); 

  /* The cleanup function. Return 0 on success.                */
  int (* mod_cleanup) (void);

  /* The preparation for reconfiguration. Return 0 on success. */
  int (* mod_reconf) (void);

  /* Section header in config file                             */
  char * conf_section; 

  /* A table of key/handler_function for config file entries   */
  sh_rconf * conf_table; 

  SH_MUTEX(mod_mutex);

} sh_mtype;


extern sh_mtype modList[];


/* #ifndef SH_MODULE_H */
#endif
