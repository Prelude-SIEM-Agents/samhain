#ifndef SH_LOGMON_H
#define SH_LOGMON_H

extern sh_rconf sh_log_check_table[];

int sh_log_check_init (struct mod_type * arg);
int sh_log_check_timer(time_t tcurrent);
int sh_log_check_check(void);
int sh_log_check_reconf(void); 
int sh_log_check_cleanup(void);

#endif
