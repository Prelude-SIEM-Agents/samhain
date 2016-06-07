
#ifndef SH_PROCESSCHECK_H
#define SH_PROCESSCHECK_H

int sh_prochk_init(struct mod_type * arg);
int sh_prochk_timer(time_t tcurrent);
int sh_prochk_check(void);
int sh_prochk_reconf(void);
int sh_prochk_cleanup(void);

extern sh_rconf sh_prochk_table[];

#endif
