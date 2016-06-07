
#ifndef SH_REGISTRY_H
#define SH_REGISTRY_H

int sh_reg_check_init(struct mod_type * arg);
int sh_reg_check_timer(time_t tcurrent);
int sh_reg_check_run(void);
int sh_reg_check_reconf(void);
int sh_reg_check_cleanup(void);

extern sh_rconf sh_reg_check_table[];

#endif
