
#ifndef SH_PORTCHECK_H
#define SH_PORTCHECK_H

int sh_portchk_init(struct mod_type * arg);
int sh_portchk_timer(time_t tcurrent);
int sh_portchk_check(void);
int sh_portchk_reconf(void);
int sh_portchk_cleanup(void);

extern sh_rconf sh_portchk_table[];

#endif
