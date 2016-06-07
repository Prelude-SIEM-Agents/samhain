
#ifndef SH_F_INOTIFY_H
#define SH_F_INOTIFY_H

int sh_fInotify_init(struct mod_type * arg);
int sh_fInotify_timer(time_t tcurrent);
int sh_fInotify_run(void);
int sh_fInotify_reconf(void);
int sh_fInotify_cleanup(void);

extern sh_rconf sh_fInotify_table[];

#endif
