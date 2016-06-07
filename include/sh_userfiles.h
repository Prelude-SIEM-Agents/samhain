/*
 * File: sh_userfiles.h
 * Desc: A module for Samhain; adds files in user directories to the check list
 * Auth: Jerry Connolly <jerry.connolly@eircom.net>
 */

#ifndef SH_USERFILES_H
#define SH_USERFILES_H

#ifdef SH_USE_USERFILES
int sh_userfiles_init  (struct mod_type * arg);
int sh_userfiles_timer (time_t tcurrent);
int sh_userfiles_check (void);
int sh_userfiles_end   (void);
int sh_userfiles_cleanup (void);
int sh_userfiles_reconf (void);

int sh_userfiles_set_uid (const char * str);
int sh_userfiles_add_file(const char *c);
int sh_userfiles_set_interval(const char *c);
int sh_userfiles_set_active(const char *c);
int sh_userfiles_check_internal(void);

extern sh_rconf sh_userfiles_table[];


#endif

/* #ifndef SH_USERFILES_H */
#endif
