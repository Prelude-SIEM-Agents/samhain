/*
 * File: sh_mounts.h
 * Desc: A module for Samhain; checks for mounts present and options on them.
 * Auth: Cian Synnott <cian.synnott@eircom.net>
 */

#ifndef SH_MOUNTS_H
#define SH_MOUNTS_H

#include "sh_modules.h"

#ifdef SH_USE_MOUNTS
int sh_mounts_init  (struct mod_type * arg);
int sh_mounts_timer (time_t tcurrent);
int sh_mounts_check (void);
int sh_mounts_cleanup (void);
int sh_mounts_reconf (void);

extern sh_rconf sh_mounts_table[];
#endif

/* #ifndef SH_MOUNTS_H */
#endif
