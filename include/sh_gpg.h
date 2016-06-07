/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999 Rainer Wichmann                                      */
/*                                                                         */
/*  This program is free software; you can redistribute it                 */
/*  and/or modify                                                          */
/*  it under the terms of the GNU General Public License as                */
/*  published by                                                           */
/*  the Free Software Foundation; either version 2 of the License, or      */
/*  (at your option) any later version.                                    */
/*                                                                         */
/*  This program is distributed in the hope that it will be useful,        */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*  GNU General Public License for more details.                           */
/*                                                                         */
/*  You should have received a copy of the GNU General Public License      */
/*  along with this program; if not, write to the Free Software            */
/*  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.              */

#if (defined(WITH_GPG) || defined(WITH_PGP))

#ifndef SH_GPG_H
#define SH_GPG_H

#define SIG_CONF 1
#define SIG_DATA 2

/* Top level function to verify file.
 */
SL_TICKET sh_gpg_extract_signed(SL_TICKET fd);

/* this function exits if configuration file
 * and/or database cannot be verified; otherwise returns 0
 */
int sh_gpg_check_sign (long file, int what);

/* log successful startup
 */
void sh_gpg_log_startup (void);

#endif

/* #ifdef WITH_GPG */
#endif














