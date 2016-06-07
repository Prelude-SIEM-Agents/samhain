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

#ifndef SH_MAIL_H
#define SH_MAIL_H

#define MAIL_IMMEDIATE 1
#define MAIL_LATER     0

/* set a relay server
 */
int sh_mail_set_relay (const char * str_s);

/* send to all recpts. in one mail
 */
int sh_mail_setFlag (const char * str);

/* set the subject string 
 */
int set_mail_subject (const char * str);

/* test mailbox
 */
int sh_mail_sigverify (const char * s);

/* maximum number of mail attempts
 */
#define SH_MAX_FAIL    48

int sh_mail_setNum (const char * str);

int sh_mail_setaddress (const char * address);
void reset_count_dev_mail(void);
int sh_mail_setaddress_int (const char * address);

/* call if not urgent
 */
int sh_mail_pushstack (int severity, const char * msg, const char * alias);

/* Set the port to use (default 25)
 */
int sh_mail_set_port (const char * str);

/* set sender of mail
 */
int sh_mail_set_sender (const char *str);

#endif
