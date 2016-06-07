/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2015 Rainer Wichmann                                */
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

#ifndef SH_XFER_H
#define SH_XFER_H

#ifndef SH_STANDALONE
int sh_xfer_set_strip (const char * str);
#endif

/* generate a random password
 */
int sh_xfer_create_password (const char * dummy);

/* set timeout for active client connections
 */
int sh_xfer_set_timeout (const char * c);

/* set time limit after which client is reported dead 
 */
int sh_xfer_set_time_limit(const char * str);

/* error level for lookup failure
 */
int sh_xfer_lookup_level (const char * c);

/* create client entry for given password
 */
int sh_xfer_make_client (const char * str);

/* set port to which we connect
 */
int sh_xfer_server_port (const char * str);

#ifdef SH_WITH_SERVER

#ifdef INET_SYSLOG
int set_syslog_active(const char * c);
#endif

/* create socket and start listening
 */
void create_server_tcp_socket (void);

/* whether to use client address as known to the communication layer
 * and set by accept()
 */
int set_socket_peer (const char * c);

/* whether to use client severity
 */
int sh_xfer_use_clt_sev (const char * c);

/* whether to use client class
 */
int sh_xfer_use_clt_class (const char * c);

/* server port
 */
int sh_xfer_set_port(const char * c);

/* server interface
 */
int sh_xfer_set_interface(const char * c);

/* a wrapper function
 */
void sh_xfer_html_write(void);

/* register a client
 */
int sh_xfer_register_client (const char * str);

/* start server
 */
void sh_xfer_start_server(void);

/* free() everything
 */
void sh_xfer_free_all (void);

#endif

#if defined(SH_WITH_CLIENT) || defined(SH_WITH_SERVER)
/* talk to server
 */
long  sh_xfer_report (char * errmsg);

/* set log server
 */
int sh_xfer_set_logserver (const char * address);
void reset_count_dev_server(void);
#endif

#ifdef SH_WITH_CLIENT

/* Throttle file download
 */
int sh_xfer_set_throttle_delay (const char * c);

/* request file from server. file may be "CONF" or "DATA" or a UUID.
 */
long sh_xfer_request_file (const char * file);

#endif

#endif

