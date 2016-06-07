/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 1999, 2000 Rainer Wichmann                                */
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

#include "config_xor.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <unistd.h>


#ifdef SH_WITH_SERVER


#include "samhain.h"
#include "sh_xfer.h"
#include "sh_error.h"
#include "sh_unix.h"
#include "sh_utils.h"
#include "sh_html.h"

#undef  FIL__
#define FIL__  _("sh_html.c")


s_stat  server_status;



static 
char * replace_stat (char * line)
{
  st_format rep_serv_tab[] = {
    { 'T', S_FMT_TIME,  0, 0, NULL},
    { 'S', S_FMT_TIME,  0, 0, NULL},
    { 'L', S_FMT_TIME,  0, 0, NULL},
    { 'O', S_FMT_ULONG, 0, 0, NULL},
    { 'A', S_FMT_ULONG, 0, 0, NULL},
    { 'M', S_FMT_ULONG, 0, 0, NULL},
    {'\0', S_FMT_ULONG, 0, 0, NULL},
  };

  rep_serv_tab[0].data_ulong = (unsigned long) time(NULL);
  rep_serv_tab[1].data_ulong = server_status.start;
  rep_serv_tab[2].data_ulong = server_status.last;
  rep_serv_tab[3].data_ulong = server_status.conn_open;
  rep_serv_tab[4].data_ulong = server_status.conn_total;
  rep_serv_tab[5].data_ulong = server_status.conn_max;

  return (sh_util_formatted(line, rep_serv_tab));
}


static
int sh_html_head(SL_TICKET ticket)
{
  long      status = SL_ENONE;
  SL_TICKET fd = (-1);
  char      line[512];
  char      endhead[512];
  char      outline[1024];
  char      ts1[81];
  char      ts2[81];
  time_t    now;
  struct tm   * time_ptr;
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
  struct tm    time_tm;
#endif

  char    * formatted;
  char    * qstr;

  char * p;

  SL_ENTER(_("sh_html_head"));

  p = sh_util_strconcat(DEFAULT_DATAROOT, _("/head.html"), NULL);

  if (p)
    {
      fd = sl_open_read (FIL__, __LINE__, p, SL_YESPRIV);
      SH_FREE(p);
    }

  if (!SL_ISERROR(fd))
    {
      while (!SL_ISERROR(status) && sh_unix_getline (fd, line, sizeof(line)) > 0) 
	{
	  formatted = replace_stat (line);
	  if (formatted)
	    {
	      status = sl_write_line (ticket, formatted, sl_strlen(formatted));
	      SH_FREE(formatted);
	    }
	}
      sl_close(fd);
    }
  else
    {
      qstr = sh_util_basename(DEFAULT_HTML_FILE);
      if (qstr != NULL)
	{
	  sl_snprintf(endhead, 511,
		      _("<meta http-equiv=%crefresh%c content=%c120; URL=./%s%c></HEAD><BODY>"),
		      34, 34, 34, qstr, 34);
	  SH_FREE(qstr);
	}
      else
	{
	  sl_snprintf(endhead, 511, _("</HEAD><BODY>"));
	}

      status = 
	sl_write_line (ticket, 
		       _("<HTML><HEAD><TITLE>Report</TITLE>"), 
		       sizeof("<HTML><HEAD><TITLE>Report</TITLE>")-1); 
      if (!SL_ISERROR(status))
	status = 
	  sl_write_line (ticket, endhead, strlen(endhead));
      if (!SL_ISERROR(status))
	status = 
	  sl_write_line (ticket, 
			 _("<H1>Samhain Server Report</H1>"), 
			 sizeof("<H1>Samhain Server Report</H1>")-1);
      if (!SL_ISERROR(status))
	{
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
	  time_ptr   = localtime_r (&(server_status.start), &time_tm);
#else
	  time_ptr   = localtime (&(server_status.start));
#endif
	  if (time_ptr != NULL) 
	    strftime (ts1, 80, _("%d-%m-%Y %H:%M:%S"), time_ptr);
	  else
	    sl_strlcpy(ts1, _("01-01-1970 00:00:00"), sizeof(ts1));
	  now = time(NULL);
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
	  time_ptr   = localtime_r (&now, &time_tm);
#else
	  time_ptr   = localtime (&now);
#endif
	  if (time_ptr != NULL) 
	    strftime (ts2, 80, _("%d-%m-%Y %H:%M:%S"), time_ptr);
	  else
	    sl_strlcpy(ts2, _("01-01-1970 00:00:00"), sizeof(ts2));

	  sl_snprintf(outline, 1023, 
		      _("<p>Time:<BR>Now: %s<BR>Start: %s</p>"), 
		      ts2, ts1);
	  status = 
	    sl_write_line (ticket, outline, sl_strlen(outline));
	}
      if (!SL_ISERROR(status))
	{
	  sl_snprintf(outline, 1023, 
		      _("<p>Connections (max. %d simultaneous):"\
			"<BR>Now: %d<BR>Total: %ld</p>"),
		      server_status.conn_max,
		      server_status.conn_open,
		      server_status.conn_total);
	  status = 
	    sl_write_line (ticket, outline, sl_strlen(outline));
	  if (server_status.last > (time_t) 0)
	    {
#if defined(HAVE_PTHREAD) && defined (_POSIX_THREAD_SAFE_FUNCTIONS) && defined(HAVE_LOCALTIME_R)
	      time_ptr   = localtime_r (&(server_status.last), &time_tm);
#else
	      time_ptr   = localtime (&(server_status.last));
#endif
	      if (time_ptr != NULL) 
		strftime (ts1, 80, _("%d-%m-%Y %H:%M:%S"), time_ptr);
	      else
		sl_strlcpy(ts1, _("01-01-1970 00:00:00"), sizeof(ts1));
	      sl_snprintf(outline, 1023, 
			  _("<p>Last connection at %s</p>"), 
			  ts1);
	      status = 
		sl_write_line (ticket, outline, sl_strlen(outline));
	    }
	}
      if (!SL_ISERROR(status))
	status = 
	  sl_write_line (ticket, 
			 _("<center><table cellpadding=5 cellspacing=2 border=2>"),
			 sizeof("<center><table cellpadding=5 cellspacing=2 border=2>")-1);
    }

  if (SL_ISERROR(status))
    SL_RETURN((-1), _("sh_html_head"));

  SL_RETURN((0), _("sh_html_head"));
}

static
int sh_html_foot(SL_TICKET ticket)
{
  long      status = SL_ENONE;
  SL_TICKET fd = (-1);
  char      line[512];
  char * p;

  SL_ENTER(_("sh_html_foot"));

  p = sh_util_strconcat(DEFAULT_DATAROOT, _("/foot.html"), NULL);

  if (p)
    {
      fd = sl_open_read (FIL__, __LINE__, p, SL_YESPRIV);
      SH_FREE(p);
    }

  if (!SL_ISERROR(fd))
    {
      while (!SL_ISERROR(status) && sh_unix_getline (fd, line, sizeof(line)) > 0) 
	{
	  status = sl_write_line (ticket, line, sl_strlen(line));
	}
      sl_close(fd);
    }
  else
    {
      status =   sl_write_line (ticket, _("</table></center></BODY></HTML>"),
				sizeof("</table></center></BODY></HTML>")-1);
    }
  if (SL_ISERROR(status))
    SL_RETURN((-1), _("sh_html_foot"));

  SL_RETURN((0), _("sh_html_foot"));
}


static 
char * replace_tab (const char * line, char * host, char * status, 
		    char * timestamp)
{
  st_format rep_serv_tab[] = {
    { 'H', S_FMT_STRING,  0, 0, NULL},
    { 'S', S_FMT_STRING,  0, 0, NULL},
    { 'T', S_FMT_STRING,  0, 0, NULL},
    {'\0', S_FMT_ULONG,   0, 0, NULL},
  };
  char * p;

  SL_ENTER(_("replace_tab"));

  rep_serv_tab[0].data_str = host;
  rep_serv_tab[1].data_str = status;
  rep_serv_tab[2].data_str = timestamp;

  p = sh_util_formatted(line, rep_serv_tab);
  SL_RETURN(p, _("replace_tab"));
}

static char * entry_orig = NULL;
static size_t entry_size = 0;

static
int sh_html_get_entry (void)
{
  long      retval = SL_ENONE;
  SL_TICKET fd = (-1);
  char      line[512];
  size_t    line_size;
  size_t    add_size = 0;
  char *    p;

  SL_ENTER(_("sh_html_get_entry"));

  p = sh_util_strconcat(DEFAULT_DATAROOT, _("/entry.html"), NULL);

  entry_size = 0;
  if (entry_orig != NULL)
    {
      free (entry_orig);
      entry_orig = NULL;
      entry_size = 0;
    }

  if (p)
    {
      fd = sl_open_read (FIL__, __LINE__, p, SL_YESPRIV);
      SH_FREE(p);
    }
  if (!SL_ISERROR(fd))
    {
      while (!SL_ISERROR(retval) && sh_unix_getline (fd, line, sizeof(line)) > 0) 
	{
	  line_size = sl_strlen(line);
	  add_size  = 0;
	  if (entry_orig != NULL)
	    {
	      char * ptr = realloc(entry_orig,           /* free() ok     */
				   entry_size + line_size + 1);
	      if (ptr) {
		entry_orig = ptr;
		add_size = line_size; 
	      } else {
		{ free(entry_orig); entry_orig = NULL; }
	      }
	    }
	  else
	    {
	      entry_orig = calloc(1, line_size + 1);        /* free() ok     */
	      if (entry_orig) { entry_orig[0] = '\0'; add_size = line_size; }
	    }
	  if (!entry_orig)
	    {
	      entry_size = 0;
	      /* add_size   = 0; *//* never read */
	      SL_RETURN( 0, _("sh_html_get_entry"));
	    }

	  sl_strlcat(&entry_orig[entry_size], line, line_size + 1);
	  entry_size += add_size;
	  SH_VALIDATE_EQ(entry_orig[entry_size], '\0');
	}
      sl_close(fd);
    }
  SL_RETURN( entry_size, _("sh_html_get_entry"));
}

static
int sh_html_entry (SL_TICKET ticket, 
		   char * host, char * status, char * timestamp, int flag)
{
  char      outline[1024];
  long      retval = SL_ENONE;

  char    * formatted;

  SL_ENTER(_("sh_html_entry"));

  if (entry_size > 0 && entry_orig != NULL)
    {
      formatted = replace_tab(entry_orig, host, status, timestamp);
      if (formatted)
	{
	  retval = sl_write_line (ticket, formatted, sl_strlen(formatted));
	  SH_FREE(formatted);
	}
    }
  else
    {
      sl_snprintf(outline, 1023, 
		  _("<tr><td>%s</td><td>%s</td><td>%s</td></tr>"),
		  host, status, timestamp);
      retval =  sl_write_line (ticket, outline, sl_strlen(outline));
    }

  /* write a status line
   */
  if ((flag == 1) && (!SL_ISERROR(retval)))
    {
      sl_snprintf(outline, 1023, 
		  _("<!-- \n[STATUS:] %s %s %s\n -->"),
		  host, status, timestamp);
      retval =  sl_write_line (ticket, outline, sl_strlen(outline));
    }

  if (SL_ISERROR(retval))
    SL_RETURN((-1), _("sh_html_entry"));

  SL_RETURN((0), _("sh_html_entry"));
}

typedef struct _sort_arr {
  char msg[TIM_MAX];
  char tim[TIM_MAX];
} sort_arr;

static sort_arr sort_stat[CLT_MAX]; 

static
int comp_arr (const void * ao, const void * bo)
{
  const sort_arr * a;
  const sort_arr * b;

  if (ao == NULL && bo == NULL)
    return 0;
  else if (ao == NULL && bo != NULL)
    return (-1);
  else if (ao != NULL && bo == NULL)
    return (1);

  a = (const sort_arr *) ao;
  b = (const sort_arr *) bo;

  return ((-1) * sl_strcmp(a->tim, b->tim));
}

static
int sh_html_print_one (SL_TICKET ticket, client_t   * top)
{
  int status;
  int clt_status;
  unsigned int i, n;

  SL_ENTER(_("sh_html_print_one"));

  if (top == NULL)
    SL_RETURN((0), _("sh_html_print_one"));

  clt_status = top->status_now;
  status = sh_html_entry (ticket, 
			  top->hostname, 
			  _(clt_stat[clt_status]), 
			  top->timestamp[clt_status], 
			  1);

  n = 0;

  if (clt_status != CLT_INACTIVE)
    {
      for (i = 1; i < CLT_MAX; ++i)
	{
	  if (top->status_arr[i] != CLT_INACTIVE)
	    {
	      clt_status = top->status_arr[i];
	      sl_strlcpy(sort_stat[n].msg, _(clt_stat[clt_status]),  TIM_MAX);
	      sl_strlcpy(sort_stat[n].tim, top->timestamp[clt_status],TIM_MAX);
	      ++n;
	    }
	}
    }

  if (n > 0)
    {
      qsort(&(sort_stat[0]), n, sizeof(sort_arr), comp_arr);
	  
      for (i = 1; i < n; ++i)
	{
	  status = sh_html_entry (ticket, 
				  " ", 
				  sort_stat[i].msg,
				  sort_stat[i].tim,
				  0);
	}
    }

  if (SL_ISERROR(status))
    SL_RETURN((-1), _("sh_html_print_one"));

  SL_RETURN((0), _("sh_html_print_one"));
}

#include "zAVLTree.h"

int sh_html_write(void  * inptr)
{
  long fd;
  zAVLCursor avlcursor;
  client_t * item;
  zAVLTree * top = (zAVLTree *) inptr;

  SL_ENTER(_("sh_html_write"));

  if (0 != (fd = tf_trust_check (DEFAULT_HTML_FILE, SL_YESPRIV)))
    {
      sh_error_handle((-1), FIL__, __LINE__, fd, MSG_E_TRUST,
		      (long) sh.effective.uid,
		      DEFAULT_HTML_FILE);
      SL_RETURN((-1), _("sh_html_write"));
    } 


  fd = sl_open_write_trunc (FIL__, __LINE__, DEFAULT_HTML_FILE, SL_YESPRIV);

  if (SL_ISERROR(fd))
    {
      sh_error_handle((-1), FIL__, __LINE__, fd, MSG_E_ACCESS,
		      (long) sh.effective.uid,
		      DEFAULT_HTML_FILE);
      SL_RETURN((-1), _("sh_html_write"));
    } 

  sh_html_get_entry();

  sh_html_head(fd);
  for (item = (client_t *) zAVLFirst(&avlcursor, top); item;
       item = (client_t *) zAVLNext(&avlcursor))
    sh_html_print_one (fd, item);
  sh_html_foot(fd);
  sl_close(fd);

  SL_RETURN((0), _("sh_html_write"));
}

int sh_html_zero()
{
  long fd;

  SL_ENTER(_("sh_html_zero"));

  if (0 != (fd = tf_trust_check (DEFAULT_HTML_FILE, SL_YESPRIV)))
    {
      SL_RETURN((-1), _("sh_html_zero"));
    }

  fd = sl_open_write_trunc (FIL__, __LINE__, DEFAULT_HTML_FILE, SL_YESPRIV);

  if (SL_ISERROR(fd))
    {
     SL_RETURN((-1), _("sh_html_zero"));
    }

  sh_html_head(fd);
  sh_html_foot(fd);

  sl_close(fd);

  SL_RETURN((0), _("sh_html_zero"));
}

/* SH_WITH_SERVER */
#endif















