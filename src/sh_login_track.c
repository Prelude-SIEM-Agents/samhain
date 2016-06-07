/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2010 Rainer Wichmann                                      */
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

#undef  FIL__
#define FIL__  _("sh_login_track.c")

#if defined(SH_USE_UTMP) && (defined(SH_WITH_CLIENT) || defined (SH_STANDALONE)) 

#include <string.h>

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_unix.h"
#include "sh_string.h"
#include "sh_tools.h"
#include "sh_ipvx.h"
#include "sh_error_min.h"

#ifdef HAVE_UTMPX_H

#include <utmpx.h>
#define SH_UTMP_S utmpx
#undef  ut_name
#define ut_name ut_user
#ifdef HAVE_UTXTIME
#undef  ut_time
#define ut_time        ut_xtime
#else
#undef  ut_time
#define ut_time        ut_tv.tv_sec
#endif

#else

#include <utmp.h>
#define SH_UTMP_S utmp

#endif


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


#define SH_LTRACK_VERSION 1

#define SH_LTRACK_USIZE  32
#define SH_LTRACK_HSIZE 256
/* One hour    (15 deg)  */
#define SH_LTRACK_HTRES  24
/* Ten minutes (2.5 deg) */
#define SH_LTRACK_GTRES 144

/* Avoid compiling against lmath by including result tables for sin, cos
 */
const double sintab_htres[SH_LTRACK_HTRES] = {
 0.13052619222005157340,  0.38268343236508978178,  0.60876142900872065589,  0.79335334029123516508,  0.92387953251128673848,  0.99144486137381038215, 
 0.99144486137381038215,  0.92387953251128673848,  0.79335334029123516508,  0.60876142900872087793,  0.38268343236508989280,  0.13052619222005157340, 
-0.13052619222005132360, -0.38268343236508967076, -0.60876142900872065589, -0.79335334029123494304, -0.92387953251128651644, -0.99144486137381038215, 
-0.99144486137381049318, -0.92387953251128662746, -0.79335334029123516508, -0.60876142900872087793, -0.38268343236509039240, -0.13052619222005168442, 
};
const double costab_htres[SH_LTRACK_HTRES] = {
 0.99144486137381038215,  0.92387953251128673848,  0.79335334029123516508,  0.60876142900872065589,  0.38268343236508983729,  0.13052619222005171218, 
-0.13052619222005160116, -0.38268343236508972627, -0.60876142900872065589, -0.79335334029123505406, -0.92387953251128673848, -0.99144486137381038215, 
-0.99144486137381049318, -0.92387953251128684951, -0.79335334029123516508, -0.60876142900872087793, -0.38268343236509033689, -0.13052619222005162891, 
 0.13052619222005126809,  0.38268343236509000382,  0.60876142900872054486,  0.79335334029123494304,  0.92387953251128651644,  0.99144486137381038215, 
};
const double sintab_gtres[SH_LTRACK_GTRES] = {
 0.02181488503456112046,  0.06540312923014306168,  0.10886687485196457070,  0.15212338618991669281,  0.19509032201612824808,  0.23768589232617309825, 
 0.27982901403099208482,  0.32143946530316158672,  0.36243803828370163567,  0.40274668985873718352,  0.44228869021900124592,  0.48098876891938763256, 
 0.51877325816052144436,  0.55557023301960217765,  0.59130964836358235193,  0.62592347218405908205,  0.65934581510006884386,  0.69151305578226940352, 
 0.72236396205975550444,  0.75183980747897738439,  0.77988448309288171956,  0.80644460426748254545,  0.83146961230254523567,  0.85491187067294649449, 
 0.87672675570750768781,  0.89687274153268836674,  0.91531147911944710227,  0.93200786928279844012,  0.94693012949510557696,  0.96004985438592871372, 
 0.97134206981326143282,  0.98078528040323043058,  0.98836151046776066220,  0.99405633822231964647,  0.99785892323860347908,  0.99976202707990913243, 
 0.99976202707990913243,  0.99785892323860347908,  0.99405633822231964647,  0.98836151046776066220,  0.98078528040323043058,  0.97134206981326143282, 
 0.96004985438592871372,  0.94693012949510568799,  0.93200786928279855115,  0.91531147911944721329,  0.89687274153268836674,  0.87672675570750779883, 
 0.85491187067294671653,  0.83146961230254545772,  0.80644460426748254545,  0.77988448309288183058,  0.75183980747897738439,  0.72236396205975561546, 
 0.69151305578226951454,  0.65934581510006895488,  0.62592347218405919307,  0.59130964836358257397,  0.55557023301960217765,  0.51877325816052133334, 
 0.48098876891938763256,  0.44228869021900130143,  0.40274668985873729454,  0.36243803828370174669,  0.32143946530316175325,  0.27982901403099230686, 
 0.23768589232617337581,  0.19509032201612860891,  0.15212338618991663730,  0.10886687485196457070,  0.06540312923014311719,  0.02181488503456121761, 
-0.02181488503456097475, -0.06540312923014286739, -0.10886687485196432090, -0.15212338618991641526, -0.19509032201612835911, -0.23768589232617312601, 
-0.27982901403099202930, -0.32143946530316153121, -0.36243803828370152464, -0.40274668985873707250, -0.44228869021900107938, -0.48098876891938741052, 
-0.51877325816052122232, -0.55557023301960195560, -0.59130964836358235193, -0.62592347218405908205, -0.65934581510006884386, -0.69151305578226929249, 
-0.72236396205975550444, -0.75183980747897727337, -0.77988448309288194160, -0.80644460426748265647, -0.83146961230254523567, -0.85491187067294660551, 
-0.87672675570750768781, -0.89687274153268825572, -0.91531147911944710227, -0.93200786928279844012, -0.94693012949510557696, -0.96004985438592860270, 
-0.97134206981326132180, -0.98078528040323031956, -0.98836151046776066220, -0.99405633822231953545, -0.99785892323860347908, -0.99976202707990913243, 
-0.99976202707990913243, -0.99785892323860347908, -0.99405633822231964647, -0.98836151046776066220, -0.98078528040323043058, -0.97134206981326143282, 
-0.96004985438592871372, -0.94693012949510568799, -0.93200786928279855115, -0.91531147911944721329, -0.89687274153268847776, -0.87672675570750790985, 
-0.85491187067294682755, -0.83146961230254545772, -0.80644460426748287851, -0.77988448309288216365, -0.75183980747897782848, -0.72236396205975605955, 
-0.69151305578226918147, -0.65934581510006873284, -0.62592347218405897102, -0.59130964836358235193, -0.55557023301960217765, -0.51877325816052144436, 
-0.48098876891938774358, -0.44228869021900141245, -0.40274668985873740557, -0.36243803828370185771, -0.32143946530316186427, -0.27982901403099241788, 
-0.23768589232617348683, -0.19509032201612871993, -0.15212338618991719241, -0.10886687485196513969, -0.06540312923014367230, -0.02181488503456178660
};
const double costab_gtres[SH_LTRACK_GTRES] = {
 0.99976202707990913243,  0.99785892323860347908,  0.99405633822231964647,  0.98836151046776066220,  0.98078528040323043058,  0.97134206981326143282, 
 0.96004985438592871372,  0.94693012949510568799,  0.93200786928279855115,  0.91531147911944721329,  0.89687274153268836674,  0.87672675570750768781, 
 0.85491187067294660551,  0.83146961230254523567,  0.80644460426748265647,  0.77988448309288183058,  0.75183980747897738439,  0.72236396205975561546, 
 0.69151305578226940352,  0.65934581510006884386,  0.62592347218405908205,  0.59130964836358235193,  0.55557023301960228867,  0.51877325816052155538, 
 0.48098876891938774358,  0.44228869021900124592,  0.40274668985873723903,  0.36243803828370169118,  0.32143946530316169774,  0.27982901403099202930, 
 0.23768589232617309825,  0.19509032201612833135,  0.15212338618991680383,  0.10886687485196473724,  0.06540312923014304780,  0.02181488503456115863, 
-0.02181488503456103373, -0.06540312923014292290, -0.10886687485196461234, -0.15212338618991669281, -0.19509032201612819257, -0.23768589232617298723, 
-0.27982901403099191828, -0.32143946530316158672, -0.36243803828370158016, -0.40274668985873712801, -0.44228869021900113490, -0.48098876891938746603, 
-0.51877325816052122232, -0.55557023301960195560, -0.59130964836358246295, -0.62592347218405908205, -0.65934581510006884386, -0.69151305578226929249, 
-0.72236396205975550444, -0.75183980747897727337, -0.77988448309288160853, -0.80644460426748243442, -0.83146961230254534669, -0.85491187067294660551, 
-0.87672675570750768781, -0.89687274153268825572, -0.91531147911944710227, -0.93200786928279844012, -0.94693012949510557696, -0.96004985438592860270, 
-0.97134206981326132180, -0.98078528040323043058, -0.98836151046776066220, -0.99405633822231964647, -0.99785892323860347908, -0.99976202707990913243, 
-0.99976202707990913243, -0.99785892323860347908, -0.99405633822231964647, -0.98836151046776077322, -0.98078528040323043058, -0.97134206981326143282, 
-0.96004985438592871372, -0.94693012949510568799, -0.93200786928279855115, -0.91531147911944721329, -0.89687274153268836674, -0.87672675570750779883, 
-0.85491187067294671653, -0.83146961230254545772, -0.80644460426748254545, -0.77988448309288183058, -0.75183980747897749541, -0.72236396205975561546, 
-0.69151305578226951454, -0.65934581510006906591, -0.62592347218405897102, -0.59130964836358224090, -0.55557023301960217765, -0.51877325816052144436, 
-0.48098876891938768807, -0.44228869021900135694, -0.40274668985873735005, -0.36243803828370180220, -0.32143946530316180876, -0.27982901403099236237, 
-0.23768589232617343132, -0.19509032201612866442, -0.15212338618991713690, -0.10886687485196507030, -0.06540312923014361679, -0.02181488503456172415, 
 0.02181488503456135639,  0.06540312923014325597,  0.10886687485196470948,  0.15212338618991677608,  0.19509032201612830359,  0.23768589232617307050, 
 0.27982901403099197379,  0.32143946530316147570,  0.36243803828370146913,  0.40274668985873701699,  0.44228869021900102387,  0.48098876891938735501, 
 0.51877325816052111129,  0.55557023301960184458,  0.59130964836358201886,  0.62592347218405863796,  0.65934581510006839977,  0.69151305578226895943, 
 0.72236396205975572649,  0.75183980747897749541,  0.77988448309288183058,  0.80644460426748254545,  0.83146961230254523567,  0.85491187067294660551, 
 0.87672675570750768781,  0.89687274153268825572,  0.91531147911944710227,  0.93200786928279844012,  0.94693012949510557696,  0.96004985438592860270, 
 0.97134206981326132180,  0.98078528040323031956,  0.98836151046776066220,  0.99405633822231953545,  0.99785892323860347908,  0.99976202707990913243
};

struct sh_track_entry_data {
  UINT64      last_login;
  UINT32      array[SH_LTRACK_HTRES]; /* 1 h resolution */
  char        hostname[SH_LTRACK_HSIZE];
};

struct sh_track_entry {
  struct sh_track_entry_data data;
  struct sh_track_entry * next;
};

struct sh_track_head {
  UINT32 version;
  UINT32 n_entries;
  UINT64 last_login;
  char   hostname[SH_LTRACK_HSIZE];
  UINT32 array[SH_LTRACK_GTRES]; /* 10 min resolution */
};

struct sh_track {
  struct sh_track_head head;
  struct sh_track_entry * list;
};


/* Returns zero/nonzero
 */
static int get_bool(char *bitarray, unsigned int index)
{
  int bool;

  bitarray += index / 8; /* skip to char */
  bool = (*bitarray & (1 << (index % 8)));

  return bool;
}

static void set_bool(char *bitarray, unsigned int index, int bool)
{
  bitarray += index / 8; /* skip to char */
  if (bool)
    *bitarray |= 1 << (index % 8);
  else    
    *bitarray &= ~(1 << (index % 8));
  return;
}


static char * build_path (const char * user)
{
  char * ui;

  if (0 != sh_util_base64_enc_alloc (&ui, user, sl_strlen(user)))
    {
      char * path = sh_util_strconcat(DEFAULT_DATAROOT, "/", ui, NULL);

      SH_FREE(ui);
      return path;
    }
  return NULL;
}

static void destroy_loaded(struct sh_track * urecord)
{
  if (urecord)
    {
      struct sh_track_entry * entry = urecord->list;
      struct sh_track_entry * entry_old;

      while(entry)
	{
	  entry_old = entry;
	  entry = entry->next;
	  SH_FREE(entry_old);
	}
      SH_FREE(urecord);
    }
  return;
}

static struct sh_track * load_data_int (char * path)
{
  struct sh_track_head * uhead;
  struct sh_track * urecord;

  urecord = SH_ALLOC(sizeof(struct sh_track));
  memset(urecord, '\0', sizeof(struct sh_track));

  uhead = &(urecord->head);
  uhead->version = SH_LTRACK_VERSION;

  if (path)
    {
      FILE * fp = fopen(path, "rb");
      
      if (fp)
	{
	  size_t n;
	  
	  n = fread(uhead, sizeof(struct sh_track_head), 1, fp);
	  
	  if (n == 1)
	    {
	      struct sh_track_entry_data entry_data;
	      struct sh_track_entry * entry;
	      
	      while (1 == fread(&entry_data, sizeof(entry_data), 1, fp))
		{
		  entry = SH_ALLOC(sizeof(struct sh_track_entry));
		  memcpy(&(entry->data), &entry_data, sizeof(entry_data));
		  entry->next   = urecord->list;
		  urecord->list = entry;
		}
	    }
	  fclose(fp);
	}
    }

  return urecord;
}

static struct sh_track * load_data (const char * user)
{
  char * path = build_path (user);
  struct sh_track * res = load_data_int (path);

  if (path)
    SH_FREE(path);
  return res;
}

static void save_data_int (struct sh_track * urecord, char * path)
{
  mode_t mask;
  FILE * fp;
  
  mask = umask(S_IWGRP | S_IWOTH);
  fp = fopen(path, "wb");
  (void) umask(mask);
  
  if (fp)
    {
      size_t n;
      
      n = fwrite(&(urecord->head), sizeof(struct sh_track_head), 1, fp);
      
      if (n == 1)
	{
	  struct sh_track_entry * entry = urecord->list;
	  
	  while (entry && (n > 0))
	    {
	      n = fwrite(&(entry->data), sizeof(struct sh_track_entry_data), 
			 1, fp);
	      entry = entry->next;
	    }
	}
      fclose(fp);
    }
  return;
}

static void save_data (struct sh_track * urecord, const char * user)
{
  char * path = build_path (user);

  if (path)
    {
      save_data_int (urecord, path);
      SH_FREE(path);
    }
  return;
}

/**************
 *
 * Configurable
 *
 **************/

enum significance { SIG00, SIG01, SIG05 };
enum checklevel   { CHECK_NONE, CHECK_HOST, CHECK_DOMAIN };
enum days         { WORKDAYS = 0, SATURDAY, SUNDAY };
#define LTRACK_NDAYS 3

static int sig_level    = SIG00;
static int check_level  = CHECK_NONE;
static int check_date   = S_FALSE;

/* We use a bit array of SH_LTRACK_GTRES bits for allowed times 
 * (10 min resolution)
 */
#define BITARRSIZ(a) ((a + 7) / 8)

static int global_init  = S_FALSE;
static char global_dates[LTRACK_NDAYS][BITARRSIZ(SH_LTRACK_GTRES)];

struct sh_track_dates {
  char user[SH_LTRACK_USIZE];
  char dates[LTRACK_NDAYS][BITARRSIZ(SH_LTRACK_GTRES)];
  struct sh_track_dates * next;
};
struct sh_track_dates * user_dates = NULL;

static int set_dates (char bitarray[][BITARRSIZ(SH_LTRACK_GTRES)], 
		      unsigned int size, const char * defstr);

void sh_login_reset (void)
{
  int i, j;
  struct sh_track_dates *u_old, *u;

  u          = user_dates;
  user_dates = NULL;

  while(u)
    {
      u_old = u;
      u     = u->next;
      SH_FREE(u_old);
    }

  for (j = 0; j < LTRACK_NDAYS; ++j)
    {
      for (i = 0; i < SH_LTRACK_GTRES; ++i)
	{ 
	  set_bool(global_dates[j], i, 0);
	}
    }
  global_init = S_FALSE;

  sig_level    = SIG00;
  check_level  = CHECK_NONE;
  check_date   = S_FALSE;

  return;
}

int sh_login_set_def_allow(const char * c)
{
  int res = set_dates(global_dates, SH_LTRACK_GTRES, c);

  if (res == 0)
    {
      check_date   = S_TRUE;
      global_init  = S_TRUE;
    }
  return res;
}

static struct sh_track_dates * find_user(const char * user)
{
  struct sh_track_dates * u = user_dates;

  while(u)
    {
      if (0 == strcmp(user, u->user))
	{
	  return u;
	}
      u = u->next;
    }
  return NULL;
}

int sh_login_set_user_allow(const char * c)
{
  unsigned int i = 0;
  const char *p = c;
  char user[SH_LTRACK_USIZE];
  
  struct sh_track_dates * u;

  while (p && *p && *p != ':' && *p != ' ' && *p != '\t')
    {
      user[i] = *p; ++p; ++i;

      if (i == SH_LTRACK_USIZE)
	return -1;
    }

  while (p && *p && (*p == ' ' || *p == '\t')) ++p;

  if (p && *p && (i < SH_LTRACK_USIZE) && (*p == ':'))
    {
      user[i] = '\0';

      ++p; while (*p && (*p == ' ' || *p == '\t')) ++p;

      if (*p)
	{
	  int res;
	  int flag = 0;

	  u = find_user(user);

	  if (!u)
	    {
	      u = SH_ALLOC(sizeof(struct sh_track_dates));
	      memset(u, '\0', sizeof(struct sh_track_dates));
	      sl_strlcpy(u->user, user, SH_LTRACK_USIZE);
	      flag = 1;
	    }

	  res = set_dates(u->dates, SH_LTRACK_GTRES, p);
	  if (res != 0)
	    {
	      if (flag == 1)
		SH_FREE(u);
	      return -1;
	    }

	  if (flag == 1)
	    {
	      u->next    = user_dates;
	      user_dates = u;
	    }

	  check_date = S_TRUE;
	  return 0;
	}
    }
  return -1;
}

int sh_login_set_siglevel(const char * c)
{
  int ret = sh_util_flagval(c, &sig_level);

  if (ret == 0)
    {
      sig_level = (sig_level == S_FALSE) ? SIG00 : SIG01;
      return 0;
    }
  else
    {
      if (0 == strcmp(c, _("paranoid")))
	{
	  sig_level = SIG05;
	  return 0;
	}
    }
  sig_level = SIG00;
  return -1;
}

int sh_login_set_checklevel(const char * c)
{
  int ret = sh_util_flagval(c, &check_level);

  if (ret == 0)
    {
      check_level = (check_level == S_FALSE) ? CHECK_NONE : CHECK_HOST;
      return 0;
    }
  else
    {
      if (0 == strcmp(c, _("domain")))
	{
	  check_level = CHECK_DOMAIN;
	  return 0;
	}
    }
  check_level = CHECK_NONE;
  return -1;
}

static int eval_range(char * bitarray, unsigned int size, char * def)
{
  unsigned int h1, m1, h2, m2;

  int res = sscanf(def, "%d:%d - %d:%d", &h1, &m1, &h2, &m2);

  if (res == 4)
    {
      unsigned int t1 = 3600*h1 + 60*m1;
      unsigned int t2 = 3600*h2 + 60*m2;
      int hres        = (60*60*24)/size;
      unsigned int i;

      if (t1 > t2 || t1 > 86340 || t2 > 86340)
	return -1;

      t1  = t1 / hres;
      t2  = t2 / hres;
      t1  = (t1 < size) ? t1 : (size-1);
      t2  = (t2 < size) ? t2 : (size-1);

      for (i = t1; i <= t2; ++i)
	{
	  set_bool(bitarray, i, 1);
	}
      return 0;
    }
  return -1;
}

static int set_ranges(char * bitarray, unsigned int size, 
		      char ** splits, unsigned int nfields)
{
  unsigned int i;
  int retval = 0;

  for (i = 0; i < nfields; ++i)
    {
      char * range = &(splits[i][0]);

      if (0 != eval_range(bitarray, size, range))
	retval = -1;
    }
  return retval;
}

/* 'always', 'never', workdays(list of ranges), (sun|satur)day(list of ranges)
 */
static int set_dates (char bitarray[][BITARRSIZ(SH_LTRACK_GTRES)], 
		      unsigned int size, 
		      const char * defstr)
{
  unsigned int i, j;
  int retval = -1;

  if (0 == strcmp(_("always"), defstr))
    {
      for (j = 0; j < LTRACK_NDAYS; ++j)
	for (i = 0; i < size; ++i)
	  set_bool(bitarray[j], i, 1);
      retval = 0;
    }
  else if (0 == strcmp(_("never"), defstr))
    {
      for (j = 0; j < LTRACK_NDAYS; ++j)
	for (i = 0; i < size; ++i)
	  set_bool(bitarray[j], i, 0);
      retval = 0;
    }
  else
    {
      unsigned int nfields = 24; /* list of ranges */
      size_t       lengths[24];
      char *       new    = NULL;
      char **      splits = NULL;

      if      (0 == strncmp(_("workdays"), defstr, 7))
	{
	  new    = sh_util_strdup(defstr);
	  splits = split_array_braced(new, _("workdays"), 
				      &nfields, lengths);
	  j = WORKDAYS;
	}
      else if (0 == strncmp(_("saturday"), defstr, 8))
	{
	  new    = sh_util_strdup(defstr);
	  splits = split_array_braced(new, _("saturday"), 
				      &nfields, lengths);
	  j = SATURDAY;
	}
      else if (0 == strncmp(_("sunday"), defstr, 6))
	{
	  new    = sh_util_strdup(defstr);
	  splits = split_array_braced(new, _("sunday"), 
				      &nfields, lengths);
	  j = SUNDAY;
	}
      else
	{
	  return -1;
	}

      if (new && splits && nfields > 0)
	{
	  retval = set_ranges(bitarray[j], size, splits, nfields);
	}

      if (new) SH_FREE(new);
    }
  return retval;
}



/**************
 *
 * Report
 *
 **************/

void report_generic(char * file, int line, 
		    const char * user, time_t time, const char * host, int what)
{
  char   ttt[TIM_MAX];

  SH_MUTEX_LOCK(mutex_thread_nolog);
  (void) sh_unix_time (time, ttt, TIM_MAX);
  sh_error_handle ((-1), file, line, 0, what,
		   user, host, ttt);
  SH_MUTEX_UNLOCK(mutex_thread_nolog);
  return;
}

void report_bad_date(char * file, int line, 
		     const char *user, time_t time, const char * host)
{
  report_generic(file, line, user, time, host, MSG_UT_BAD);
}

void report_first(char * file, int line, 
		  const char *user, time_t time, const char * host)
{
  report_generic(file, line, user, time, host, MSG_UT_FIRST);
}

void report_outlier(char * file, int line, 
		    const char *user, time_t time, const char * host)
{
  report_generic(file, line, user, time, host, MSG_UT_OUTLIER);
}

/**************
 *
 * Dates
 *
 **************/

static int check_login_date(const char * user, unsigned int index, int wday)
{
  unsigned int i, j;
  struct sh_track_dates * allowed = NULL;
  int day;

  /* Use an intermediate array 'char* b[m]' to cast 'char a[m][n]' to 'char** c' */
  char * aux[LTRACK_NDAYS];
  char **good = (char **) aux;

  for (i = 0; i < LTRACK_NDAYS; ++i)
    {
      aux[i] = (char *) &global_dates[i][0];
      /* + i * BITARRSIZ(SH_LTRACK_GTRES); */
    }

  if (wday > 0 && wday < 6)
    day = WORKDAYS;
  else if (wday == 6)
    day = SATURDAY;
  else
    day = SUNDAY;

  if (check_date != S_FALSE)
    {
      if (S_FALSE == global_init)
	{
	  for (j = 0; j < LTRACK_NDAYS; ++j)
	    {
	      for (i = 0; i < SH_LTRACK_GTRES; ++i) 
		set_bool(global_dates[j], i, 1);
	    }
	  global_init = S_TRUE;
	}

      if (user) {
	allowed = find_user(user);
      }

      if (allowed)
	{
	  for (i = 0; i < LTRACK_NDAYS; ++i)
	    {
	      aux[i] = (char *)&(allowed->dates)[i][0]; 
	      /* + i*BITARRSIZ(SH_LTRACK_GTRES); */
	    }
	}
      
      if (0 == get_bool(good[day], index))
	{
	  return -1;
	}
    }
  return 0;
} 

/**************
 *
 * Statistics
 *
 **************/

/* Compute sqrt(s) using the babylonian algorithm
 * (to avoid linking with -lm).
 */ 
static double sh_sqrt(double s)
{
  double eps = 1.0e-6;
  double x0  = 1.0;
  double xs  = s;

  double diff = xs - x0;
  diff = (diff > 0.0) ? diff : -diff;

  while (diff > eps)
    {
      xs = x0;
      x0 = 0.5 * (x0 + (s/x0));
      diff = xs - x0;
      diff = (diff > 0.0) ? diff : -diff;
    }
  return x0;
}

static double M_crit(int n, int flag)
{
#define SH_MCSIZE 10
  const double M_05[SH_MCSIZE] = { 0.975, 0.918, 0.855, 0.794, 0.739, 0.690, 0.647, 0.577, 0.497, 0.406 };
  const double M_01[SH_MCSIZE] = { 0.995, 0.970, 0.934, 0.891, 0.845, 0.799, 0.760, 0.688, 0.603, 0.498 };
  const int    M_nn[SH_MCSIZE] = {     4,     5,     6,     7,     8,     9,    10,    12,    15,    20 };

  if (n > M_nn[SH_MCSIZE-1])
    {
      return ((flag == SIG05) ? M_05[SH_MCSIZE-1] : M_01[SH_MCSIZE-1]);
    }
  else
    {
      unsigned int i;

      for (i = 1; i < SH_MCSIZE; ++i)
	{
	  if (n < M_nn[i])
	    {
	      return ((flag == SIG05) ? M_05[i-1] : M_01[i-1]);
	    }
	}
    }

  return ((flag == SIG05) ? M_05[SH_MCSIZE-1] : M_01[SH_MCSIZE-1]);
}

static int check_statistics (unsigned int index, UINT32 * array, unsigned int size,
			     const double * costab, const double * sintab)
{
  double C = 0.0;
  double S = 0.0;
  double R, Rk, M;

  unsigned int i, n = 0;

  if (sig_level != SIG00)
    {
      for (i = 0; i < size; ++i)
	{
	  n += array[i];
	  C += (array[i] * costab[i]);
	  S += (array[i] * sintab[i]);
	}
      
      if (n > 2) /* current is at least 4th datapoint */
	{
	  R = sh_sqrt(S*S + C*C);
	  
	  C += array[index] * costab[index];
	  S += array[index] * sintab[index];
	  Rk = sh_sqrt(S*S + C*C);
	  ++n;
	  
	  M  = (Rk - R + 1.0)/((double)n - R);
	  
	  if (M > M_crit(n, sig_level))
	    {
	      return -1;
	    }
	}
    }
  return 0;
}

static char * stripped_hostname (const char * host)
{
  char *p, *q;
  
  if (sh_ipvx_is_numeric(host))
    {
      p = sh_util_strdup(host);
      q = strrchr(p, '.');
      if (q) 
	{
	  *q = '\0';
	  q = strrchr(p, '.');
	  if (q)
	    {
	      *q = '\0';
	    }
	}
    }
  else
    {
      q = strchr(host, '.'); 
      if (q && *q)
	{
	  ++q;
	  p = sh_util_strdup(q);
	}
      else
	{
	  p = sh_util_strdup(host);
	}
    }
  return p;
}

static unsigned int time_to_index(struct tm * tp, int nbin)
{
  int hres  = (60*60*24)/nbin;
  int index = tp->tm_hour * 3600 + tp->tm_min * 60 + tp->tm_sec;
  index  = index / hres;
  index  = (index < nbin) ? index : (nbin-1);

  return index;
}

static struct sh_track_entry * check_host(struct sh_track_entry * list, 
					  const char * user, time_t time, const char * host,
					  struct tm * tp)
{
  unsigned int    index = time_to_index(tp, SH_LTRACK_HTRES);
  struct sh_track_entry * entry = list;

  char * p = NULL;
  const char * q;

  if (check_level == CHECK_DOMAIN)
    {
      p = stripped_hostname(host);
      q = p;
    }
  else
    {
      q = host;
    }

  while (entry)
    {
      if (0 == strncmp(q, (entry->data).hostname, SH_LTRACK_HSIZE))
	break;
      entry = entry->next;
    }

  if (entry)
    {
      int isAlert;

      (entry->data).last_login    = time;

      /* Check host statistics here 
       */
      isAlert = check_statistics (index, (entry->data).array, SH_LTRACK_HTRES, 
				  costab_htres, sintab_htres); 

      if (isAlert != 0) 
	{
	  report_outlier(FIL__, __LINE__, user, time, host);
	}

      /* Update array afterwards
       */
      (entry->data).array[index] += 1;
    }
  else
    {
      entry = SH_ALLOC(sizeof(struct sh_track_entry));
      memset(entry, '\0', sizeof(struct sh_track_entry));
      (entry->data).last_login    = time;
      (entry->data).array[index]  = 1;
      sl_strlcpy((entry->data).hostname, q, SH_LTRACK_HSIZE);

      /* Report first login from this host 
       */
      if (check_level != CHECK_NONE) 
	{ 
	  report_first (FIL__, __LINE__, user, time, host);
	}
      
      if (p)
	SH_FREE(p);
      return entry;
    }

  if (p)
    SH_FREE(p);
  return NULL;
}

/********************************************************
 *
 * Public Function
 *
 ********************************************************/

void sh_ltrack_check(struct SH_UTMP_S * ut)
{
  int gres;
  const char * user;
  time_t time;
#if defined(HAVE_UTHOST)
  const char * host;
#else
  const char * host;
#endif
  struct sh_track * urecord;
  time_t last_login;

  /* Just return if we are not supposed to do anything
   */
  if (sig_level == SIG00 && check_level == CHECK_NONE && check_date == S_FALSE)
    return;


#if defined(HAVE_UTHOST)
  host = ut->ut_host;
#else
  host = sh_util_strdup(_("unknown"));
#endif
  time = ut->ut_time;
  user = ut->ut_name;

  gres  = (60*60*24)/SH_LTRACK_GTRES;

  urecord    = load_data(user);
  last_login = (urecord->head).last_login;

  if (   last_login < time &&
	 ( (time - last_login) >= gres || 
	   0 != strcmp(host, (urecord->head).hostname)
	   )
	 )
    {
      struct tm ts;
      unsigned int  index;
      int isAlert;
      struct sh_track_entry * entry;

      (urecord->head).last_login = time;
      sl_strlcpy((urecord->head).hostname, host, SH_LTRACK_HSIZE);
      (urecord->head).n_entries += 1;

      memcpy(&ts, localtime(&time), sizeof(struct tm));
      index = time_to_index(&ts, SH_LTRACK_GTRES);
      
      /* Check global statistics here 
       */
      isAlert = check_statistics (index, (urecord->head).array, 
				  SH_LTRACK_GTRES, 
				  costab_gtres, sintab_gtres);
      
      if (isAlert != 0) 
	{
	  report_outlier(FIL__, __LINE__, user, time, host);
	}
      

      if (check_date != S_FALSE)
	{
	  int isBad = check_login_date(user, index, ts.tm_wday);

	  if (isBad != 0)
	    {
	      report_bad_date(FIL__, __LINE__, user, time, host);
	    }
	}

      /* Update array afterwards 
       */
      (urecord->head).array[index] += 1;

      entry = check_host(urecord->list, user, time, host, &ts);
      if (entry)
	{
	  entry->next   = urecord->list;
	  urecord->list = entry;
	}

      save_data(urecord, user);
    } 

  destroy_loaded(urecord);

#if !defined(HAVE_UTHOST)
  SH_FREE(host);
#endif
  return;
}

#ifdef SH_CUTEST
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "CuTest.h"

void Test_login (CuTest *tc) {
  char bitarr[10] = { 0,0,0,0,0,0,0,0,0,128 };
  unsigned int i;
  int j, k;
  char buf[1024];
  char *p, *q;
  size_t l1, l2;

  /* Check bitarray */

  for (i = 0; i < 72; ++i)
    {
      set_bool(bitarr, i, 1);
    }
  for (i = 72; i < 80; ++i)
    {
      set_bool(bitarr, i, 0);
    }
  for (i = 0; i < 80; ++i)
    {
      j = get_bool(bitarr, i);
      if (i < 72)
	CuAssertTrue(tc, j > 0);
      else
	CuAssertIntEquals(tc, 0, j);
    }

  /* check build_path */

  j = sl_strlcpy(buf, DEFAULT_DATAROOT, sizeof(buf));
  CuAssertIntEquals(tc, 0, j);

  p = build_path("rainer");
  q = sh_util_dirname(p);
  j = strncmp(buf, q, strlen(buf));
  l1 = strlen(buf); l2 = strlen(q);
  CuAssertTrue(tc, l2 >= l1);
  CuAssertIntEquals(tc, 0, j);

  q = sh_util_basename(p);
  CuAssertStrEquals(tc, q, "cmFpbmVy");

  { /* Check load/save of user data */
    struct sh_track urecord, *precord;
    struct sh_track_entry uentry0, *pentry;
    struct sh_track_entry uentry1;

    urecord.head.version   = 40;
    urecord.head.n_entries = 41;
    urecord.head.last_login = 42;
    for (i = 0; i < SH_LTRACK_GTRES; ++i)
      urecord.head.array[i] = 0;
    urecord.head.array[30] = 30;

    urecord.list = &uentry0;
    uentry0.next = &uentry1;
    uentry1.next = NULL;

    uentry0.data.last_login = 52;
    strcpy(uentry0.data.hostname, "host0");
    for (i = 0; i < SH_LTRACK_HTRES; ++i)
      uentry0.data.array[i] = 0;
    uentry0.data.array[5] = 50;

    uentry1.data.last_login = 62;
    strcpy(uentry1.data.hostname, "host1");
    for (i = 0; i < SH_LTRACK_HTRES; ++i)
      uentry1.data.array[i] = 0;
    uentry1.data.array[6] = 60;

    snprintf(buf, sizeof(buf), "cutest_%06d", (int) getpid());

    save_data_int(&urecord, buf);

    precord = load_data_int(buf);

    CuAssertIntEquals(tc, urecord.head.version, (precord->head).version);
    CuAssertIntEquals(tc, urecord.head.n_entries, (precord->head).n_entries);
    CuAssertIntEquals(tc, urecord.head.last_login, (precord->head).last_login);
    for (i = 0; i < SH_LTRACK_GTRES; ++i)
      CuAssertIntEquals(tc, urecord.head.array[i], (precord->head).array[i]);

    CuAssertPtrNotNull(tc, precord->list);
    pentry = precord->list;
    CuAssertIntEquals(tc, uentry1.data.last_login, (pentry->data).last_login);
    CuAssertStrEquals(tc, uentry1.data.hostname, (pentry->data).hostname);
    for (i = 0; i < SH_LTRACK_HTRES; ++i)
      CuAssertIntEquals(tc, uentry1.data.array[i], (pentry->data).array[i]);

    CuAssertPtrNotNull(tc, pentry->next);
    pentry = pentry->next;
    CuAssertIntEquals(tc, uentry0.data.last_login, (pentry->data).last_login);
    CuAssertStrEquals(tc, uentry0.data.hostname, (pentry->data).hostname);
    for (i = 0; i < SH_LTRACK_HTRES; ++i)
      CuAssertIntEquals(tc, uentry0.data.array[i], (pentry->data).array[i]);

    CuAssertPtrEquals(tc, pentry->next, NULL);
    destroy_loaded(precord);
    unlink(buf);

    precord = load_data_int("supacalifragilistic");
    CuAssertPtrNotNull(tc, precord);
    CuAssertPtrEquals(tc, precord->list, NULL);
    CuAssertIntEquals(tc, SH_LTRACK_VERSION, (precord->head).version);
    CuAssertIntEquals(tc, 0, (precord->head).n_entries);
    CuAssertIntEquals(tc, 0, (precord->head).last_login);
    for (i = 0; i < SH_LTRACK_GTRES; ++i)
      CuAssertIntEquals(tc, 0, (precord->head).array[i]);
    destroy_loaded(precord);

    precord = load_data_int(NULL);
    CuAssertPtrNotNull(tc, precord);
    CuAssertPtrEquals(tc, precord->list, NULL);
    CuAssertIntEquals(tc, SH_LTRACK_VERSION, (precord->head).version);
    CuAssertIntEquals(tc, 0, (precord->head).n_entries);
    CuAssertIntEquals(tc, 0, (precord->head).last_login);
    for (i = 0; i < SH_LTRACK_GTRES; ++i)
      CuAssertIntEquals(tc, 0, (precord->head).array[i]);
    destroy_loaded(precord);
  }

  /* check configuration */

  j = sh_login_set_siglevel("duh");
  CuAssertIntEquals(tc, -1, j);
  CuAssertIntEquals(tc, SIG00, sig_level);

  j = sh_login_set_siglevel("yes");
  CuAssertIntEquals(tc, 0, j);
  CuAssertIntEquals(tc, SIG01, sig_level);
  j = sh_login_set_siglevel("no");
  CuAssertIntEquals(tc, 0, j);
  CuAssertIntEquals(tc, SIG00, sig_level);
  j = sh_login_set_siglevel("paranoid");
  CuAssertIntEquals(tc, 0, j);
  CuAssertIntEquals(tc, SIG05, sig_level);

  j = sh_login_set_checklevel("duh");
  CuAssertIntEquals(tc, -1, j);
  CuAssertIntEquals(tc, CHECK_NONE, check_level);

  j = sh_login_set_checklevel("yes");
  CuAssertIntEquals(tc, 0, j);
  CuAssertIntEquals(tc, CHECK_HOST, check_level);
  j = sh_login_set_checklevel("no");
  CuAssertIntEquals(tc, 0, j);
  CuAssertIntEquals(tc, CHECK_NONE, check_level);
  j = sh_login_set_checklevel("domain");
  CuAssertIntEquals(tc, 0, j);
  CuAssertIntEquals(tc, CHECK_DOMAIN, check_level);

  j = sh_login_set_def_allow("always");
  CuAssertIntEquals(tc, 0, j);
  for (j = 0; j < LTRACK_NDAYS; ++j)
    {
      for (i = 0; i < SH_LTRACK_GTRES; ++i)
	{
	  k = get_bool(global_dates[j], i);
	  CuAssertTrue(tc, k > 0);
	}
    }

  j = sh_login_set_def_allow("never");
  CuAssertIntEquals(tc, 0, j);
  for (j = 0; j < LTRACK_NDAYS; ++j)
    {
      for (i = 0; i < SH_LTRACK_GTRES; ++i)
	{
	  k = get_bool(global_dates[j], i);
	  CuAssertIntEquals(tc, 0, k);
	}
    }

  j = sh_login_set_def_allow("workdays( 0:12-1:30, 07:30-18:29,23:30-23:59)");
  CuAssertIntEquals(tc, 0, j);
  for (j = 0; j < LTRACK_NDAYS; ++j)
    {
      for (i = 0; i < SH_LTRACK_GTRES; ++i)
	{
	  k = get_bool(global_dates[j], i);
	  // fprintf(stderr, "%d: %d: %d\n", j, i, k);
	  if (j == WORKDAYS)
	    {
	      if ( (i>=1 && i<=9) || (i>=45 && i <=110) || (i>=141 && i<=143))
		CuAssertTrue(tc, k > 0);
	      else
		CuAssertIntEquals(tc, 0, k);
	    }
	  else
	    {
	      CuAssertIntEquals(tc, 0, k);
	    }
	}
    }

  j = sh_login_set_user_allow("rainer :workdays( 0:12-1:30, 07:30-18:29,23:30-23:59)");
  CuAssertIntEquals(tc, 0, j);
  j = sh_login_set_user_allow("rainer :saturday( 0:0-23:59)");
  CuAssertIntEquals(tc, 0, j);
  j = sh_login_set_user_allow("rain : workdays(0:12-1:30, 07:30-18:29,23:30-23:59)");
  CuAssertIntEquals(tc, 0, j);
  j = sh_login_set_user_allow("cat: workdays( 0:12-1:30, 07:30-18:29,23:30-23:59 )");
  CuAssertIntEquals(tc, 0, j);
  j = sh_login_set_user_allow("cat: sunday(0:00-23:59)");
  CuAssertIntEquals(tc, 0, j);

  {
    int count = 0;
    struct sh_track_dates * u = user_dates;
    
    CuAssertPtrNotNull(tc, u);

    do {

      if (count == 0) {
	CuAssertStrEquals(tc, u->user, "cat");
	CuAssertPtrNotNull(tc, u->next);
      }
      else if (count == 1) {
	CuAssertStrEquals(tc, u->user, "rain");
	CuAssertPtrNotNull(tc, u->next);
      }
      else if (count == 2) {
	CuAssertStrEquals(tc, u->user, "rainer");
	CuAssertPtrEquals(tc, u->next, NULL);
      }

      for (j = 0; j < LTRACK_NDAYS; ++j)
	{
	  for (i = 0; i < SH_LTRACK_GTRES; ++i)
	    {
	      k = get_bool(u->dates[j], i);
	      // fprintf(stderr, "%d: %d: %d\n", j, i, k);
	      if (j == WORKDAYS)
		{
		  if ( (i>=1 && i<=9) || (i>=45 && i <=110) || 
		       (i>=141 && i<=143) )
		    {
		      CuAssertTrue(tc, k > 0);
		    }
		  else
		    {
		      CuAssertIntEquals(tc, 0, k);
		    }
		}
	      else
		{
		  if ((count == 0 && j == SUNDAY) || 
		      (count == 2 && j == SATURDAY))
		    CuAssertTrue(tc, k > 0);
		  else
		    CuAssertIntEquals(tc, 0, k);
		}
	    }
	}

      if (u->next == NULL)
	break;

      u = u->next; ++count;

    } while (1 == 1);
  }

  sh_login_reset();
  CuAssertIntEquals(tc, SIG00, sig_level);
  CuAssertIntEquals(tc, CHECK_NONE, check_level);

  /* check dates */

  j = sh_login_set_def_allow("workdays( 0:12-1:30, 07:30-18:29,23:30-23:59)");
  CuAssertIntEquals(tc, 0, j);

  j = check_login_date("rainer", 0, 2);
  CuAssertIntEquals(tc, -1, j);
  j = check_login_date("rainer", 1, 2);
  CuAssertIntEquals(tc,  0, j);
  j = check_login_date("rainer",50, 3);
  CuAssertIntEquals(tc,  0, j);
  j = check_login_date("rainer",142, 5);
  CuAssertIntEquals(tc,  0, j);
  j = check_login_date("rainer", 1, 0);
  CuAssertIntEquals(tc, -1, j);
  j = check_login_date("rainer", 1, 6);
  CuAssertIntEquals(tc, -1, j);
  j = sh_login_set_user_allow("rainer :saturday( 0:0-23:59)");
  CuAssertIntEquals(tc, 0, j);
  j = check_login_date("rainer", 1, 6);
  CuAssertIntEquals(tc,  0, j);
  j = sh_login_set_user_allow("mouse :sunday( 0:0-23:59)");
  CuAssertIntEquals(tc, 0, j);
  j = sh_login_set_user_allow("cat :saturday(0:0-23:59)");
  CuAssertIntEquals(tc, 0, j);
  j = check_login_date("rainer", 1, 6);
  CuAssertIntEquals(tc,  0, j);
  j = check_login_date("mouse", 1, 6);
  CuAssertIntEquals(tc, -1, j);
  j = check_login_date("mouse", 1, 0);
  CuAssertIntEquals(tc,  0, j);
  j = check_login_date("cat", 1, 6);
  CuAssertIntEquals(tc,  0, j);
  j = check_login_date("dog", 1, 6);
  CuAssertIntEquals(tc, -1, j);

  sh_login_reset();

  /* statistics, critical values */
  {
    double f;

    f = M_crit(1, SIG05);
    CuAssertTrue(tc, f > 0.974 && f < 0.976);
    f = M_crit(13, SIG05);
    CuAssertTrue(tc, f > 0.576 && f < 0.578);
    f = M_crit(22, SIG05);
    CuAssertTrue(tc, f > 0.405 && f < 0.407);
    f = M_crit(10, SIG05);
    CuAssertTrue(tc, f > 0.646 && f < 0.648);
    f = M_crit(10, SIG01);
    CuAssertTrue(tc, f > 0.759 && f < 0.761);
  }

  /* stripped hostname */
  p = stripped_hostname("127.20.120.100");
  CuAssertStrEquals(tc, "127.20", p);

  p = stripped_hostname("foo.www.example.com");
  CuAssertStrEquals(tc, p, "www.example.com");

  p = stripped_hostname("www.example.com");
  CuAssertStrEquals(tc, p, "example.com");

  p = stripped_hostname("localhost");
  CuAssertStrEquals(tc, p, "localhost");

  {
    struct tm tt;

    tt.tm_hour =  0;
    tt.tm_min  = 30;
    tt.tm_sec  =  0;

    for (i = 0; i < 24; ++i)
      {
	tt.tm_hour =  i;
	j = time_to_index(&tt, SH_LTRACK_HTRES);
	CuAssertIntEquals(tc, j, i);
      }

    tt.tm_min  = 10;

    for (i = 0; i < 24; ++i)
      {
	tt.tm_hour =  i;
	j = time_to_index(&tt, SH_LTRACK_GTRES);
	CuAssertIntEquals(tc, 1+i*6, j);
      }
  } 
}
/* #ifdef SH_CUTEST */
#endif

#else

#ifdef SH_CUTEST
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "CuTest.h"

void Test_login (CuTest *tc) {
  (void) tc;
}

/* #ifdef SH_CUTEST */
#endif

#endif
