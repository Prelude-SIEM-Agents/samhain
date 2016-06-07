#ifndef SH_HTML_H
#define SH_HTML_H

#ifdef SH_WITH_SERVER


#define CLT_INACTIVE 0
#define CLT_STARTED  1
#define CLT_ILLEGAL  2
#define CLT_FAILED   3
#define CLT_EXITED   4
#define CLT_PANIC    5
#define CLT_POLICY   6
#define CLT_FILE     7
#define CLT_MSG      8
#define CLT_TOOLONG  9
#define CLT_SUSPEND  10
#define CLT_CHECK    11
#define CLT_MAX      12

/************************
char * clt_stat[] = {
  N_("Inactive"),
  N_("Started"),
  N_("ILLEGAL"),
  N_("FAILED"),
  N_("Exited"),
  N_("PANIC"),
  N_("POLICY"),
  N_("File transfer"),
  N_("Message"),
  N_("TIMEOUT_EXCEEDED"),
};
**************************/

extern char * clt_stat[];

#ifdef SH_ENCRYPT
#include "rijndael-api-fst.h"
#endif
 
/* --- client status ---
 */
typedef struct client_entry {
  char                  * hostname;
  char                  * salt;
  char                  * verifier;
  char                    session_key[KEY_LEN+1];
  time_t                  session_key_timer;
  time_t                  last_connect;
  int                     exit_flag;
  int                     dead_flag;
  int                     encf_flag;
  int                     ency_flag;
  int                     ivst_flag;
  int                     status_now;
  int                     status_arr[CLT_MAX];
  char                    timestamp[CLT_MAX][TIM_MAX];
#ifdef SH_ENCRYPT
  keyInstance             keyInstE;
  keyInstance             keyInstD;
#endif
} client_t;

/* --- server status ---
 */
typedef struct _s_stat {
  time_t  start;
  time_t  last;
  int     conn_open;
  int     conn_max;
  long    conn_total;
} s_stat;

extern s_stat  server_status;

/* write html report. Expects (client_t *) inptr.
 */
int sh_html_write(void * inptr);

#endif

#endif
