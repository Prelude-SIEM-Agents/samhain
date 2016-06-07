#ifndef SH_FILTER_H
#define SH_FILTER_H

/* Filtering
 */

#define SH_FILT_NUM 32
#define SH_FILT_OR  0
#define SH_FILT_AND 1
#define SH_FILT_NOT 2
#define SH_FILT_INIT { 0, { NULL }, 0, { NULL }, 0, { NULL }}

/* Pattern storage is of type void since it may be a char*
 * or a regex_t*
 */
typedef struct _sh_filter_type
{
  int      for_c;
  void   * for_v[SH_FILT_NUM];
  int      fand_c;
  void   * fand_v[SH_FILT_NUM];
  int      fnot_c;
  void   * fnot_v[SH_FILT_NUM];

} sh_filter_type;

int  sh_filter_add (const char * str, sh_filter_type * filter, int type);

void sh_filter_free (sh_filter_type * filter);

int  sh_filter_filter (const char * message, sh_filter_type * filter);

sh_filter_type * sh_filter_alloc(void);

#endif
