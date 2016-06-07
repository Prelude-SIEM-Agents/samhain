#ifndef SH_INOTIFY_H
#define SH_INOTIFY_H

#define SH_INOTIFY_MAX 128

typedef struct 
{
  void * list_of_watches;
  void * dormant_watches;

  /*
  int    watch[SH_INOTIFY_MAX];
  int    flag[SH_INOTIFY_MAX];
  char * file[SH_INOTIFY_MAX];
  */

  int     count;
  int  max_count;
} sh_watches;

/* #define SH_INOTIFY_INITIALIZER { { 0 }, { 0 }, { NULL}, 0, 0 } */

#define SH_INOTIFY_INITIALIZER { NULL, NULL, 0, 0 }

#define SH_INOTIFY_FILE 0
#define SH_INOTIFY_DIR  1

int sh_inotify_wait_for_change(char * filename, sh_watches * watches, 
			       int  * errnum,   int waitsec);

int sh_inotify_rm_watch (sh_watches * watches, sh_watches * save, int wd);

int sh_inotify_add_watch(char * filename, sh_watches * watches, int  * errnum,
			 int class, unsigned long check_flags, int type, int rdepth);

int sh_inotify_add_watch_later(const char * filename, sh_watches * watches, 
			       int  * errnum,
			       int class, unsigned long check_flags, 
			       int type, int rdepth);

char * sh_inotify_pop_dormant(sh_watches * watches, int * class, 
			      unsigned long * check_flags, int * type, int * rdepth);

void sh_inotify_purge_dormant(sh_watches * watches);
void sh_inotify_remove(sh_watches * watches);
void sh_inotify_init(sh_watches * watches);
void sh_inotify_close();

char * sh_inotify_search_item(sh_watches * watches, int watch, 
			      int * class, unsigned long * check_flags, 
			      int * type, int * rdepth);
ssize_t sh_inotify_read(char * buffer, size_t count);
ssize_t sh_inotify_read_timeout(char * buffer, size_t count, int timeout);
int sh_inotify_recheck_watches (sh_watches * watches, sh_watches * save);

#define SH_INOTIFY_ERROR(a) (a != 0)

#endif
