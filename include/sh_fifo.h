
#ifndef SH_FIFO_H
#define SH_FIFO_H

/*****************************************************
 *
 * the maximum number of entries the fifo will hold
 * - additional entries are simply not accepted -
 *
 *****************************************************/

#define SH_FIFO_MAX 16384

/*****************************************************
 *
 * the type definitions for the fifo
 *
 *****************************************************/

struct dlist {
  struct dlist * next;
  char         * data;
  char         * s_xtra;
  int            i_xtra;
  int            transact;
  struct dlist * prev;
};

typedef struct fifo_str {
  struct dlist * head_ptr;
  struct dlist * tail_ptr;
  int            fifo_cts;
} SH_FIFO;

#define SH_FIFO_INITIALIZER { NULL, NULL, 0 }

/*****************************************************
 *
 * fifo functions
 *
 *****************************************************/

/* Initialize the list.
 *
 */
#define fifo_init(fifo_p) { (fifo_p)->fifo_cts = 0; (fifo_p)->head_ptr = NULL; \
    (fifo_p)->tail_ptr = NULL; }


/* Push an item on the head of the list.
 *
 * Returns: -1 if the list is full, 0 on success 
 */
int push_list (SH_FIFO * fifo, const char * indat, int in_i, const char * in_str);
#define sh_fifo_push(a, b) push_list((a), (b), 0, NULL)

/* Push an item on the tail of the list.
 *
 * Returns: -1 if the list is full, 0 on success 
 */
int push_tail_list (SH_FIFO * fifo, const char * indat, int in_i, const char * in_str);
#define sh_fifo_push_tail(a, b) push_tail_list((a), (b), 0, NULL)

/* pop an item from the tail of the list
 *
 * Returns: NULL if the list is empty, 
 *          freshly allocated memory on success (should be free'd by caller) 
 */
char * pop_list (SH_FIFO * fifo);
#define sh_fifo_pop(a) pop_list((a))

/* ----  Special functions -------------------------------------------------*/

/* This is for eMail where different recipients may be eligible for         *
 * different subsets of messages. We need to delete all that were sent      *
 * to all intended recipients, and keep all with at least one failure.      */

/* Iterate over list and check for each if it is valid for 'tag';
 * i.e. (item->s_extra == tag). If yes, add to the returned string.
 * If (okNull == False) then item->s_xtra must be defined
 */
sh_string * tag_list (SH_FIFO * fifo, char * tag,
		      int(*check)(int, const char*, const char*, const void*),
		      const void * info, int okNull);

/* Flag all tagged as candidate to keep */
void rollback_list (SH_FIFO * fifo);
/* Flag all tagged as candidate to delete */
void mark_list (SH_FIFO * fifo);
/* Remove all flags */
void reset_list (SH_FIFO * fifo);
/* Delete all marked for delete that are not flagged for keep */
int commit_list (SH_FIFO * fifo);

#endif
