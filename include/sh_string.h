#ifndef SH_STRING_H
#define SH_STRING_H

#include <stdio.h>

/* String definition and utility functions.
 */
typedef struct sh_str_struct
{
  char * str; /* always NULL terminated               */
  size_t len; /* without terminating \0               */
  size_t siz; /* size of allocated buffer             */
} sh_string;

sh_string * sh_string_new(size_t size);
void sh_string_destroy(sh_string ** s);
#define sh_string_str(a) ((a)->str)
#define sh_string_len(a) ((a)->len)

/* concat string to sh_string
 */
sh_string * sh_string_cat_lchar(sh_string * s, const char * str, size_t len);

/* add char array to end of string */
sh_string * sh_string_add_from_char(sh_string * s, const char * str);

/* set sh_string from string
 */
sh_string * sh_string_set_from_char(sh_string * s, const char * str);

/* create new sh_string from array of given length
 */
sh_string * sh_string_new_from_lchar(const char * str, size_t len);

#define sh_string_copy(a)  ((a) ? sh_string_new_from_lchar(((a)->str), ((a)->len)) : NULL)
#define sh_string_add(a,b) ((a && b) ? sh_string_cat_lchar((a), ((b)->str), ((b)->len)) : NULL)

/* create new sh_string from three arrays of given length
 */
sh_string * sh_string_new_from_lchar3(const char * str1, size_t len1,
                                      const char * str2, size_t len2,
                                      const char * str3, size_t len3);

/* Truncate to desired length.
 */
sh_string * sh_string_truncate(sh_string * s, size_t len);

/* If requested increase is zero, increase by default amount. 
 */
sh_string * sh_string_grow(sh_string * s, size_t increase);

/* Read a string from a file, with maxlen. Return 0 on EOF,
 * -1 on error, and -2 if a line exceeds maxlen.
 */
size_t sh_string_read(sh_string * s, FILE * fp, size_t maxlen);

/* Read a string from a file, with maxlen. Return 0 on EOF,
 * -1 on error, and -2 if a line exceeds maxlen.
 * If 'cont' != NULL, continuation lines starting with a char
 * in 'cont' are concatenated.
 */
size_t sh_string_read_cont(sh_string * s, FILE * fp, size_t maxlen, char *cont);

/* Split array at delim in at most nfields fields. 
 * Empty fields are returned as empty (zero-length) strings. 
 * Leading and trailing WS are removed from token. 
 * The number of fields is returned in 'nfields', their
 * lengths in 'lengths'.
 * A single delimiter will return two empty fields.
 */
char ** split_array(char *line, unsigned int * nfields, 
                    char delim, size_t * lengths);

/* Split array at whitespace in at most nfields fields.
 * Multiple whitespaces are collapsed. 
 * Empty fields are returned as empty (zero-length) strings.
 * The number of fields is returned in nfields.
 * An empty string will return zero fields.
 * If nfields < actual fields, last string will be remainder.
 */
char ** split_array_ws(char *line, unsigned int * nfields, size_t * lengths);

/* Same as above, but split on [space, tab, comma]
 */ 
char ** split_array_list(char *line, unsigned int * nfields, size_t * lengths);

/* Same as above, but split on delimiter list (token)
 */ 
char ** split_array_token (char *line, 
			   unsigned int * nfields, size_t * lengths,
			   const char * token);

/* Return a split_array_list() of a list contained in 'PREFIX\s*( list ).*'
 */
char ** split_array_braced (char *line, const char * prefix,
			    unsigned int * nfields, size_t * lengths);

/* Replaces fields in s with 'replacement'. Fields are given
 * in the ordered array ovector, comprising ovecnum pairs 
 * ovector[i], ovector[i+1] which list offset of first char
 * of field, offset of first char after field (this is how
 * the pcre library does it).
 */  
sh_string * sh_string_replace(const sh_string * s, 
                              const int * ovector, int ovecnum, 
                              const char * replacement, size_t rlen);

#endif
