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


#ifndef SH_HASH_H
#define SH_HASH_H

#include <limits.h>

#include "samhain.h"
#include "sh_unix.h"
#include "sh_error.h"

/* the report_checkflags flag
 */
int get_report_checkflags();

/* whether to report checkflags
 */
int set_report_checkflags(const char * c);

/* convert to policy string
 */
const char * sh_hash_getpolicy(int class);

/* format a uint64
 */
char * sh_hash_size_format(void);

/* report on a missing file
 */
int hashreport_missing( char *fullpath, int level);

/* remove internal db record for a file (checks for some flags).
 */
void sh_hash_remove (const char * path);

/* remove internal db record for a file
 */
void sh_hash_remove_unconditional (const char * path);

/* Insert a "null" record in-memory (representing a missing file).
 */
void sh_hash_insert_null(char * str);

#ifdef SH_DBIO_INT_H
/* Check for "null" record
 */
int sh_hash_is_null_record(sh_filestore_t * theFile);
#endif

/* Dont report on ctm/mtm change for directories
 */
int sh_hash_loosedircheck(const char * str);

/* List database content for a single file
 */
int set_list_file (const char * c);

/* Set the path of that file
 */
char * get_list_file();

/* List database content with full detail
 */
int set_full_detail (const char * c);

/* List database content with full detail, comma delimited
 */
int set_list_delimited (const char * c);

/* Read the database from disk.
 */
void sh_hash_init (void);

/* Check init status
 */
int sh_hash_get_initialized();

/* Read the database from disk and fill sh.data.hash with checksum.
 */
void sh_hash_init_and_checksum();

/* Set status to 'database is read in'.
 */
void sh_hash_set_initialized();

/* Check whether a file is present in the database.
 */
int sh_hash_have_it (const char * newname);

/* Get a file if it is present in the database.
 * If fileHash != NULL also return checksum.
 */
int sh_hash_get_it (const char * newname, file_type * tmpFile, char * fileHash);

/* Delete the database from memory.
 */
void sh_hash_hashdelete (void);

/* Insert a file into the database.
 */ 
void sh_hash_pushdata (file_type * buf, char * fileHash);

/* reset sh_hash_pushdata to use 'update' in daemon mode
 */
void sh_hash_pushdata_reset (void);

/* Insert a file into the in-memory database.
 */ 
void sh_hash_pushdata_memory (file_type * theFile, char * fileHash);

/* Get file flags from in-memory database
 */
int sh_hash_getflags (char * filename);

/* Set file flags in in-memory database
 */
int sh_hash_setflags (char * filename, int flags);

/* Set a file flag in in-memory database
 */
void sh_hash_set_flag  (char * filename, int flag);

/* Unset a file flag in in-memory database
 */
void sh_hash_clear_flag (char * filename, int flag_to_set);

/* Compare a file with its status in the database.
 */ 
int sh_hash_compdata (int class, file_type * theFile, char * fileHash,
		      char * policy_override, int severity_override);

/* Search for files in the database that have been deleted from disk.
 */
void sh_hash_unvisited (ShErrLevel level);

/* Search for unvisited entries in the database, custom error handler.
 */
void sh_hash_unvisited_custom (char prefix, void(*handler)(const char * key));

/* Set a file's status to 'visited'. This is required for
 * files that should be ignored, and may be present in the
 * database, but not on disk.
 */
int sh_hash_set_visited (char * newname);

/* As above, but only set the 'visited' flag
 */
int sh_hash_set_visited_true (char * newname);

/* cause the record to be deleted without a 'missing' message
 */
int sh_hash_set_missing (char * newname);

/* Make a complete directory tree invisible
 */
int hash_remove_tree (char * s);

/* Make every entry visible 
 */
int hash_full_tree (void); 

/* Insert data.
 * 'key' -> path
 * 'str' -> binary with size 'size'
 */
struct store2db {
  UINT64 val0;
  UINT64 val1;
  UINT64 val2;
  UINT64 val3;
  char   checksum[KEY_LEN+1];
  unsigned char * str;
  int size;
};

void sh_hash_push2db (const char * key, struct store2db * save);


/* Retrieve data
 */
char * sh_hash_db2pop (const char * key,  struct store2db * get);


/* Write out database
 */
int sh_hash_writeout(void);
#endif
