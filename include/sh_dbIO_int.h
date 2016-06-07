/* SAMHAIN file system integrity testing                                   */
/* Copyright (C) 2015 Rainer Wichmann                                      */
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


#ifndef SH_DBIO_INT_H
#define SH_DBIO_INT_H

#define SH_DEADFILE 0x44454144

typedef struct store_info_old {

  UINT32           mode;
  UINT32           linkmode;

  UINT64           dev;
  UINT64           rdev;

  UINT32           hardlinks;
  UINT32           ino;

  UINT64           size;
  UINT64           atime;
  UINT64           mtime;
  UINT64           ctime;

  UINT32           owner;
  UINT32           group;

  UINT32           attributes;

  char             c_attributes[ATTRBUF_SIZE]; /* 16 = 2*UINT64 */

  unsigned short   mark;
  char             c_owner[USER_MAX+2];
  char             c_group[GROUP_MAX+2];
  char             c_mode[CMODE_SIZE];
  char             checksum[KEY_LEN+1];
  
} sh_filestore_old_t;

typedef struct store_info {

  UINT32           mode;
  UINT32           linkmode;

  UINT64           dev;
  UINT64           rdev;

  UINT32           hardlinks;
  UINT32           ino;

  UINT64           size;
  UINT64           atime;
  UINT64           mtime;
  UINT64           ctime;

  UINT32           owner;
  UINT32           group;

  UINT32           attributes;

  char             c_attributes[ATTRBUF_SIZE]; /* 16 = 2*UINT64 */

  unsigned short   mark;
  char             c_owner[USER_MAX+2];
  char             c_group[GROUP_MAX+2];
  char             c_mode[CMODE_SIZE];
  char             checksum[KEY_LEN+1];
  
  /* If 'checkflags' is elsewhere, the compiler would still use
   * a 6-byte padding to align the whole struct to an 8-byte boundary.
   * ipad, opad: make explicit what the compiler does on a 64-byte system.
   */
  char             ipad[2];
  UINT32           checkflags;
  char             opad[4];

} sh_filestore_t;
  
typedef struct file_info {
  sh_filestore_t   theFile;
  char           * fullpath;
  char           * linkpath;
  char           * attr_string;
  int              fflags;
  unsigned long    modi_mask;
  struct           file_info * next;
} sh_file_t;

//* must fit an int              */
#define TABSIZE 65536

/* must fit an unsigned short   */
/* changed for V0.8, as the     */
/* database format has changed  */
/* changed again for V0.9       */
/* #define REC_MAGIC 19         */
/* changed again for V1.3       */
/* #define REC_MAGIC 20         */
/* changed again for V1.4       */
/* #define REC_MAGIC 21         */
#define OLD_REC_MAGIC 21 
/* changed again for V3.2       */
#define REC_MAGIC 22

#define REC_FLAGS_ATTR (1<<8)
#define REC_FLAGS_MASK 0xFF00

/* Insert into database table
 */
void hashinsert (sh_file_t * tab[TABSIZE], sh_file_t * s); 

/* Internal conversion function
 */
file_type * sh_hash_create_ft (const sh_file_t * p, char * fileHash);

/* Print what's in the link path
 */
int sh_hash_printcontent(char * linkpath);

/* List database entry
 */
void sh_hash_list_db_entry (sh_file_t * p);

/* get the location of the default/main database table
 */
sh_file_t ** get_default_data_table();

/* Write whole database
 */
int sh_dbIO_writeout(sh_file_t * mtab[TABSIZE], const char * outpath, int truncate);

/* Load from the default source into hash table 'tab'
 */
int sh_dbIO_load_db(sh_file_t * tab[TABSIZE]);

/* Load from the file 'filepath' into hash table 'tab'
 */
int sh_dbIO_load_db_file(sh_file_t * tab[TABSIZE], const char * filepath);

#endif
