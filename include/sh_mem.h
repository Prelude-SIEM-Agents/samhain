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


#ifndef SH_MEM_H
#define SH_MEM_H


#ifdef MEM_DEBUG

void   sh_mem_openf (char * file, int fd);
void   sh_mem_closef (int fd);
void   sh_mem_check (void);
void   sh_mem_dump (void);
void   sh_mem_free (void * a, char * file, int line);
void * sh_mem_malloc (size_t size, char * file, int line);
void sh_mem_stat (void);

#define SH_FREE(a)   sh_mem_free((a), FIL__, __LINE__)
#define SH_ALLOC(a)  sh_mem_malloc((a), FIL__, __LINE__) 
#define SH_OALLOC(a,b,c)  sh_mem_malloc((a), (b), (c)) 

#else

#if defined(__GNUC__) && (__GNUC__ >= 3)
#undef  SH_GNUC_MALLOC
#define SH_GNUC_MALLOC   __attribute__((malloc))
#else
#undef  SH_GNUC_MALLOC
#define SH_GNUC_MALLOC
#endif

void   sh_mem_free (/*@only@*//*@out@*//*@null@*/ void * a);
/*@only@*//*@notnull@*/void * sh_mem_malloc (size_t size) SH_GNUC_MALLOC;

#define SH_FREE(a)   sh_mem_free(a)
#define SH_ALLOC(a)  sh_mem_malloc(a)
#define SH_OALLOC(a,b,c)  ((void) (b),		 \
			   (void) (c),		 \
			   sh_mem_malloc(a))	 \

#endif

/* #ifndef SH_MEM_H */
#endif
