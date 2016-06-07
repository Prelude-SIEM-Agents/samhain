/*
 * zAVLTree.h: Header file for zAVLTrees.
 * Copyright (C) 1998,2001  Michael H. Buselli
 * This is version 0.1.3 (alpha).
 * Generated from $Id: xAVLTree.h.sh,v 1.5 2001/06/07 06:58:28 cosine Exp $
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * The author of this library can be reached at the following address:
 * Michael H. Buselli
 * 30051 N. Waukegan Rd. Apt. 103
 * Lake Bluff, IL  60044-5412
 *
 * Or you can send email to <cosine@cosine.org>.
 * The official web page for this product is:
 * http://www.cosine.org/project/AVLTree/
 */

#ifndef _ZAVLTREE_H_
#define _ZAVLTREE_H_

/* typedef the keytype */
typedef const void * zAVLKey;

/* Comparison function for strings is strcmp(). */
/* #define zAVLKey_cmp(tree, a, b) (strcmp((a), (b))) */

#define zAVL_KEY_STRING 0
#define zAVL_KEY_INT    1


typedef struct _zAVLNode {
  zAVLKey key;
  long depth;
  void *item;
  struct _zAVLNode *parent;
  struct _zAVLNode *left;
  struct _zAVLNode *right;
} zAVLNode;


typedef struct {
  zAVLNode *top;
  long count;
  zAVLKey (*getkey)(const void *item);
  int keytype;
} zAVLTree;


typedef struct {
  const zAVLTree *avltree;
  const zAVLNode *curnode;
} zAVLCursor;


extern zAVLTree *zAVLAllocTree (zAVLKey (*getkey)(void const *item), int keytype);
extern void zAVLFreeTree (zAVLTree *avltree, void (freeitem)(void *item));
extern int zAVLInsert (zAVLTree *avltree, void *item);
extern void *zAVLSearch (zAVLTree const *avltree, zAVLKey key);
extern int zAVLDelete (zAVLTree *avltree, zAVLKey key);
extern void *zAVLFirst (zAVLCursor *avlcursor, zAVLTree const *avltree);
extern void *zAVLNext (zAVLCursor *avlcursor);

extern char * zAVL_string_get (zAVLTree * tree, const char * key);
/* uses strdup to insert a copy */
extern int zAVL_string_set (zAVLTree ** tree, const char * key); 
extern void zAVL_string_reset (zAVLTree * tree);
extern void zAVL_string_del (zAVLTree * tree, const char * key);

#endif
