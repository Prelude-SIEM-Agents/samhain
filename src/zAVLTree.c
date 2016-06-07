/*
 * zAVLTree.c: Source code for zAVLTrees.
 * Copyright (C) 1998,2001  Michael H. Buselli
 * This is version 0.1.3 (alpha).
 * Generated from $Id: xAVLTree.c.sh,v 1.5 2001/06/07 06:58:28 cosine Exp $
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

#include <stdlib.h>
#include <string.h>
#include "zAVLTree.h"

/* Interface for handling "string only" items rw 2014-06-26
 */
static zAVLKey zstring_key (void const * arg)
{
  return (zAVLKey) arg;
}

char * dummy_zfree_string;
#ifdef __clang__
char * dummy_zfree_str;
#endif

static void zfree_string (void * inptr)
{
#ifdef __clang__
  dummy_zfree_str = (char *) inptr;
#else
  char * str = (char *) inptr;
#endif

  /* Take the address to circumvent gcc 4.9 optimizer bug */
  dummy_zfree_string = (char *) &inptr;

#ifdef __clang__
  dummy_zfree_str[0] = '\0';
  free (dummy_zfree_str);
#else
  str[0] = '\0';
  free (inptr);
#endif
  return;
}
void zAVL_string_reset (zAVLTree * tree)
{
  if (tree)
    zAVLFreeTree (tree, zfree_string);
  return;
}
int zAVL_string_set (zAVLTree ** tree, const char * key)
{
  if (tree && key)
    {
      zAVLTree * itree = (*tree);
      if (!itree)
	{
	  itree = zAVLAllocTree (zstring_key, zAVL_KEY_STRING);
	  if (!itree) 
	    {
	      return -1;
	    }
	}
      *tree = itree;
      return zAVLInsert (itree, strdup(key));
    }
  return -1;
}
char * zAVL_string_get (zAVLTree * tree, const char * key)
{
  /* zAVLSearch() checks for NULL tree 
   */
  if (key)
    {
      return ((char *) zAVLSearch (tree, key));
    }
  return NULL;
}
void zAVL_string_del (zAVLTree * tree, const char * key)
{
  /* zAVLSearch() checks for NULL tree 
   */
  if (key)
    {
      char * item = ((char *) zAVLSearch (tree, key));
      if (item)
	{
	  zAVLDelete(tree, key);
	  zfree_string(item);
	}
    }
  return;
}



/* Wed Nov 23 17:57:42 CET 2005 rw: introduce third argument in
 * zAVLCloseSearchNode() to avoid redundant strcmp
 */
static zAVLNode *zAVLCloseSearchNode (zAVLTree const *avltree, zAVLKey key,
				      int * ok);
static void zAVLRebalanceNode (zAVLTree *avltree, zAVLNode *avlnode);
static void zAVLFreeBranch (zAVLNode *avlnode, void (freeitem)(void *item));
static void zAVLFillVacancy (zAVLTree *avltree,
        zAVLNode *origparent, zAVLNode **superparent,
        zAVLNode *left, zAVLNode *right);

#define MAX(x, y)      ((x) > (y) ? (x) : (y))
#define MIN(x, y)      ((x) < (y) ? (x) : (y))
#define L_DEPTH(n)     ((n)->left ? (n)->left->depth : 0)
#define R_DEPTH(n)     ((n)->right ? (n)->right->depth : 0)
#define CALC_DEPTH(n)  (MAX(L_DEPTH(n), R_DEPTH(n)) + 1)

#define ZAVL_OK 1
#define ZAVL_NO 0

/* The comparison function. Was a macro, but this allows for more
 * flexibility (non-string keys). The key is a (void *) now, and
 * the type is stored in the zAVLTree struct. Oct 21, 2011, rw
 */
static int zAVLKey_cmp(const zAVLTree * tree, zAVLKey a, zAVLKey b)
{
  if (tree->keytype == zAVL_KEY_STRING)
    {
      return (strcmp((const char*)a, (const char *)b));
    }
  else /* zAVL_KEY_INT */
    {
      const int x = *((const int *)a);
      const int y = *((const int *)b);

      if      (x > y) return  1;
      else if (x < y) return -1;
      else return 0;
    }
}

/*
 * AVLAllocTree:
 * Allocate memory for a new AVL tree and set the getkey function for
 * that tree.  The getkey function should take an item and return an
 * AVLKey that is to be used for indexing this object in the AVL tree.
 * On success, a pointer to the malloced AVLTree is returned.  If there
 * was a malloc failure, then NULL is returned.
 */
zAVLTree *zAVLAllocTree (zAVLKey (*getkey)(void const *item), int keytype)
{
  zAVLTree *rc;

  rc = calloc(1, sizeof(zAVLTree));
  if (rc == NULL)
    return NULL;

  rc->top = NULL;
  rc->count = 0;
  rc->getkey = getkey;
  rc->keytype = keytype;
  return rc;
}


/*
 * AVLFreeTree:
 * Free all memory used by this AVL tree.  If freeitem is not NULL, then
 * it is assumed to be a destructor for the items reference in the AVL
 * tree, and they are deleted as well.
 */
void zAVLFreeTree (zAVLTree *avltree, void (freeitem)(void *item))
{
  if (NULL == avltree)  /* R.W. Mon Nov 19 21:15:44 CET 2001 */
    return;
  if (avltree->top)
    zAVLFreeBranch(avltree->top, freeitem);
  free(avltree);
}


/*
 * AVLInsert:
 * Create a new node and insert an item there.
 *
 * Returns  0 on success,
 *         -1 on malloc failure,
 *          3 if duplicate key.
 */
int zAVLInsert (zAVLTree *avltree, void *item)
{
  zAVLNode *newnode;
  zAVLNode *node;
  zAVLNode *balnode;
  zAVLNode *nextbalnode;
  int       ok;

  newnode = calloc(1, sizeof(zAVLNode));
  if (newnode == NULL)
    return -1;

  newnode->key = avltree->getkey(item);
  newnode->item = item;
  newnode->depth = 1;
  newnode->left = NULL;
  newnode->right = NULL;
  newnode->parent = NULL;

  if (avltree->top != NULL) {
    node = zAVLCloseSearchNode(avltree, newnode->key, &ok);

    if (ok == ZAVL_OK) { /* exists already */
      free(newnode);
      return 3;
    }

    newnode->parent = node;

    if (zAVLKey_cmp(avltree, newnode->key, node->key) < 0) {
      node->left = newnode;
      node->depth = CALC_DEPTH(node);
    }

    else {
      node->right = newnode;
      node->depth = CALC_DEPTH(node);
    }

    for (balnode = node->parent; balnode; balnode = nextbalnode) {
      nextbalnode = balnode->parent;
      zAVLRebalanceNode(avltree, balnode);
    }
  }

  else {
    avltree->top = newnode;
  }

  avltree->count++;
  return 0;
}


/*
 * zAVLSearch:
 * Return a pointer to the item with the given key in the AVL tree.  If
 * no such item is in the tree, then NULL is returned.
 */
void *zAVLSearch (zAVLTree const *avltree, zAVLKey key)
{
  zAVLNode *node;
  int       ok;

  if (NULL == avltree)  /* R.W. Mon Nov 19 21:15:44 CET 2001 */
    return NULL;

  node = zAVLCloseSearchNode(avltree, key, &ok);

  if (node && ok == ZAVL_OK)
    return node->item;

  return NULL;
}


/*
 * zAVLDelete:
 * Deletes the node with the given key.  Does not delete the item at
 * that key.  Returns 0 on success and -1 if a node with the given key
 * does not exist.
 */
int zAVLDelete (zAVLTree *avltree, zAVLKey key)
{
  zAVLNode *avlnode;
  zAVLNode *origparent;
  zAVLNode **superparent;
  int        ok;

  avlnode = zAVLCloseSearchNode(avltree, key, &ok);
  if (avlnode == NULL || ok == ZAVL_NO) /* does not exist */
    return -1;

  origparent = avlnode->parent;

  if (origparent) {
    if (zAVLKey_cmp(avltree, avlnode->key, avlnode->parent->key) < 0)
      superparent = &(avlnode->parent->left);
    else
      superparent = &(avlnode->parent->right);
  }
  else
    superparent = &(avltree->top);

  zAVLFillVacancy(avltree, origparent, superparent,
                  avlnode->left, avlnode->right);
  free(avlnode);
  avltree->count--;
  return 0;
}


/*
 * zAVLFirst:
 * Initializes an zAVLCursor object and returns the item with the lowest
 * key in the zAVLTree.
 */
void *zAVLFirst (zAVLCursor *avlcursor, zAVLTree const *avltree)
{
  const zAVLNode *avlnode;

  if (NULL == avltree)  /* R.W. Mon Nov 19 21:15:44 CET 2001 */
    return NULL;

  avlcursor->avltree = avltree;

  if (avltree->top == NULL) {
    avlcursor->curnode = NULL;
    return NULL;
  }

  for (avlnode = avltree->top;
       avlnode->left != NULL;
       avlnode = avlnode->left);
  avlcursor->curnode = avlnode;
  return avlnode->item;
}


/*
 * zAVLNext:
 * Called after an zAVLFirst() call, this returns the item with the least
 * key that is greater than the last item returned either by zAVLFirst()
 * or a previous invokation of this function.
 */
void *zAVLNext (zAVLCursor *avlcursor)
{
  const zAVLNode *avlnode;

  avlnode = avlcursor->curnode;

  if (avlnode->right != NULL) {
    for (avlnode = avlnode->right;
         avlnode->left != NULL;
         avlnode = avlnode->left);
    avlcursor->curnode = avlnode;
    return avlnode->item;
  }

  while (avlnode->parent && avlnode->parent->left != avlnode) {
    avlnode = avlnode->parent;
  }

  if (avlnode->parent == NULL) {
    avlcursor->curnode = NULL;
    return NULL;
  }

  avlcursor->curnode = avlnode->parent;
  return avlnode->parent->item;
}


/*
 * zAVLCloseSearchNode:
 * Return a pointer to the node closest to the given key.
 * Returns NULL if the AVL tree is empty.
 */
static zAVLNode *zAVLCloseSearchNode (zAVLTree const *avltree, zAVLKey key, 
				      int * ok)
{
  zAVLNode *node;

  *ok = ZAVL_NO;

  node = avltree->top;

  if (!node)
    return NULL;

  for (;;) {
    if (!zAVLKey_cmp(avltree, node->key, key))
      {
	*ok = ZAVL_OK;
	return node;
      }

    if (zAVLKey_cmp(avltree, node->key, key) < 0) {
      if (node->right)
        node = node->right;
      else
        return node;
    }

    else {
      if (node->left)
        node = node->left;
      else
        return node;
    }
  }
}


/*
 * zAVLRebalanceNode:
 * Rebalances the AVL tree if one side becomes too heavy.  This function
 * assumes that both subtrees are AVL trees with consistant data.  This
 * function has the additional side effect of recalculating the depth of
 * the tree at this node.  It should be noted that at the return of this
 * function, if a rebalance takes place, the top of this subtree is no
 * longer going to be the same node.
 */
static void zAVLRebalanceNode (zAVLTree *avltree, zAVLNode *avlnode)
{
  long depthdiff;
  zAVLNode *child;
  zAVLNode *gchild;
  zAVLNode *origparent;
  zAVLNode **superparent;

  origparent = avlnode->parent;

  if (origparent) {
    if (zAVLKey_cmp(avltree, avlnode->key, avlnode->parent->key) < 0)
      superparent = &(avlnode->parent->left);
    else
      superparent = &(avlnode->parent->right);
  }
  else
    superparent = &(avltree->top);

  depthdiff = R_DEPTH(avlnode) - L_DEPTH(avlnode);

  if (depthdiff <= -2 && avlnode->left) {
    child = avlnode->left;

    if (L_DEPTH(child) >= R_DEPTH(child)) {
      avlnode->left = child->right;
      if (avlnode->left != NULL)
        avlnode->left->parent = avlnode;
      avlnode->depth = CALC_DEPTH(avlnode);
      child->right = avlnode;
      if (child->right != NULL)
        child->right->parent = child;
      child->depth = CALC_DEPTH(child);
      *superparent = child;
      child->parent = origparent;
    }

    else {
      gchild = child->right;
      if (gchild)
	{
	  avlnode->left = gchild->right;
	  if (avlnode->left != NULL)
	    avlnode->left->parent = avlnode;
	  avlnode->depth = CALC_DEPTH(avlnode);
	  child->right = gchild->left;
	  if (child->right != NULL)
	    child->right->parent = child;
	  child->depth = CALC_DEPTH(child);
	  gchild->right = avlnode;
	  if (gchild->right != NULL)
	    gchild->right->parent = gchild;
	  gchild->left = child;
	  if (gchild->left != NULL)
	    gchild->left->parent = gchild;
	  gchild->depth = CALC_DEPTH(gchild);
	  *superparent = gchild;
	  gchild->parent = origparent;
	}
    }
  }

  else if (depthdiff >= 2 && avlnode->right) {
    child = avlnode->right;

    if (R_DEPTH(child) >= L_DEPTH(child)) {
      avlnode->right = child->left;
      if (avlnode->right != NULL)
        avlnode->right->parent = avlnode;
      avlnode->depth = CALC_DEPTH(avlnode);
      child->left = avlnode;
      if (child->left != NULL)
        child->left->parent = child;
      child->depth = CALC_DEPTH(child);
      *superparent = child;
      child->parent = origparent;
    }

    else {
      gchild = child->left;
      if (gchild)
	{
	  avlnode->right = gchild->left;
	  if (avlnode->right != NULL)
	    avlnode->right->parent = avlnode;
	  avlnode->depth = CALC_DEPTH(avlnode);
	  child->left = gchild->right;
	  if (child->left != NULL)
	    child->left->parent = child;
	  child->depth = CALC_DEPTH(child);
	  gchild->left = avlnode;
	  if (gchild->left != NULL)
	    gchild->left->parent = gchild;
	  gchild->right = child;
	  if (gchild->right != NULL)
	    gchild->right->parent = gchild;
	  gchild->depth = CALC_DEPTH(gchild);
	  *superparent = gchild;
	  gchild->parent = origparent;
	}
    }
  }

  else {
    avlnode->depth = CALC_DEPTH(avlnode);
  }
}


/*
 * zAVLFreeBranch:
 * Free memory used by this node and its item.  If the freeitem argument
 * is not NULL, then that function is called on the items to free their
 * memory as well.  In other words, the freeitem function is a
 * destructor for the items in the tree.
 */
static void zAVLFreeBranch (zAVLNode *avlnode, void (freeitem)(void *item))
{
  if (avlnode->left)
    zAVLFreeBranch(avlnode->left, freeitem);
  if (avlnode->right)
    zAVLFreeBranch(avlnode->right, freeitem);
  if (freeitem) {
    freeitem(avlnode->item);
    avlnode->item = NULL;
  }
  free(avlnode);
}


/*
 * zAVLFillVacancy:
 * Given a vacancy in the AVL tree by it's parent, children, and parent
 * component pointer, fill that vacancy.
 */
static void zAVLFillVacancy (zAVLTree *avltree,
			     zAVLNode *origparent, zAVLNode **superparent,
			     zAVLNode *left, zAVLNode *right)
{
  zAVLNode *avlnode;
  zAVLNode *balnode;
  zAVLNode *nextbalnode;

  if (left == NULL) {
    if (right)
      right->parent = origparent;

    *superparent = right;
    balnode = origparent;
  }

  else {
    for (avlnode = left; avlnode->right != NULL; avlnode = avlnode->right);

    if (avlnode == left) {
      balnode = avlnode;
    }
    else {
      balnode = avlnode->parent;
      balnode->right = avlnode->left;
      if (balnode->right != NULL)
        balnode->right->parent = balnode;
      avlnode->left = left;
      left->parent = avlnode;
    }

    avlnode->right = right;
    if (right != NULL)
      right->parent = avlnode;
    *superparent = avlnode;
    avlnode->parent = origparent;
  }

  for (; balnode; balnode = nextbalnode) {
    nextbalnode = balnode->parent;
    zAVLRebalanceNode(avltree, balnode);
  }
}
