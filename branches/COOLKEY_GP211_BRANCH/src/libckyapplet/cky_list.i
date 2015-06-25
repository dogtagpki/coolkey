/* ***** BEGIN COPYRIGHT BLOCK *****
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * ***** END COPYRIGHT BLOCK ***** */

#ifndef CKY_LIST_I
#define CKY_LIST_I 1

#define CKYLIST_IMPLEMENT(name,type) \
                                                                          \
/*                                                                        \
 * name##List is implemented as a pointer to a NULL terminated array of   \
 * type##s. A NULL name##List is valid and means a list with '0' elements \
 * The actual type is a void * and the follow functions are designed to   \
 * hide the underlying structure of name##List.                           \
 */                                                                       \
                                                                          \
/* get the number of elements in the reader List */                       \
unsigned long                                                             \
name##List_GetCount(name##List list)                                      \
{                                                                         \
    type *current;                                                        \
    int count;                                                            \
                                                                          \
    if (list == NULL) {                                                   \
	return 0;                                                         \
    }                                                                     \
                                                                          \
    for (count=0, current = (type *)list; *current; current++, count++) { \
	/* EMPTY */ ;                                                     \
    }                                                                     \
                                                                          \
    return count;                                                         \
}                                                                         \
                                                                          \
                                                                          \
/* returns the 'index'th element of the list.                             \
 *  index is not checked for overruns in this implementation.             \
 *                                                                        \
 * This provides one way  of walking the list...                          \
 *                                                                        \
 *   // acquire name##List list                                           \
 *  int count;                                                            \
 *  int i;                                                                \
 *                                                                        \
 *  count =  name##List_GetCount(list);                                   \
 *  for (i=0; i < count; i++) {                                           \
 *   const type value = name##List_GetValue(list, i);                     \
 *                                                                        \
 *    // Process value                                                    \
 * }                                                                      \
 */                                                                       \
const type                                                                \
name##List_GetValue(name##List list, unsigned long index)                 \
{                                                                         \
    type *array = (type *)list;                                           \
                                                                          \
    /* should probably be an assert */                                    \
    if (list == NULL) {                                                   \
	return NULL;                                                      \
    }                                                                     \
    return array[index];                                                  \
}                                                                         \
                                                                          \
/*  Destroy a list */                                                     \
void                                                                      \
name##List_Destroy(name##List list)                                       \
{                                                                         \
    type *cur;                                                            \
    if (list == NULL) {                                                   \
 	return ;                                                          \
    }                                                                     \
                                                                          \
    for (cur =(type *)list; *cur; cur++) {                                 \
	name##_Destroy(*cur);                                             \
    }                                                                     \
    free(list);                                                           \
}                                                                         \
                                                                          \
/*                                                                        \
 * The following iterators allows someone to easily walk the list using   \
 * the following sample code. These functions hide the underlying         \
 * implementation.                                                        \
 *                                                                        \
 *  // acquire name##List list                                            \
 *  name##Iterator iter;                                                  \
 *                                                                        \
 *  for (iter = name##List_GetIterator(list); !name##Iterator_End(inter); \
 *                                 iter = name##Iterator_Next(iter) ) {   \
 *      const type value = name##Iterator_GetValue(iter);                 \
 *      // process value                                                  \
 *   }                                                                    \
 *                                                                        \
 */                                                                       \
name##Iterator                                                            \
name##List_GetIterator(name##List list)                                   \
{                                                                         \
    return (name##Iterator) list;                                         \
}                                                                         \
                                                                          \
CKYBool                                                                    \
name##Iterator_End(name##Iterator iter)                                   \
{                                                                         \
    if (iter == NULL) {                                                   \
	return 1;                                                         \
    }                                                                     \
    return *(type *)iter == NULL;                                         \
}                                                                         \
                                                                          \
name##Iterator                                                            \
name##Iterator_Next(name##Iterator iter)                                  \
{                                                                         \
    if (iter == NULL) {                                                   \
	return NULL;                                                      \
    }                                                                     \
    return (name##Iterator) (((type *)iter)+1);                           \
}                                                                         \
                                                                          \
const type                                                                \
name##Iterator_GetValue(name##Iterator iter)                              \
{                                                                         \
    /* assert(iter != NULL); */                                           \
    return *(type *)iter;                                                 \
}                                                                         \
                                                                          \
/*                                                                        \
 * add functions to create lists, & add elements to lists                 \
 */                                                                       \
	

#endif /* CKY_LIST_I */
