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

#ifndef CKY_LIST_H
#define CKY_LIST_H 1
/*
 * Macro to declare methods and types for CoolKey Lists.
 */
#define CKYLIST_DECLARE(name, type)                                        \
typedef void *name##List;                                                 \
typedef void *name##Iterator;                                             \
                                                                          \
CKY_BEGIN_PROTOS                                                           \
/* get the number of elements in the name##List */                        \
unsigned long name##List_GetCount(name##List list);                       \
                                                                          \
/* returns the 'index'th element of the list.                             \
 * This provides one way  of walking the list...                          \
 *                                                                        \
 *  // acquire name##List list                                            \
 *  int count;                                                            \
 *  int i;                                                                \
 *                                                                        \
 *  count =  name##List_GetCount(list);                                   \
 *  for (i=0; i < count; i++) {                                           \
 *    const type value = name##List_GetValue(list, i);                    \
 *                                                                        \
 *    // Process value                                                    \
 * }                                                                      \
 */                                                                       \
const type name##List_GetValue(name##List list, unsigned long index);     \
                                                                          \
/* * Destroy a list */                                                    \
void name##List_Destroy(name##List list);                                 \
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
 *                                 iter = name##Interator_Next(iter) ) {  \
 *      const type value = name##Interator_GetValue(iter);                \
 *                                                                        \
 *    // Process value                                                    \
 *   }                                                                    \
 *                                                                        \
 */                                                                       \
name##Iterator name##List_GetIterator(name##List list);                   \
CKYBool name##Iterator_End(name##Iterator iter);                           \
name##Iterator name##Iterator_Next(name##Iterator iter);                  \
const type name##Iterator_GetValue(name##Iterator iter);                  \
CKY_END_PROTOS                                                             \
/* end of Declarations */

#endif /* CKY_LIST_H */
