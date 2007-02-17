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

#ifndef CKY_BASE_H
#ifndef CKY_BASEI_H
#define CKY_BASEI_H 1

#define CKYBUFFER_PRIVATE \
    CKYSize len; \
    CKYSize size; \
    CKYByte *data; \
    void   *reserved; 

#define CKYAPDU_PRIVATE \
    CKYBuffer apduBuf; \
    void *reserved;
    
#endif /* CKY_BASE_H */
#endif /* CKY_BASEI_H */
