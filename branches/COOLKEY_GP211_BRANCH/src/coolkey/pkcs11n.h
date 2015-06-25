/* ***** BEGIN COPYRIGHT BLOCK ***** 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 * ***** END COPYRIGHT BLOCK *****/

#ifndef _PKCS11N_H_
#define _PKCS11N_H_

#ifdef DEBUG
static const char CKT_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * pkcs11n.h
 *
 * This file contains the NSS-specific type definitions for Cryptoki
 * (PKCS#11).
 */

/*
 * NSSCK_VENDOR_NETSCAPE
 *
 * Cryptoki reserves the high half of all the number spaces for
 * vendor-defined use.  I'd like to keep all of our Netscape-
 * specific values together, but not in the oh-so-obvious
 * 0x80000001, 0x80000002, etc. area.  So I've picked an offset,
 * and constructed values for the beginnings of our spaces.
 *
 * Note that some "historical" Netscape values don't fall within
 * this range.
 */
#define NSSCK_VENDOR_NETSCAPE 0x4E534350 /* NSCP */

/*
 * Netscape-defined object classes
 * 
 */
#define CKO_NETSCAPE (CKO_VENDOR_DEFINED|NSSCK_VENDOR_NETSCAPE)
#define CKO_MOZ_READER			(CKO_NETSCAPE + 5)

/*
 * Netscape-defined object attributes
 *
 */
#define CKA_NETSCAPE (CKA_VENDOR_DEFINED|NSSCK_VENDOR_NETSCAPE)
#define CKA_MOZ_IS_COOL_KEY          (CKA_NETSCAPE +  24)
#define CKA_MOZ_ATR                     (CKA_NETSCAPE +  25)
#define CKA_MOZ_TPS_URL                 (CKA_NETSCAPE +  26)

#endif /* _PKCS11N_H_ */
