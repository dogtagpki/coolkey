/** BEGIN COPYRIGHT BLOCK
* This Program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; version 2 of the License.
*
* This Program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
* Place, Suite 330, Boston, MA 02111-1307 USA.
*
* Copyright (C) 2003-2004 Identity Alliance

* All rights reserved.
* END COPYRIGHT BLOCK **/

// cspres.h : main header file for the cspres.dll
//

#ifndef __INCLUDE_CSPRES_H__
#define __INCLUDE_CSPRES_H__

#ifdef __cplusplus
extern "C" {
#endif

int CSPDisplayPinDialog(char* pin, int max_len);
void CSPCancelPinDialog();
void CSPSetParentPinDialog(void* parent);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_CSPRES_H__ */
