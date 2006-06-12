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
 * ***** END COPYRIGHT BLOCK *****/

#ifndef COOLKEY_PARAMS_H
#define COOLKEY_PARAMS_H


class Params {

private:
   static char *params;
public:
   static void SetParams(const char *_params) {
	ClearParams();
	params = strdup(_params);
   };
   static void ClearParams() {
	if (params) free (params);
	params = NULL;
   };
   static char *hasParam(const char *key) {
	char * index;
	if (!params) return NULL;
	index  = strstr(params, key);
	if (!index) return NULL;
	index += strlen(key);
	if (*index == '=') {
	   return index+1;
	}
	return NULL;
   };
};
#endif
