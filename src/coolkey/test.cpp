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

#include "list.h"
#include <stdlib.h>
#include <stdio.h>

#include <list>
#include <string>

using std::list;
using std::string;

void*
operator new(unsigned int len)
{
    void* p = malloc(len);
    printf("operator new(%d) returns 0x%08x\n", len, p);
    return p;
}

void
operator delete(void *p)
{
    printf("operator delete(0x%08x)\n", p);
}

void
mylist()
{
    List<int> intlist;

    List<int>::Iterator iter;

    iter = intlist.begin();

    intlist.insert(iter, 5);

    iter++;

    intlist.insert(iter, 7);

    iter = intlist.find_item(intlist.begin(), intlist.end(), 7);

    intlist.insert(iter, 9);


    List<string> stringlist;

    List<string>::Iterator siter;

    siter = stringlist.begin();

    string bob("hello, world");
    bob += "5";
    stringlist.insert(siter, bob);

    siter = stringlist.begin();

    string boo = *siter;

    printf("boo is %s\n", boo.c_str());

    stringlist.remove(siter);

}

void
stllist()
{
    list<int> intlist;

    std::list<int>::iterator iter;

    iter = intlist.begin();

    intlist.insert(iter, 5);

    iter++;

    intlist.insert(iter, 7);

    intlist.insert(iter, 9);


    list<string> stringlist;
    std::list<string>::iterator siter;
    siter = stringlist.begin();
    stringlist.insert(siter, "hello, world");

}

int
main(int argc, char *argv[])
{
    printf("Doing mylist\n");
    mylist();
    printf("Doing stllist\n");
    stllist();
    return 0;
}

