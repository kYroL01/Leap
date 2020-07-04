/**
   Implementation of main functions

   Leap - network protocols and much more
   Copyright (C) 2020 Michele Campus <fci1908@gmail.com>
   Copyright (C) 2020 Giusepe Longo  <giuseppe@glongo.it>

   Leap is free software: you can redistribute it and/or modify it under the
   terms of the GNU General Public License as published by the Free Software
   Foundation, either version 3 of the License, or (at your option) any later
   version.

   Leap is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE. See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along with
   Leap. If not, see <http://www.gnu.org/licenses/>.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/functions.h"
#include "../include/structures.h"
#include "../include/uthash.h"
#include "../include/flow.h"


/* ### Declaration of HASH TABLE ### */
extern struct Hash_Table *HT_Flows;


/* TODO */
// ADD NEW FLOW
static void add_flow(struct Flow_key *key, struct Hash_T *flow_in)

    
// FIND FLOW BY KEY
struct Hash_T *find_flow_by_key(struct Flow_key *key)
{
    struct Hash_T *flow_in;

    // search the flow by key
    HASH_FIND(hh, HT_Flows, key, sizeof(struct Flow_key), flow_in);

    return flow_in;
}


// DELETE FLOW BY KEY
void delete_flow_by_key(struct Flow_key *key)
{
    struct Hash_T *flow_in;

    // search the flow by a key
    HASH_FIND(hh, HT_Flows, key, sizeof(struct Flow_key), flow_in);
    if(flow_in) {
        HASH_DEL(HT_Flows, flow_in);
        free(flow_in);
    }
    else
        printf("Flow not found\n");
}


// DELETE ALL FLOWS
void delete_all_flows()
{
    struct Hash_T *f, *tmp;

    HASH_ITER(hh, HT_Flows, f, tmp) {
        HASH_DEL(HT_Flows, f);  /* delete it (and advance to next) */
        free(f);
    }
}
