/**
   Implementation of main functions

   Leap - network protocols and much more
   Copyright (C) 2020 Michele Campus <michelecampus5@gmail.com>
   Copyright (C) 2020 Giuseppe Longo <giuseppe@glongo.it>

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
extern struct Hash_T *HT_Flows;


// ADD NEW FLOW
static void add_flow(struct Flow_KEY *key)
{
    struct Hash_T *new_flow;

    /* check if the flow is in the hashtable */
    HASH_FIND(hh, HT_Flows, &key, sizeof(struct Flow_KEY), new_flow);

    if(new_flow == NULL) {
        
        // alloc mem for new elem
        new_flow = malloc(sizeof(struct Hash_T));
        // set memory to 0
        memset(new_flow, 0, sizeof(struct Hash_T));
        // set KEY
        memcpy(&new_flow->flow_key_hash, key, sizeof(struct Flow_key));
        /* flow_in.flow_key_hash = key; */ // TODO check if we can assign a structure in this way
        // add new elem in Hash Table
        HASH_ADD(hh, HT_Flows, flow_key_hash, sizeof(struct Flow_KEY), new_flow);
        
    } else {
        // TODO Update existing flow
    }
    
    // TODO check if there are mandatory operations
}

    
// FIND FLOW BY KEY
struct Hash_T *find_flow_by_key(struct Flow_KEY *key)
{
    struct Hash_T *flow_in;

    // search the flow by key
    HASH_FIND(hh, HT_Flows, key, sizeof(struct Flow_KEY), flow_in);

    return flow_in;
}


// DELETE FLOW BY KEY
void delete_flow_by_key(struct Flow_KEY *key)
{
    struct Hash_T *flow_in;

    // search the flow by a key
    HASH_FIND(hh, HT_Flows, key, sizeof(struct Flow_KEY), flow_in);
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
    struct Hash_T *flow, *tmp;

    HASH_ITER(hh, HT_Flows, flow, tmp) {
        HASH_DEL(HT_Flows, flow);  /* delete it (and advance to next) */
        free(flow);
    }
}


// PRINT FLOWS
void print_Flows(uint8_t ip_version)
{
    struct Hash_T *el;
    int n = 1, f = 1;

    printf("\n###### HASH TABLE ######\n");
    printf("Total flows stored = %d\n", n = HASH_COUNT(HT_Flows));

    if(n > 0) {
        for(el = HT_Flows; el != NULL; el = (struct Hash_Table*)(el->hh.next)) {

            printf("Flow %d: \n", f++);

            printf("IP Source Addr = ");
            if(ip_version == IPv4)
                print_ipv4(el->flow_key_hash.ip_src);
            else
                print_ipv6(&el->flow_key_hash.ipv6_src);

            printf("IP Dest Addr = ");
            if(ip_version == IPv4)
                print_ipv4(el->flow_key_hash.ip_dst);
            else
                print_ipv6(&el->flow_key_hash.ipv6_dst);

            printf("Src Port = %d\n", el->flow_key_hash.src_port);
            printf("Dst Port = %d\n", el->flow_key_hash.dst_port);
        }
    }
}
