/**
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

#ifndef FLOW_H_
#define FLOW_H_

#include "structures.h"
#include "uthash.h"

union ip_src
{
    // IPv4
    u_int32_t ip_src;
    // IPv6
    struct ipv6_addr ipv6_src;
};
union ip_dst
{
    // IPv4
    u_int32_t ip_dst;
    // IPv6
    struct ipv6_addr ipv6_dst;
}

/* Flow_KEY is the key in the hashtable */
struct Flow_KEY
{
    union ip_src ip_src;
    union ip_dst ip_dst;
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int8_t proto_id_l3;
};

/*** HASH TABLE ***/
struct Hash_T
{
    struct Flow_KEY flow_key_hash; // Key
    // TODO check which field we need to add
    UT_hash_handle hh;
};


/***** Functions for the HASH TABLE *****/

/**
   Add new flow
   @par key     : the key
   @par flow_in : the value
 **/
static void add_flow(struct Flow_KEY *key)

/**
   Find flow by key
   @par key
   
   @return elem : if elem exists in the hash table
   @return NULL : if elem is not present
**/
struct Hash_T *find_flow_by_key(struct Flow_KEY *key);

/**
   Delete flow by key
   @par key
**/
void delete_flow_by_key(struct Flow_KEY *key);

/**
   Delete all flows
**/
void delete_all_flows();


#endif
