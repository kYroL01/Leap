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

#ifndef FUNCTIONS_H_
#define FUNCTIONS_H_

#include <pcap.h>
#include <signal.h>
#include "structures.h"

/* global variable to represent SIGINT signal */
extern volatile sig_atomic_t signal_flag;

/**
   Get the pcap error occurred
**/
inline static void pcap_fatal(const char *err_name, ...)
{
    fprintf(stderr, "Fatal Error in %s \n", err_name);
}

/**
   Protocol callback function call in pcap_loop 
**/
void callback_proto(u_char *, const struct pcap_pkthdr *, const u_char *);

/**
   Init data flow struct 
**/
struct flow_callback_proto * flow_callback_proto_init(pcap_t *);

/**
   Print statistics
**/
void print_stats(struct flow_callback_proto *);


/** ##### ##### ##### DISSECTOR PROTOTYPES ##### ##### ##### */

// TODO list of dissectors callback

#endif
