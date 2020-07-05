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
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include "../include/functions.h"
#include "../include/structures.h"
#include "../include/uthash.h"
#include "../include/flow.h"


/* Definition of Hash Table */
struct Hash_T *HT_Flows = NULL;


/* get the pcap error occurred */
extern inline void pcap_fatal(const char *, ...);


/**
   @return n bit from position p of number x
**/
static inline uint8_t getBits(uint16_t x, int p, int n)
{
    return (x >> (p+1-n)) & ~(~0 << n);
}


/**
   Init handle data flow for the callback
   @par p_handle      : the handle of data (pcap or live)
   @return flow_data  : the pointer to data flow
**/
struct flow_callback_proto *flow_callback_proto_init(pcap_t * p_handle)
{
    if(p_handle == NULL)
        exit(EXIT_FAILURE);
    
    struct flow_callback_proto *flow_data = malloc(sizeof(struct flow_callback_proto));
    memset(flow_data, 0, sizeof(struct flow_callback_proto));
    if(flow_data = NULL) {
        perror("flow malloc failed\n");
        return NULL;
    }
    
    flow_data->p_handle = p_handle;

    return flow_data;
}


/**
   Print IPv4 address 
**/
void print_ipv4(uint32_t addr)
{
    unsigned char bytes[4];
    bytes[0] = addr & 0xFF;
    bytes[1] = (addr >> 8) & 0xFF;
    bytes[2] = (addr >> 16) & 0xFF;
    bytes[3] = (addr >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}


/**
   Print IPv6 address 
**/
void print_ipv6(const struct ipv6_addr *addr) {

    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           (int)addr->ipv6_addr[0], (int)addr->ipv6_addr[1],
           (int)addr->ipv6_addr[2], (int)addr->ipv6_addr[3],
           (int)addr->ipv6_addr[4], (int)addr->ipv6_addr[5],
           (int)addr->ipv6_addr[6], (int)addr->ipv6_addr[7],
           (int)addr->ipv6_addr[8], (int)addr->ipv6_addr[9],
           (int)addr->ipv6_addr[10], (int)addr->ipv6_addr[11],
           (int)addr->ipv6_addr[12], (int)addr->ipv6_addr[13],
           (int)addr->ipv6_addr[14], (int)addr->ipv6_addr[15]);
}


/* Function to create the Flow Key from passed arguments */
static void create_Flow_KEY(struct Flow_key *flow_key,
                            const uint8_t ip_version,
                            const struct ipv4_hdr *iphv4,
                            const struct ipv6_hdr *iphv6,
                            const uint16_t src_port,
                            const uint16_t dst_port,
                            const uint8_t proto_id_l3)
{
    // IPv4
    if(ip_version == IPv4) {
        flow_key->ip_src = iphv4->ip_src_addr; // SRC address
        flow_key->ip_dst = iphv4->ip_dst_addr; // DST address
    }
    // IPv6
    else {
        // SRC address
        flow_key->ipv6_src.ipv6_addr[0] = iphv6->ipv6_src.ipv6_addr[0];
        flow_key->ipv6_src.ipv6_addr[1] = iphv6->ipv6_src.ipv6_addr[1];
        flow_key->ipv6_src.ipv6_addr[2] = iphv6->ipv6_src.ipv6_addr[2];
        flow_key->ipv6_src.ipv6_addr[3] = iphv6->ipv6_src.ipv6_addr[3];
        flow_key->ipv6_src.ipv6_addr[4] = iphv6->ipv6_src.ipv6_addr[4];
        flow_key->ipv6_src.ipv6_addr[5] = iphv6->ipv6_src.ipv6_addr[5];
        flow_key->ipv6_src.ipv6_addr[6] = iphv6->ipv6_src.ipv6_addr[6];
        flow_key->ipv6_src.ipv6_addr[7] = iphv6->ipv6_src.ipv6_addr[7];
        flow_key->ipv6_src.ipv6_addr[8] = iphv6->ipv6_src.ipv6_addr[8];
        flow_key->ipv6_src.ipv6_addr[9] = iphv6->ipv6_src.ipv6_addr[9];
        flow_key->ipv6_src.ipv6_addr[10] = iphv6->ipv6_src.ipv6_addr[10];
        flow_key->ipv6_src.ipv6_addr[11] = iphv6->ipv6_src.ipv6_addr[11];
        flow_key->ipv6_src.ipv6_addr[12] = iphv6->ipv6_src.ipv6_addr[12];
        flow_key->ipv6_src.ipv6_addr[13] = iphv6->ipv6_src.ipv6_addr[13];
        flow_key->ipv6_src.ipv6_addr[14] = iphv6->ipv6_src.ipv6_addr[14];
        flow_key->ipv6_src.ipv6_addr[15] = iphv6->ipv6_src.ipv6_addr[15];
        // DST address
        flow_key->ipv6_dst.ipv6_addr[0] = iphv6->ipv6_dst.ipv6_addr[0];
        flow_key->ipv6_dst.ipv6_addr[1] = iphv6->ipv6_dst.ipv6_addr[1];
        flow_key->ipv6_dst.ipv6_addr[2] = iphv6->ipv6_dst.ipv6_addr[2];
        flow_key->ipv6_dst.ipv6_addr[3] = iphv6->ipv6_dst.ipv6_addr[3];
        flow_key->ipv6_dst.ipv6_addr[4] = iphv6->ipv6_dst.ipv6_addr[4];
        flow_key->ipv6_dst.ipv6_addr[5] = iphv6->ipv6_dst.ipv6_addr[5];
        flow_key->ipv6_dst.ipv6_addr[6] = iphv6->ipv6_dst.ipv6_addr[6];
        flow_key->ipv6_dst.ipv6_addr[7] = iphv6->ipv6_dst.ipv6_addr[7];
        flow_key->ipv6_dst.ipv6_addr[8] = iphv6->ipv6_dst.ipv6_addr[8];
        flow_key->ipv6_dst.ipv6_addr[9] = iphv6->ipv6_dst.ipv6_addr[9];
        flow_key->ipv6_dst.ipv6_addr[10] = iphv6->ipv6_dst.ipv6_addr[10];
        flow_key->ipv6_dst.ipv6_addr[11] = iphv6->ipv6_dst.ipv6_addr[11];
        flow_key->ipv6_dst.ipv6_addr[12] = iphv6->ipv6_dst.ipv6_addr[12];
        flow_key->ipv6_dst.ipv6_addr[13] = iphv6->ipv6_dst.ipv6_addr[13];
        flow_key->ipv6_dst.ipv6_addr[14] = iphv6->ipv6_dst.ipv6_addr[14];
        flow_key->ipv6_dst.ipv6_addr[15] = iphv6->ipv6_dst.ipv6_addr[15];
    }

    // SRC port
    flow_key->src_port = src_port;
    // DST port
    flow_key->dst_port = dst_port;

    // PROTO ID L3 (L4)
    flow_key->proto_id_l3 = proto_id_l3;
}


/**
   Function to process a packet
**/
static unsigned int process_packet(const uchar * payload,
                                   const uint16_t size_payload,
                                   const uint8_t ip_version,
                                   const struct ipv4_hdr *iphv4,
                                   const struct ipv6_hdr *iphv6,
                                   const uint16_t src_port,
                                   const uint16_t dst_port,
                                   const uint8_t proto_id_l3,
                                   struct flow_callback_proto *fcp)
{
    int ret = 0;
    
    /**
     *
     * ### KEY ###
     * NOTE: every time a pkt is processed, a new Key is created.
     * The Key is used to check if the pkt belong to an existing flow
     * or we must create a new one.
     * 
     */
    struct Flow_key *flow_key = NULL;
    flow_key = malloc(sizeof(struct Flow_key));
    if(flow_key == NULL) {
        fprintf(stderr, "No memory allocated for flow Key\n");
        exit(EXIT_FAILURE);
    }
    memset(flow_key, 0, sizeof(struct Flow_key));

    /* create the flow key */
    create_Flow_KEY(flow_key, ip_version, iphv4, iph46, src_port, dst_port, proto_id_l3);

    /**
       #################
       # UDP Protocols #
       ################# 
    **/
    if(proto_id_l3 == IPPROTO_UDP) {
        
        // TODO UDP protocols callback here
        
        /* The flow must be added or created inside the protocol dissector
           now we're just trying... */
        // TODO ADD_FLOW
        
    }
    
    /**
       #################
       # TCP Protocols #
       ################# 
    **/
    else if(proto_id_l3 == IPPROTO_TCP){

        // TODO TCP protocols callback here

        /* The flow must be added or created inside the protocol dissector
           now we're just trying... */
        // TODO ADD_FLOW

    } 
    
    return ret;
}



// Protocol callback function
void callback_proto(u_char *args, const struct pcap_pkthdr *pkt_header, const u_char *packet) {


    // define flow based on thread_id on call_thread array
    struct flow_callback_proto *fcp = (struct flow_callback_proto*) args;

    // define ethernet header
    const struct ether_hdr *ethernet_header = NULL;
    // define vlan header
    const struct vlan_hdr *vlan_header = NULL;
    // define mpls 
    union mpls {
        uint32_t u32;
        struct mpls_header mpls;
    } mpls;
    // define radio_tap header
    const struct radiotap_hdr *radiotap_header = NULL;
    // define wifi header
    /* const struct wifi_hdr *wifi_header = NULL; */ // TODO FIX
    // define llc header
    const struct llc_snap_hdr *llc_snap_header = NULL;
    // define ipv4 header
    const struct ipv4_hdr *ipv4_header = NULL;
    // define ipv4 header
    const struct ipv6_hdr *ipv6_header = NULL;
    // define tcp header
    const struct tcp_hdr *tcp_header = NULL;
    // define udp header
    const struct udp_hdr *udp_header = NULL;
    // define payload container
    const u_char *payload = NULL;

    /* lengths and offsets */
    uint16_t check, type = 0, pyld_eth_len = 0;
    uint16_t wifi_len = 0, radiotap_len = 0; /* fc; */
    uint16_t link_offset = 0, ipv4_offset = 0, ipv6_offset = 0;
    uint16_t tcp_offset = 0, udp_offset = 0;
    uint16_t size_payload = 0;

    // check if a SIGINT is arrived
    if(signal_flag){
        /* incoming SIGINT, forcing termination */
        pcap_breakloop(fcp->p_handle);
    }

    printf("\n==== Got a %d byte packet ====\n", pkt_header->len);

    /* ----------------------------------------------------------- */

    /**
       Check Datalink layer
    **/
    const int datalink_type = pcap_datalink(fcp->p_handle);
    switch(datalink_type)
    {
        /** IEEE 802.3 Ethernet - 1 **/
    case DLT_EN10MB:
        ethernet_header = (const struct ether_hdr*)(packet);
        check = ntohs(ethernet_header->type_or_len);
        // ethernet - followed by llc snap 05DC
        if(check <= 1500)
            pyld_eth_len = check;
        // ethernet II - ether type 0600
        else if (check >= 1536)
            type = check;

        // set datalink offset
        link_offset = sizeof(struct ether_hdr);

        // check for LLC layer with SNAP extension
        if(pyld_eth_len != 0) {
            if(packet[link_offset] == SNAP) {
                llc_snap_header = (struct llc_snap_hdr *)(packet + link_offset);
                // SNAP field tells the upper layer protocol
                type = llc_snap_header->type;
                // update datalink offset with LLC/SNAP header len
                link_offset += + 8;
            }
        }
        // update stats
        fcp->stats.ethernet_pkts++;
        break;

        /** Radiotap link-layer**/
    case DLT_IEEE802_11_RADIO:
        radiotap_header = (struct radiotap_hdr *) packet;
        radiotap_len = radiotap_header->len;
        uint8_t flags;
        // Check for FLAG fields
        flags = getBits(radiotap_header->present, 1, 1);
        printf("Flags = %d\n", flags);

        // TODO fix RADIO with WIFI
        
    	break;
        // Wifi data present - check LLC
        llc_snap_header = (struct llc_snap_hdr*)(packet + wifi_len + radiotap_len);
        if(llc_snap_header->dsap == SNAP)
            type = ntohs(llc_snap_header->type);
        else {
            int data = pkt_header->len - radiotap_len - IEEE80211HDR_SIZE;
            printf("Probably a wifi packet of %d bytes with data encription\n", data);
            // update stats
            fcp->stats.wifi_pkts++;
            return;
        }
        link_offset = radiotap_len + wifi_len + sizeof(struct llc_snap_hdr);
        break;

        /*** Linux Cooked Capture ***/
        #ifdef __linux__
    case DLT_LINUX_SLL:
        type = (packet[link_offset+14] << 8) + packet[link_offset+15];
        link_offset = ISDNHDR_SIZE;
        break;
        #endif

        /*** Wi-fi ***/
    case DLT_IEEE802_11:
        // TODO FIX
        break;

    default:
        perror("unsupported interface type\n");
    }

    uint16_t ipv4_type = 0, ipv6_type = 0;
    
    /** CHECK ETHER TYPE **/
    switch(type)
    {
        // IPv4
    case ETHERTYPE_IPv4:
        ipv4_type = 1;
        break;
        // ARP
    case ETHERTYPE_ARP:
        // update stats
        fcp->stats.arp_pkts++;
        break;
        // IPv6
    case ETHERTYPE_IPv6:
        ipv6_type = 1;
        break;
        // VLAN
    case ETHERTYPE_VLAN:
        // update stats
        fcp->stats.vlan_pkts++;
        vlan_header = (struct vlan_hdr *) (packet + link_offset);
        type = ntohs(vlan_header->type);
        // double tagging for 802.1Q
        if(type == 0x8100) {
            link_offset += 4;
            vlan_header = (struct vlan_hdr *) (packet + link_offset);
            type = ntohs(vlan_header->type);
        }
        ipv4_type = (type == ETHERTYPE_IPv4) ? 1 : 0;
        ipv6_type = (type == ETHERTYPE_IPv6) ? 1 : 0;
        link_offset += 4;
        break;
        // MPLS
    case ETHERTYPE_MPLS_UNI:
    case ETHERTYPE_MPLS_MULTI:
        // update stats
        fcp->stats.mpls_pkts++;
        mpls.u32 = *((uint32_t *) &packet[link_offset]);
        mpls.u32 = ntohl(mpls.u32);
        type = ETHERTYPE_IPv4;
        link_offset += 4;
        // multiple MPLS fields
        while(!mpls.mpls.s) {
            mpls.u32 = *((uint32_t *) &packet[link_offset]);
            mpls.u32 = ntohl(mpls.u32);
            link_offset += 4;
        }
        ipv4_type = 1;
        break;
        // PPPoE
    case ETHERTYPE_PPPoE:
        fcp->stats.pppoe_pkts++;
        break;
    }

    /* ----------------------------------------------------------- */

    /**
       Check Network layer
    **/
    uint8_t ip_version;
    uint8_t ip_proto;

    // IPv4
    if(ipv4_type == 1) {
        // decode IP layer
        ip_version = IPv4; // pass to dissector
        ipv4_header = (const struct ipv4_hdr*)(packet + link_offset);
        ipv4_offset = ((uint16_t)ipv4_header->ihl * 4);
        if(ipv4_offset < 20) {
            fprintf(stderr, "Invalid IPv4 header length: %u bytes\n", ipv4_offset);
            return;
        }
        ip_proto = ipv4_header->ip_proto;
        // update stats
        fcp->stats.ipv4_pkts++;
    }
    // IPv6
    else if(ipv6_type == 1) {
        ip_version = IPv6; // pass to dissector
        ipv6_header = (const struct ipv6_hdr*)(packet + link_offset);
        ipv6_offset = sizeof(const struct ipv6_hdr); //IPV6_HDR_LEN
        if(ipv6_offset < IPV6_HDR_LEN) {
            fprintf(stderr, "Invalid IPv6 header length: %u bytes\n", ipv6_offset);
            return;
        }
        ip_proto = ipv6_header->ipv6_ctlun.ipv6_un1.ipv6_un1_next;
        // update stats
        fcp->stats.ipv6_pkts++;
    }
    // NO IP LAYER
    else {
        fprintf(stderr, "No IP layer found -> skip packet\n");
        fcp->stats.discarded_bytes += pkt_header->len;
        return;
    }

    // set ip_offset
    uint16_t ip_offset = (ipv4_type == 0) ? ipv6_offset : ipv4_offset;

    /* ----------------------------------------------------------- */

    /**
       Check Transport layer
    **/
    switch(ip_proto)
    {
    case IPPROTO_TCP: // TCP
        printf("\t Protocol: TCP\n");
        tcp_header = (const struct tcp_hdr *)(packet + link_offset + ip_offset);
        tcp_offset = tcp_header->tcp_offset * 4;
        if(tcp_offset < 20) {
            fprintf(stderr, "Invalid TCP header length: %u bytes\n", tcp_offset);
            return;
        }
        // update stats
        fcp->stats.tcp_pkts++;
        break;
    case IPPROTO_UDP: // UDP
        printf("\t Protocol: UDP\n");
        udp_header = (const struct udp_hdr *)(packet + link_offset + ip_offset);
        // calculate udp header length is useless (UDP header is always 8 byte)
        udp_offset = UDP_HDR_LEN;
        // update stats
        fcp->stats.udp_pkts++;
        break;
    default:
        printf("\t Protocol: unknown\n");
        return;
    }

    // set L4 offset
    uint16_t l4_offset = (ip_proto == IPPROTO_TCP) ? tcp_offset : udp_offset;

    /* ----------------------------------------------------------- */
    
    /**
       Decode payload
    **/
    payload = ((u_char *)(packet + link_offset + ip_offset + l4_offset));

    // compute payload (segment) size
    size_payload = pkt_header->len - ip_offset - l4_offset - link_offset;
    
    // TODO check if we have VSS-monitoring ethernet trailer in latest 2 bytes
    /* size_payload = check_vss_trailer(payload, size_payload); */
    
    if(size_payload > 0)
        printf("\t Payload (%d bytes):\n", size_payload);

    /**
       Function to process a packet
    **/
    check = process_packet(payload,
                           size_payload,
                           ip_version,
                           ipv4_header,
                           ipv6_header,
                           (ip_proto == IPPROTO_TCP) ? ntohs(tcp_header->tcp_src_port) : ntohs(udp_header->udp_src_port),
                           (ip_proto == IPPROTO_TCP) ? ntohs(tcp_header->tcp_dst_port) : ntohs(udp_header->udp_dst_port),
                           ip_proto,
                           fcp);
    if(check == 0) {
        /* printf("Protocol found and parsed\n"); */
    }
    else {
        /* printf("\n\t Other protocols\n\n"); */
    }
}



/**
   Print statistic about the entire session
*/
void print_stats(struct flow_callback_proto * fcp)
{
    printf(" \n---------- DECODER STATISTICS ----------\n\n");

    printf(" # Discarded bytes             = %d\n",   fcp->stats.discarded_bytes);
    printf(" # Ethernet pkts               = %d\n",   fcp->stats.ethernet_pkts);

    printf(" # ARP pkts                    = %d\n",   fcp->stats.arp_pkts);
    printf(" # IPv4 pkts                   = %d\n",   fcp->stats.ipv4_pkts);
    printf(" # IPv6 pkts                   = %d\n",   fcp->stats.ipv6_pkts);

    printf(" # VLAN pkts                   = %d\n",   fcp->stats.vlan_pkts);
    printf(" # MPLS pkts                   = %d\n",   fcp->stats.mpls_pkts);
    printf(" # PPPoE pkts                  = %d\n",   fcp->stats.pppoe_pkts);

    printf(" # TCP pkts                    = %d\n",   fcp->stats.tcp_pkts);
    printf(" # UDP pkts                    = %d\n\n", fcp->stats.udp_pkts);

    printf("\033[0;33m");
    // TODO L7 protocol stats
    printf("\033[0m");

    printf(" ---------- ------------------ ----------\n\n");
}
