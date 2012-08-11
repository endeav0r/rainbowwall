#include "net.h"

#include <arpa/inet.h>
#include <stdlib.h>

int rw_packet_net_proto (struct _packet * packet)
{
    // IEE 802.3 frames
    if (ntohs(packet->ethernet_header->h_proto) < 0x600)
        return RW_PACKET_IEEE8023;
    
    // Regular EtherType frames
    switch (ntohs(packet->ethernet_header->h_proto)) {
    case ETH_P_IP :
        return RW_PACKET_IPV4;
    case ETH_P_IPV6 :
        return RW_PACKET_IPV6;
    case ETH_P_ARP :
        return RW_PACKET_ARP;
    }
    
    return RW_PACKET_UNKNOWN;
}


uint32_t rw_packet_ipv4_src (struct _packet * packet)
{
    return packet->ipv4_header->saddr;
}


uint32_t rw_packet_ipv4_dst (struct _packet * packet)
{
    return packet->ipv4_header->daddr;
}


struct in6_addr * rw_packet_ipv6_src (struct _packet * packet)
{
   return &(packet->ipv6_header->ip6_src);
}


struct in6_addr * rw_packet_ipv6_dst (struct _packet * packet)
{
   return &(packet->ipv6_header->ip6_dst);
}


const char * rw_packet_net_dst_str (struct _packet * packet)
{
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
        return inet_ntop(AF_INET, &(packet->ipv4_header->daddr),
                         packet->dst_net_addr, RW_PACKET_ADDR_STR_LEN);
        break;
    case RW_PACKET_IPV6 :
        return inet_ntop(AF_INET6, &(packet->ipv6_header->ip6_dst),
                         packet->dst_net_addr, RW_PACKET_ADDR_STR_LEN);
        break;
    }
    return NULL;
}

    
const char * rw_packet_net_src_str (struct _packet * packet)
{
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
        return inet_ntop(AF_INET, &(packet->ipv4_header->saddr),
                         packet->src_net_addr, RW_PACKET_ADDR_STR_LEN);
        break;
    case RW_PACKET_IPV6 :
        return inet_ntop(AF_INET6, &(packet->ipv6_header->ip6_src),
                         packet->src_net_addr, RW_PACKET_ADDR_STR_LEN);
        break;
    }
    return NULL;
}


// these are the currently supported IPV6 headers
int rw_packet_ipv6_valid_extension (int next_header)
{
    switch (next_header) {
    case IPPROTO_HOPOPTS  :  /* 0  ipv6 hop opts */
    case IPPROTO_ROUTING  :  /* 43 ipv6 routing header */
    case IPPROTO_FRAGMENT :  /* 44 ipv6 fragment header */
    case IPPROTO_DSTOPTS :   /* 60 ipv6 destination options */
        return 1;
    }
    return 0;
}


// get the last extension header
struct ip6_ext * rw_packet_ipv6_last_ext (struct _packet * packet,
                                          int * headers_n)
{
    struct ip6_ext * ext;
    
    *headers_n = 0;
    
    // is this an ipv6 packet
    if (rw_packet_net_proto(packet) != RW_PACKET_IPV6) {
        *headers_n = RW_PACKET_ERR_NET;
        return NULL;
    }
    
    // is the first next header a valid ipv6 extension
    if (! rw_packet_ipv6_valid_extension(
            packet->ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt))
        return NULL;
    
    // loop through extension headers 
    ext = ((void *) packet->ipv6_header) + sizeof(struct ip6_hdr);
    while (rw_packet_ipv6_valid_extension(ext->ip6e_nxt)) {
        switch (ext->ip6e_nxt) {
        case IPPROTO_HOPOPTS :
        case IPPROTO_ROUTING :
        case IPPROTO_DSTOPTS :
            ext = ((void *) ext) + (ext->ip6e_len * 8) + 8;
            break;
        case IPPROTO_FRAGMENT :
            ext = ((void *) ext) + sizeof(struct ip6_frag);
            break;
        // we found a valid extension header, but we're not sure how
        // to calculate the size of it.
        // **this shouldn't happen**
        default :
            *headers_n = RW_PACKET_ERR_IPV6EXT;
            return NULL;
        }
        headers_n++;
    }
    
    // ext should now point to the last extension header, and the next
    // header is not an ipv6 extension header
    return ext;
}


int rw_packet_ipv6_ext_num (struct _packet * packet)
{
    int headers_n = 0;
    
    rw_packet_ipv6_last_ext(packet, &headers_n);
    
    return headers_n;
}


int rw_packet_ipv6_trans_proto (struct _packet * packet)
{
    int headers_n = 0;
    struct ip6_ext * ext;
    
    ext = rw_packet_ipv6_last_ext(packet, &headers_n);
    
    if (headers_n < 0)
        return headers_n;
    else if (headers_n == 0)
        return packet->ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    else
        return ext->ip6e_nxt;
}
    


void * rw_packet_ipv6_data (struct _packet * packet, int * size)
{
    int headers_n;
    void * data = NULL;
    struct ip6_ext * ext;
    
    // get a pointer to the last extensions
    ext = rw_packet_ipv6_last_ext(packet, &headers_n);
    // if headers_n < 0, there was an error. return it
    if (headers_n < 0) {
        *size = headers_n;
        return NULL;
    }
    
    *size = ntohs(packet->ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
    
    // if headers_n == 0, no extension headers. ext should be NULL, so
    // return the address immediately following ipv6_header
    if (headers_n == 0)
        return ((void *) packet->ipv6_header) + sizeof(struct ip6_hdr);
    
    // if headers_n > 0, then we're point at the last extension header.
    // we need to
    // - skip over this extension header
    // - subtract from size
    
    // skip over this extension header
    switch (ext->ip6e_nxt) {
    case IPPROTO_HOPOPTS :
    case IPPROTO_ROUTING :
    case IPPROTO_DSTOPTS :
        data = ((void *) ext) + (ext->ip6e_len * 8) + 8;
    case IPPROTO_FRAGMENT :
        data = ((void *) ext) + sizeof(struct ip6_frag);
    // ** this shouldn't happen **
    default :
        *size = RW_PACKET_ERR_IPV6EXT;
        return NULL;
    }
    
    // readjust size
    // data = the beginning of data
    // everything_else = the address of the first extension header
    *size -= data - (((void *) packet->ipv6_header) + sizeof(struct ip6_hdr));
    
    return data;
}


int rw_packet_ipv4_checksum_gen (struct _packet * packet)
{
    uint16_t old_checksum;
    int checksum = 0;
    uint16_t * data;
    int len, i;
    
    if (rw_packet_net_proto(packet) != RW_PACKET_IPV4)
        return RW_PACKET_ERR_NET;
    
    // replace current checksum with zeros
    old_checksum = packet->ipv4_header->check;
    packet->ipv4_header->check = 0;
    
    data = (uint16_t *) packet->ipv4_header;
    len = packet->ipv4_header->ihl * 4;
    
    // add up all the bytes
    for (i = 0; i < len / 2; i++)
        checksum += data[i];
    
    // fold checksum on itself
    while (checksum >> 16)
        checksum = (checksum & 0xffff) + (checksum >> 16);
    
    // restore checksum
    packet->ipv4_header->check = old_checksum;
    
    return ~checksum & 0x0000ffff;

}


int rw_packet_ipv4_checksum_regen (struct _packet * packet)
{
    if (rw_packet_net_proto(packet) != RW_PACKET_IPV4)
        return RW_PACKET_ERR_NET;
    
    packet->ipv4_header->check = 
                         (uint16_t) rw_packet_ipv4_checksum_gen(packet);

    return 0;
}
