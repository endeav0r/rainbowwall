#include "packet.h"
#include "net.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//#define PACKET_DEBUG


void rw_packet_zero(struct _packet * packet)
{
    memset(packet, 0, sizeof(struct _packet));
}


int rw_packet_set (struct _packet * packet, void * data, int size)
{
    if (size > RW_PACKET_FRAME_LEN)
        return RW_PACKET_ERR_SIZE;
    
    memcpy(packet->data, data, size);
    packet->size = size;
    return rw_packet_quick_set(packet);
}


int rw_packet_quick_set (struct _packet * packet)
{
    void * network; // pointer to start of network layer bytes
    int tmp;
    
    if ((packet->size < 0) || (packet->size > RW_PACKET_FRAME_LEN))
        return RW_PACKET_ERR_SIZE;

    packet->ethernet_header = (struct ethhdr *) packet->data;
    network = packet->data + sizeof(struct ethhdr);

    // check for IEE 802.3 packets
    if (ntohs(packet->ethernet_header->h_proto) < 0x600)
        return 0;
    
    // check for regular EtherType packets
    switch (ntohs(packet->ethernet_header->h_proto)) {
    case ETH_P_IP :
        packet->ipv4_header = (struct iphdr *) network;
        // we aren't concerned with checking whether this is actually a
        // udp/tcp packet just yet
        packet->tcp_header = ((void *) packet->ipv4_header) +
                             ((packet->ipv4_header->ihl & 0xf) * 4);
        return 0;
    case ETH_P_ARP :
        packet->arp_header = (struct ether_arp *) network;
        return 0;
    case ETH_P_IPV6 :
        packet->ipv6_header = (struct ip6_hdr *) network;
        // we aren't concerned with checking whether this is actually a
        // udp/tcp packet just yet
        packet->tcp_header = rw_packet_ipv6_data(packet, &tmp);
        return 0;
    default :
        #ifdef PACKET_DEBUG
            printf("proto: %04x\n", ntohs(packet->ethernet_header->h_proto));
            fflush(stdout);
            FILE * fh = fopen("packet_debug", "wb");
            fwrite(packet->data, 1, packet->size, fh);
            fclose(fh);
            exit(-1);
        #endif
        return RW_PACKET_ERR_NET;
    }
}


void * rw_packet_raw(struct _packet * packet, int * size)
{
    *size = packet->size;
    return packet->data;
}


unsigned char * rw_packet_ether_src (struct _packet * packet)
{
    return packet->ethernet_header->h_source;
}


unsigned char * rw_packet_ether_dst (struct _packet * packet)
{
    return packet->ethernet_header->h_dest;
}
