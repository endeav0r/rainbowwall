#include "arp.h"

#include "net.h"
#include <string.h>

unsigned char * rw_packet_arp_sender_hw (struct _packet * packet)
{
    if (rw_packet_net_proto(packet) != RW_PACKET_ARP)
        return NULL;
    return packet->arp_header->arp_sha;
}


uint32_t rw_packet_arp_sender_ip (struct _packet * packet)
{
    uint32_t ip;
    if (rw_packet_net_proto(packet) != RW_PACKET_ARP)
        return RW_PACKET_ERR_NET;
    memcpy(&ip, packet->arp_header->arp_spa, 4);
    return ip;
}


unsigned char * rw_packet_arp_target_hw (struct _packet * packet)
{
    if (rw_packet_net_proto(packet) != RW_PACKET_ARP)
        return NULL;
    return packet->arp_header->arp_tha;
}



uint32_t rw_packet_arp_target_ip (struct _packet * packet)
{
    uint32_t ip;
    if (rw_packet_net_proto(packet) != RW_PACKET_ARP)
        return RW_PACKET_ERR_NET;
    memcpy(&ip, packet->arp_header->arp_tpa, 4);
    return ip;
}


int rw_packet_arp_opcode (struct _packet * packet)
{
    if (rw_packet_net_proto(packet) != RW_PACKET_ARP)
        return RW_PACKET_ERR_NET;
    return ntohs(packet->arp_header->ea_hdr.ar_op);
}
