#ifndef arp_HEADER
#define arp_HEADER

#include "packet.h"

// These need to match the values found in the RFC
#define RW_PACKET_ARP_REQUEST   1
#define RW_PACKET_ARP_REPLY     2
#define RW_PACKET_ARP_RREQUEST  3
#define RW_PACKET_ARP_RREPLY    4
#define RW_PACKET_ARP_INREQUEST 5
#define RW_PACKET_ARP_INREPLY   9
#define RW_PACKET_ARP_NAK       10

unsigned char * rw_packet_arp_sender_hw (struct _packet * packet);
uint32_t        rw_packet_arp_sender_ip (struct _packet * packet);
unsigned char * rw_packet_arp_target_hw (struct _packet * packet);
uint32_t        rw_packet_arp_target_ip (struct _packet * packet);
int             rw_packet_arp_opcode    (struct _packet * packet);

#endif
