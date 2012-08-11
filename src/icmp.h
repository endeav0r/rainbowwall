#ifndef icmp_HEADER
#define icmp_HEADER

#include "packet.h"

#include <netinet/ip_icmp.h>

// these should be set to the actual ICMP values
#define RW_PACKET_ICMP_ECHOREPLY    1
#define RW_PACKET_ICMP_ECHO         2

#define RW_PACKET_ICMP_NET_UNREACH  3
#define RW_PACKET_ICMP_HOST_UNREACH 4

#define RW_PACKET_ICMP_UNKNOWN         -3000
#define RW_PACKET_ICMP_UNREACH_UNKNOWN -3001

/** get the type of this ICMP packet. Combines common type and code
 *  fields
 * @param packet
 * @return A RW_PACKET_ICMP_ designator, or RW_PACKET_ERR_NET on an 
 *         invalid network layer protocol, or RW_PACKET_ERR_TRANS if
 *         this is not an ICMP packet (yes, I know ICMP isn't really
 *         trans layer, but it does sit on top of ipv4/ipv6)
 */
int rw_packet_icmp_type (struct _packet * packet);

#endif
