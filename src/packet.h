#ifndef packet_HEADER
#define packet_HEADER

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <inttypes.h>

#define RW_PACKET_ADDR_STR_LEN 64
/* must be greater than largest possible packet (usually defined as
 * 1518 in ETH_FRAME_LEN).
 * this will greatly affect memory usage from lua.
 */

#define RW_PACKET_FRAME_LEN    16000

// all of the below constants should be unique and non-zero
// don't pay attention to what category they're in
// they should be UNIQUE BECAUSE YOU DON'T KNOW HOW THEY'RE USED
// (unique)

#define RW_PACKET_UNKNOWN      -1 /* used several times when the matched
                                     value/protocol is unknown */
#define RW_PACKET_ERR_SIZE     -2 /* size of frame was too large/small */
#define RW_PACKET_ERR_NET      -3 /* invalid (or unsupported) network
                                     layer protocol */
#define RW_PACKET_ERR_IPV6EXT  -4 /* invalid ipv6 extension */
#define RW_PACKET_ERR_TRANS    -5 /* invalid (or unsupported) trans layer
                                     protocol */
                                     
                                     
/* RW_PACKET_ERR_ RANGE VALUES RESERVED
 * These error values are to be used by the respective modules only
 * -500  through -999  for capture
 * -1000 through -1999 for trans
 * -2000 through -2999 for net
 * -3000 through -3999 for icmp
 * -4000 through -4999 for tcp_streams
 * -5000 through -5999 for pcap
 */

#define RW_PACKET_IPV4     4
#define RW_PACKET_IPV6     6
#define RW_PACKET_ARP      7
#define RW_PACKET_IEEE8023 8 /* If the length field of an ethernet frame
                             * is < 0x600, then h_proto field of the
                             * ethernet frame is actually a length field
                             * as determined by the IEE 802.3 standard.
                             * This is a huge PITA, mark the packet as
                             * IEE8023 and if we're concerned with the
                             * contents later we'll deal with it then.
                             */

#define RW_PACKET_TCP  10
#define RW_PACKET_UDP  11
#define RW_PACKET_ICMP 12
#define RW_PACKET_OSPF 13
#define RW_PACKET_IGMP 14


struct _packet {
    // size and data of the complete, raw fraw
    int size;
    unsigned char data[RW_PACKET_FRAME_LEN];
    
    // these hold the ASCII representations of the src/dst address
    char dst_net_addr[RW_PACKET_ADDR_STR_LEN];
    char src_net_addr[RW_PACKET_ADDR_STR_LEN];
    
    struct ethhdr *  ethernet_header;
    
    union {
        struct iphdr *     ipv4_header;
        struct ip6_hdr *   ipv6_header;
        struct ether_arp * arp_header;
    };
    union {
        struct tcphdr *  tcp_header;
        struct udphdr *  udp_header;
        struct icmphdr * icmp_header;
    };
};


/** zeroes out all fields of the packet
 * @param packet packet to zero out
 */
void rw_packet_zero (struct _packet * packet);

/** sets a packet header appropriately based on passed data, which should point
 *  to a raw ethernet frame
 * @param packet an allocated _packet struct
 * @param data the raw ethernet frame
 * @param size size of data in bytes
 * return 0 on success, error code on failure.
 */
int rw_packet_set (struct _packet * packet, void * data, int size);

/** sets the packet header appropriately based off the data and size
 *  values already used in the packet.
 * @param packet the packet with data and size already set
 */
int rw_packet_quick_set (struct _packet * packet);

/** returns the raw packet data
 * @param packet
 * @param size will be set to the size of data in bytes
 * @return a pointer to the raw packet data
 */
void * rw_packet_raw (struct _packet * packet, int * size);

/** returns a pointer to 6 bytes which hold the source ethernet address
 * @param packet the _packet for the frame
 * @return a pointer to the 6 bytes of the ethernet source address, or NULL on
 *         error
 */
unsigned char * rw_packet_ether_src (struct _packet * packet);

/** returns a pointer to 6 bytes which hold the destination ethernet address
 * @param packet the _packet for the frame
 * @return a pointer to the 6 bytes of the ethernet destination address, or
 *         NULL on error
 */
unsigned char * rw_packet_ether_dst (struct _packet * packet);

#endif
