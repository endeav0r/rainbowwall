/*
 * Functions for dealing with the network layer of packets
 */

#ifndef net_HEADER
#define net_HEADER

#include "packet.h"

/** Get the network layer protocol
 * @param packet
 * @return network layer protocol
 */
int rw_packet_net_proto (struct _packet * packet);

/** Get the ipv4 destination host address
 * @param packet
 * @return 4 bytes for the ip dst in network byte order
 */
uint32_t rw_packet_ipv4_dst (struct _packet * packet);

/** Get the ipv4 source host address
 * @param packet
 * @return 4 bytes for the ip src in network byte order
 */
uint32_t rw_packet_ipv4_src (struct _packet * packet);

/** Get the ipv6 destination host address
 * @param packet
 * @return pointer to the destination in6_addr struct
 */
struct in6_addr * rw_packet_ipv6_dst (struct _packet * packet);

/** Get the ipv6 source host address
 * @param packet
 * @return pointer to the destination in6_addr struct
 */
struct in6_addr * rw_packet_ipv6_src (struct _packet * packet);

/** returns a string representation of the destination host address
 * @param packet
 * @return a string representation of the destination host address. 
 *         Returns NULL on an invalid network layer protocol.
 */
const char * rw_packet_net_dst_str (struct _packet * packet);

/** returns a string representation of the destination host address
 * @param packet
 * @return a string representation of the destination host address.
 *         Returns NULL on an invalid network layer protocol.
 */
const char * rw_packet_net_src_str (struct _packet * packet);

/** returns the number of extension headers this IPv6 packet contains.
 * @param packet
 * @return >= 0 for the number of extension headers in this packet,
 *         RW_PACKET_ERR_IPV6EXT fs an ipv6 extension was found but its
 *         implementation is incomplete, RW_PACKET_ERR_NET if this is
 *         not an IPV6 packet.
 */
int rw_packet_ipv6_ext_num (struct _packet * packet);

/** returns the transport layer protocol carried by this ipv6 packet
 *  after all extension headers have been skipped over
 * @param packet
 * @param size contains the size of data in bytes, or, it negative,
 *        contains an error code RW_PACKET_ERR_NET if not ipv6,
 *        RW_PACKET_ERR_IPV6EXT if invalid ipv6 extension found (contact
 *        upstream on RW_PACKET_ERR_IPV6EXT
 * @return a pointer to the data, or NULL on error
 */
void * rw_packet_ipv6_data (struct _packet * packet, int * size);

/** return the transport layer protocol (next header after last valid 
 *  ipv6 extension). This returns the actual value in the ipv6 header.
 *  For RW_PACKET_ values, use rw_packet_trans_proto.
 * @param packet
 * @return The transport layer protocol, or RW_PACKET_ERR_NET if not an
 *         ipv6 packet, or RW_PACKET_ERR_IPV6EXT (contact upstream)
 */
int rw_packet_ipv6_trans_proto (struct _packet * packet);

/** generates a network (ipv4) checksum for the packet. note ipv6 does
 *  not generate a checksum
 * @param packet a valid ipv4 packet
 * @return 1 16-bit checksum in network order, or, if negative,
 *         RW_PACKET_ERR_NET to indicate an invalid network layer packet
 */
int rw_packet_ipv4_checksum_gen (struct _packet * packet);

/** regenerates the checksum for the network layer packet (ipv4) and
 *  sets the packet checksum appropriately
 * @param packet a valid ipv4 packet
 * @return 0 on success, or RW_PACKET_ERR_NET to indicate an invalid
 *         network layer packet
 */
int rw_packet_ipv4_checksum_regen (struct _packet * packet);

#endif
