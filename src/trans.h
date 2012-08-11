/*
 * Generic code for dealing with transport layer
 * All TCP/UDP code lives here
 */

#ifndef trans_HEADER
#define trans_HEADER

#include <inttypes.h>

#include "packet.h"

/* When we call rw_packet_tcp_resize, we check to make sure that the new
 * packet size will be less than max(original packet size, or
 * RW_PACKET_TCP_DATA_RESIZE). If resizing the packet would cause the
 * total packet size to go over that length, we return an error.
 */
#define RW_PACKET_TCP_DATA_RESIZE 1500


#define RW_PACKET_ERR_TCP_RESIZE -1000

// These should be set to the actual values used in TCP Packets
#define RW_PACKET_TCP_SYN  0x1
#define RW_PACKET_TCP_FIN  0x2
#define RW_PACKET_TCP_RST  0x4
#define RW_PACKET_TCP_PUSH 0x8
#define RW_PACKET_TCP_ACK  0x10
#define RW_PACKET_TCP_URG  0x20


/** Get the raw transportation layer protocol number straight from the
 *  packet. Often used for debugging
 * @param packet
 * @return trans protocol id straight from packet, as defined in RFC, or
 *         RW_PACKET_ERR_NET for invalid network layer protocol
 */
int rw_packet_trans_proto_raw (struct _packet * packet);

/** Get the transportation (or equivalent) layer protocol
 * @param packet
 * @return transportation layer protocol, RW_PACKET_ERR_NET on invalid
 *         network layer protocol, and RW_PACKET_ERR_TRANS on invalid
 *         transport layer protocol.
 */
int rw_packet_trans_proto (struct _packet * packet);

/** returns the transport layer source port number, or -1 if there is no
 *  valid transport layer for port numbers
 * @param packet
 * @param port number in host-byte order, or RW_PACKET_ERR_TRANS for
 *        invalid transport layer protocol
 */
int rw_packet_trans_port_src (struct _packet * packet);

/** returns the transport layer destination port number, or -1 if there
 *  is no svalid transport layer for port numbers
 * @param packet
 * @param port number in host-byte order, or RW_PACKET_ERR_TRANS for
 *        invalid transport layer protocol
 */
int rw_packet_trans_port_dst (struct _packet * packet);

/** returns the number of bytes in this packet's data segment. Most
 *  useful in TCP/UDP.
 * @param packet
 * @return >= 0 for the number of data bytes in this packet, or 
 *         RW_PACKET_ERR_TRANS for an invalid transport layer.
 */
int rw_packet_data_size (struct _packet * packet);

/** returns a pointer to the data bytes of this packet
 * @param packet
 * @return a valid pointer to the data bytes of this packet, or NULL on
 *         error (most likely invalid protocol).
 */
void * rw_packet_data (struct _packet * packet);

/** returns the tcp flags
 * @param packet
 * @return an integer with the TCP flags set, or RW_PACKET_ERR_TRANS if
 *         this is not a TCP packet. Check for the error!
 */
int rw_packet_tcp_flags (struct _packet * packet);

/** generates a tcp checksum for the packet, which must be tcp on top of
 *  either ipv4 or ipv6
 * @param packet tcp packet on top of ipv4 or ipv6
 * @return the 16-bit checksum in network order, or an error if negative. 
 *         errors are RW_PACKET_ERR_TRANS if not TCP or
 *         RW_PACKET_ERR_NET if invalid (or unsupported) network layer
 */
int rw_packet_tcp_checksum_gen (struct _packet * packet);

/** regenerates the tcp checksum for the packet, and sets the tcp packet
 *  checksum accordingly
 * @param packet tcp packet on top of ipv4 or ipv6
 * @return 0 on success, RW_PACKET_ERR_NET on invalid net layer,
 *         RW_PACKET_ERR_TRANS on non-tcp transport layer
 */
int rw_packet_tcp_checksum_regen (struct _packet * packet);

/** updates data for a tcp packet, setting all of the necessary fields
 *  in the tcp and ip headers to allow the packet to validate
 * @param packet a tcp packet to modify
 * @param data the data to replace existing data with
 * @param size the size of data in bytes
 * @return 0 on success, RW_PACKET_ERR_TRANS if this is not a tcp
 *         packet, or RW_PACKET_ERR_TCP_RESIZE if this modification
 *         would cause the packet to become too large
 */
int rw_packet_tcp_update_data (struct _packet * packet,
                               void * data,
                               int data_len);

/** returns the tcp sequence number
 * @param packet a valid tcp packet
 * @return The TCP sequence number in host order. This returns 0 on
 *         error, but as 0 is also a valid TCP Sequence number, you 
 *         should check that this is a valid TCP packet with 
 *         rw_packet_trans_proto()
 */
uint32_t rw_packet_tcp_seq (struct _packet * packet);

/** returns the tcp acknowledgement number
 * @param packet a valid tcp packet
 * @return The TCP acknowledgement number in host order. This returns 0
 *         on error, but as 0 is also a valid TCP sequence number, you
 *         should check that this is a valid TCP packet with
 *         rw_packet_trans_proto()
 */
uint32_t rw_packet_tcp_ack (struct _packet * packet);

#endif
