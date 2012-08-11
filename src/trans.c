#include "trans.h"

#include "net.h"

#include <stdio.h>
#include <string.h>

// netinet/in.h dropping the ball
#ifndef IPPROTO_OSPF
    #define IPPROTO_OSPF 89
#endif


int rw_packet_trans_proto_raw (struct _packet * packet)
{
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
        return packet->ipv4_header->protocol;
    case RW_PACKET_IPV6 :
        return rw_packet_ipv6_trans_proto(packet);
    }
    return RW_PACKET_ERR_NET;
}


int rw_packet_trans_proto (struct _packet * packet)
{
    int protocol = rw_packet_trans_proto_raw(packet);
    
    if (protocol < 0)
        return protocol;
    
    switch (protocol) {
    case IPPROTO_TCP  : return RW_PACKET_TCP;
    case IPPROTO_UDP  : return RW_PACKET_UDP;
    case IPPROTO_ICMP : return RW_PACKET_ICMP;
    case IPPROTO_OSPF : return RW_PACKET_OSPF;
    case IPPROTO_IGMP : return RW_PACKET_IGMP;
    }
    
    return RW_PACKET_ERR_TRANS;

}


int rw_packet_trans_port_src (struct _packet * packet)
{
    switch (rw_packet_trans_proto(packet)) {
    case RW_PACKET_TCP :
        return ntohs(packet->tcp_header->source);
    case RW_PACKET_UDP :
        return ntohs(packet->udp_header->source);
    }
    return RW_PACKET_ERR_TRANS;
}


int rw_packet_trans_port_dst (struct _packet * packet)
{
    switch (rw_packet_trans_proto(packet)) {
    case RW_PACKET_TCP :
        return ntohs(packet->tcp_header->dest);
    case RW_PACKET_UDP :
        return ntohs(packet->udp_header->dest);
    }
    return RW_PACKET_ERR_TRANS;
}


int rw_packet_data_size (struct _packet * packet)
{
    void * tmp;
    int size;
    
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
        switch (rw_packet_trans_proto(packet)) {
        case RW_PACKET_TCP :
            return ntohs(packet->ipv4_header->tot_len) - 
                   (packet->ipv4_header->ihl * 4) -
                   (packet->tcp_header->doff * 4);
        case RW_PACKET_UDP :
            return ntohs(packet->ipv4_header->tot_len) - 
                   (packet->ipv4_header->ihl * 4) -
                   sizeof(struct udphdr);
        }
    
    case RW_PACKET_IPV6 :
        switch (rw_packet_trans_proto(packet)) {
        case RW_PACKET_TCP :
            tmp = rw_packet_ipv6_data(packet, &size);
            if (tmp) return size - (packet->tcp_header->doff * 4);
            else return RW_PACKET_ERR_IPV6EXT;
        case RW_PACKET_UDP :
            tmp = rw_packet_ipv6_data(packet, &size);
            if (tmp) return size - sizeof(struct udphdr);
            else return RW_PACKET_ERR_IPV6EXT;
        }
    };
    return RW_PACKET_ERR_TRANS;
}


void * rw_packet_data (struct _packet * packet)
{
    if (rw_packet_data_size(packet) < 0)
        return NULL;
    
    switch (rw_packet_trans_proto(packet)) {
    case RW_PACKET_TCP :
        return ((void *) packet->tcp_header) + 
               (packet->tcp_header->doff * 4);
    case RW_PACKET_UDP :
        return ((void *) packet->tcp_header) + sizeof (struct udphdr);
    }
    
    return NULL;
}


int rw_packet_tcp_flags (struct _packet * packet)
{
    int flags = 0;
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        return RW_PACKET_ERR_TRANS;
        
    flags = ((packet->tcp_header->syn) ? RW_PACKET_TCP_SYN  : 0) | 
            ((packet->tcp_header->fin) ? RW_PACKET_TCP_FIN  : 0) | 
            ((packet->tcp_header->rst) ? RW_PACKET_TCP_RST  : 0) | 
            ((packet->tcp_header->psh) ? RW_PACKET_TCP_PUSH : 0) | 
            ((packet->tcp_header->ack) ? RW_PACKET_TCP_ACK  : 0) | 
            ((packet->tcp_header->urg) ? RW_PACKET_TCP_URG  : 0);
            
    return flags;
}


int rw_packet_tcp_checksum_gen (struct _packet * packet) {
    int checksum = 0;
    uint16_t old_checksum;
    uint16_t * data;
    int len;
    int i;
    
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        return RW_PACKET_ERR_TRANS;
    
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
        data = (uint16_t *) packet->tcp_header;
        len  = packet->tcp_header->doff * 4;
        len += rw_packet_data_size(packet);
        
        // temporarily set the checksum to 0
        old_checksum = packet->tcp_header->check;
        packet->tcp_header->check = 0;
        
        /* this is the format of the tcp pseudo header for ipv4 tcp
         *  checksum
         * [16 bit word] descrption of data
         * [0-1] SRC IP
         * [2-3] DST IP
         * [4]   IPPROTO_TCP
         * [5]   TCP_LENGTH
         *       The TCP Length is the TCP header length plus the data length in
         *       octets (this is not an explicitly transmitted quantity, but is
         *       computed), and it does not count the 12 octets of the pseudo
         *       header.
         */
        // compute checksum for pseudo header
        checksum += packet->ipv4_header->saddr >> 16;
        checksum += packet->ipv4_header->saddr & 0xffff;
        checksum += packet->ipv4_header->daddr >> 16;
        checksum += packet->ipv4_header->daddr & 0xffff;
        checksum += ntohs(IPPROTO_TCP);
        checksum += ntohs(len);
        
        for (i = 0; i < len / 2; i++)
            checksum += data[i];
        
        // if len was odd, adjust appropriately
        if (len & 1)
            checksum += data[i] & 0x00ff;
        
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        
        // restore old checksum
        packet->tcp_header->check = old_checksum;
        
        return ~checksum & 0x0000ffff;
    
    case RW_PACKET_IPV6 :
        data = (uint16_t *) packet->tcp_header;
        len  = packet->tcp_header->doff * 4;
        len += rw_packet_data_size(packet);
        
        // temporarily set the checksum to 0
        old_checksum = packet->tcp_header->check;
        packet->tcp_header->check = 0;
        
        /* this is the format of the tcp pseudo header for ipv6 tcp
         *  checksum
         * [16 bit word] descrption of data
         * [0-7]   SRC IP
         * [8-15]  DST IP
         * [16-19] TCP_LENGTH
         *       The TCP Length is the TCP header length plus the data length in
         *       octets (this is not an explicitly transmitted quantity, but is
         *       computed), and it does not count the pseudo header.
         * [20-22] Zeroes
         * [23]    IPPROTO_TCP
         */
         
        // compute checksum for pseudo header
        // ipv6 src address
        data = (uint16_t *) &(packet->ipv6_header->ip6_src);
        for (i = 0; i < 8; i++)
            checksum += data[i];
        
        // ipv6 dst address
        data = (uint16_t *) &(packet->ipv6_header->ip6_dst);
        for (i = 0; i < 8; i++)
            checksum += data[i];
        
        // len
        checksum += len >> 16;
        checksum += len & 0xffff;
        
        // IPPROTO_TCP
        checksum += IPPROTO_TCP;
        
        for (i = 0; i < len / 2; i++)
            checksum += data[i];
        
        // if len was odd, adjust appropriately
        if (len & 1)
            checksum += data[i] & 0x00ff;
        
        while (checksum >> 16)
            checksum = (checksum & 0xffff) + (checksum >> 16);
        
        // restore old checksum
        packet->tcp_header->check = old_checksum;
        
        return ~checksum & 0x0000ffff;
    }
    
    return RW_PACKET_ERR_NET;
}


int rw_packet_tcp_checksum_regen (struct _packet * packet)
{
    int checksum;
    
    checksum = rw_packet_tcp_checksum_gen(packet);
    
    if (checksum < 0)
        return checksum;
    
    packet->tcp_header->check = (uint16_t) checksum;
    
    return 0;
}


int rw_packet_tcp_update_data (struct _packet * packet,
                               void * data,
                               int data_len)
{
    int size_diff;
    void * tcp_data;
    
    // check for tcp packet
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        return RW_PACKET_ERR_TRANS;

    // will resizing this packet cause the whole packet to become
    // too large
    size_diff = data_len - rw_packet_data_size(packet);
    if (size_diff > 0) {
        if (packet->size + size_diff > RW_PACKET_TCP_DATA_RESIZE)
            return RW_PACKET_ERR_TCP_RESIZE;
    }
    
    // tcp operations
    // update the data
    tcp_data = rw_packet_data(packet);
    memcpy(tcp_data, data, data_len);
    
    // regen tcp checksum
    rw_packet_tcp_checksum_regen(packet);
    
    // ipv4/ipv6 operations
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
        // update ipv4 packet totlen
        packet->ipv4_header->tot_len = 
         htons(((int) ntohs(packet->ipv4_header->tot_len)) + size_diff);
        
        // regen ip checksum
        rw_packet_ipv4_checksum_regen(packet);
        
        return 0;
    case RW_PACKET_IPV6 :
        // update ipv6 payload length
        packet->ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen =
htons(((int) ntohs(packet->ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen)) +
               size_diff);
        
        return 0;
    }
    // this should never happen. we probably corrupted the packet too!
    return RW_PACKET_ERR_NET;
}


uint32_t rw_packet_tcp_seq (struct _packet * packet)
{
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        return 0;
   
    return ntohl(packet->tcp_header->seq);
}


uint32_t rw_packet_tcp_ack (struct _packet * packet)
{
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        return 0;
   
    return ntohl(packet->tcp_header->ack_seq);
}
