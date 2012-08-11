#include "icmp.h"

#include "net.h"
#include "trans.h"

int rw_packet_icmp_type (struct _packet * packet)
{
    // deal with valid ICMP packets
    switch (rw_packet_trans_proto(packet)) {
    case RW_PACKET_ICMP :
        switch (packet->icmp_header->type) {
        case ICMP_ECHO      : return RW_PACKET_ICMP_ECHO;
        case ICMP_ECHOREPLY : return RW_PACKET_ICMP_ECHOREPLY;
        case ICMP_DEST_UNREACH :
            switch (packet->icmp_header->code) {
            case ICMP_NET_UNREACH  : return RW_PACKET_ICMP_NET_UNREACH;
            case ICMP_HOST_UNREACH : return RW_PACKET_ICMP_HOST_UNREACH;
            default : return RW_PACKET_ICMP_UNREACH_UNKNOWN;
            }
        default : return RW_PACKET_UNKNOWN;
        }
    }
    
    // make sure not a net layer error
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :
    case RW_PACKET_IPV6 :
        return RW_PACKET_ERR_TRANS;
    }
    
    return RW_PACKET_ERR_NET;
}       
