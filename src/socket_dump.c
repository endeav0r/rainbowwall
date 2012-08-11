#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "capture.h"
#include "packet.h"
#include "net.h"
#include "trans.h"
#include "arp.h"

char tmp_string[128];

char * mac_string (unsigned char * mac_address)
{
    snprintf(tmp_string, 128, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_address[0], mac_address[1], mac_address[2],
             mac_address[3], mac_address[4], mac_address[5]);
    return tmp_string;
}

char * ipv4_string (uint32_t addr)
{
    snprintf(tmp_string, 128, "%d.%d.%d.%d",
             (addr & 0xff),       (addr >> 8) & 0xff,
             (addr >> 16) & 0xff, (addr >> 24) & 0xff);
    return tmp_string;
}

char * printable_buf (const char * data, int length)
{
    int i;
    
    if (length < 0)
        return NULL;
        
    if (length > 127) length = 127;
    for (i = 0; i < length; i++) {
        if ((data[i] >= 32) && (data[i] < 127))
            tmp_string[i] = data[i];
        else
            tmp_string[i] = '.';
    }
    
    tmp_string[i] = '\0';
    return tmp_string;
}

int main ()
{
    int i;
    struct _packet  packet;
    struct _capture capture;
    
    int error;
    
    if (getuid() != 0) {
        fprintf(stderr, "this program must be run as root\n");
        return -1;
    }

    rw_capture_init(&capture, NULL);
    rw_packet_zero(&packet);
    
    for (i = 0; i < 100000; i++) {
        if ((error = rw_capture_recv(&capture, &packet))) {
            printf("capture error %d\n", error);
            continue;
        }
        
        /*
        printf("%s ",    mac_string(rw_packet_ether_src(&packet)));
        printf(" => %s | ", mac_string(rw_packet_ether_dst(&packet)));
        */
        
        switch (rw_packet_net_proto(&packet)) {
        case RW_PACKET_IPV4 : printf("ipv4 (");  break;
        case RW_PACKET_IPV6 : printf("ipv6 ("); break;
        case RW_PACKET_ARP  :
            printf("arp ");
            printf("(%s ", mac_string(rw_packet_arp_sender_hw(&packet)));
            printf("%s) => (", ipv4_string(rw_packet_arp_sender_ip(&packet)));
            printf("(%s ", mac_string(rw_packet_arp_target_hw(&packet)));
            printf("%s) ", ipv4_string(rw_packet_arp_target_ip(&packet)));
            switch (rw_packet_arp_opcode(&packet)) {
            case ARPOP_REQUEST  : printf("REQUEST\n"); break;
            case ARPOP_REPLY    : printf("REPLY\n"); break;
            case ARPOP_RREQUEST : printf("RREQUEST\n"); break;
            case ARPOP_RREPLY   : printf("RREPLY\n"); break;
            default : printf("????\n");
            }   
            continue;
        default : printf("unknown net proto\n"); continue;
        }
        
        
        printf("%s => %s) | ",
               rw_packet_net_src_str(&packet),
               rw_packet_net_dst_str(&packet));
        
        
        switch (rw_packet_trans_proto(&packet)) {
        case RW_PACKET_TCP :
            printf("tcp [%d] (%d => %d)\n",
                   rw_packet_data_size(&packet),
                   rw_packet_trans_port_src(&packet),
                   rw_packet_trans_port_dst(&packet));
            break;
        case RW_PACKET_UDP :
            printf("udp [%d] (%d => %d)\n",
                   rw_packet_data_size(&packet),
                   rw_packet_trans_port_src(&packet),
                   rw_packet_trans_port_dst(&packet));
            break;
        case RW_PACKET_ICMP :
            printf("icmp\n");
            continue;
        default :
            printf("unknown\n");
            continue;
        }
        
        if (rw_packet_data_size(&packet) > 0)
            printf("%s\n", printable_buf(rw_packet_data(&packet),
                                         rw_packet_data_size(&packet)));
    }
    rw_capture_destroy(&capture);
    
    return 0;
}
