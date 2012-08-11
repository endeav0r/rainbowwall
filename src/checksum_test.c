/*
 * the purpose of this program is to check tcp checksum generation
 * it filters tcp packets, regenerates the checksum and then prints
 *  the given checksum against the generated checksum
 */

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
    int ipv4_checksum = 0;
    int tcp_checksum = 0;
    struct _packet  packet;
    struct _capture capture;
    
    int error;
    
    if (getuid() != 0) {
        fprintf(stderr, "this program must be run as root\n");
        return -1;
    }

    rw_capture_init(&capture, "eth0");
    rw_packet_zero(&packet);
    
    while (1) {
        if ((error = rw_capture_recv(&capture, &packet))) {
            printf("capture error %d\n", error);
            continue;
        }
        
        // we only care about tcp packets
        if (rw_packet_trans_proto(&packet) != RW_PACKET_TCP)
            continue;
        
        // on port 80
        if (rw_packet_trans_port_src(&packet) != 80)
            continue;
        
        // get the tcp checksum
        tcp_checksum = rw_packet_tcp_checksum_gen(&packet);
        
        if (tcp_checksum < 0) {
            switch (tcp_checksum) {
            case RW_PACKET_ERR_TRANS :
                printf("RW_PACKET_ERR_TRANS\n");
                continue;
            case RW_PACKET_ERR_NET :
                printf("RW_PACKET_ERR_NET\n");
                continue;
            default :
                printf("UNKNOWN TCP CHECKSUM ERROR\n");
                continue;
            }
        }
        
        // if this is an ipv4 packet, get the ipv4 checksum
        if (rw_packet_net_proto(&packet) == RW_PACKET_IPV4) {
            ipv4_checksum = rw_packet_ipv4_checksum_gen(&packet);
        
            if (ipv4_checksum < 0) {
                switch (ipv4_checksum) {
                case RW_PACKET_ERR_NET :
                    printf("RW_PACKET_ERR_NET\n");
                    continue;
                default :
                    printf("UNKNOWN IPV4 CHECKSUM ERROR\n");
                    continue;
                }
            }
        
            // print out pass/fail info
            if (    (packet.tcp_header->check == tcp_checksum)
                 && (packet.ipv4_header->check == ipv4_checksum))
                printf("OK ");
            else
                printf("FAIL ");
        
            printf("%s => %s [%04d] %04x %04x | [%04d] %04x %04x\n",
                   rw_packet_net_src_str(&packet),
                   rw_packet_net_dst_str(&packet),
                   ntohs(packet.ipv4_header->tot_len),
                   packet.ipv4_header->check,
                   ipv4_checksum,
                   rw_packet_data_size(&packet),
                   packet.tcp_header->check,
                   tcp_checksum);
        }
        else {
            if (packet.tcp_header->check == tcp_checksum)
                printf("OK ");
            else
                printf("FAIL ");
        
            printf("%s => %s [%04d] %04x %04x\n",
                   rw_packet_net_src_str(&packet),
                   rw_packet_net_dst_str(&packet),
                   rw_packet_data_size(&packet),
                   packet.tcp_header->check,
                   tcp_checksum);
       }
    }
    rw_capture_destroy(&capture);
    
    return 0;
}
