#include "capture.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <sys/ioctl.h>

#include <errno.h>


int rw_capture_init (struct _capture * capture, const char * interface)
{
    int error;
    struct ifreq req; // for getting index of interface
    
    capture->sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (capture->sock == -1)
        return RW_CAPTURE_ERR_SOCKFAIL;
    
    if (interface != NULL) {
        // get interface index
        strncpy(req.ifr_ifrn.ifrn_name, interface, IFNAMSIZ);
        error = ioctl(capture->sock, SIOCGIFINDEX, &req);
        if (error == -1)
            return RW_CAPTURE_ERR_FIND_IFACE;
        
        // bind to that interface
        capture->sockaddr.sll_family = AF_PACKET;
        capture->sockaddr.sll_protocol = htons(ETH_P_IP);
        capture->sockaddr.sll_ifindex = req.ifr_ifindex;
        error = bind(capture->sock,
                     (struct sockaddr *) &(capture->sockaddr),
                     sizeof(struct sockaddr_ll));
        if (error)
            return RW_CAPTURE_ERR_BIND_IFACE;
    }
    
    return 0;
}


int rw_capture_destroy (struct _capture * capture)
{
    close(capture->sock);
    return 0;
}


int rw_capture_recv (struct _capture * capture, struct _packet * packet)
{
    packet->size = recvfrom(capture->sock, packet->data, RW_PACKET_FRAME_LEN,
                            0, NULL, NULL);
    return rw_packet_quick_set(packet);
}


int rw_capture_send (struct _capture * capture, struct _packet * packet)
{
    int bytes_sent;
    
    bytes_sent = sendto(capture->sock, packet->data, packet->size, 0, 
                        (struct sockaddr *) &(capture->sockaddr),
                        sizeof(struct sockaddr_ll));
    
    if (bytes_sent == -1)
        printf("%s\n", strerror(errno));
    return packet->size - bytes_sent;
}
