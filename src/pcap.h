#ifndef pcap_HEADER
#define pcap_HEADER

#include "packet.h"

#include <pcap/pcap.h>

#define RW_PCAP_ERR -5000 /* failed to create socket */
#define RW_PCAP_EOF -5001 /* no more packets in file */ 

struct _pcap {
    pcap_t * pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
};

int rw_pcap_init    (struct _pcap * pcap, const char * filename);

int rw_pcap_destroy (struct _pcap * pcap);

int rw_pcap_recv    (struct _pcap * pcap, struct _packet * packet);

#endif
