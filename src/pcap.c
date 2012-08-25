#include "pcap.h"

#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>


int rw_pcap_init (struct _pcap * pcap, const char * filename)
{
    pcap->pcap = pcap_open_offline(filename, pcap->errbuf);
    if (pcap->pcap == NULL)
        return -1;

    return 0;
}


int rw_pcap_destroy (struct _pcap * pcap)
{
    pcap_close(pcap->pcap);

    return 0;
}


int rw_pcap_recv (struct _pcap * pcap, struct _packet * packet)
{
    int error;
    struct pcap_pkthdr  * pkthdr;
    const unsigned char * data;

    error = pcap_next_ex(pcap->pcap, &pkthdr, &data);
    
    if (error == 1) {
        packet->size = pkthdr->caplen > RW_PACKET_FRAME_LEN
                       ? RW_PACKET_FRAME_LEN : pkthdr->caplen;
        memcpy(packet->data, data, packet->size);
        return rw_packet_quick_set(packet);
    }
    else if (error == -2)
        return RW_PCAP_EOF;

    return RW_PCAP_ERR;
}