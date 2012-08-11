#ifndef capture_HEADER
#define capture_HEADER

#include "packet.h"

#include <linux/if_packet.h>

#define RW_CAPTURE_ERR_SOCKFAIL   -1 /* failed to create socket */
#define RW_CAPTURE_ERR_BIND_IFACE -2 /* failed to bind sock to interface */
#define RW_CAPTURE_ERR_FIND_IFACE -3 /* failed to find interface */

struct _capture {
    int sock;
    struct sockaddr_ll sockaddr;
};

/** Sets up the socket to begin capturing packets
 * @param capture this should be already allocated memory for keeping
 *                the state of the capture interface
 * @param interface This should be either the name of a valid interface,
 *                  or NULL for any interface
 * @return 0 on success, or a RW_CAPTURE_ERR_ code on error.
 */
int rw_capture_init    (struct _capture * capture,
                        const char * interface);

int rw_capture_destroy (struct _capture * capture);

int rw_capture_recv    (struct _capture * capture, 
                        struct _packet * packet);

int rw_capture_send    (struct _capture * capture,
                        struct _packet * packet);

#endif
