#ifndef lrw_HEADER
#define lrw_HEADER

/*
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
*/

#include "config.h"

#include "capture.h"
#include "pcap.h"

int lrw_capture_new  (lua_State * L);
int lrw_capture_recv (lua_State * L);
int lrw_capture_send (lua_State * L);
int lrw_capture_gc   (lua_State * L);

int lrw_pcap_new  (lua_State * L);
int lrw_pcap_recv (lua_State * L);
int lrw_pcap_gc   (lua_State * L);

struct _capture * lrw_capture_check (lua_State * L, int position);
struct _packet *  lrw_packet_check  (lua_State * L, int position);
struct _pcap *    lrw_pcap_check    (lua_State * L, int position);

int lrw_packet_new            (lua_State * L);
int lrw_packet_raw            (lua_State * L);
int lrw_packet_eth_src        (lua_State * L);
int lrw_packet_eth_dst        (lua_State * L);
int lrw_packet_net_proto      (lua_State * L);
int lrw_packet_net_src        (lua_State * L);
int lrw_packet_net_dst        (lua_State * L);
int lrw_packet_trans_proto    (lua_State * L);
int lrw_packet_trans_port_src (lua_State * L);
int lrw_packet_trans_port_dst (lua_State * L);
int lrw_packet_data           (lua_State * L);
int lrw_packet_tcp_flags      (lua_State * L);
int lrw_packet_tcp_seq        (lua_State * L);
int lrw_packet_tcp_ack        (lua_State * L);
int lrw_packet_icmp_type      (lua_State * L);
int lrw_packet_arp_opcode     (lua_State * L);

#endif
