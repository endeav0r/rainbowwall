#include "lrw.h"

#include <stdio.h>
#include <unistd.h>

#include "arp.h"
#include "icmp.h"
#include "net.h"
#include "trans.h"


static const struct luaL_Reg lrw_capture_lib_f [] = {
    {"new", lrw_capture_new},
    {NULL, NULL}
};


static const struct luaL_Reg lrw_capture_lib_m [] = {
    {"__gc", lrw_capture_gc},
    {"recv", lrw_capture_recv},
    {"send", lrw_capture_send},
    {NULL, NULL}
};


static const struct luaL_Reg lrw_packet_lib_f [] = {
    {"new", lrw_packet_new},
    {NULL, NULL}
};


static const struct luaL_Reg lrw_packet_lib_m [] = {
    {"raw",            lrw_packet_eth_src},
    {"eth_src",        lrw_packet_eth_src},
    {"eth_dst",        lrw_packet_eth_dst},
    
    {"net_proto",      lrw_packet_net_proto},
    {"net_src",        lrw_packet_net_src},
    {"net_dst",        lrw_packet_net_dst},
    
    {"trans_proto",    lrw_packet_trans_proto},
    {"trans_port_src", lrw_packet_trans_port_src},
    {"trans_port_dst", lrw_packet_trans_port_dst},
    {"port_src",       lrw_packet_trans_port_src},
    {"port_dst",       lrw_packet_trans_port_dst},
    {"data",           lrw_packet_data},
    
    {"tcp_flags",      lrw_packet_tcp_flags},
    {"tcp_seq",        lrw_packet_tcp_seq},
    {"tcp_ack",        lrw_packet_tcp_ack},
    
    {"icmp_type",      lrw_packet_icmp_type},
    
    {"arp_opcode",     lrw_packet_arp_opcode},
    {NULL, NULL}
};


LUALIB_API int luaopen_lrw (lua_State * L)
{   
    if (getuid() != 0)
        luaL_error(L, "trying to run lrw as a user other than root!");
    
    luaL_newmetatable(L, "lrw.rw_capture_t");
    lua_pushstring   (L, "__index");
    lua_pushvalue    (L, -2);
    lua_settable     (L, -3);
    luaL_register    (L, NULL, lrw_capture_lib_m);
    luaL_register    (L, "lrw_capture_t", lrw_capture_lib_f);
    
    luaL_newmetatable(L, "lrw.rw_packet_t");
    lua_pushstring   (L, "__index");
    lua_pushvalue    (L, -2);
    lua_settable     (L, -3);
    luaL_register    (L, NULL, lrw_packet_lib_m);
    luaL_register    (L, "lrw_packet_t", lrw_packet_lib_f);
    
    return 2;
}


struct _capture * lrw_capture_check (lua_State * L, int position)
{
    struct _capture * capture;
    void * userdata = luaL_checkudata(L, position, "lrw.rw_capture_t");
    luaL_argcheck(L, userdata != NULL, position, "lrw.rw_capture_t expected");
    capture = (struct _capture *) userdata;
    return capture;
}


int lrw_capture_new (lua_State * L)
{
    int error;
    struct _capture * capture;
    
    const char * interface;
    
    if (lua_isstring(L, 1)) {
        interface = luaL_checkstring(L, 1);
        lua_pop(L, 1);
    }
    else
        interface = NULL;
    
    capture = lua_newuserdata(L, sizeof(struct _capture));
    luaL_getmetatable(L, "lrw.rw_capture_t");
    lua_setmetatable(L, -2); 
    
    error = rw_capture_init(capture, interface);
    if (error) {
        switch (error) {
        case RW_CAPTURE_ERR_SOCKFAIL :
            luaL_error(L, "failed to create socket");
            return 0;
        case RW_CAPTURE_ERR_FIND_IFACE :
            luaL_error(L, "failed to find interface %s", interface);
            return 0;
        case RW_CAPTURE_ERR_BIND_IFACE :
            luaL_error(L, "failed to bind to interface %s", interface);
            return 0;
        }
    }
    
    return 1;
}


int lrw_capture_recv  (lua_State * L)
{
    struct _capture * capture;
    struct _packet  * packet;
    int error;
    
    capture = lrw_capture_check(L,-1);
    lua_pop(L, 1);
    
    lrw_packet_new(L);
    packet = lrw_packet_check(L, -1);
    
    rw_capture_recv(capture, packet);
    error = rw_packet_quick_set(packet);
    
    switch (error) {
    case RW_PACKET_ERR_SIZE :
        luaL_error(L, "RW_PACKET_ERR_SIZE");
        break;
    case RW_PACKET_ERR_NET :
        luaL_error(L, "RW_PACKET_ERR_NET");
        break;
    }
    
    return 1;
}


int lrw_capture_send  (lua_State * L)
{
    struct _capture * capture;
    struct _packet  * packet;
    int error;
    
    packet = lrw_packet_check(L, -1);
    capture = lrw_capture_check(L,-2);
    lua_pop(L, 2);
    
    error = rw_capture_send(capture, packet);
    if (error)
        luaL_error(L, "error sending packet, %d bytes not send", error);
    
    return 0;
}


int lrw_capture_gc (lua_State * L)
{
    struct _capture * capture;
    
    capture = lrw_capture_check(L, 1);
    
    lua_pop(L, 1);
    
    rw_capture_destroy(capture);
    
    return 0;
}


struct _packet * lrw_packet_check (lua_State * L, int position)
{
    struct _packet * packet;
    void * userdata = luaL_checkudata(L, position, "lrw.rw_packet_t");
    luaL_argcheck(L, userdata != NULL, position, "lrw.rw_packet_t expected");
    packet = (struct _packet *) userdata;
    return packet;
}


int lrw_packet_new (lua_State * L)
{
    struct _packet * packet;
    
    packet = lua_newuserdata(L, sizeof(struct _packet));
    luaL_getmetatable(L, "lrw.rw_packet_t");
    lua_setmetatable(L, -2); 
    
    rw_packet_zero(packet);
    
    return 1;
}


int lrw_packet_raw (lua_State * L)
{
    int size;
    void * data;
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    data = rw_packet_raw(packet, &size);
    lua_pushlstring(L, data, size);
    
    return 1;
}


int lrw_packet_eth_src (lua_State * L)
{
    char tmp[32];
    unsigned char * mac_address;
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    mac_address = rw_packet_ether_src(packet);
    snprintf(tmp, 32, "%02X:%02x:%02x:%02x:%02x:%02x",
             mac_address[0], mac_address[1], mac_address[2],
             mac_address[3], mac_address[4], mac_address[5]);
    
    lua_pushstring(L, tmp);
    
    return 1;
}


int lrw_packet_eth_dst (lua_State * L)
{
    char tmp[32];
    unsigned char * mac_address;
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    mac_address = rw_packet_ether_dst(packet);
    snprintf(tmp, 32, "%02X:%02x:%02x:%02x:%02x:%02x",
             mac_address[0], mac_address[1], mac_address[2],
             mac_address[3], mac_address[4], mac_address[5]);
    
    lua_pushstring(L, tmp);
    
    return 1;
}


int lrw_packet_net_proto (lua_State * L)
{
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    switch (rw_packet_net_proto(packet)) {
    case RW_PACKET_IPV4 :     lua_pushstring(L, "ipv4"); break;
    case RW_PACKET_IPV6 :     lua_pushstring(L, "ipv6"); break;
    case RW_PACKET_ARP  :     lua_pushstring(L, "arp");  break;
    case RW_PACKET_IEEE8023 : lua_pushstring(L, "ieee 802.3"); break;
    default :
        luaL_error(L, "unknown net protocol");
        return 0;
    }
    
    return 1;
}


int lrw_packet_net_src (lua_State * L)
{
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    lua_pushstring(L, rw_packet_net_src_str(packet));
    
    return 1;
}


int lrw_packet_net_dst (lua_State * L)
{
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    lua_pushstring(L, rw_packet_net_dst_str(packet));
    
    return 1;
}


int lrw_packet_trans_proto (lua_State * L)
{
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    switch (rw_packet_trans_proto(packet)) {
    case RW_PACKET_TCP :     lua_pushstring(L, "tcp"); break;
    case RW_PACKET_UDP :     lua_pushstring(L, "udp"); break;
    case RW_PACKET_ICMP :    lua_pushstring(L, "icmp"); break;
    case RW_PACKET_OSPF :    lua_pushstring(L, "ospf"); break;
    case RW_PACKET_IGMP :    lua_pushstring(L, "igmp"); break;
    case RW_PACKET_ERR_NET :
        luaL_error(L, "invalid network layer protocol");
        return 0;
    case RW_PACKET_ERR_TRANS :
        luaL_error(L, "invalid transport layer protocol %d\n",
                   rw_packet_trans_proto_raw(packet));
        return 0;
    default :
        luaL_error(L, "unknown trans protocol error %d",
                   rw_packet_trans_proto(packet));
        return 0;
    }
    
    return 1;
}


int lrw_packet_trans_port_src (lua_State * L)
{
    int port;
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    port = rw_packet_trans_port_src(packet);
    if (port == RW_PACKET_ERR_TRANS) {
        luaL_error(L, "invalid transport layer protocol");
        return 0;
    }
    
    lua_pushinteger(L, port);
    return 1;
}


int lrw_packet_trans_port_dst (lua_State * L)
{
    int port;
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    port = rw_packet_trans_port_dst(packet);
    if (port == RW_PACKET_ERR_TRANS) {
        luaL_error(L, "invalid transport layer protocol");
        return 0;
    }
    
    lua_pushinteger(L, port);
    return 1;
}


int lrw_packet_data (lua_State * L)
{
    struct _packet * packet;
    void * data;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    data = rw_packet_data(packet);
    
    if (data == NULL) {
        luaL_error(L, "error getting packet data");
        return 0;
    }
    
    lua_pushlstring(L, data, rw_packet_data_size(packet));
    return 1;
}


int lrw_packet_tcp_flags (lua_State * L)
{
    struct _packet * packet;
    int flags;
    int index = 1;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    flags = rw_packet_tcp_flags(packet);
    
    if (flags == RW_PACKET_ERR_TRANS) {
        luaL_error(L, "called tcp_flags on invalid packet");
        return 0;
    }
    
    lua_newtable(L);
    
    if (flags & RW_PACKET_TCP_ACK) {
        lua_pushinteger(L, index++);
        lua_pushstring(L, "ack");
        lua_settable(L, -3);
    }
    if (flags & RW_PACKET_TCP_FIN) {
        lua_pushinteger(L, index++);
        lua_pushstring(L, "fin");
        lua_settable(L, -3);
    }
    if (flags & RW_PACKET_TCP_PUSH) {
        lua_pushinteger(L, index++);
        lua_pushstring(L, "push");
        lua_settable(L, -3);
    }
    if (flags & RW_PACKET_TCP_RST) {
        lua_pushinteger(L, index++);
        lua_pushstring(L, "rst");
        lua_settable(L, -3);
    }
    if (flags & RW_PACKET_TCP_SYN) {
        lua_pushinteger(L, index++);
        lua_pushstring(L, "syn");
        lua_settable(L, -3);
    }
    if (flags & RW_PACKET_TCP_URG) {
        lua_pushinteger(L, index++);
        lua_pushstring(L, "urg");
        lua_settable(L, -3);
    }
    
    return 1;
}


int lrw_packet_tcp_seq (lua_State * L)
{
    struct _packet * packet;
   
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
   
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        luaL_error(L, "not a tcp packet");
   
    lua_pushnumber(L, rw_packet_tcp_seq(packet));
   
    return 1;
}


int lrw_packet_tcp_ack (lua_State * L)
{
    struct _packet * packet;
   
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
   
    if (rw_packet_trans_proto(packet) != RW_PACKET_TCP)
        luaL_error(L, "not a tcp packet");
   
    lua_pushnumber(L, rw_packet_tcp_ack(packet));
   
    return 1;
}


int lrw_packet_icmp_type (lua_State * L)
{
    int type;
    struct _packet * packet;
    void * data;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    type = rw_packet_icmp_type(packet);

    switch (type) {
    case RW_PACKET_ERR_NET :
        luaL_error(L, "invalid network layer protocol");
        return 0;
    case RW_PACKET_ERR_TRANS :
        luaL_error(L, "not an icmp packet");
        return 0;
    case RW_PACKET_ICMP_ECHOREPLY : 
        lua_pushstring(L, "echoreply"); break;
    case RW_PACKET_ICMP_ECHO :
        lua_pushstring(L, "echo"); break;
    case RW_PACKET_ICMP_NET_UNREACH :
        lua_pushstring(L, "net_unreach"); break;
    case RW_PACKET_ICMP_HOST_UNREACH :
        lua_pushstring(L, "host_unreach"); break;
    case RW_PACKET_ICMP_UNKNOWN :
        lua_pushstring(L, "unknown"); break;
    case RW_PACKET_ICMP_UNREACH_UNKNOWN :
        lua_pushstring(L, "unreach_unknown"); break;
    default :
        luaL_error(L, "unknown type from rw_packet_icmp_type");
        return 0;
    }
    
    return 1;
}


int lrw_packet_arp_opcode (lua_State * L)
{
    struct _packet * packet;
    
    packet = lrw_packet_check(L, -1);
    lua_pop(L, 1);
    
    switch (rw_packet_arp_opcode(packet)) {
    case RW_PACKET_ARP_REQUEST :
        lua_pushstring(L, "request");
        return 1;
    case RW_PACKET_ARP_REPLY :
        lua_pushstring(L, "reply");
        return 1;
    case RW_PACKET_ARP_RREQUEST :
        lua_pushstring(L, "rrequest");
        return 1;
    case RW_PACKET_ARP_RREPLY :
        lua_pushstring(L, "rreply");
        return 1;
    case RW_PACKET_ARP_INREQUEST :
        lua_pushstring(L, "inrequest");
        return 1;
    case RW_PACKET_ARP_INREPLY :
        lua_pushstring(L, "inreply");
        return 1;
    case RW_PACKET_ARP_NAK :
        lua_pushstring(L, "nak");
        return 1;
    case RW_PACKET_ERR_NET :
        luaL_error(L, "arp_opcode() called on non-arp packet");
        return 0;
    }
    
    luaL_error(L, "unknown return value from rw_packet_arp_opcode");
    return 0;
}
