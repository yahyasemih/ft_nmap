//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#ifndef NET_UTILS_H
#define NET_UTILS_H

#include "ft_nmap.h"

int dns_resolve(struct in_addr host_addr, char *dest, int size);

int initialize_socket(nmap_context_t *ctx);

tcpip_packet_t  create_tcp_packet(struct in_addr dst_ip, u_short port, scan_type_t scan_type, nmap_context_t *ctx);

udpip_packet_t  create_udp_packet(struct in_addr dst_ip, u_short port, nmap_context_t *ctx);

void    udp_packet_trace(udpip_packet_t *packet);

void    tcp_packet_trace(tcpip_packet_t *packet);

#endif
