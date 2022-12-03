//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "ft_nmap.h"

int initialize_socket(nmap_context_t *ctx);

int dns_resolve(struct in_addr host_addr, char *dest, int size);

tcpip_packet_t  create_tcp_packet(struct in_addr dst_ip, u_short port, scan_type_t scan_type);

udpip_packet_t  create_udp_packet(struct in_addr dst_ip, u_short port);
