//
// Created by Yahya Ez-zainabi on 11/30/22.
//

#ifndef FT_NMAP_HPP
#define FT_NMAP_HPP


#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define SCAN_EMPTY				0x00
#define SCAN_NULL				0x01
#define SCAN_SYN				0x02
#define SCAN_ACK				0x04
#define SCAN_FIN				0x08
#define SCAN_XMAS				0x10
#define SCAN_UDP				0x20
#define SCAN_ALL				(SCAN_NULL | SCAN_SYN | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP)
#define INVALID_SCAN_TYPE		0xff

#define INVALID_THREADS_NUMBER	(uint8_t)0xff

typedef struct {
    uint16_t    port;
    int         results[6];
    int         conclusion;
}   scan_result_entry_t;

typedef struct {
    in_addr_t           port;
    uint16_t            open_ports;
    uint16_t            total_ports;
    scan_result_entry_t *entries;
}   scan_result_t;

typedef struct {
	uint8_t			scan_types;
	uint8_t			threads_number;
	uint16_t		*ports;
	struct in_addr	*ips;
	uint16_t		ports_number;
	uint16_t		ips_number;
    int             socket_fd;
    scan_result_t   *scan_result;
}	nmap_context_t;

typedef struct {
    struct iphdr    ip_hdr;
    struct tcphdr   tcp_hdr;
}   tcpip_packet_t;

#endif //FT_NMAP_HPP
