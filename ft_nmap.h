//
// Created by Yahya Ez-zainabi on 11/30/22.
//

#ifndef FT_NMAP_HPP
#define FT_NMAP_HPP


#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

typedef enum scan_type_e {
    SCAN_EMPTY          = 0x00,
    SCAN_NULL           = 0x01,
    SCAN_SYN            = 0x02,
    SCAN_ACK            = 0x04,
    SCAN_FIN            = 0x08,
    SCAN_XMAS           = 0x10,
    SCAN_UDP            = 0x20,
    SCAN_ALL            = SCAN_NULL | SCAN_SYN | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP,
    INVALID_SCAN_TYPE   = 0xff
}   scan_type_t;

#define INVALID_THREADS_NUMBER	(uint8_t)0xff

typedef enum port_state_e {
    NO_RESULT           = 0x00,
    UNFILTERED_PORT     = 0x01,
    FILTERED_PORT       = 0x02,
    OPEN_FILTERED_PORT  = 0x04,
    CLOSED_PORT         = 0x08,
    OPEN_PORT           = 0x10
}   port_state_t;

typedef struct scan_result_entry_s {
    uint16_t        port;
    port_state_t    results[6];
    port_state_t    conclusion;
}   scan_result_entry_t;

typedef struct scan_result_s {
    uint16_t            open_ports;
    uint16_t            total_ports;
    scan_result_entry_t *entries;
}   scan_result_t;

typedef struct nmap_context_s {
    scan_type_t		scan_types;
	uint8_t			threads_number;
	uint16_t		*ports;
	struct in_addr	*ips;
	uint16_t		ports_number;
	uint16_t		ips_number;
    int             tcp_socket_fd;
    int             udp_socket_fd;
    scan_result_t   *scan_result;
    char            *interface;
    struct sockaddr *socket_addr;
    uint8_t         ttl;
    uint16_t        source_port;
    int             packet_trace;
    struct ifaddrs  *if_addr;
    pcap_t          *pcap_handle;
    bpf_u_int32     subnet_mask;
    bpf_u_int32     ip;
    pthread_mutex_t mutex;
}	nmap_context_t;

typedef struct tcpip_packet_s {
    struct iphdr    ip_hdr;
    struct tcphdr   tcp_hdr;
}   tcpip_packet_t;

typedef struct udpip_packet_s {
    struct iphdr    ip_hdr;
    struct udphdr   udp_hdr;
}   udpip_packet_t;

typedef struct thread_context_s {
    nmap_context_t  *nmap_ctx;
    int             ip_index;
    int             ips_number;
    int             port_index;
    int             ports_number;
}   thread_context_t;

void    clear_nmap_context(nmap_context_t *ctx);

#endif //FT_NMAP_HPP
