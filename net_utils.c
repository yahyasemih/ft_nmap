//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "net_utils.h"
#include "utilities.h"

int dns_resolve(struct in_addr host_addr, char *dest, int size) {
    struct sockaddr_in socket_address;
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr = host_addr;
    return getnameinfo((struct sockaddr *)&socket_address, sizeof(socket_address), dest, size, NULL, 0, NI_NAMEREQD);
}

static void ft_ip_checksum(u_short *addr) {
    struct iphdr *ip_hdr = (struct iphdr*)(addr);
	int n_left = sizeof(struct iphdr);
	int sum = 0;
	u_short *w = addr;
    u_short answer = 0;

    ip_hdr->check = 0;
	while (n_left > 1) {
		sum += *w++;
        n_left -= 2;
	}
	if (n_left == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	answer = ~sum;
    ip_hdr->check = answer;
}

static void ft_tcp_checksum(struct iphdr *ip_header, u_short *tcp_payload) {
    u_long sum = 0;
    u_short tcp_len = ntohs(ip_header->tot_len) - (ip_header->ihl << 2);
    struct tcphdr *tcp_hdr = (struct tcphdr *)(tcp_payload);
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);
    tcp_hdr->check = 0;
    while (tcp_len > 1) {
        sum += * tcp_payload++;
        tcp_len -= 2;
    }
    if (tcp_len > 0) {
        sum += ((*tcp_payload) & htons(0xFF00));
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    tcp_hdr->check = (u_short)sum;
}

static void ft_udp_checksum(struct iphdr *ip_header, u_short *udp_payload) {
    u_long sum = 0;
    u_short tcp_len = ntohs(ip_header->tot_len) - (ip_header->ihl << 2);
    struct udphdr *udp_hdr = (struct udphdr *)(udp_payload);
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);
    udp_hdr->check = 0;
    while (tcp_len > 1) {
        sum += * udp_payload++;
        tcp_len -= 2;
    }
    if (tcp_len > 0) {
        sum += ((*udp_payload) & htons(0xFF00));
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    udp_hdr->check = (u_short)sum;
}

int initialize_socket(nmap_context_t *ctx) {
    ctx->tcp_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (ctx->tcp_socket_fd < 0) {
        fprintf(stderr, "ft_nmap: TCP socket: %s\n", strerror(errno));
        return 1;
    }
    ctx->udp_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (ctx->udp_socket_fd < 0) {
        fprintf(stderr, "ft_nmap: UDP socket: %s\n", strerror(errno));
        return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    int options = 1;

    if (setsockopt(ctx->tcp_socket_fd, IPPROTO_IP, IP_HDRINCL, &options, sizeof(options)) < 0
        || setsockopt (ctx->tcp_socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt (ctx->tcp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt( ctx->tcp_socket_fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->interface, ft_strlen(ctx->interface)) < 0) {
        fprintf(stderr, "ft_nmap: TCP setsockopt: %s\n", strerror(errno));
        return 1;
    }
    if (setsockopt(ctx->udp_socket_fd, IPPROTO_IP, IP_HDRINCL, &options, sizeof(options)) < 0
        || setsockopt (ctx->udp_socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt (ctx->udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt( ctx->udp_socket_fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->interface, ft_strlen(ctx->interface)) < 0) {
        fprintf(stderr, "ft_nmap: UDP setsockopt: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

static uint8_t scan_type_to_th_flags(scan_type_t scan_type) {
    if (scan_type == SCAN_SYN) {
        return TH_SYN;
    } else if (scan_type == SCAN_ACK) {
        return TH_ACK;
    } else if (scan_type == SCAN_FIN) {
        return TH_FIN;
    } else if (scan_type == SCAN_XMAS) {
        return TH_FIN | TH_PUSH | TH_URG;
    } else {
        return 0;
    }
}

tcpip_packet_t  create_tcp_packet(struct in_addr dst_ip, u_short port, scan_type_t scan_type, nmap_context_t *ctx) {
    tcpip_packet_t  packet;
    struct timeval tv;

    ft_bzero(&packet, sizeof(packet));
    gettimeofday(&tv, NULL);
    inet_pton(AF_INET, "10.11.100.232", &packet.ip_hdr.saddr);
    packet.ip_hdr.daddr = dst_ip.s_addr;
    packet.ip_hdr.version = 4;
    packet.ip_hdr.ihl = 5;
    packet.ip_hdr.tos = 0;
    packet.ip_hdr.tot_len = htons(sizeof(tcpip_packet_t));
    packet.ip_hdr.id = htons(tv.tv_usec & 0xFFFF);
    packet.ip_hdr.frag_off = 0;
    packet.ip_hdr.ttl = ctx->ttl;
    packet.ip_hdr.protocol = IPPROTO_TCP;
    ft_ip_checksum((u_short *)&packet.ip_hdr);
    packet.tcp_hdr.th_flags = scan_type_to_th_flags(scan_type);
    packet.tcp_hdr.seq = ((tv.tv_sec & 0xFFFFFFFF) + tv.tv_usec) & 0xFFFFFFFF;
    packet.tcp_hdr.doff = 5;
    packet.tcp_hdr.window = htons(1024);
    packet.tcp_hdr.th_dport = htons(port);
    packet.tcp_hdr.th_sport = htons(ctx->source_port);
    ft_tcp_checksum(&packet.ip_hdr, (u_short *)&packet.tcp_hdr);

    return packet;
}

udpip_packet_t  create_udp_packet(struct in_addr dst_ip, u_short port, nmap_context_t *ctx) {
    udpip_packet_t  packet;
    struct timeval  tv;

    ft_bzero(&packet, sizeof(packet));
    gettimeofday(&tv, NULL);
    inet_pton(AF_INET, "10.11.100.232", &packet.ip_hdr.saddr);
    packet.ip_hdr.daddr = dst_ip.s_addr;
    packet.ip_hdr.version = 4;
    packet.ip_hdr.ihl = 5;
    packet.ip_hdr.tos = 0;
    packet.ip_hdr.tot_len = htons(sizeof(udpip_packet_t));
    packet.ip_hdr.id = htons(tv.tv_usec & 0xFFFF);
    packet.ip_hdr.frag_off = 0;
    packet.ip_hdr.ttl = ctx->ttl;
    packet.ip_hdr.protocol = IPPROTO_UDP;
    ft_ip_checksum((u_short *)&packet.ip_hdr);
    packet.udp_hdr.source = htons(ctx->source_port);
    packet.udp_hdr.dest = htons(port);
    packet.udp_hdr.len = htons(sizeof(struct udphdr));
    ft_udp_checksum(&packet.ip_hdr, (u_short *)&packet.udp_hdr);

    return packet;
}

void    tcp_packet_trace(tcpip_packet_t *packet) {
    struct in_addr src = {packet->ip_hdr.saddr};
    struct in_addr dst = {packet->ip_hdr.daddr};
    printf("TCP %s:%d > %s:%d ", inet_ntoa(src), ntohs(packet->tcp_hdr.th_sport), inet_ntoa(dst),
            ntohs(packet->tcp_hdr.th_dport));
    if (packet->tcp_hdr.th_flags) {
        if (packet->tcp_hdr.urg) {
            printf("U");
        }
        if (packet->tcp_hdr.ack) {
            printf("A");
        }
        if (packet->tcp_hdr.psh) {
            printf("P");
        }
        if (packet->tcp_hdr.rst) {
            printf("R");
        }
        if (packet->tcp_hdr.syn) {
            printf("S");
        }
        if (packet->tcp_hdr.fin) {
            printf("F");
        }
    }
    printf(" ttl=%d id=%d iplen %d ", packet->ip_hdr.ttl, ntohs(packet->ip_hdr.id), ntohs(packet->ip_hdr.tot_len));
    printf(" seq=%d win=%d\n", ntohs(packet->tcp_hdr.seq), ntohs(packet->tcp_hdr.window));
}

void    udp_packet_trace(udpip_packet_t *packet) {
    struct in_addr src = {packet->ip_hdr.saddr};
    struct in_addr dst = {packet->ip_hdr.daddr};
    printf("UDP %s:%d > %s:%d ", inet_ntoa(src), ntohs(packet->udp_hdr.uh_sport), inet_ntoa(dst),
            ntohs(packet->udp_hdr.uh_dport));
    printf("ttl=%d id=%d iplen %d\n", packet->ip_hdr.ttl, ntohs(packet->ip_hdr.id), ntohs(packet->ip_hdr.tot_len));
}
