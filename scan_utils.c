//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "scan_utils.h"
#include "net_utils.h"
#include "pcap_utils.h"
#include "utilities.h"

static port_state_t do_udp_scan(nmap_context_t *ctx, struct in_addr host_addr, uint16_t port) {
    struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);
    char    filter_exp[100] = {0};
    struct bpf_program filter;

    udpip_packet_t packet = create_udp_packet(host_addr, port, ctx);
    ssize_t sent = sendto(ctx->udp_socket_fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&dst_addr,
            dst_addr_len);
    if (ctx->packet_trace) {
        printf("SENT ");
        udp_packet_trace(&packet);
    }
    if (sent < 0) {
        return NO_RESULT;
    }
    ft_bzero(&packet, sizeof(packet));
    sprintf(filter_exp, "src %s and (udp or icmp)", inet_ntoa(host_addr));
    pthread_mutex_lock(&ctx->mutex);
    if (pcap_compile(ctx->pcap_handle, &filter, filter_exp, 0, ctx->ip) == PCAP_ERROR) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(ctx->pcap_handle));
        pthread_mutex_unlock(&ctx->mutex);
        return NO_RESULT;
    }
    if (pcap_setfilter(ctx->pcap_handle, &filter) == PCAP_ERROR) {
        fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(ctx->pcap_handle));
        pcap_freecode(&filter);
        pthread_mutex_unlock(&ctx->mutex);
        return NO_RESULT;
    }
    alarm(2);
    if (pcap_dispatch(ctx->pcap_handle, 1, pcap_udp_callback, (unsigned char *)&packet) == PCAP_ERROR) {
        fprintf(stderr, "Error while dispatching - %s\n", pcap_geterr(ctx->pcap_handle));
        pcap_freecode(&filter);
        pthread_mutex_unlock(&ctx->mutex);
        return NO_RESULT;
    }
    alarm(0);
    pcap_freecode(&filter);
    pthread_mutex_unlock(&ctx->mutex);
    if (ctx->packet_trace && (packet.ip_hdr.protocol == IPPROTO_UDP || packet.ip_hdr.protocol == IPPROTO_ICMP)) {
        printf("RCVD ");
        udp_packet_trace(&packet);
    }
    if (packet.ip_hdr.protocol == IPPROTO_UDP) {
        return OPEN_PORT;
    } else if (packet.ip_hdr.protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_hdr = (struct icmphdr *)&packet.udp_hdr;
        if (icmp_hdr->type == 3 && icmp_hdr->code == 3) {
            return CLOSED_PORT;
        } else {
            return FILTERED_PORT;
        }
    } else {
        return OPEN_FILTERED_PORT;
    }
}

static void set_tcp_result(tcpip_packet_t packet, nmap_context_t *ctx, scan_type_t scan_type, struct in_addr host_addr, int ip_idx, int result_idx) {
    uint16_t port = ntohs(packet.tcp_hdr.source);
    port_state_t result;
    int port_idx = 0;
    while (port_idx < ctx->ports_number && ctx->ports[port_idx] != port) {
        ++port_idx;
    }
    if (port_idx == ctx->ports_number) {
        return;
    }
    if (scan_type == SCAN_NULL || scan_type == SCAN_XMAS || scan_type == SCAN_FIN) {
        if (packet.ip_hdr.saddr == host_addr.s_addr) {
            if (packet.tcp_hdr.th_flags == (TH_ACK | TH_RST)) {
                result = CLOSED_PORT;
            } else {
                result = OPEN_FILTERED_PORT;
            }
        } else {
            result = OPEN_FILTERED_PORT;
        }
    } else if (scan_type == SCAN_ACK) {
        if (packet.ip_hdr.protocol == IPPROTO_TCP) {
            if (packet.tcp_hdr.th_flags == TH_RST) {
                result = UNFILTERED_PORT;
            } else {
                result = OPEN_FILTERED_PORT;
            }
        } else {
            result = FILTERED_PORT;
        }
    } else if (scan_type == SCAN_SYN) {
        if (packet.ip_hdr.protocol == IPPROTO_TCP) {
            if (packet.tcp_hdr.th_flags == (TH_ACK | TH_SYN)) {
                result = OPEN_PORT;
            } else if (packet.tcp_hdr.th_flags == (TH_ACK | TH_RST)) {
                result = CLOSED_PORT;
            } else {
                result = FILTERED_PORT;
            }
        } else {
            result = FILTERED_PORT;
        }
    }
    pthread_mutex_lock(&ctx->mutex);
    ctx->scan_result[ip_idx].entries[port_idx].results[result_idx] = result;
    pthread_mutex_unlock(&ctx->mutex);
}

static void do_tcp_scan(nmap_context_t *ctx, struct in_addr host_addr, uint16_t port, scan_type_t scan_type, int ip_idx,
        int result_idx) {
	struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);
    char    filter_exp[100] = {0};
    struct bpf_program filter;

    tcpip_packet_t packet = create_tcp_packet(host_addr, port, scan_type, ctx);
	ssize_t sent = sendto(ctx->tcp_socket_fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&dst_addr,
            dst_addr_len);
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->packet_trace) {
        printf("SENT ");
        tcp_packet_trace(&packet);
    }
    if (sent < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }
    ft_bzero(&packet, sizeof(packet));
    sprintf(filter_exp, "src %s and tcp", inet_ntoa(host_addr));
    if (pcap_compile(ctx->pcap_handle, &filter, filter_exp, 0, ctx->ip) == PCAP_ERROR) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(ctx->pcap_handle));
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }
    if (pcap_setfilter(ctx->pcap_handle, &filter) == PCAP_ERROR) {
        fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(ctx->pcap_handle));
        pcap_freecode(&filter);
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }
    alarm(2);
    if (pcap_dispatch(ctx->pcap_handle, 1, pcap_tcp_callback, (unsigned char *)&packet) == PCAP_ERROR) {
        fprintf(stderr, "Error while dispatching - %s\n", pcap_geterr(ctx->pcap_handle));
        pcap_freecode(&filter);
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }
    alarm(0);
    pcap_freecode(&filter);
    if (ctx->packet_trace && packet.ip_hdr.protocol == IPPROTO_TCP) {
        printf("RCVD ");
        tcp_packet_trace(&packet);
    }
    pthread_mutex_unlock(&ctx->mutex);
    set_tcp_result(packet, ctx, scan_type, host_addr, ip_idx, result_idx);
}

void    perform_scans(nmap_context_t *ctx, int ip_idx, int ips_number, int port_idx, int ports_number) {
    for (int i = 0; i < ips_number && ip_idx + i < ctx->ips_number; ++i) {
        for (int j = 0; j < ports_number && port_idx + j < ctx->ports_number; ++j) {
            ctx->scan_result[ip_idx + i].entries[port_idx + j].port = ctx->ports[port_idx + j];
            ctx->scan_result[ip_idx + i].total_ports = ctx->ports_number;
            ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion = NO_RESULT;
            int  k = 0;
            for (scan_type_t scan_type = SCAN_NULL; scan_type <= SCAN_UDP; scan_type *= 2, ++k) {
                if (!(scan_type & ctx->scan_types)) {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] = NO_RESULT;
                    continue;
                }
                if (scan_type == SCAN_UDP) {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] = do_udp_scan(ctx,
                            ctx->ips[ip_idx + i], ctx->ports[port_idx + j]);
                } else {
                    do_tcp_scan(ctx, ctx->ips[ip_idx + i], ctx->ports[port_idx + j], scan_type, i, k);
                }
            }
        }
    }
}
