//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "scan_utils.h"
#include "net_utils.h"
#include "utilities.h"

static port_state_t do_udp_scan(nmap_context_t *ctx, struct in_addr host_addr, uint16_t port) {
    struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);

    udpip_packet_t packet = create_udp_packet(dst_addr.sin_addr, port, ctx);
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
	ssize_t received = recvfrom(ctx->udp_socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr,
            &dst_addr_len);
    if (received < 0) {
        return OPEN_FILTERED_PORT;
    }
    if (ctx->packet_trace) {
        printf("RCVD ");
        udp_packet_trace(&packet);
    }
    return CLOSED_PORT;
}

static port_state_t    do_tcp_scan(nmap_context_t *ctx, struct in_addr host_addr, uint16_t port, scan_type_t scan_type) {
	struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);

    tcpip_packet_t packet = create_tcp_packet(dst_addr.sin_addr, port, scan_type, ctx);
	ssize_t sent = sendto(ctx->tcp_socket_fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&dst_addr,
            dst_addr_len);
    if (ctx->packet_trace) {
        printf("SENT ");
        tcp_packet_trace(&packet);
    }
    if (sent < 0) {
        return NO_RESULT;
    }
    ft_bzero(&packet, sizeof(packet));
	ssize_t received = recvfrom(ctx->tcp_socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr,
            &dst_addr_len);
    if (received < 0) {
        return FILTERED_PORT;
    }
    if (ctx->packet_trace) {
        printf("RCVD ");
        tcp_packet_trace(&packet);
    }
    if (scan_type == SCAN_NULL || scan_type == SCAN_XMAS || scan_type == SCAN_FIN) {
        if (packet.ip_hdr.saddr == host_addr.s_addr) {
            if (packet.tcp_hdr.th_flags == (TH_ACK | TH_RST)) {
                return CLOSED_PORT;
            } else {
                return OPEN_FILTERED_PORT;
            }
        } else {
            return OPEN_FILTERED_PORT;
        }
    } else if (scan_type == SCAN_ACK) {
        if (packet.ip_hdr.saddr == host_addr.s_addr) {
            if (packet.tcp_hdr.th_flags == TH_RST) {
                return UNFILTERED_PORT;
            } else {
                return OPEN_FILTERED_PORT;
            }
        } else {
            return FILTERED_PORT;
        }
    } else if (scan_type == SCAN_SYN) {
        if (packet.ip_hdr.saddr == host_addr.s_addr) {
            if (packet.tcp_hdr.th_flags == (TH_ACK | TH_SYN)) {
                return OPEN_PORT;
            } else if (packet.tcp_hdr.th_flags == (TH_ACK | TH_RST)) {
                return CLOSED_PORT;
            } else {
                return FILTERED_PORT;
            }
        } else {
            return FILTERED_PORT;
        }
    }
    return NO_RESULT;
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
                if (scan_type != SCAN_UDP) {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] = do_tcp_scan(ctx,
                            ctx->ips[ip_idx + i], ctx->ports[port_idx + j], scan_type);
                } else {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] = do_udp_scan(ctx,
                            ctx->ips[ip_idx + i], ctx->ports[port_idx + j]);
                }
                if (ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] >
                        ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion) {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion =
                            ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k];
                }
            }
            if (ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion == OPEN_PORT) {
                ctx->scan_result[ip_idx + i].open_ports++;
            }
        }
    }
}
