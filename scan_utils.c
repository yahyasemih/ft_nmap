//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "scan_utils.h"
#include "net_utils.h"

static port_state_t do_udp_scan(int socket_fd, struct in_addr host_addr, uint16_t port) {
    struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);

    udpip_packet_t packet = create_udp_packet(dst_addr.sin_addr, port);
    ssize_t sent = sendto(socket_fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&dst_addr, dst_addr_len);
    if (sent < 0) {
        perror("sendto");
        return NO_RESULT;
    }
    bzero(&packet, sizeof(packet));
	ssize_t received = recvfrom(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr, &dst_addr_len);
    if (received < 0) {
        return OPEN_PORT | FILTERED_PORT;
    }
    return CLOSED_PORT;
}

static port_state_t    do_tcp_scan(int socket_fd, struct in_addr host_addr, uint16_t port, scan_type_t scan_type) {
	struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);

    tcpip_packet_t packet = create_tcp_packet(dst_addr.sin_addr, port, scan_type);
	ssize_t sent = sendto(socket_fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&dst_addr, dst_addr_len);
    if (sent < 0) {
        return NO_RESULT;
    }
    bzero(&packet, sizeof(packet));
	ssize_t received = recvfrom(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr, &dst_addr_len);
    if (received < 0) {
        return FILTERED_PORT;
    }
    if (scan_type == SCAN_NULL || scan_type == SCAN_XMAS || scan_type == SCAN_FIN) {
        if (packet.ip_hdr.saddr == host_addr.s_addr) {
            if (packet.tcp_hdr.th_flags == (TH_ACK | TH_RST)) {
                return CLOSED_PORT;
            } else {
                return OPEN_PORT | FILTERED_PORT;
            }
        } else {
            return OPEN_PORT | FILTERED_PORT;
        }
    } else if (scan_type == SCAN_ACK) {
        if (packet.ip_hdr.saddr == host_addr.s_addr) {
            if (packet.tcp_hdr.th_flags == TH_RST) {
                return UNFILTERED_PORT;
            } else {
                return OPEN_PORT | FILTERED_PORT;
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
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] = do_tcp_scan(
                            ctx->tcp_socket_fd, ctx->ips[ip_idx + i], ctx->ports[port_idx + j], scan_type);
                } else {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] = do_udp_scan(
                            ctx->udp_socket_fd, ctx->ips[ip_idx + i], ctx->ports[port_idx + j]);
                }
                // TODO: change how to decide on conclusion
                if (ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] == OPEN_PORT) {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion = OPEN_PORT;
                } else if (ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] >
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
