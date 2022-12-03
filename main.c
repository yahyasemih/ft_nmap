//
// Created by Yahya Ez-zainabi on 11/30/22.
//

#include "ft_nmap.h"
#include "options_utils.h"
#include "printing_utils.h"
#include "thread_utils.h"

void clear_nmap_context(nmap_context_t *ctx) {
    close(ctx->socket_fd);
    ctx->socket_fd = -1;
    free(ctx->ports);
    ctx->ports = NULL;
    free(ctx->ips);
    ctx->ips = NULL;
    if (ctx->scan_result != NULL) {
        for (int i = 0; i < ctx->ips_number; ++i) {
            free(ctx->scan_result[i].entries);
        }
        free(ctx->scan_result);
        ctx->scan_result = NULL;
    }
}

void ft_ip_checksum(u_short *addr) {
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

void ft_tcp_checksum(struct iphdr *ip_header, u_short *tcp_payload) {
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

int initialize_socket(nmap_context_t *ctx) {
    ctx->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (ctx->socket_fd < 0) {
        fprintf(stderr, "ft_nmap: socket: %s\n", strerror(errno));
        return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    char* interface = "enp0s3";
    int options = 1;

    if (setsockopt(ctx->socket_fd, IPPROTO_IP, IP_HDRINCL, &options, sizeof(options)) < 0
        || setsockopt (ctx->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt (ctx->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0
        || setsockopt( ctx->socket_fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
        fprintf(stderr, "ft_nmap: setsockopt: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

uint8_t scan_type_to_th_flags(scan_type_t scan_type) {
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

tcpip_packet_t  create_tcp_packet(struct in_addr dst_ip, u_short port, scan_type_t scan_type) {
    tcpip_packet_t  packet;
    struct timeval tv;

    bzero(&packet, sizeof(packet));
    gettimeofday(&tv, NULL);
    inet_pton(AF_INET, "10.11.100.232", &packet.ip_hdr.saddr);
    packet.ip_hdr.daddr = dst_ip.s_addr;
    packet.ip_hdr.version = 4;
    packet.ip_hdr.ihl = 5;
    packet.ip_hdr.tos = 0;
    packet.ip_hdr.tot_len = htons(sizeof(tcpip_packet_t));
    packet.ip_hdr.id = htons(tv.tv_usec & 0xFFFF);
    packet.ip_hdr.frag_off = 0;
    packet.ip_hdr.ttl = 255;
    packet.ip_hdr.protocol = IPPROTO_TCP;
    ft_ip_checksum((u_short *)&packet.ip_hdr);
    packet.tcp_hdr.th_flags = scan_type_to_th_flags(scan_type);
    packet.tcp_hdr.seq = ((tv.tv_sec & 0xFFFFFFFF) + tv.tv_usec) & 0xFFFFFFFF;
    packet.tcp_hdr.doff = 5;
    packet.tcp_hdr.window = htons(1024);
    packet.tcp_hdr.th_dport = htons(port);
    ft_tcp_checksum(&packet.ip_hdr, (u_short *)&packet.tcp_hdr);

    return packet;
}

int do_tcp_scan(int socket_fd, struct in_addr host_addr, uint16_t port, scan_type_t scan_type) {
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
        return NO_RESULT;
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
                            ctx->socket_fd, ctx->ips[ip_idx + i], ctx->ports[port_idx + j], scan_type);
                } else {
                    // TODO: implement UDP scan
                }
                // TODO: change how to decide on conclusion
                if (ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k] >
                        ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion) {
                    ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion =
                            ctx->scan_result[ip_idx + i].entries[port_idx + j].results[k];
                }
            }
            if (ctx->scan_result[ip_idx + i].entries[port_idx + j].conclusion & OPEN_PORT) {
                ctx->scan_result[ip_idx + i].open_ports++;
            }
        }
    }
}

int initialize_results(nmap_context_t *ctx) {
    ctx->scan_result = (scan_result_t *)malloc(ctx->ips_number * sizeof(scan_result_t));
    if (ctx->scan_result == NULL) {
        return 1;
    }
    for (uint16_t i = 0; i < ctx->ips_number; i++) {
        ctx->scan_result[i].entries = (scan_result_entry_t *)malloc(ctx->ports_number * sizeof(scan_result_entry_t));
        if (ctx->scan_result[i].entries == NULL) {
            return 1;
        }
        bzero(ctx->scan_result[i].entries, ctx->ports_number * sizeof(scan_result_entry_t));
        ctx->scan_result[i].open_ports = 0;
        ctx->scan_result[i].total_ports = ctx->ports_number;
    }
    return 0;
}

int	main(int argc, char **argv) {
	nmap_context_t ctx = {0, 0, NULL, NULL, 0, 0, -1, NULL};
    struct timeval start_tv;
    struct timeval end_tv;
//	if (getuid() != 0) {
//		fprintf(stderr, "please run as root to be able to create raw sockets\n");
//		return 1;
//	}
	if (argc == 1) {
		display_help(argv[0]);
		return 1;
	}
	if (parse_options(argc, argv, &ctx) || initialize_socket(&ctx) || initialize_results(&ctx)) {
        clear_nmap_context(&ctx);
		return 1;
	}
    print_configurations(&ctx);
    printf("Scanning..\n");
    gettimeofday(&start_tv, NULL);
    // TODO: sort and remove duplicated ports
    if (ctx.threads_number == 0) {
        perform_scans(&ctx, 0, ctx.ips_number, 0, ctx.ports_number);
    } else {
        if (use_threads(&ctx)) {
            clear_nmap_context(&ctx);
            return 1;
        }
    }
    gettimeofday(&end_tv, NULL);
    long u_secs = end_tv.tv_usec - start_tv.tv_usec;
    long secs = end_tv.tv_sec - start_tv.tv_sec;
    if (u_secs < 0) {
        secs--;
        u_secs += 1000000;
    }
    printf("Scan took %ld.%ld secs\n", secs, u_secs);
    print_results(&ctx);
    clear_nmap_context(&ctx);
	return 0;
}
