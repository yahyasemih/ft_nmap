//
// Created by Yahya Ez-zainabi on 11/30/22.
//

#include "ft_nmap.hpp"

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

uint16_t    *append_port(uint16_t port, uint16_t *ports, uint16_t ports_number) {
    uint16_t *new_ports = (uint16_t *)malloc((ports_number + 1) * sizeof(uint16_t));

    if (new_ports == NULL) {
        free(ports);
        return NULL;
    }
    memcpy(new_ports, ports, ports_number * sizeof(uint16_t));
    new_ports[ports_number] = port;
    free(ports);
    return new_ports;
}

int is_port_range(const char *arg, int len) {
    if (arg == NULL) {
        return 0;
    }
    int i = 0;
    while (i < len && arg[i] != '-') {
        ++i;
    }
    if (arg[i] == '-' && i + 1 < len) {
        return i;
    } else {
        return 0;
    }
}

int is_valid_port(const char *arg, int len) {
    for (int i = 0; i < len; ++i) {
        if (arg[i] > '9' || arg[i] < '0') {
            return 0;
        }
    }
    return 1;
}

int process_ports(char *arg, nmap_context_t *ctx) {
    char	*start_ptr;
    char	*end_ptr;
    int     range_idx;
    int     port;
    int     port_a;
    int     port_b;

    start_ptr = arg;
    while (start_ptr != NULL && *start_ptr != '\0') {
        end_ptr = start_ptr;
        while (*end_ptr != '\0' && *end_ptr != ',') {
            end_ptr++;
        }
        range_idx = is_port_range(start_ptr, (int)(end_ptr - start_ptr));
        if (range_idx > 0) {
            port_a = atoi(start_ptr);
            port_b = atoi(start_ptr + range_idx + 1);
            if (port_a < 0 || port_a > 65535 || port_b < 0 || port_b > 65535 || port_a > port_b) {
                return 1;
            }
            for (port = port_a; port <= port_b; ++port) {
                ctx->ports = append_port((uint16_t)port, ctx->ports, ctx->ports_number++);
            }
        } else if (is_valid_port(start_ptr, (int)(end_ptr - start_ptr))) {
            port = atoi(start_ptr);
            if (port < 0 || port > 65535) {
                return 1;
            }
            ctx->ports = append_port((uint16_t)port, ctx->ports, ctx->ports_number++);
            if (ctx->ports == NULL) {
                return 1;
            }
        } else {
            return 1;
        }
        if (*end_ptr == '\0')
            break;
        start_ptr = end_ptr + 1;
    }
    return 0;
}

struct in_addr  *append_ip(char *ip, struct in_addr *ips, uint8_t ips_number) {
	struct addrinfo *info = NULL;
	int res = getaddrinfo(ip, NULL, NULL, &info);
	if (res) {
		fprintf(stderr, "ft_nmap: failed to resolve `%s' : `%s'\n", ip, gai_strerror(res));
		free(ips);
		return NULL;
	}
	struct in_addr *new_ips = (struct in_addr *)malloc(sizeof(struct in_addr) * (ips_number + 1));
	if (new_ips == NULL) {
		free(ips);
		return NULL;
	}
	memcpy(new_ips, ips, ips_number * sizeof(struct in_addr));
	new_ips[ips_number].s_addr = *(in_addr_t *)(info->ai_addr->sa_data + 2);
	free(ips);
	freeaddrinfo(info);
	return new_ips;
}

int read_ips_from_file(char *filename, nmap_context_t *ctx) {
	char address[255];
	FILE *f = fopen(filename, "rb");
	if (f == NULL) {
		return 1;
	}
	while (!feof(f)) {
		int i = 0;
		char c;
		while (fread(&c, 1, 1, f) != 0 && c != '\n') {
			address[i++] = c;
		}
		address[i] = '\0';
		if (i != 0) {
			ctx->ips = append_ip(address, ctx->ips, ctx->ips_number++);
			if (ctx->ips == NULL) {
				return 1;
			}
		}
	}
	fclose(f);
	return 0;
}

uint8_t get_threads_number(char *arg) {
	int x = atoi(arg);
	if (x < 0 || x > 250) {
		return INVALID_THREADS_NUMBER;
	} else {
		return (uint8_t)x;
	}
}

int	is_valid_option(const char *arg) {
	return arg != NULL && arg[0] == '-' && arg[1] == '-' && arg[2] != '\0';
}

uint8_t get_scans(char *arg) {
	uint8_t	scans = 0;
	char	*start_ptr;
	char	*end_ptr;

	start_ptr = arg;
	while (start_ptr != NULL && *start_ptr != '\0') {
		end_ptr = start_ptr;
		while (*end_ptr != '\0' && *end_ptr != ',') {
			end_ptr++;
		}
		if (strncmp(start_ptr, "NULL", end_ptr - start_ptr) == 0) {
			scans |= SCAN_NULL;
		} else if (strncmp(start_ptr, "SYN", end_ptr - start_ptr) == 0) {
			scans |= SCAN_SYN;
		} else if (strncmp(start_ptr, "ACK", end_ptr - start_ptr) == 0) {
			scans |= SCAN_ACK;
		} else if (strncmp(start_ptr, "FIN", end_ptr - start_ptr) == 0) {
			scans |= SCAN_FIN;
		} else if (strncmp(start_ptr, "XMAS", end_ptr - start_ptr) == 0) {
			scans |= SCAN_XMAS;
		} else if (strncmp(start_ptr, "UDP", end_ptr - start_ptr) == 0) {
			scans |= SCAN_UDP;
		} else {
			scans = INVALID_SCAN_TYPE;
		}
		if (*end_ptr == '\0' || scans == INVALID_SCAN_TYPE)
			break;
		start_ptr = end_ptr + 1;
	}
	return scans;
}

void display_help(char *path) {
	printf("Help Screen\n");
	printf("%s [OPTIONS]\n", path);
	printf("--help\t\tPrint this help screen\n");
	printf("--ports\t\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf("--ip\t\tip addresses to scan in dot format\n");
	printf("--file\t\tFile name containing IP addresses to scan\n");
	printf("--speedup\t[250 max] number of parallel threads to use\n");
	printf("--scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
}

int	parse_options(int argc, char **argv, nmap_context_t *ctx) {
	for (int i = 1; i < argc; ++i) {
		if (!is_valid_option(argv[i])) {
			fprintf(stderr, "ft_nmap: invalid option: `%s'\n", argv[i]);
			return 1;
		}
		if (strcmp(argv[i], "--ip") == 0) {
			ctx->ips = append_ip(argv[++i], ctx->ips, ctx->ips_number++);
			if (ctx->ips == NULL) {
				return 1;
			}
		} else if (strcmp(argv[i], "--file") == 0) {
			if (read_ips_from_file(argv[++i], ctx)) {
				return 1;
			}
		} else if (strcmp(argv[i], "--speedup") == 0) {
			ctx->threads_number = get_threads_number(argv[++i]);
			if (ctx->threads_number == INVALID_THREADS_NUMBER) {
				fprintf(stderr, "ft_nmap: invalid number of threads: %s", argv[i]);
				return 1;
			}
		} else if (strcmp(argv[i], "--scan") == 0) {
			ctx->scan_types = get_scans(argv[++i]);
			if (ctx->scan_types == INVALID_SCAN_TYPE) {
				fprintf(stderr, "ft_nmap: invalid scan: `%s'", argv[i]);
				return 1;
			}
        } else if (strcmp(argv[i], "--ports") == 0) {
            if (process_ports(argv[++i], ctx)) {
                fprintf(stderr, "ft_nmap: invalid port argument: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
			display_help(argv[0]);
            clear_nmap_context(ctx);
			exit(0);
		} else {
			fprintf(stderr, "ft_nmap: invalid option: `%s'\n", argv[i]);
			display_help(argv[0]);
			return 1;
		}
	}
    if (ctx->scan_types == SCAN_EMPTY) {
        ctx->scan_types = SCAN_ALL;
    }
	return 0;
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
    timeout.tv_sec = 10;
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

uint8_t scan_type_to_th_flags(int scan_type) {
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

tcpip_packet_t  create_tcp_packet(struct in_addr dst_ip, u_short port, int scan_type) {
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

uint8_t do_tcp_scan(int socket_fd, struct in_addr host_addr, uint16_t port, int scan_type) {
	struct sockaddr_in dst_addr = {AF_INET, port, host_addr, {0}};
	socklen_t dst_addr_len = sizeof(dst_addr);

    tcpip_packet_t packet = create_tcp_packet(dst_addr.sin_addr, port, scan_type);
    printf("sent tcp seq: %u, ack: %u, ack seq: %u\n", packet.tcp_hdr.seq, packet.tcp_hdr.ack, packet.tcp_hdr.ack_seq);
    printf("tcp sum %d\n", packet.tcp_hdr.check);
	ssize_t sent = sendto(socket_fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&dst_addr, dst_addr_len);
	printf("sent %zu\n", sent);
	perror("sendto:");
    memset(&packet, 0, sizeof(packet));
	ssize_t received = recvfrom(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr, &dst_addr_len);
    perror("recvfrom:");
	printf("received %zu\n", received);
    struct in_addr src = {packet.ip_hdr.saddr};
    struct in_addr dst = {packet.ip_hdr.daddr};
    printf("id: %d\n", packet.ip_hdr.id);
    printf("ip_src: %s, ip_dst: %s\n", inet_ntoa(src), inet_ntoa(dst));
	printf("th_flags: %u\n", packet.tcp_hdr.th_flags);
	printf("tcp seq: %u, ack: %u, ack seq: %u\n", packet.tcp_hdr.seq, packet.tcp_hdr.ack, packet.tcp_hdr.ack_seq);

	return packet.tcp_hdr.th_flags;
}

void    perform_scans(nmap_context_t *ctx, int ip_idx, int ips_number, int port_idx, int ports_number) {
    for (int i = 0; i < ips_number; ++i) {
        for (int j = 0; j < ports_number; ++j) {
            for (int scan_type = SCAN_NULL; scan_type <= SCAN_UDP; scan_type *= 2) {
                if (!(scan_type & ctx->scan_types)) {
                    continue;
                }
                if (scan_type != SCAN_UDP) {
                    do_tcp_scan(ctx->socket_fd, ctx->ips[ip_idx + i], ctx->ports[port_idx + j], scan_type);
                }
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
	for (uint16_t i = 0; i < ctx.ips_number; ++i) {
		printf("%s\n", inet_ntoa(ctx.ips[i]));
	}
    for (uint16_t i = 0; i < ctx.ports_number; ++i) {
        printf("%d\n", ctx.ports[i]);
    }
    // TODO: sort and remove duplicated ports
    if (ctx.threads_number == 0) {
        perform_scans(&ctx, 0, ctx.ips_number, 0, ctx.ports_number);
    } else {
        // TODO: add threads
    }
    clear_nmap_context(&ctx);
	return 0;
}
