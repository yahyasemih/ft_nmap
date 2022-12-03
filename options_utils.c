//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "options_utils.h"

static uint16_t    *append_port(uint16_t port, uint16_t *ports, uint16_t ports_number) {
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

static int is_port_range(const char *arg, int len) {
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

static int is_valid_port(const char *arg, int len) {
    for (int i = 0; i < len; ++i) {
        if (arg[i] > '9' || arg[i] < '0') {
            return 0;
        }
    }
    return 1;
}

static int process_ports(char *arg, nmap_context_t *ctx) {
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

static struct in_addr  *append_ip(char *ip, struct in_addr *ips, uint8_t ips_number) {
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

static int read_ips_from_file(char *filename, nmap_context_t *ctx) {
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
                fclose(f);
				return 1;
			}
		}
	}
	fclose(f);
	return 0;
}

static uint8_t get_threads_number(char *arg) {
	int x = atoi(arg);
	if (x < 0 || x > 250) {
		return INVALID_THREADS_NUMBER;
	} else {
		return (uint8_t)x;
	}
}

static int	is_valid_option(const char *arg) {
	return arg != NULL && arg[0] == '-' && arg[1] == '-' && arg[2] != '\0';
}

static scan_type_t get_scans(char *arg) {
    scan_type_t	scans = 0;
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

static void    clean_ports(nmap_context_t *ctx) {
    uint16_t    tmp;

    for (int i = 0; i < ctx->ports_number; ++i) {
        for (int j = i + 1; j < ctx->ports_number; ++j) {
            if (ctx->ports[j] > ctx->ports[i]) {
                tmp = ctx->ports[i];
                ctx->ports[i] = ctx->ports[j];
                ctx->ports[j] = tmp;
            }
        }
    }
    int duplicated = 0;
    uint16_t    *new_ports;
    for (int i = 1; i < ctx->ports_number; ++i) {
        if (ctx->ports[i] == ctx->ports[i - 1]) {
            ++duplicated;
        }
    }
    if (duplicated == 0) {
        return;
    }
    new_ports = (uint16_t *)malloc(sizeof(uint16_t) * (ctx->ports_number - duplicated));
    if (new_ports != NULL) {
        new_ports[0] = ctx->ports[0];
        int j = 1;
        for (int i = 1; i < ctx->ports_number; ++i) {
            if (ctx->ports[i] != ctx->ports[i - 1]) {
                new_ports[j++] = ctx->ports[i];
            }
        }
        free(ctx->ports);
        ctx->ports = new_ports;
        ctx->ports_number -= duplicated;
    }
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
    if (ctx->ports_number == 0) {
        for (uint16_t port = 1; port <= 1024; ++port) {
            ctx->ports = append_port((uint16_t)port, ctx->ports, ctx->ports_number++);
        }
    } else {
        clean_ports(ctx);
        if (ctx->ports_number > 1024) {
            fprintf(stderr, "ft_nmap: number of ports should not exceed 1024\n");
            return 1;
        }
    }
	return 0;
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
