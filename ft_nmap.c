//
// Created by Yahya Ez-zainabi on 11/30/22.
//

#include "ft_nmap.h"
#include "net_utils.h"
#include "options_utils.h"
#include "pcap_utils.h"
#include "printing_utils.h"
#include "scan_utils.h"
#include "thread_utils.h"
#include "utilities.h"

void clear_nmap_context(nmap_context_t *ctx) {
    if (ctx->tcp_socket_fd >= 0) {
        close(ctx->tcp_socket_fd);
        ctx->tcp_socket_fd = -1;
    }
    if (ctx->udp_socket_fd >= 0) {
        close(ctx->udp_socket_fd);
        ctx->udp_socket_fd = -1;
    }
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
    freeifaddrs(ctx->if_addr);
    ctx->if_addr = NULL;
    if (ctx->pcap_handle != NULL) {
        pcap_close(ctx->pcap_handle);
    }
    ctx->pcap_handle = NULL;
    pthread_mutex_destroy(&ctx->mutex);
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
        ft_bzero(ctx->scan_result[i].entries, ctx->ports_number * sizeof(scan_result_entry_t));
        ctx->scan_result[i].open_ports = 0;
        ctx->scan_result[i].total_ports = ctx->ports_number;
    }
    return 0;
}

void    choose_default_interface(nmap_context_t *ctx) {
    struct ifaddrs *if_addr, *if_addr_it;

    if (getifaddrs(&if_addr)) {
        fprintf(stderr, "ft_nmap: error while getting available interface: %s\n", strerror(errno));
        exit(1);
    }
    if_addr_it = if_addr;
    while (if_addr_it) {
        if (if_addr_it->ifa_addr != NULL && if_addr_it->ifa_addr->sa_family == AF_INET
                && if_addr_it->ifa_name != NULL && ft_strcmp(if_addr_it->ifa_name, "lo") != 0) {
            ctx->interface = if_addr_it->ifa_name;
            ctx->socket_addr = if_addr_it->ifa_addr;
            break;
        }
        if_addr_it = if_addr_it->ifa_next;
    }
    if (ctx->socket_addr == NULL || ctx->interface == NULL) {
        fprintf(stderr, "ft_nmap: could not choose an interface to use\n");
        freeifaddrs(if_addr);
        exit(1);
    }
    ctx->if_addr = if_addr;
}

nmap_context_t  *signal_ctx;

void    signal_handler(int sig) {
    if (sig == SIGALRM && signal_ctx != NULL) {
        pcap_breakloop(signal_ctx->pcap_handle);
    }
}

int	main(int argc, char **argv) {
	if (getuid() != 0) {
		fprintf(stderr, "please run as root to be able to create raw sockets\n");
		return 1;
	}
	if (argc == 1) {
		display_help(argv[0]);
		return 1;
	}
    struct timeval start_tv;
    struct timeval end_tv;
	nmap_context_t ctx = {0, 0, NULL, NULL, 0, 0, -1, -1, NULL, NULL, NULL, 255, 1337, 0, NULL, NULL, 0, 0, {}};
    signal_ctx = &ctx;
    choose_default_interface(&ctx);
	if (parse_options(argc, argv, &ctx) || initialize_socket(&ctx) || initialize_pcap(&ctx) || initialize_results(&ctx)) {
        clear_nmap_context(&ctx);
		return 1;
	}
    if (pthread_mutex_init(&ctx.mutex, NULL)) {
        fprintf(stderr, "ft_nmap: error when initilizing mutex: %s\n", strerror(errno));
        return 1;
    }
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    action.sa_handler = signal_handler;
    sigaction(SIGALRM, &action, NULL);
    print_configurations(&ctx);
    printf("Scanning..\n");
    gettimeofday(&start_tv, NULL);
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
