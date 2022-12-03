//
// Created by Yahya Ez-zainabi on 11/30/22.
//

#include "ft_nmap.h"
#include "net_utils.h"
#include "options_utils.h"
#include "printing_utils.h"
#include "scan_utils.h"
#include "thread_utils.h"

void clear_nmap_context(nmap_context_t *ctx) {
    close(ctx->tcp_socket_fd);
    close(ctx->udp_socket_fd);
    ctx->tcp_socket_fd = -1;
    ctx->udp_socket_fd = -1;
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
	nmap_context_t ctx = {0, 0, NULL, NULL, 0, 0, -1, -1, NULL};
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
