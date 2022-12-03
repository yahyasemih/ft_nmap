//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "thread_utils.h"

void    *thread_routine(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    perform_scans(ctx->nmap_ctx, ctx->ip_index, ctx->ips_number, ctx->port_index, ctx->ports_number);
    return NULL;
}

int    use_threads(nmap_context_t *nmap_ctx) {
    pthread_t           threads[nmap_ctx->threads_number];
    int         ips_by_thread = nmap_ctx->ips_number / nmap_ctx->threads_number;
    int         ports_by_thread = nmap_ctx->ports_number / nmap_ctx->threads_number;
    thread_context_t    *thread_ctx = malloc(sizeof(thread_context_t) * nmap_ctx->threads_number);

    if (thread_ctx == NULL) {
        return 1;
    }
    if (nmap_ctx->ips_number % nmap_ctx->threads_number != 0) {
        ips_by_thread++;
    }
    if (nmap_ctx->ports_number % nmap_ctx->threads_number != 0) {
        ports_by_thread++;
    }

    for (u_int8_t i = 0; i < nmap_ctx->threads_number; ++i) {
        thread_ctx[i].nmap_ctx = nmap_ctx;
        thread_ctx[i].ip_index = 0;
        thread_ctx[i].ips_number = nmap_ctx->ips_number;
        thread_ctx[i].port_index = i * ports_by_thread;
        thread_ctx[i].ports_number = ports_by_thread;
        if (pthread_create(threads + i, NULL, thread_routine, thread_ctx + i)) {
            perror("pthread_create");
            free(thread_ctx);
            return 1;
        }
    }
    for (u_int8_t i = 0; i < nmap_ctx->threads_number; ++i) {
        if (pthread_join(threads[i], NULL)) {
            perror("pthread_join");
            free(thread_ctx);
            return 1;
        }
    }
    free(thread_ctx);
    return 0;
}
