//
// Created by Yahya Ez-zainabi on 12/03/22.
//

#include "printing_utils.h"
#include "net_utils.h"

static const char  *port_state_to_str(port_state_t state) {
    if (state == OPEN_PORT) {
        return "Open";
    } else if (state == CLOSED_PORT) {
        return "Closed";
    } else if (state == FILTERED_PORT) {
        return "Filtered";
    } else if (state == UNFILTERED_PORT) {
        return "Unfiltered";
    } else if (state == (OPEN_FILTERED_PORT)) {
        return "Open|filtered";
    } else {
        return "UNDEFINED";
    }
}

static int scans_number(scan_type_t scans) {
    int i = 0;
    for (scan_type_t scan_type = SCAN_NULL; scan_type <= SCAN_UDP; scan_type *= 2) {
        if (scan_type & scans) {
            ++i;
        }
    }
    return i;
}

static const char  *scan_type_to_str(scan_type_t scan_type) {
    if (scan_type == SCAN_SYN) {
        return "SYN";
    } else if (scan_type == SCAN_NULL) {
        return "NULL";
    } else if (scan_type == SCAN_FIN) {
        return "FIN";
    } else if (scan_type == SCAN_XMAS) {
        return "XMAS";
    } else if (scan_type == SCAN_ACK) {
        return "ACK";
    } else if (scan_type == SCAN_UDP) {
        return "UDP";
    } else {
        return "UNDEFINED";
    }
}

static int    result_to_str(port_state_t results[6], scan_type_t scans) {
    int res = 0;
    for (int i = 0; i < 6; ++i) {
        if (results[i] == NO_RESULT) {
            continue;
        }
        res += printf(" %s(%s)", scan_type_to_str(1 << i), port_state_to_str(results[i]));
    }
    return res % (scans_number(scans) * 20 + 1);
}

static void    print_ports(scan_result_t *result, const char *type, int number, port_state_t state, scan_type_t scans) {
    if (number > 0) {
        printf("%s ports:\n", type);
        printf("%-10s %-30s %-*s %-20s\n", "Port", "Service Name (if applicable)", scans_number(scans) * 20, "Results",
                "Conclusion");
        for (int i = 0; i < scans_number(scans) * 20 + 60; ++i) {
            printf("-");
        }
        printf("\n");
        for (int i = 0; i < result->total_ports; ++i) {
            if (!(result->entries[i].conclusion & state)) {
                continue;
            }
            struct servent *s = getservbyport(htons(result->entries[i].port), NULL);
            char *name;
            if (s == NULL) {
                name = "Unassigned";
            } else {
                name = s->s_name;
            }
            printf("%-10d %-30s", result->entries[i].port, name);
            printf(" %*s", scans_number(scans) * 20 - result_to_str(result->entries[i].results, scans), "");
            printf(" %-20s\n", port_state_to_str(result->entries[i].conclusion));
        }
        printf("\n");
    }
}

static void    print_scans(scan_type_t scans) {
    for (scan_type_t scan_type = SCAN_NULL; scan_type <= SCAN_UDP; scan_type *= 2) {
        if (scan_type & scans) {
            printf(" %s", scan_type_to_str(scan_type));
        }
    }
    printf("\n");
}

void    print_results(nmap_context_t *ctx) {
    for (int i = 0; i < ctx->ips_number; ++i) {
        char hostname[NI_MAXHOST + 1];
        if (dns_resolve(ctx->ips[i], hostname, NI_MAXHOST)) {
            printf("IP address: %s\n", inet_ntoa(ctx->ips[i]));
        } else {
            printf("IP address: %s (%s)\n", inet_ntoa(ctx->ips[i]), hostname);
        }
        print_ports(ctx->scan_result + i, "Open", ctx->scan_result->open_ports, OPEN_PORT, ctx->scan_types);
        print_ports(ctx->scan_result + i, "Closed/Filtered/Unfiltered",
                    ctx->ports_number - ctx->scan_result->open_ports, ~OPEN_PORT, ctx->scan_types);
    }
}

void    print_configurations(nmap_context_t *ctx) {
    printf("Scan Configurations\n");
    printf("No of Ports to scan : %d\n", ctx->ports_number);
    printf("Scans to be performed :");
    print_scans(ctx->scan_types);
    printf("No of threads : %d\n", ctx->threads_number);
}
