
#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include "ft_nmap.h"

int initialize_pcap(nmap_context_t *ctx);

void pcap_tcp_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

void pcap_udp_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif
