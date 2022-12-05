#include "pcap_utils.h"
#include "utilities.h"

int initialize_pcap(nmap_context_t *ctx) {
    char error_buffer[PCAP_ERRBUF_SIZE];

    ctx->pcap_handle = pcap_open_live(ctx->interface, BUFSIZ, 1, 1000, error_buffer);
    if (ctx->pcap_handle == NULL) {
        printf("ft_nmap: error openning live capture: %s\n", error_buffer);
        return 1;
    }
    if (pcap_lookupnet(ctx->interface, &ctx->ip, &ctx->subnet_mask, error_buffer) == -1) {
        printf("ft_nmap: could not get information for device: %s\n", ctx->interface);
        ctx->ip = 0;
        ctx->subnet_mask = 0;
    }
    return 0;
}

void pcap_tcp_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ether_header *eth_header;
    tcpip_packet_t      *tcp_packet;

    (void)header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    tcp_packet = (tcpip_packet_t *)args;
    ft_memcpy(tcp_packet, packet + sizeof(struct ether_header), sizeof(tcpip_packet_t));
}

void pcap_udp_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ether_header *eth_header;
    udpip_packet_t      *udp_packet;

    (void)header;
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    udp_packet = (udpip_packet_t *)args;
    ft_memcpy(udp_packet, packet + sizeof(struct ether_header), sizeof(udpip_packet_t));
}
