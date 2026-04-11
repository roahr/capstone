#ifndef NETPROBE_H
#define NETPROBE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PACKET_SIZE  65535
#define PARSE_BUF_SIZE   1024
#define MAX_HOSTNAME     256
#define CMD_BUF_SIZE     512

typedef struct {
    uint8_t  version;
    uint8_t  protocol;
    uint16_t total_length;
    uint32_t src_addr;
    uint32_t dst_addr;
} ip_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t payload_len;
    uint8_t  payload[MAX_PACKET_SIZE];
} packet_t;

typedef struct {
    char hostname[MAX_HOSTNAME];
    char resolved_ip[64];
    double latency_ms;
    int    status;
} dns_result_t;

typedef struct {
    char interface[32];
    int  count;
    int  timeout;
    int  verbose;
    char target[MAX_HOSTNAME];
} probe_config_t;

int  parse_packet(const uint8_t *raw, size_t raw_len, packet_t *pkt);
int  extract_payload(const packet_t *pkt, uint8_t *dest);

dns_result_t *resolve_hostname(const char *hostname);
int           batch_resolve(const char **hosts, int count, dns_result_t *results);

size_t calculate_buffer_size(uint32_t count, uint32_t element_size);

probe_config_t parse_probe_args(int argc, char **argv);

#endif
