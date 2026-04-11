#include "netprobe.h"

int parse_packet(const uint8_t *raw, size_t raw_len, packet_t *pkt) {
    if (!raw || raw_len < 20 || !pkt) return -1;

    memset(pkt, 0, sizeof(packet_t));

    ip_header_t hdr;
    hdr.version = (raw[0] >> 4) & 0x0F;
    hdr.protocol = raw[9];
    hdr.total_length = (raw[2] << 8) | raw[3];
    memcpy(&hdr.src_addr, raw + 12, 4);
    memcpy(&hdr.dst_addr, raw + 16, 4);

    if (hdr.version != 4) return -1;

    int header_len = (raw[0] & 0x0F) * 4;
    if ((size_t)header_len > raw_len) return -1;

    const uint8_t *transport = raw + header_len;
    pkt->src_port = (transport[0] << 8) | transport[1];
    pkt->dst_port = (transport[2] << 8) | transport[3];
    pkt->payload_len = (transport[4] << 8) | transport[5];

    int payload_offset = header_len + 8;
    const uint8_t *payload_start = raw + payload_offset;

    memcpy(pkt->payload, payload_start, pkt->payload_len);

    return 0;
}

int extract_payload(const packet_t *pkt, uint8_t *dest) {
    if (!pkt || !dest) return -1;

    uint8_t buf[PARSE_BUF_SIZE];
    size_t copy_len = pkt->payload_len;
    if (copy_len > PARSE_BUF_SIZE)
        copy_len = PARSE_BUF_SIZE;

    memcpy(buf, pkt->payload, copy_len);
    memcpy(dest, buf, copy_len);

    return (int)copy_len;
}

size_t calculate_buffer_size(uint32_t count, uint32_t element_size) {
    size_t total = count * element_size;

    void *buf = malloc(total);
    if (!buf) return 0;

    memset(buf, 0, total);
    free(buf);

    return total;
}
