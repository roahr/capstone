#include "netprobe.h"
#include <unistd.h>

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <command> [options]\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  capture   Capture packets from interface\n");
    fprintf(stderr, "  dns       Resolve hostname\n");
    fprintf(stderr, "  analyze   Analyze packet capture\n");
}

probe_config_t parse_probe_args(int argc, char **argv) {
    probe_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.interface, "eth0", sizeof(cfg.interface) - 1);
    cfg.count = 100;
    cfg.timeout = 30;
    cfg.verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "i:c:t:v")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(cfg.interface, optarg, sizeof(cfg.interface) - 1);
                break;
            case 'c':
                cfg.count = atoi(optarg);
                break;
            case 't':
                cfg.timeout = atoi(optarg);
                break;
            case 'v':
                cfg.verbose = 1;
                break;
        }
    }
    if (optind < argc) {
        strncpy(cfg.target, argv[optind], MAX_HOSTNAME - 1);
    }
    return cfg;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];
    probe_config_t cfg = parse_probe_args(argc - 1, argv + 1);

    if (strcmp(command, "dns") == 0) {
        if (cfg.target[0] == '\0') {
            fprintf(stderr, "dns: hostname required\n");
            return 1;
        }
        dns_result_t *result = resolve_hostname(cfg.target);
        if (result && result->status == 0) {
            printf("%s -> %s (%.2fms)\n", result->hostname,
                   result->resolved_ip, result->latency_ms);
        } else {
            printf("Resolution failed for %s\n", cfg.target);
        }
        free(result);
    } else if (strcmp(command, "capture") == 0) {
        printf("Capturing %d packets on %s...\n", cfg.count, cfg.interface);
        uint8_t raw[MAX_PACKET_SIZE];
        packet_t pkt;
        memset(raw, 0, sizeof(raw));
        parse_packet(raw, sizeof(raw), &pkt);
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
