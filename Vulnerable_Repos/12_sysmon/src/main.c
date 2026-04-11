#include "sysmon.h"
#include <signal.h>

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

config_t parse_args(int argc, char **argv) {
    config_t cfg;
    cfg.interval = DEFAULT_INTERVAL;
    cfg.daemonize = 0;
    strncpy(cfg.logpath, "/var/log/sysmon.log", MAX_PATH_LEN - 1);
    cfg.remote[0] = '\0';

    int opt;
    while ((opt = getopt(argc, argv, "i:l:r:d")) != -1) {
        switch (opt) {
            case 'i':
                cfg.interval = atoi(optarg);
                if (cfg.interval < 1) cfg.interval = 1;
                break;
            case 'l':
                strncpy(cfg.logpath, optarg, MAX_PATH_LEN - 1);
                cfg.logpath[MAX_PATH_LEN - 1] = '\0';
                break;
            case 'r':
                strncpy(cfg.remote, optarg, sizeof(cfg.remote) - 1);
                cfg.remote[sizeof(cfg.remote) - 1] = '\0';
                break;
            case 'd':
                cfg.daemonize = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i interval] [-l logpath] [-r remote] [-d]\n", argv[0]);
                exit(1);
        }
    }
    return cfg;
}

int main(int argc, char **argv) {
    config_t cfg = parse_args(argc, argv);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (cfg.daemonize) {
        if (daemon(0, 0) < 0) {
            perror("daemon");
            return 1;
        }
    }

    log_ctx_t *log = logger_open(cfg.logpath);
    if (!log) {
        fprintf(stderr, "Failed to open log: %s\n", cfg.logpath);
        return 1;
    }

    printf("sysmon started (interval=%ds, log=%s)\n", cfg.interval, cfg.logpath);

    metrics_t m;
    while (running) {
        memset(&m, 0, sizeof(m));
        m.timestamp = time(NULL);

        collect_cpu(&m);
        collect_memory(&m);
        collect_disk(&m);

        char *line = format_metric("cpu=%.1f%% mem=%.0f/%.0fMB disk=%.1f/%.1fGB", &m);
        if (line) {
            logger_write(log, line);
            free(line);
        }

        sleep(cfg.interval);
    }

    logger_close(log);
    printf("sysmon stopped.\n");
    return 0;
}
