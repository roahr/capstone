#ifndef SYSMON_H
#define SYSMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_METRIC_LEN 256
#define MAX_LOG_LINE   512
#define MAX_PATH_LEN   256
#define DEFAULT_INTERVAL 5

typedef struct {
    double cpu_percent;
    double mem_used_mb;
    double mem_total_mb;
    double disk_used_gb;
    double disk_total_gb;
    time_t timestamp;
} metrics_t;

typedef struct {
    char filepath[MAX_PATH_LEN];
    FILE *handle;
    int remote_fd;
    char remote_addr[64];
    int is_active;
} log_ctx_t;

typedef struct {
    int interval;
    int daemonize;
    char logpath[MAX_PATH_LEN];
    char remote[64];
} config_t;

int  collect_cpu(metrics_t *m);
int  collect_memory(metrics_t *m);
int  collect_disk(metrics_t *m);
char *format_metric(const char *fmt, metrics_t *m);

log_ctx_t *logger_open(const char *path);
void logger_write(log_ctx_t *ctx, const char *message);
void logger_close(log_ctx_t *ctx);
void logger_flush_and_disconnect(log_ctx_t *ctx);

config_t parse_args(int argc, char **argv);

#endif
