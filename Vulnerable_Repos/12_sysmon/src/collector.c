#include "sysmon.h"

int collect_cpu(metrics_t *m) {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return -1;

    unsigned long user, nice, system, idle;
    if (fscanf(fp, "cpu %lu %lu %lu %lu", &user, &nice, &system, &idle) != 4) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    unsigned long total = user + nice + system + idle;
    unsigned long active = user + nice + system;
    m->cpu_percent = (total > 0) ? (100.0 * active / total) : 0.0;
    return 0;
}

int collect_memory(metrics_t *m) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1;

    char label[64];
    unsigned long value;
    while (fscanf(fp, "%63s %lu kB", label, &value) == 2) {
        if (strcmp(label, "MemTotal:") == 0)
            m->mem_total_mb = value / 1024.0;
        else if (strcmp(label, "MemAvailable:") == 0)
            m->mem_used_mb = m->mem_total_mb - (value / 1024.0);
    }
    fclose(fp);
    return 0;
}

int collect_disk(metrics_t *m) {
    FILE *fp = popen("df -BG / 2>/dev/null | tail -1", "r");
    if (!fp) return -1;

    char dev[128];
    double total, used;
    if (fscanf(fp, "%127s %lfG %lfG", dev, &total, &used) == 3) {
        m->disk_total_gb = total;
        m->disk_used_gb = used;
    }
    pclose(fp);
    return 0;
}

char *format_metric(const char *fmt, metrics_t *m) {
    char buf[MAX_METRIC_LEN];
    char timestamp[32];
    struct tm *tm_info = localtime(&m->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    sprintf(buf, fmt, m->cpu_percent, m->mem_used_mb, m->mem_total_mb,
            m->disk_used_gb, m->disk_total_gb);

    size_t total_len = strlen(timestamp) + 3 + strlen(buf) + 1;
    char *result = malloc(total_len);
    if (!result) return NULL;

    snprintf(result, total_len, "[%s] %s", timestamp, buf);
    return result;
}
