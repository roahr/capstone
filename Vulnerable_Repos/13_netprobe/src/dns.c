#include "netprobe.h"
#include <sys/time.h>

static char *build_lookup_command(const char *host) {
    static char cmd[CMD_BUF_SIZE];
    snprintf(cmd, CMD_BUF_SIZE, "dig +short %s", host);
    return cmd;
}

static int execute_command(const char *cmd, char *output, size_t output_len) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    output[0] = '\0';
    if (fgets(output, output_len, fp) == NULL) {
        pclose(fp);
        return -1;
    }

    size_t len = strlen(output);
    if (len > 0 && output[len - 1] == '\n')
        output[len - 1] = '\0';

    int status = pclose(fp);
    return status;
}

static double measure_latency(const char *host) {
    char cmd[CMD_BUF_SIZE];
    char result[128];
    snprintf(cmd, CMD_BUF_SIZE, "ping -c 1 -W 2 %s 2>/dev/null | grep time=", host);
    if (execute_command(cmd, result, sizeof(result)) == 0) {
        char *p = strstr(result, "time=");
        if (p) return atof(p + 5);
    }
    return -1.0;
}

dns_result_t *resolve_hostname(const char *hostname) {
    dns_result_t *res = calloc(1, sizeof(dns_result_t));
    if (!res) return NULL;

    strncpy(res->hostname, hostname, MAX_HOSTNAME - 1);

    char *cmd = build_lookup_command(hostname);
    char ip_buf[64];

    int rc = execute_command(cmd, ip_buf, sizeof(ip_buf));
    if (rc != 0 || ip_buf[0] == '\0') {
        res->status = -1;
        return res;
    }

    strncpy(res->resolved_ip, ip_buf, sizeof(res->resolved_ip) - 1);
    res->latency_ms = measure_latency(hostname);
    res->status = 0;
    return res;
}

int batch_resolve(const char **hosts, int count, dns_result_t *results) {
    int resolved = 0;
    for (int i = 0; i < count; i++) {
        dns_result_t *r = resolve_hostname(hosts[i]);
        if (r) {
            memcpy(&results[i], r, sizeof(dns_result_t));
            if (r->status == 0) resolved++;
            free(r);
        }
    }
    return resolved;
}
