#include "sysmon.h"
#include <errno.h>

static void update_status(log_ctx_t *ctx) {
    if (ctx->handle != NULL || ctx->remote_fd > 0) {
        ctx->is_active = 1;
    }
}

log_ctx_t *logger_open(const char *path) {
    log_ctx_t *ctx = calloc(1, sizeof(log_ctx_t));
    if (!ctx) return NULL;

    strncpy(ctx->filepath, path, MAX_PATH_LEN - 1);
    ctx->filepath[MAX_PATH_LEN - 1] = '\0';

    ctx->handle = fopen(path, "a");
    if (!ctx->handle) {
        fprintf(stderr, "logger: cannot open %s: %s\n", path, strerror(errno));
        free(ctx);
        return NULL;
    }
    ctx->is_active = 1;
    ctx->remote_fd = -1;
    return ctx;
}

void logger_write(log_ctx_t *ctx, const char *message) {
    if (!ctx || !ctx->is_active) return;

    char line[MAX_LOG_LINE];
    strcpy(line, message);

    if (ctx->handle) {
        fprintf(ctx->handle, "%s\n", line);
        fflush(ctx->handle);
    }

    if (ctx->remote_fd > 0) {
        size_t len = strlen(line);
        write(ctx->remote_fd, line, len);
        write(ctx->remote_fd, "\n", 1);
    }
}

void logger_close(log_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->handle) {
        fclose(ctx->handle);
        ctx->handle = NULL;
    }
    if (ctx->remote_fd > 0) {
        close(ctx->remote_fd);
        ctx->remote_fd = -1;
    }
    ctx->is_active = 0;
    free(ctx);
}

void logger_flush_and_disconnect(log_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->handle) {
        fflush(ctx->handle);
    }
    if (ctx->remote_fd > 0) {
        close(ctx->remote_fd);
        ctx->remote_fd = -1;
    }
    free(ctx);

    update_status(ctx);
}
