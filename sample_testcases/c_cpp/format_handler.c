/**
 * format_handler.c - String formatting and logging functions for SEC-C test cases
 *
 * This file contains logging and string formatting utilities that
 * demonstrate both vulnerable and safe uses of printf-family functions.
 * Common in server-side C code that logs user actions and messages.
 *
 * Part of: SEC-C Sample Test Cases (C/C++)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#define LOG_BUFFER_SIZE 512
#define MAX_MSG_LEN 256

/* Log level constants */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3
} log_level_t;

static const char *level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

/**
 * get_timestamp - Write the current timestamp into the provided buffer.
 * @buf:  output buffer (must be at least 32 bytes)
 * @size: size of the output buffer
 */
static void get_timestamp(char *buf, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* ===================================================================
 * TRUE POSITIVE #2: CWE-134 Format String Vulnerability
 * Passes user-controlled string directly as the format argument
 * to printf(). An attacker can inject format specifiers like %x, %n
 * to read/write arbitrary memory.
 * =================================================================== */

/**
 * log_user_message - Log a message received from a user.
 * @msg: the user-supplied message string (untrusted input)
 *
 * Intended to print the user's message to stdout for logging purposes.
 * WARNING: This function is vulnerable to format string attacks because
 * the user-controlled msg is passed directly as printf's format argument.
 */
void log_user_message(const char *msg)
{
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(stdout, "[%s] USER_MSG: ", timestamp);

    /* BUG: User-controlled string used directly as format string.
     * If msg contains %x, %s, %n etc., attacker can read stack
     * memory or write to arbitrary addresses. */
    printf(msg);

    printf("\n");
}

/**
 * handle_client_request - Simulates processing a client request that
 * includes a user-supplied description field.
 */
int handle_client_request(const char *client_id, const char *description)
{
    if (client_id == NULL || description == NULL)
        return -1;

    printf("Processing request from client: %s\n", client_id);

    /* Vulnerable: description is user-controlled */
    log_user_message(description);

    return 0;
}

/* ===================================================================
 * FALSE POSITIVE #7: CWE-134 FP (Basic tier, SAST resolves)
 * Uses printf with an explicit "%s" format specifier. The user message
 * is passed as a data argument, not as the format string itself.
 * SAST tools should trivially distinguish this from a true format
 * string vulnerability by checking the format argument is a literal.
 * =================================================================== */

/**
 * log_safe - Safely log a user-supplied message using explicit format specifier.
 * @msg: the user-supplied message string (untrusted input)
 *
 * Uses printf("%s", msg) which treats msg purely as data, preventing
 * any format specifier interpretation regardless of msg contents.
 */
void log_safe(const char *msg)
{
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(stdout, "[%s] SAFE_MSG: ", timestamp);

    /* SAFE: Explicit format specifier "%s" ensures msg is treated as
     * a data argument, not as a format string. No format string
     * vulnerability here even if msg contains %x, %n, etc. */
    printf("%s", msg);

    printf("\n");
}

/**
 * log_formatted - A safe variadic logging function that uses vfprintf
 * with a caller-provided format string (intended for internal use only,
 * not for user-controlled input).
 */
void log_formatted(log_level_t level, const char *fmt, ...)
{
    char timestamp[32];
    va_list args;

    if (fmt == NULL || level < LOG_DEBUG || level > LOG_ERROR)
        return;

    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(stdout, "[%s] [%s] ", timestamp, level_strings[level]);

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fprintf(stdout, "\n");
}
