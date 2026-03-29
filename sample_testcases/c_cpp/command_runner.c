/**
 * command_runner.c - Shell command execution functions for SEC-C test cases
 *
 * This file contains functions that execute system commands, demonstrating
 * both vulnerable command injection patterns and safe hardcoded command usage.
 * Common in network utilities and system administration tools written in C.
 *
 * Part of: SEC-C Sample Test Cases (C/C++)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_BUFFER_SIZE 512
#define HOSTNAME_MAX 253
#define RESULT_BUFFER 4096

/* ===================================================================
 * TRUE POSITIVE #3: CWE-78 OS Command Injection
 * Builds a shell command by interpolating user-supplied hostname directly
 * into a command string using sprintf, then executes it with system().
 * An attacker can inject arbitrary commands via the hostname parameter
 * (e.g., "8.8.8.8; rm -rf /").
 * =================================================================== */

/**
 * ping_host - Ping a remote host to check network connectivity.
 * @hostname: the target hostname or IP address (untrusted user input)
 *
 * Returns: the exit code from the system() call
 *
 * WARNING: This function directly interpolates the hostname into a shell
 * command without any sanitization. An attacker can append arbitrary
 * commands using shell metacharacters (;, &&, ||, |, $(), backticks).
 */
int ping_host(const char *hostname)
{
    char cmd[CMD_BUFFER_SIZE];

    if (hostname == NULL)
        return -1;

    /* BUG: User input is directly interpolated into shell command.
     * Input like "8.8.8.8; cat /etc/passwd" will execute both commands.
     * sprintf does not sanitize shell metacharacters. */
    sprintf(cmd, "ping -c 3 %s", hostname);

    printf("Executing network check: %s\n", cmd);

    /* BUG: system() passes the command string to /bin/sh for interpretation,
     * allowing shell metacharacter injection from the hostname. */
    return system(cmd);
}

/**
 * network_diagnostic - Higher-level function that calls ping_host with
 * a user-provided target. Demonstrates the vulnerability in context.
 */
int network_diagnostic(const char *target)
{
    int result;

    printf("Running network diagnostic for: %s\n", target);

    result = ping_host(target);

    if (result == 0) {
        printf("Host %s is reachable.\n", target);
    } else {
        printf("Host %s is unreachable or command failed.\n", target);
    }

    return result;
}

/* ===================================================================
 * FALSE POSITIVE #8: CWE-78 FP (Contextual tier, Graph resolves)
 * Uses system() with a completely hardcoded command string. There is
 * no user input flowing into the command at any point. SAST tools may
 * flag the system() call generically, but control-flow/data-flow graph
 * analysis will confirm no tainted data reaches the command string.
 * =================================================================== */

/**
 * check_disk_space - Check available disk space on /tmp.
 *
 * Uses a hardcoded system command with no external input. The command
 * string is a compile-time constant and cannot be influenced by users.
 *
 * Returns: the exit code from the system() call
 */
int check_disk_space(void)
{
    /* SAFE: Command string is a hardcoded literal. No user input flows
     * into this call. Graph-based analysis (data flow / taint tracking)
     * confirms the argument to system() has no tainted sources. */
    return system("df -h /tmp");
}

/**
 * get_system_uptime - Another safe hardcoded system command example.
 * Returns the system uptime information.
 */
int get_system_uptime(void)
{
    return system("uptime");
}

/**
 * validate_hostname - Basic hostname validation helper.
 * Checks that the hostname contains only allowed characters.
 * This is an example of how ping_host SHOULD sanitize input.
 *
 * Returns: 1 if valid, 0 if invalid
 */
int validate_hostname(const char *hostname)
{
    size_t i, len;

    if (hostname == NULL)
        return 0;

    len = strlen(hostname);
    if (len == 0 || len > HOSTNAME_MAX)
        return 0;

    for (i = 0; i < len; i++) {
        char c = hostname[i];
        /* Allow alphanumeric, hyphens, dots, and colons (for IPv6) */
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '.' || c == ':')) {
            return 0;
        }
    }

    return 1;
}
