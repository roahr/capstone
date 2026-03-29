/**
 * buffer_ops.c - Buffer manipulation functions for SEC-C test cases
 *
 * This file contains functions that perform various buffer operations
 * commonly found in systems-level C code. Includes both vulnerable
 * and safe implementations for security analysis testing.
 *
 * Part of: SEC-C Sample Test Cases (C/C++)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define USERNAME_MAX 64
#define DEST_CAPACITY 256
#define INPUT_BUFSIZE 1024

/* ===================================================================
 * TRUE POSITIVE #1: CWE-120 Buffer Overflow
 * Copies a username into a fixed-size buffer without bounds checking.
 * If src exceeds 64 bytes, this overflows the destination buffer.
 * =================================================================== */

/**
 * copy_username - Copy a username string into the destination buffer.
 * @dest: destination buffer (caller-allocated, expected to be USERNAME_MAX bytes)
 * @src:  source username string (untrusted input)
 *
 * WARNING: This function does not validate the length of src before
 * copying. The caller must ensure src fits within dest.
 */
void copy_username(char *dest, const char *src)
{
    /* BUG: No bounds check on src length - classic buffer overflow */
    strcpy(dest, src);
}

/**
 * register_user - Demonstrates the vulnerable copy_username in context.
 * Allocates a fixed-size buffer on the stack and copies user input into it.
 */
int register_user(const char *username)
{
    char user_buf[USERNAME_MAX];

    if (username == NULL)
        return -1;

    /* Vulnerable: username could exceed USERNAME_MAX bytes */
    copy_username(user_buf, username);

    printf("Registered user: %s\n", user_buf);
    return 0;
}

/* ===================================================================
 * TRUE POSITIVE #5: CWE-120 Buffer Overflow #2
 * Uses gets() to read input, completely ignoring the size parameter.
 * gets() has no way to limit input length and is inherently unsafe.
 * =================================================================== */

/**
 * read_input - Read a line of user input into the provided buffer.
 * @buffer: destination buffer for user input
 * @size:   intended maximum size of buffer (IGNORED by implementation)
 *
 * Returns: 0 on success, -1 on failure
 *
 * NOTE: The size parameter exists to suggest safe usage, but the
 * implementation incorrectly uses gets() which cannot enforce it.
 */
int read_input(char *buffer, int size)
{
    if (buffer == NULL || size <= 0)
        return -1;

    printf("Enter input (max %d chars): ", size - 1);

    /* BUG: gets() ignores size parameter entirely - unbounded read */
    gets(buffer);

    return 0;
}

/* ===================================================================
 * FALSE POSITIVE #6: CWE-120 FP (Basic tier, SAST resolves)
 * Uses strncpy with explicit bounds and null-termination.
 * SAST tools should recognize strncpy with proper size limiting
 * as safe and filter this out at the basic analysis tier.
 * =================================================================== */

/**
 * safe_copy - Safely copy src into dest with explicit bounds checking.
 * @dest:      destination buffer
 * @dest_size: total size of the destination buffer in bytes
 * @src:       source string to copy
 *
 * Uses strncpy limited to dest_size-1, then explicitly null-terminates.
 * This is a standard safe string copy pattern.
 */
void safe_copy(char *dest, size_t dest_size, const char *src)
{
    if (dest == NULL || src == NULL || dest_size == 0)
        return;

    /* SAFE: strncpy bounded by dest_size - 1, then explicit null terminator */
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

/* ===================================================================
 * FALSE POSITIVE #10: CWE-120 FP (Adversarial tier, LLM resolves)
 * Uses strcpy (which normally triggers CWE-120 alarms), but is preceded
 * by an assert that guarantees strlen(src) < DEST_CAPACITY. SAST tools
 * cannot resolve this cross-function semantic guarantee; the LLM tier
 * must reason about the assertion's effect on reachability.
 * =================================================================== */

/**
 * copy_bounded - Copy src to dest, relying on caller-enforced length guarantee.
 * @dest: destination buffer (must be at least DEST_CAPACITY bytes)
 * @src:  source string (must be validated by caller to fit in DEST_CAPACITY)
 *
 * Precondition: strlen(src) < DEST_CAPACITY is asserted before the copy.
 * The strcpy is safe because the assertion guarantees the source fits.
 */
void copy_bounded(char *dest, const char *src)
{
    /* Precondition: caller guarantees src fits within DEST_CAPACITY */
    assert(strlen(src) < DEST_CAPACITY);

    /* SAFE: The assert above guarantees src fits in dest (>= DEST_CAPACITY bytes).
     * SAST tools flag strcpy unconditionally, but this is a false positive
     * because the assertion enforces the length constraint before we reach here.
     * Only an LLM can reason about this semantic guarantee. */
    strcpy(dest, src);
}

/**
 * process_message - Example caller that uses copy_bounded correctly.
 * Validates message length before passing it to copy_bounded.
 */
int process_message(const char *message)
{
    char output[DEST_CAPACITY];

    if (message == NULL)
        return -1;

    /* Length is checked by assert inside copy_bounded */
    copy_bounded(output, message);

    printf("Processed: %s\n", output);
    return 0;
}
