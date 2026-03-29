/**
 * memory_manager.c - Dynamic memory management functions for SEC-C test cases
 *
 * This file contains functions that manage dynamically allocated memory,
 * demonstrating both use-after-free vulnerabilities and safe realloc patterns.
 * Common in data processing pipelines and server connection handlers.
 *
 * Part of: SEC-C Sample Test Cases (C/C++)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_BUF_SIZE 128
#define MAX_BUF_SIZE 4096

/**
 * buffer_t - A managed buffer structure for holding variable-length data.
 */
typedef struct buffer {
    char *data;       /* pointer to the actual data payload */
    size_t size;      /* allocated size of the data region */
    size_t used;      /* number of bytes currently in use */
    int    ref_count; /* reference count for shared buffers */
} buffer_t;

/**
 * buffer_create - Allocate and initialize a new buffer_t.
 * @initial_size: the initial allocation size for the data region
 *
 * Returns: pointer to a new buffer_t, or NULL on failure
 */
buffer_t *buffer_create(size_t initial_size)
{
    buffer_t *buf;

    if (initial_size == 0)
        initial_size = DEFAULT_BUF_SIZE;

    buf = (buffer_t *)malloc(sizeof(buffer_t));
    if (buf == NULL)
        return NULL;

    buf->data = (char *)malloc(initial_size);
    if (buf->data == NULL) {
        free(buf);
        return NULL;
    }

    buf->size = initial_size;
    buf->used = 0;
    buf->ref_count = 1;
    memset(buf->data, 0, initial_size);

    return buf;
}

/**
 * buffer_destroy - Free a buffer_t and its data region.
 * @buf: the buffer to destroy
 */
void buffer_destroy(buffer_t *buf)
{
    if (buf == NULL)
        return;

    if (buf->data != NULL) {
        memset(buf->data, 0, buf->size);  /* scrub sensitive data */
        free(buf->data);
    }

    free(buf);
}

/* ===================================================================
 * TRUE POSITIVE #4: CWE-416 Use After Free
 * Frees the buffer structure and then accesses a field through the
 * freed pointer. The access to buf->data after free(buf) is undefined
 * behavior and can lead to information leaks or code execution.
 * =================================================================== */

/**
 * process_buffer - Process a buffer's contents and clean up.
 *
 * This function creates a temporary buffer, processes its data, and
 * attempts to log the contents. However, it incorrectly accesses the
 * buffer after freeing it, resulting in a use-after-free vulnerability.
 *
 * Returns: 0 on success, -1 on failure
 */
int process_buffer(void)
{
    buffer_t *buf;
    size_t data_len;

    buf = buffer_create(256);
    if (buf == NULL)
        return -1;

    /* Simulate filling the buffer with some data */
    strncpy(buf->data, "sensitive_payload_data", buf->size - 1);
    buf->used = strlen(buf->data);

    printf("Processing buffer at %p, size=%zu\n", (void *)buf, buf->size);

    /* Finished processing - free the buffer */
    free(buf);

    /* BUG: Use-after-free! buf has been freed above, but we still
     * dereference buf->data here. The memory may have been reallocated
     * to another object, leading to data corruption or info leak.
     * This is a classic CWE-416 vulnerability. */
    printf("Buffer contained: %s\n", buf->data);

    return 0;
}

/* ===================================================================
 * FALSE POSITIVE #9: CWE-416 FP (Contextual tier, Graph resolves)
 * Uses realloc() which can return a different pointer, but the code
 * correctly checks the return value before updating the pointer.
 * SAST may flag the pattern (pointer used after realloc) but graph
 * analysis of the control flow shows buf is only accessed through
 * new_buf after the NULL check, meaning the old pointer is never
 * dereferenced after realloc succeeds.
 * =================================================================== */

/**
 * resize_buffer - Safely resize an existing buffer to a new size.
 * @buf:      pointer to the buffer to resize
 * @new_size: the desired new size in bytes
 *
 * Returns: 0 on success, -1 on failure (original buffer unchanged)
 *
 * This function uses realloc correctly: it stores the result in a
 * temporary pointer and only updates the original if realloc succeeds.
 * The old pointer (buf) is never dereferenced after a successful realloc.
 */
int resize_buffer(buffer_t *buf, size_t new_size)
{
    buffer_t *new_buf;

    if (buf == NULL || new_size == 0 || new_size > MAX_BUF_SIZE)
        return -1;

    /* realloc may move the block and free the old one. We must check
     * the return value before using it. */
    new_buf = realloc(buf, new_size);

    /* SAFE: We only update buf's fields through new_buf after confirming
     * realloc succeeded. If realloc returns NULL, we leave buf untouched.
     * Graph analysis confirms no path dereferences the old pointer after
     * a successful realloc - new_buf IS the valid pointer. */
    if (new_buf != NULL) {
        buf = new_buf;
        buf->size = new_size;
        printf("Buffer resized to %zu bytes at %p\n", new_size, (void *)buf);
    } else {
        fprintf(stderr, "Failed to resize buffer to %zu bytes\n", new_size);
        return -1;
    }

    return 0;
}

/**
 * buffer_append - Append data to a buffer, resizing if needed.
 * @buf:  the target buffer
 * @data: the data to append
 * @len:  number of bytes to append
 *
 * Returns: 0 on success, -1 on failure
 */
int buffer_append(buffer_t *buf, const char *data, size_t len)
{
    if (buf == NULL || data == NULL || len == 0)
        return -1;

    /* Check if we need more space */
    if (buf->used + len >= buf->size) {
        size_t new_size = (buf->used + len) * 2;
        char *new_data;

        if (new_size > MAX_BUF_SIZE)
            return -1;

        new_data = (char *)realloc(buf->data, new_size);
        if (new_data == NULL)
            return -1;

        buf->data = new_data;
        buf->size = new_size;
    }

    memcpy(buf->data + buf->used, data, len);
    buf->used += len;

    return 0;
}
