/**
 * Demo Case 2b: GNN Stage Escalation (C/C++ - primary GNN language)
 *
 * C/C++ memory safety vulnerabilities with multi-step data flows.
 * The GNN was trained primarily on C/C++ code (20K samples) so this
 * is the strongest language for demonstrating GNN inference.
 *
 * Expected: SAST finds patterns, complexity/severity triggers escalation
 * to GNN which classifies and produces conformal prediction sets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-120: Buffer Overflow via multi-step copy */
char *read_user_input(void) {
    char *buf = malloc(256);
    if (!buf) return NULL;
    fgets(buf, 1024, stdin);  /* Reads up to 1024 into 256-byte buffer */
    return buf;
}

void transform_data(char *src, char *dst) {
    /* No bounds checking on destination */
    strcpy(dst, src);
    strcat(dst, " -- processed");
}

void log_result(const char *data) {
    char log_buf[64];
    sprintf(log_buf, "[LOG] %s", data);  /* CWE-120: stack overflow */
    printf("%s\n", log_buf);
}

void process_request(void) {
    char *input = read_user_input();    /* Hop 1: source */
    char output[128];
    transform_data(input, output);       /* Hop 2: propagation */
    log_result(output);                  /* Hop 3: sink (sprintf overflow) */
    free(input);
}


/* CWE-416: Use After Free with indirect access */
struct Connection {
    int fd;
    char *hostname;
    void (*cleanup)(struct Connection *);
};

void free_connection(struct Connection *conn) {
    free(conn->hostname);
    free(conn);
}

void reuse_freed_memory(struct Connection *conn) {
    /* Accesses freed memory through struct pointer */
    printf("Host: %s\n", conn->hostname);  /* CWE-416: UAF */
    conn->fd = -1;
}

void handle_disconnect(struct Connection *conn) {
    free_connection(conn);     /* Hop 1: free */
    /* ... error handling ... */
    reuse_freed_memory(conn);  /* Hop 2: use after free */
}


/* CWE-190: Integer Overflow leading to undersized buffer */
void *allocate_buffer(unsigned int count, unsigned int element_size) {
    unsigned int total = count * element_size;  /* CWE-190: can overflow */
    return malloc(total);
}

void fill_buffer(void *buf, unsigned int count, unsigned int elem_size) {
    memset(buf, 0x41, count * elem_size);  /* Writes more than allocated */
}

void process_array(unsigned int n) {
    void *buf = allocate_buffer(n, sizeof(int));  /* Hop 1 */
    if (buf) {
        fill_buffer(buf, n, sizeof(int));          /* Hop 2: overflow */
        free(buf);
    }
}


int main(int argc, char *argv[]) {
    process_request();

    if (argc > 1) {
        unsigned int count = (unsigned int)atoi(argv[1]);
        process_array(count);
    }

    struct Connection *conn = malloc(sizeof(struct Connection));
    if (conn) {
        conn->hostname = strdup("example.com");
        conn->fd = 42;
        handle_disconnect(conn);
    }

    return 0;
}
