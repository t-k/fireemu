/* Minimal exec boundary: do not let a Python launcher dominate a small daemon's
 * cgroup memory.peak. The helper's small footprint is still explicitly included.
 * argv: marker-path, cwd, exec-gate-fifo, command, arguments...
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: exec_engine marker cwd gate command [args...]\n"); return 126; }
    if (geteuid() == 0 && getenv("BENCH_ALLOW_ROOT_SELFTEST") == NULL) {
        fprintf(stderr, "refusing root benchmark engine\n"); return 126;
    }
    if (chdir(argv[2]) != 0) { perror("chdir"); return 126; }
    /* Wait until the observer has attached to the transient cgroup. This keeps
     * systemd-run/systemctl setup latency out of the measured exec-to-ready time. */
    int gate = open(argv[3], O_RDONLY | O_CLOEXEC);
    if (gate < 0) { perror("gate open"); return 126; }
    char go = 0;
    ssize_t got;
    do { got = read(gate, &go, 1); } while (got < 0 && errno == EINTR);
    close(gate);
    if (got != 1 || go != '1') { fprintf(stderr, "exec gate was not released\n"); return 126; }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { perror("marker open"); return 126; }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { perror("clock"); close(fd); return 126; }
    char out[200];
    int n = snprintf(out, sizeof out, "{\"pid\":%ld,\"exec_monotonic_ns\":%lld}\n",
                     (long)getpid(), (long long)now.tv_sec * 1000000000LL + now.tv_nsec);
    if (n < 0 || (size_t)n >= sizeof out || write(fd, out, (size_t)n) != n) {
        perror("marker write"); close(fd); return 126;
    }
    close(fd);
    execvp(argv[4], &argv[4]);
    perror("execvp");
    return 127;
}
