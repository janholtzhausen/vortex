#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static log_level_t  g_level  = LOG_INFO;
static log_format_t g_fmt    = LOG_FMT_JSON;
static int          g_log_fd = -1;       /* O_WRONLY|O_APPEND — write() is atomic */
static bool         g_own_fd = false;    /* true if we opened it (vs. stderr) */
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static const char *level_str[] = { "debug", "info", "warn", "error" };

void log_init(log_level_t level, log_format_t fmt, const char *file_path)
{
    g_level = level;
    g_fmt   = fmt;

    if (g_own_fd && g_log_fd >= 0) {
        close(g_log_fd);
        g_log_fd = -1;
        g_own_fd = false;
    }

    if (file_path) {
        int fd = open(file_path, O_WRONLY | O_CREAT | O_APPEND, 0640);
        if (fd < 0) {
            fprintf(stderr, "log_init: failed to open %s: %s, using stderr\n",
                    file_path, strerror(errno));
            g_log_fd = STDERR_FILENO;
            g_own_fd = false;
        } else {
            g_log_fd = fd;
            g_own_fd = true;
        }
    } else {
        g_log_fd = STDERR_FILENO;
        g_own_fd = false;
    }
}

void log_close(void)
{
    if (g_own_fd && g_log_fd >= 0) {
        close(g_log_fd);
    }
    g_log_fd = -1;
    g_own_fd = false;
}

void log_msg(log_level_t level, const char *event, const char *fmt, ...)
{
    if (level < g_level) return;
    if (g_log_fd < 0) g_log_fd = STDERR_FILENO;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_buf;
    gmtime_r(&ts.tv_sec, &tm_buf);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", &tm_buf);

    char msgbuf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
    va_end(ap);

    /* Format the complete log line into a stack buffer — all work outside the lock */
    char linebuf[4096];
    int llen;

    if (g_fmt == LOG_FMT_JSON) {
        /* Escape message for JSON */
        char escaped[2560];
        size_t j = 0;
        for (size_t i = 0; msgbuf[i] && j < sizeof(escaped) - 4; i++) {
            if (msgbuf[i] == '"')       { escaped[j++] = '\\'; escaped[j++] = '"'; }
            else if (msgbuf[i] == '\\') { escaped[j++] = '\\'; escaped[j++] = '\\'; }
            else if (msgbuf[i] == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
            else                        { escaped[j++] = msgbuf[i]; }
        }
        escaped[j] = '\0';

        llen = snprintf(linebuf, sizeof(linebuf),
            "{\"ts\":\"%s.%03ldZ\",\"level\":\"%s\",\"event\":\"%s\",\"msg\":\"%s\"}\n",
            timebuf, ts.tv_nsec / 1000000,
            level_str[level], event ? event : "", escaped);
    } else {
        llen = snprintf(linebuf, sizeof(linebuf),
            "%s.%03ldZ [%-5s] %s: %s\n",
            timebuf, ts.tv_nsec / 1000000,
            level_str[level], event ? event : "", msgbuf);
    }

    if (llen <= 0) return;
    if (llen >= (int)sizeof(linebuf))
        llen = (int)sizeof(linebuf) - 1;

    /* Critical section is now just a single write() syscall */
    pthread_mutex_lock(&g_mu);
    (void)write(g_log_fd, linebuf, (size_t)llen);
    pthread_mutex_unlock(&g_mu);
}
