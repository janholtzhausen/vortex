#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

static log_level_t  g_level  = LOG_INFO;
static log_format_t g_fmt    = LOG_FMT_JSON;
static FILE        *g_out    = NULL;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static const char *level_str[] = { "debug", "info", "warn", "error" };

void log_init(log_level_t level, log_format_t fmt, const char *file_path)
{
    g_level = level;
    g_fmt   = fmt;
    if (file_path) {
        g_out = fopen(file_path, "a");
        if (!g_out) {
            fprintf(stderr, "log_init: failed to open %s, using stderr\n", file_path);
            g_out = stderr;
        }
    } else {
        g_out = stderr;
    }
}

void log_close(void)
{
    if (g_out && g_out != stderr) {
        fclose(g_out);
    }
    g_out = NULL;
}

void log_msg(log_level_t level, const char *event, const char *fmt, ...)
{
    if (level < g_level) return;
    if (!g_out) g_out = stderr;

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

    pthread_mutex_lock(&g_mu);

    if (g_fmt == LOG_FMT_JSON) {
        /* Escape message for JSON — simple version */
        char escaped[4096];
        size_t j = 0;
        for (size_t i = 0; msgbuf[i] && j < sizeof(escaped) - 4; i++) {
            if (msgbuf[i] == '"')       { escaped[j++] = '\\'; escaped[j++] = '"'; }
            else if (msgbuf[i] == '\\') { escaped[j++] = '\\'; escaped[j++] = '\\'; }
            else if (msgbuf[i] == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
            else                        { escaped[j++] = msgbuf[i]; }
        }
        escaped[j] = '\0';

        fprintf(g_out,
            "{\"ts\":\"%s.%03ldZ\",\"level\":\"%s\",\"event\":\"%s\",\"msg\":\"%s\"}\n",
            timebuf, ts.tv_nsec / 1000000,
            level_str[level], event ? event : "", escaped);
    } else {
        fprintf(g_out, "%s.%03ldZ [%-5s] %s: %s\n",
            timebuf, ts.tv_nsec / 1000000,
            level_str[level], event ? event : "", msgbuf);
    }

    fflush(g_out);
    pthread_mutex_unlock(&g_mu);
}
