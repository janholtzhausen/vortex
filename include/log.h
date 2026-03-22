#pragma once

#include <stdarg.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
} log_level_t;

typedef enum {
    LOG_FMT_JSON = 0,
    LOG_FMT_TEXT,
} log_format_t;

void log_init(log_level_t level, log_format_t fmt, const char *file_path);
void log_close(void);
void log_msg(log_level_t level, const char *event, const char *fmt, ...);

#define log_debug(event, ...) log_msg(LOG_DEBUG, event, __VA_ARGS__)
#define log_info(event, ...)  log_msg(LOG_INFO,  event, __VA_ARGS__)
#define log_warn(event, ...)  log_msg(LOG_WARN,  event, __VA_ARGS__)
#define log_error(event, ...) log_msg(LOG_ERROR, event, __VA_ARGS__)
