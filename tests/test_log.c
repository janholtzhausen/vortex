#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/log.h"

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  PASS: %s\n", msg); \
} while(0)

int main(void)
{
    printf("=== test_log ===\n");

    /* Test JSON format */
    {
        const char *tmpfile = "/tmp/vortex_log_test.json";
        log_init(LOG_DEBUG, LOG_FMT_JSON, tmpfile);
        log_info("test_event", "key=%s val=%d", "hello", 42);
        log_warn("test_warn", "warning %s", "message");
        log_error("test_error", "error %d", 99);
        log_debug("test_debug", "debug msg");
        log_close();

        FILE *f = fopen(tmpfile, "r");
        ASSERT(f != NULL, "log file created");

        char line[1024];
        int lines = 0;
        while (fgets(line, sizeof(line), f)) {
            ASSERT(line[0] == '{', "JSON line starts with {");
            ASSERT(strstr(line, "\"level\"") != NULL, "JSON has level field");
            ASSERT(strstr(line, "\"event\"") != NULL, "JSON has event field");
            ASSERT(strstr(line, "\"ts\"") != NULL,    "JSON has ts field");
            ASSERT(strstr(line, "\"msg\"") != NULL,   "JSON has msg field");
            lines++;
        }
        fclose(f);
        ASSERT(lines == 4, "4 log lines written");
        remove(tmpfile);
    }

    /* Test level filtering */
    {
        const char *tmpfile = "/tmp/vortex_log_filter.json";
        log_init(LOG_WARN, LOG_FMT_JSON, tmpfile);
        log_debug("dbg", "should not appear");
        log_info("inf", "should not appear");
        log_warn("wrn", "should appear");
        log_error("err", "should appear");
        log_close();

        FILE *f = fopen(tmpfile, "r");
        ASSERT(f != NULL, "filtered log file created");
        char line[1024];
        int lines = 0;
        while (fgets(line, sizeof(line), f)) lines++;
        fclose(f);
        ASSERT(lines == 2, "only warn+error lines appear with WARN level filter");
        remove(tmpfile);
    }

    /* Test text format */
    {
        const char *tmpfile = "/tmp/vortex_log_text.log";
        log_init(LOG_INFO, LOG_FMT_TEXT, tmpfile);
        log_info("text_event", "hello world");
        log_close();

        FILE *f = fopen(tmpfile, "r");
        ASSERT(f != NULL, "text log file created");
        char line[1024];
        ASSERT(fgets(line, sizeof(line), f) != NULL, "text log has content");
        ASSERT(strstr(line, "info") != NULL, "text log has level");
        ASSERT(strstr(line, "text_event") != NULL, "text log has event");
        ASSERT(strstr(line, "hello world") != NULL, "text log has message");
        fclose(f);
        remove(tmpfile);
    }

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
