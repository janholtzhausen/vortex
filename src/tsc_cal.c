#define _GNU_SOURCE
/*
 * tsc_cal.c — TSC frequency calibration.
 *
 * Priority order (most accurate first):
 *  1. /sys/devices/system/cpu/cpu0/tsc_freq_khz   — kernel-reported invariant TSC rate
 *  2. /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq — nominal CPU max (close to TSC on
 *     invariant-TSC platforms, can be wrong on Turbo systems)
 *  3. 10 ms calibration loop against CLOCK_MONOTONIC
 *  4. Hard-coded 3 GHz fallback
 *
 * All paths set g_tsc_hz before any worker thread starts.
 */
#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint64_t g_tsc_hz = 3000000000ULL; /* fallback: 3 GHz */

static uint64_t read_khz_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    unsigned long long khz = 0;
    if (sscanf(buf, "%llu", &khz) != 1 || khz == 0) return 0;
    return (uint64_t)khz * 1000ULL; /* kHz → Hz */
}

static uint64_t calibrate_against_monotonic(void)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t tsc0 = rdtsc();

    /* Spin for ~10 ms using nanosleep so we don't burn a CPU core */
    struct timespec sleep_req = {0, 10000000}; /* 10 ms */
    nanosleep(&sleep_req, NULL);

    uint64_t tsc1 = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &t1);

    uint64_t elapsed_ns =
        (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    uint64_t tsc_delta = tsc1 - tsc0;
    if (elapsed_ns == 0) return 0;
    /* hz = tsc_delta / (elapsed_ns / 1e9) = tsc_delta * 1e9 / elapsed_ns */
    return tsc_delta * 1000000000ULL / elapsed_ns;
}

void tsc_hz_init(void)
{
    uint64_t hz;

    hz = read_khz_file("/sys/devices/system/cpu/cpu0/tsc_freq_khz");
    if (hz > 100000000ULL && hz < 10000000000ULL) { /* 100 MHz – 10 GHz sanity */
        g_tsc_hz = hz;
        return;
    }

    hz = read_khz_file("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
    if (hz > 100000000ULL && hz < 10000000000ULL) {
        g_tsc_hz = hz;
        return;
    }

    hz = calibrate_against_monotonic();
    if (hz > 100000000ULL && hz < 10000000000ULL) {
        g_tsc_hz = hz;
        return;
    }
    /* g_tsc_hz stays at the 3 GHz fallback */
}
