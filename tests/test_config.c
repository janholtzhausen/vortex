#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "../src/config.h"
#include "../src/log.h"

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  PASS: %s\n", msg); \
} while(0)

static void write_test_yaml(const char *path)
{
    FILE *f = fopen(path, "w");
    assert(f);
    fprintf(f,
        "global:\n"
        "  workers: 4\n"
        "  bind_address: \"127.0.0.1\"\n"
        "  bind_port: 8443\n"
        "  interface: \"lo\"\n"
        "  log_level: \"debug\"\n"
        "  log_format: \"text\"\n"
        "\n"
        "tls:\n"
        "  ktls: false\n"
        "  session_timeout: 1800\n"
        "\n"
        "xdp:\n"
        "  mode: \"skb\"\n"
        "  rate_limit:\n"
        "    enabled: true\n"
        "    requests_per_second: 500\n"
        "    burst: 1000\n"
        "\n"
        "cache:\n"
        "  enabled: true\n"
        "  index_entries: 2048\n"
        "  slab_size_mb: 32\n"
        "  default_ttl: 120\n"
        "\n"
        "metrics:\n"
        "  enabled: true\n"
        "  port: 9091\n"
        "\n"
        "routes:\n"
        "  - hostname: \"test.example.com\"\n"
        "    backends:\n"
        "      - address: \"10.0.0.1:8080\"\n"
        "        weight: 1\n"
        "    cert_provider: \"static_file\"\n"
        "    cert_path: \"/tmp/cert.pem\"\n"
        "    key_path: \"/tmp/key.pem\"\n"
        "    cache:\n"
        "      enabled: true\n"
        "      ttl: 60\n"
    );
    fclose(f);
}

int main(void)
{
    log_init(LOG_DEBUG, LOG_FMT_TEXT, NULL);
    printf("=== test_config ===\n");

    /* Test 1: defaults */
    {
        struct vortex_config cfg;
        config_set_defaults(&cfg);
        ASSERT(cfg.bind_port == 443,  "default bind_port=443");
        ASSERT(cfg.http_port == 80,   "default http_port=80");
        ASSERT(cfg.tls.ktls == true,  "default ktls=true");
        ASSERT(cfg.cache.enabled == true, "default cache.enabled=true");
        ASSERT(cfg.cache.index_entries == 16384, "default index_entries=16384");
        ASSERT(cfg.metrics.port == 9090, "default metrics.port=9090");
    }

    /* Test 2: load from file */
    {
        const char *tmpfile = "/tmp/vortex_test.yaml";
        write_test_yaml(tmpfile);

        struct vortex_config cfg;
        int ret = config_load(tmpfile, &cfg);
        ASSERT(ret == 0, "config_load returns 0");
        ASSERT(cfg.workers == 4,      "workers=4");
        ASSERT(cfg.bind_port == 8443, "bind_port=8443");
        ASSERT(!strcmp(cfg.interface, "lo"), "interface=lo");
        ASSERT(!strcmp(cfg.log_level, "debug"), "log_level=debug");
        ASSERT(cfg.tls.ktls == false, "tls.ktls=false");
        ASSERT(cfg.tls.session_timeout == 1800, "session_timeout=1800");
        ASSERT(cfg.xdp.mode == XDP_MODE_SKB, "xdp.mode=skb");
        ASSERT(cfg.xdp.rate_limit_rps == 500, "rate_limit_rps=500");
        ASSERT(cfg.xdp.rate_limit_burst == 1000, "rate_limit_burst=1000");
        ASSERT(cfg.cache.index_entries == 2048, "cache.index_entries=2048");
        ASSERT(cfg.cache.slab_size_bytes == 32ULL*1024*1024, "slab_size_mb=32");
        ASSERT(cfg.cache.default_ttl == 120, "cache.default_ttl=120");
        ASSERT(cfg.metrics.port == 9091, "metrics.port=9091");
        ASSERT(cfg.route_count == 1,  "route_count=1");
        ASSERT(!strcmp(cfg.routes[0].hostname, "test.example.com"), "route hostname");
        ASSERT(cfg.routes[0].backend_count == 1, "backend_count=1");
        ASSERT(!strcmp(cfg.routes[0].backends[0].address, "10.0.0.1:8080"), "backend address");
        ASSERT(cfg.routes[0].cert_provider == CERT_PROVIDER_STATIC, "cert_provider=static");
        ASSERT(cfg.routes[0].cache.enabled == true, "route cache.enabled");
        ASSERT(cfg.routes[0].cache.ttl == 60, "route cache.ttl=60");

        unlink(tmpfile);
    }

    /* Test 3: env var substitution */
    {
        setenv("TEST_API_TOKEN", "mysecrettoken", 1);
        const char *tmpfile = "/tmp/vortex_env_test.yaml";
        FILE *f = fopen(tmpfile, "w");
        fprintf(f,
            "acme:\n"
            "  enabled: true\n"
            "  dns_provider_config:\n"
            "    api_token: \"${TEST_API_TOKEN}\"\n"
        );
        fclose(f);

        struct vortex_config cfg;
        config_set_defaults(&cfg);
        int ret = config_load(tmpfile, &cfg);
        ASSERT(ret == 0, "env var config loads");
        ASSERT(!strcmp(cfg.acme.dns_api_token, "mysecrettoken"),
            "env var ${TEST_API_TOKEN} expanded");
        unlink(tmpfile);
    }

    /* Test 4: nonexistent file */
    {
        struct vortex_config cfg;
        int ret = config_load("/nonexistent/path/vortex.yaml", &cfg);
        ASSERT(ret == -1, "nonexistent config returns -1");
    }

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
