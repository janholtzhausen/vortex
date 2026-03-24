#define _GNU_SOURCE

#include "dashboard.h"
#include "bpf_loader.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DASHBOARD_CLIENT_MAX 8
#define DASHBOARD_HTML_PATH "/"
#define DASHBOARD_WS_PATH   "/ws"
#define DASHBOARD_HTML_BUF  (16 * 1024)
#define DASHBOARD_JSON_BUF  (256 * 1024)

struct route_sample {
    uint64_t bytes_in;
    uint64_t bytes_out;
};

struct blocked_ip {
    uint32_t ip_host;
    time_t   expire_at;
};

static const char k_dashboard_html[] =
"<!doctype html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<title>vortex dashboard</title>\n"
"<style>\n"
":root{color-scheme:dark;--bg:#0a1019;--panel:#101a28;--panel2:#152235;--line:#25344b;--text:#e9f0ff;--muted:#8fa4c2;--good:#4dd9a6;--warn:#ffb347;--bad:#ff6b6b;--accent:#66b3ff}\n"
"*{box-sizing:border-box}body{margin:0;font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;color:var(--text);background:radial-gradient(circle at top,#183253 0,#0a1019 55%)}\n"
".wrap{max-width:1400px;margin:0 auto;padding:20px}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:18px}.title h1{margin:0;font-size:28px;letter-spacing:.03em;text-transform:uppercase}.title p{margin:6px 0 0;color:var(--muted)}\n"
".live{display:flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid var(--line);background:rgba(16,26,40,.78);border-radius:14px}.dot{width:10px;height:10px;border-radius:50%;background:var(--bad);box-shadow:0 0 14px currentColor}.dot.on{background:var(--good)}\n"
".grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:14px}.card,.section{border:1px solid var(--line);background:linear-gradient(180deg,rgba(16,26,40,.94),rgba(11,18,29,.98));border-radius:16px;overflow:hidden}.card{padding:16px}.card h2,.section h2{margin:0 0 12px;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}\n"
".metric{font-size:34px;font-weight:700}.sub{color:var(--muted);margin-top:4px}.section{padding:16px;margin-bottom:14px}.routes{display:grid;gap:12px}.route{padding:14px;border:1px solid var(--line);border-radius:14px;background:rgba(21,34,53,.72)}.route-head{display:flex;justify-content:space-between;gap:12px;align-items:center}.route-name{font-size:18px;font-weight:700}.route-stats{color:var(--muted)}.badges{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.badge{padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:#0c1522;color:var(--text)}.badge.open{border-color:rgba(255,107,107,.5);color:#ffd1d1}.badge.half{border-color:rgba(255,179,71,.5);color:#ffe0b2}.badge.closed{border-color:rgba(77,217,166,.45);color:#cbffe8}\n"
".split{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.bar{height:14px;background:#09111b;border-radius:999px;overflow:hidden;border:1px solid var(--line);margin-top:12px}.fill{height:100%;background:linear-gradient(90deg,var(--good),var(--accent))}.security{display:grid;grid-template-columns:1fr 1fr;gap:14px}.kv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 12px}.kv div{padding:10px 12px;background:rgba(10,16,25,.64);border:1px solid var(--line);border-radius:12px}.label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.value{display:block;font-size:22px;font-weight:700;margin-top:2px}.list{margin-top:12px;display:grid;gap:8px}.ip{display:flex;justify-content:space-between;gap:8px;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:rgba(10,16,25,.64)}\n"
"@media (max-width:1100px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.split,.security{grid-template-columns:1fr}}@media (max-width:720px){.wrap{padding:14px}.top{flex-direction:column;align-items:stretch}.grid{grid-template-columns:1fr}.route-head,.ip{flex-direction:column;align-items:flex-start}}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"wrap\">\n"
"<div class=\"top\"><div class=\"title\"><h1>vortex dashboard</h1><p>Real-time route, cache, TLS, and XDP state</p></div><div class=\"live\"><span id=\"dot\" class=\"dot\"></span><strong id=\"live\">offline</strong><span id=\"stamp\">waiting</span></div></div>\n"
"<div class=\"grid\" id=\"summary\"></div>\n"
"<div class=\"section\"><h2>Routes</h2><div class=\"routes\" id=\"routes\"></div></div>\n"
"<div class=\"split\"><div class=\"section\"><h2>Cache</h2><div id=\"cache\"></div></div><div class=\"section\"><h2>TLS</h2><div id=\"tls\"></div></div></div>\n"
"<div class=\"section\"><h2>Security</h2><div class=\"security\"><div id=\"blocklist\"></div><div id=\"xdp\"></div></div></div>\n"
"</div>\n"
"<script>\n"
"const $=s=>document.querySelector(s);const fmtInt=n=>new Intl.NumberFormat().format(n||0);const fmtRate=n=>{n=Number(n)||0;if(n>=1e9)return(n/1e9).toFixed(2)+' GB/s';if(n>=1e6)return(n/1e6).toFixed(2)+' MB/s';if(n>=1e3)return(n/1e3).toFixed(2)+' KB/s';return n+' B/s'};const fmtBytes=n=>{n=Number(n)||0;if(n>=1<<30)return(n/(1<<30)).toFixed(2)+' GB';if(n>=1<<20)return(n/(1<<20)).toFixed(1)+' MB';if(n>=1<<10)return(n/(1<<10)).toFixed(1)+' KB';return n+' B'};const fmtDur=s=>{s=Math.max(0,Math.floor(s||0));const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=s%60;return h?`${h}h ${m}m`:m?`${m}m ${x}s`:`${x}s`};const esc=s=>String(s==null?'':s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\n"
"function render(data){$('#dot').classList.add('on');$('#live').textContent='live';$('#stamp').textContent=`up ${fmtDur(data.uptime_seconds)}   ${data.generated_at}`;$('#summary').innerHTML=[['Active',fmtInt(data.summary.active),`${data.summary.workers} workers`],['Total',fmtInt(data.summary.accepted),`${fmtInt(data.summary.errors)} errors`],['Cache',`${data.cache.hit_rate.toFixed(1)}%`,`${fmtInt(data.cache.hits)} hits`],['TLS',fmtInt(data.summary.tls13+data.summary.tls12),`kTLS ${fmtInt(data.summary.ktls)}`]].map(([a,b,c])=>`<div class=\"card\"><h2>${a}</h2><div class=\"metric\">${b}</div><div class=\"sub\">${c}</div></div>`).join('');\n"
"$('#routes').innerHTML=data.routes.map(r=>`<div class=\"route\"><div class=\"route-head\"><div><div class=\"route-name\">${esc(r.hostname)}</div><div class=\"route-stats\">Active ${fmtInt(r.active)}   Down ${fmtRate(r.bps_in)}   Up ${fmtRate(r.bps_out)}</div></div><div class=\"route-stats\">${fmtInt(r.backends.length)} backends</div></div><div class=\"badges\">${r.backends.map(b=>`<span class=\"badge ${b.state}\">${b.state==='open'?'⚡':b.state==='half'?'◐':'●'} ${esc(b.address)}${b.fail_count?` (${fmtInt(b.fail_count)} fail)`:''}${b.state==='open'&&b.open_for_ms?` ${Math.ceil(b.open_for_ms/1000)}s`:''}</span>`).join('')}</div></div>`).join('')||'<div class=\"sub\">No routes configured.</div>';\n"
"$('#cache').innerHTML=`<div class=\"kv\"><div><span class=\"label\">Hits</span><span class=\"value\">${fmtInt(data.cache.hits)}</span></div><div><span class=\"label\">Misses</span><span class=\"value\">${fmtInt(data.cache.misses)}</span></div><div><span class=\"label\">Evictions</span><span class=\"value\">${fmtInt(data.cache.evictions)}</span></div><div><span class=\"label\">Memory</span><span class=\"value\">${fmtBytes(data.cache.slab_size)}</span></div></div><div class=\"bar\"><div class=\"fill\" style=\"width:${Math.max(0,Math.min(100,data.cache.hit_rate))}%\"></div></div><div class=\"sub\">Stores ${fmtInt(data.cache.stores)} in the shared cache</div>`;\n"
"$('#tls').innerHTML=`<div class=\"kv\"><div><span class=\"label\">TLS 1.2</span><span class=\"value\">${fmtInt(data.summary.tls12)}</span></div><div><span class=\"label\">TLS 1.3</span><span class=\"value\">${fmtInt(data.summary.tls13)}</span></div><div><span class=\"label\">kTLS</span><span class=\"value\">${fmtInt(data.summary.ktls)}</span></div><div><span class=\"label\">Completed</span><span class=\"value\">${fmtInt(data.summary.completed)}</span></div></div>`;\n"
"$('#blocklist').innerHTML=`<div class=\"kv\"><div><span class=\"label\">Tarpitted Now</span><span class=\"value\">${fmtInt(data.security.tarpit_active)}</span></div><div><span class=\"label\">Tarpit Total</span><span class=\"value\">${fmtInt(data.security.tarpit_total)}</span></div><div><span class=\"label\">Blocked IPs</span><span class=\"value\">${fmtInt(data.security.blocked.length)}</span></div><div><span class=\"label\">Workers</span><span class=\"value\">${fmtInt(data.summary.workers)}</span></div></div><div class=\"list\">${data.security.blocked.map(ip=>`<div class=\"ip\"><strong>${esc(ip.ip)}</strong><span>${ip.ttl_seconds>0?`expires ${fmtDur(ip.ttl_seconds)}`:'expired'}</span></div>`).join('')||'<div class=\"sub\">No blocked IPs.</div>'}</div>`;\n"
"$('#xdp').innerHTML=`<div class=\"kv\"><div><span class=\"label\">Status</span><span class=\"value\">${data.xdp.active?'active':'inactive'}</span></div><div><span class=\"label\">RX Packets</span><span class=\"value\">${fmtInt(data.xdp.rx_packets)}</span></div><div><span class=\"label\">RX Bytes</span><span class=\"value\">${fmtBytes(data.xdp.rx_bytes)}</span></div><div><span class=\"label\">Passed</span><span class=\"value\">${fmtInt(data.xdp.passed)}</span></div><div><span class=\"label\">Rate Limit</span><span class=\"value\">${fmtInt(data.xdp.dropped_ratelimit)}</span></div><div><span class=\"label\">Blocklist</span><span class=\"value\">${fmtInt(data.xdp.dropped_blocklist)}</span></div><div><span class=\"label\">Invalid</span><span class=\"value\">${fmtInt(data.xdp.dropped_invalid)}</span></div><div><span class=\"label\">Conntrack</span><span class=\"value\">${fmtInt(data.xdp.dropped_conntrack)}</span></div></div>`}\n"
"let ws;function connect(){$('#dot').classList.remove('on');$('#live').textContent='reconnecting';const proto=location.protocol==='https:'?'wss':'ws';ws=new WebSocket(`${proto}://${location.host}/ws`);ws.onmessage=e=>{try{render(JSON.parse(e.data))}catch(_){}};ws.onopen=()=>{$('#dot').classList.add('on');$('#live').textContent='live'};ws.onclose=()=>{setTimeout(connect,1000)};ws.onerror=()=>ws.close()}connect();\n"
"</script>\n"
"</body>\n"
"</html>\n";

static void sha1_bytes(const uint8_t *data, size_t len, uint8_t out[20])
{
    uint64_t bit_len = (uint64_t)len * 8ULL;
    size_t total = len + 1 + 8;
    size_t padded = (total + 63U) & ~63U;
    uint8_t *msg = calloc(1, padded);
    if (!msg) {
        memset(out, 0, 20);
        return;
    }
    memcpy(msg, data, len);
    msg[len] = 0x80;
    for (int i = 0; i < 8; i++)
        msg[padded - 1 - i] = (uint8_t)(bit_len >> (i * 8));

    uint32_t h0 = 0x67452301U;
    uint32_t h1 = 0xEFCDAB89U;
    uint32_t h2 = 0x98BADCFEU;
    uint32_t h3 = 0x10325476U;
    uint32_t h4 = 0xC3D2E1F0U;

    for (size_t off = 0; off < padded; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            size_t j = off + (size_t)i * 4U;
            w[i] = ((uint32_t)msg[j] << 24) |
                   ((uint32_t)msg[j + 1] << 16) |
                   ((uint32_t)msg[j + 2] << 8) |
                   ((uint32_t)msg[j + 3]);
        }
        for (int i = 16; i < 80; i++) {
            uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (v << 1) | (v >> 31);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999U;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1U;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCU;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6U;
            }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }

    free(msg);
    uint32_t h[5] = { h0, h1, h2, h3, h4 };
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

static void base64_encode(const uint8_t *in, size_t len, char *out, size_t out_sz)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 4 < out_sz; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(len - i);
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out[pos++] = table[(v >> 18) & 0x3F];
        out[pos++] = table[(v >> 12) & 0x3F];
        out[pos++] = rem > 1 ? table[(v >> 6) & 0x3F] : '=';
        out[pos++] = rem > 2 ? table[v & 0x3F] : '=';
    }
    out[pos] = '\0';
}

static int appendf(char *buf, size_t bufsz, size_t *pos, const char *fmt, ...)
{
    if (*pos >= bufsz) return -1;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, bufsz - *pos, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= bufsz - *pos) {
        *pos = bufsz;
        return -1;
    }
    *pos += (size_t)n;
    return 0;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static const char *find_header_value(const char *req, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = req;
    while ((p = strstr(p, name)) != NULL) {
        if ((p == req || p[-1] == '\n') && strncasecmp(p, name, nlen) == 0) {
            p += nlen;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
        p += nlen;
    }
    return NULL;
}

static void trim_header_value(char *s)
{
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\r' || e[-1] == '\n' || e[-1] == ' ' || e[-1] == '\t'))
        *--e = '\0';
}

static void send_http_simple(int fd, const char *status, const char *ctype,
                             const void *body, size_t body_len)
{
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        status, ctype, body_len);
    if (hlen > 0) {
        send_all(fd, header, (size_t)hlen);
        if (body && body_len > 0) send_all(fd, body, body_len);
    }
}

static void ipv4_to_str(uint32_t ip_host, char buf[INET_ADDRSTRLEN])
{
    struct in_addr addr = { .s_addr = htonl(ip_host) };
    if (!inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN))
        snprintf(buf, INET_ADDRSTRLEN, "0.0.0.0");
}

static void format_hms_utc(char out[16], time_t now)
{
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(out, 16, "%H:%M:%S", &tmv);
}

static void collect_blocked_ips(struct dashboard_server *ds,
                                struct blocked_ip **out_ips, size_t *out_count)
{
    *out_ips = NULL;
    *out_count = 0;

    size_t total = 0;
    for (int wi = 0; wi < ds->num_workers; wi++)
        total += ds->workers[wi]->blocked_count;
    if (total == 0) return;

    struct blocked_ip *ips = calloc(total, sizeof(*ips));
    if (!ips) return;

    size_t used = 0;
    for (int wi = 0; wi < ds->num_workers; wi++) {
        struct worker *w = ds->workers[wi];
        for (uint32_t i = 0; i < w->blocked_count; i++) {
            uint32_t idx = (w->blocked_head + i) % WORKER_BLOCKED_MAX;
            struct blocked_entry *be = &w->blocked_list[idx];
            bool merged = false;
            for (size_t j = 0; j < used; j++) {
                if (ips[j].ip_host == be->ip_host) {
                    if (be->expire_at > ips[j].expire_at)
                        ips[j].expire_at = be->expire_at;
                    merged = true;
                    break;
                }
            }
            if (!merged && used < total) {
                ips[used].ip_host = be->ip_host;
                ips[used].expire_at = be->expire_at;
                used++;
            }
        }
    }

    *out_ips = ips;
    *out_count = used;
}

static int build_snapshot_json(struct dashboard_server *ds,
                               struct route_sample *prev,
                               char *buf, size_t bufsz, size_t *out_len)
{
    uint64_t accepted = 0, completed = 0, errors = 0;
    uint64_t active = 0, tls12 = 0, tls13 = 0, ktls = 0;
    uint64_t tarpit_active = 0, tarpit_total = 0;
    uint64_t cache_hits = 0, cache_misses = 0, cache_evictions = 0;
    uint64_t cache_stores = 0, cache_slab_size = 0;
    uint64_t route_active[VORTEX_MAX_ROUTES];
    struct route_sample cur[VORTEX_MAX_ROUTES];
    memset(route_active, 0, sizeof(route_active));
    memset(cur, 0, sizeof(cur));

    for (int wi = 0; wi < ds->num_workers; wi++) {
        struct worker *w = ds->workers[wi];
        accepted += w->accepted;
        completed += w->completed;
        errors += w->errors;
        active += w->pool.active;
        tls12 += w->tls12_count;
        tls13 += w->tls13_count;
        ktls += w->ktls_count;
        tarpit_active += w->tarpit_count;
        tarpit_total += w->tarpit_total;

        for (uint32_t ci = 0; ci < w->pool.capacity; ci++) {
            struct conn_hot *h = &w->pool.hot[ci];
            if (h->state == CONN_STATE_FREE) continue;
            if (h->route_idx >= (uint16_t)ds->cfg->route_count) continue;
            route_active[h->route_idx]++;
            cur[h->route_idx].bytes_in += h->bytes_in;
            cur[h->route_idx].bytes_out += h->bytes_out;
        }
    }

    if (ds->cache) {
        cache_hits = ds->cache->hits;
        cache_misses = ds->cache->misses;
        cache_evictions = ds->cache->evictions;
        cache_stores = ds->cache->stores;
        cache_slab_size = ds->cache->slab_size;
    }

    double hit_rate = 0.0;
    uint64_t cache_total = cache_hits + cache_misses;
    if (cache_total > 0) hit_rate = ((double)cache_hits * 100.0) / (double)cache_total;

    time_t now_wall = time(NULL);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    char timebuf[16];
    format_hms_utc(timebuf, now_wall);

    struct vortex_metrics xdp = {0};
    int xdp_active = bpf_loader_is_active();
    if (xdp_active) (void)bpf_metrics_read(&xdp);

    struct blocked_ip *blocked = NULL;
    size_t blocked_count = 0;
    collect_blocked_ips(ds, &blocked, &blocked_count);

    size_t pos = 0;
    if (appendf(buf, bufsz, &pos,
        "{\"generated_at\":\"%s\",\"uptime_seconds\":%llu,"
        "\"summary\":{\"workers\":%d,\"active\":%llu,\"accepted\":%llu,"
        "\"completed\":%llu,\"errors\":%llu,\"tls12\":%llu,\"tls13\":%llu,\"ktls\":%llu},"
        "\"routes\":[",
        timebuf,
        (unsigned long long)(now_wall - (time_t)ds->start_time),
        ds->num_workers,
        (unsigned long long)active,
        (unsigned long long)accepted,
        (unsigned long long)completed,
        (unsigned long long)errors,
        (unsigned long long)tls12,
        (unsigned long long)tls13,
        (unsigned long long)ktls) < 0) {
        free(blocked);
        return -1;
    }

    for (int ri = 0; ri < ds->cfg->route_count; ri++) {
        const struct route_config *rc = &ds->cfg->routes[ri];
        uint64_t route_bps_in = 0, route_bps_out = 0;
        if (cur[ri].bytes_in >= prev[ri].bytes_in)
            route_bps_in = cur[ri].bytes_in - prev[ri].bytes_in;
        if (cur[ri].bytes_out >= prev[ri].bytes_out)
            route_bps_out = cur[ri].bytes_out - prev[ri].bytes_out;

        if (appendf(buf, bufsz, &pos,
            "%s{\"hostname\":\"%s\",\"active\":%llu,\"bps_in\":%llu,\"bps_out\":%llu,\"backends\":[",
            ri ? "," : "",
            rc->hostname,
            (unsigned long long)route_active[ri],
            (unsigned long long)route_bps_in,
            (unsigned long long)route_bps_out) < 0) {
            free(blocked);
            return -1;
        }

        for (int bi = 0; bi < rc->backend_count; bi++) {
            uint32_t max_fail_count = 0;
            uint64_t max_open_until = 0;
            bool seen_half_open = false;
            for (int wi = 0; wi < ds->num_workers; wi++) {
                struct worker *w = ds->workers[wi];
                uint32_t fail_count = w->backend_cb[ri][bi].fail_count;
                uint64_t open_until = w->backend_cb[ri][bi].open_until_ns;
                if (fail_count > max_fail_count) max_fail_count = fail_count;
                if (open_until > max_open_until) max_open_until = open_until;
                if (open_until != 0 && open_until <= now_ns) seen_half_open = true;
            }
            const char *state = "closed";
            uint64_t open_for_ms = 0;
            if (max_open_until > now_ns) {
                state = "open";
                open_for_ms = (max_open_until - now_ns) / 1000000ULL;
            } else if (seen_half_open) {
                state = "half";
            }
            if (appendf(buf, bufsz, &pos,
                "%s{\"address\":\"%s\",\"fail_count\":%u,\"state\":\"%s\",\"open_for_ms\":%llu}",
                bi ? "," : "",
                rc->backends[bi].address,
                max_fail_count,
                state,
                (unsigned long long)open_for_ms) < 0) {
                free(blocked);
                return -1;
            }
        }

        if (appendf(buf, bufsz, &pos, "]}") < 0) {
            free(blocked);
            return -1;
        }
    }

    if (appendf(buf, bufsz, &pos,
        "],\"cache\":{\"hits\":%llu,\"misses\":%llu,\"evictions\":%llu,\"stores\":%llu,"
        "\"slab_size\":%llu,\"hit_rate\":%.1f},"
        "\"security\":{\"tarpit_active\":%llu,\"tarpit_total\":%llu,\"blocked\":[",
        (unsigned long long)cache_hits,
        (unsigned long long)cache_misses,
        (unsigned long long)cache_evictions,
        (unsigned long long)cache_stores,
        (unsigned long long)cache_slab_size,
        hit_rate,
        (unsigned long long)tarpit_active,
        (unsigned long long)tarpit_total) < 0) {
        free(blocked);
        return -1;
    }

    for (size_t i = 0; i < blocked_count; i++) {
        char ipbuf[INET_ADDRSTRLEN];
        ipv4_to_str(blocked[i].ip_host, ipbuf);
        long ttl = (long)(blocked[i].expire_at - now_wall);
        if (appendf(buf, bufsz, &pos,
            "%s{\"ip\":\"%s\",\"ttl_seconds\":%ld}",
            i ? "," : "",
            ipbuf, ttl > 0 ? ttl : 0L) < 0) {
            free(blocked);
            return -1;
        }
    }
    free(blocked);

    if (appendf(buf, bufsz, &pos,
        "]},\"xdp\":{\"active\":%s,\"rx_packets\":%llu,\"rx_bytes\":%llu,"
        "\"passed\":%llu,\"dropped_ratelimit\":%llu,\"dropped_blocklist\":%llu,"
        "\"dropped_invalid\":%llu,\"dropped_conntrack\":%llu}}",
        xdp_active ? "true" : "false",
        (unsigned long long)xdp.rx_packets,
        (unsigned long long)xdp.rx_bytes,
        (unsigned long long)xdp.passed,
        (unsigned long long)xdp.dropped_ratelimit,
        (unsigned long long)xdp.dropped_blocklist,
        (unsigned long long)xdp.dropped_invalid,
        (unsigned long long)xdp.dropped_conntrack) < 0) {
        return -1;
    }

    memcpy(prev, cur, sizeof(cur));
    *out_len = pos;
    return 0;
}

static int websocket_send_text(int fd, const char *payload, size_t len)
{
    uint8_t header[10];
    size_t hlen = 0;
    header[hlen++] = 0x81;
    if (len < 126) {
        header[hlen++] = (uint8_t)len;
    } else if (len <= 0xFFFF) {
        header[hlen++] = 126;
        header[hlen++] = (uint8_t)(len >> 8);
        header[hlen++] = (uint8_t)len;
    } else {
        header[hlen++] = 127;
        for (int i = 7; i >= 0; i--)
            header[hlen++] = (uint8_t)(len >> (i * 8));
    }
    return send_all(fd, header, hlen) == 0 && send_all(fd, payload, len) == 0 ? 0 : -1;
}

static int websocket_accept(int fd, const char *req)
{
    const char *key = find_header_value(req, "Sec-WebSocket-Key:");
    if (!key) return -1;

    char client_key[128];
    size_t key_len = 0;
    while (key[key_len] && key[key_len] != '\r' && key[key_len] != '\n' &&
           key_len + 1 < sizeof(client_key)) {
        client_key[key_len] = key[key_len];
        key_len++;
    }
    client_key[key_len] = '\0';
    trim_header_value(client_key);

    char concat[256];
    snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    uint8_t digest[20];
    sha1_bytes((const uint8_t *)concat, strlen(concat), digest);
    char accept_key[64];
    base64_encode(digest, sizeof(digest), accept_key, sizeof(accept_key));

    char resp[256];
    int len = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",
        accept_key);
    return send_all(fd, resp, (size_t)len);
}

static int handle_http_client(struct dashboard_server *ds, int fd, int *is_ws)
{
    (void)ds;
    *is_ws = 0;
    char req[4096];
    ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
    if (n <= 0) return -1;
    req[n] = '\0';

    if (strncmp(req, "GET ", 4) != 0) {
        send_http_simple(fd, "405 Method Not Allowed", "text/plain", "method not allowed\n", 19);
        return -1;
    }

    char path[128] = {0};
    if (sscanf(req, "GET %127s", path) != 1) {
        send_http_simple(fd, "400 Bad Request", "text/plain", "bad request\n", 12);
        return -1;
    }

    if (strcmp(path, DASHBOARD_HTML_PATH) == 0) {
        send_http_simple(fd, "200 OK", "text/html; charset=utf-8",
                         k_dashboard_html, strlen(k_dashboard_html));
        return -1;
    }

    if (strcmp(path, DASHBOARD_WS_PATH) == 0 &&
        strstr(req, "Upgrade: websocket") != NULL) {
        if (websocket_accept(fd, req) == 0) {
            *is_ws = 1;
            return 0;
        }
        send_http_simple(fd, "400 Bad Request", "text/plain", "bad websocket request\n", 22);
        return -1;
    }

    send_http_simple(fd, "404 Not Found", "text/plain", "not found\n", 10);
    return -1;
}

static void *dashboard_thread(void *arg)
{
    struct dashboard_server *ds = arg;
    int clients[DASHBOARD_CLIENT_MAX];
    struct route_sample prev[VORTEX_MAX_ROUTES];
    memset(clients, -1, sizeof(clients));
    memset(prev, 0, sizeof(prev));

    set_nonblock(ds->listen_fd);
    log_info("dashboard_init", "dashboard endpoint: http://%s:%u/",
             ds->cfg->dashboard.bind_address, (unsigned)ds->cfg->dashboard.port);

    while (ds->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ds->listen_fd, &rfds);
        int maxfd = ds->listen_fd;
        for (int i = 0; i < DASHBOARD_CLIENT_MAX; i++) {
            if (clients[i] >= 0) {
                FD_SET(clients[i], &rfds);
                if (clients[i] > maxfd) maxfd = clients[i];
            }
        }

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (rc > 0 && FD_ISSET(ds->listen_fd, &rfds)) {
            for (;;) {
                struct sockaddr_in client_addr;
                socklen_t addrlen = sizeof(client_addr);
                int fd = accept(ds->listen_fd, (struct sockaddr *)&client_addr, &addrlen);
                if (fd < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }
                int is_ws = 0;
                if (handle_http_client(ds, fd, &is_ws) == 0 && is_ws) {
                    set_nonblock(fd);
                    int placed = 0;
                    for (int i = 0; i < DASHBOARD_CLIENT_MAX; i++) {
                        if (clients[i] < 0) {
                            clients[i] = fd;
                            placed = 1;
                            break;
                        }
                    }
                    if (!placed) close(fd);
                } else {
                    close(fd);
                }
            }
        }

        for (int i = 0; i < DASHBOARD_CLIENT_MAX; i++) {
            if (clients[i] >= 0 && rc > 0 && FD_ISSET(clients[i], &rfds)) {
                char tmp[256];
                ssize_t n = recv(clients[i], tmp, sizeof(tmp), 0);
                if (n <= 0) {
                    close(clients[i]);
                    clients[i] = -1;
                }
            }
        }

        char *json = malloc(DASHBOARD_JSON_BUF);
        if (!json) continue;
        size_t json_len = 0;
        if (build_snapshot_json(ds, prev, json, DASHBOARD_JSON_BUF, &json_len) == 0) {
            for (int i = 0; i < DASHBOARD_CLIENT_MAX; i++) {
                if (clients[i] >= 0 && websocket_send_text(clients[i], json, json_len) != 0) {
                    close(clients[i]);
                    clients[i] = -1;
                }
            }
        }
        free(json);
    }

    for (int i = 0; i < DASHBOARD_CLIENT_MAX; i++) {
        if (clients[i] >= 0) close(clients[i]);
    }
    return NULL;
}

int dashboard_init(struct dashboard_server *ds,
                   const char *bind_addr, uint16_t port,
                   struct worker **workers, int num_workers,
                   struct cache *cache, struct vortex_config *cfg)
{
    memset(ds, 0, sizeof(*ds));
    ds->workers = workers;
    ds->num_workers = num_workers;
    ds->cache = cache;
    ds->cfg = cfg;
    ds->start_time = (uint64_t)time(NULL);
    ds->listen_fd = -1;

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, bind_addr, &sa.sin_addr) != 1) {
        log_error("dashboard_init", "invalid bind address %s", bind_addr);
        return -1;
    }

    ds->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ds->listen_fd < 0) {
        log_error("dashboard_init", "socket: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(ds->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(ds->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_error("dashboard_init", "bind %s:%u: %s", bind_addr, (unsigned)port, strerror(errno));
        close(ds->listen_fd);
        ds->listen_fd = -1;
        return -1;
    }
    if (listen(ds->listen_fd, DASHBOARD_CLIENT_MAX) < 0) {
        log_error("dashboard_init", "listen: %s", strerror(errno));
        close(ds->listen_fd);
        ds->listen_fd = -1;
        return -1;
    }
    return 0;
}

int dashboard_start(struct dashboard_server *ds)
{
    ds->running = 1;
    return pthread_create(&ds->thread, NULL, dashboard_thread, ds);
}

void dashboard_stop(struct dashboard_server *ds)
{
    ds->running = 0;
    if (ds->listen_fd >= 0) shutdown(ds->listen_fd, SHUT_RDWR);
}

void dashboard_join(struct dashboard_server *ds)
{
    pthread_join(ds->thread, NULL);
    if (ds->listen_fd >= 0) {
        close(ds->listen_fd);
        ds->listen_fd = -1;
    }
}
