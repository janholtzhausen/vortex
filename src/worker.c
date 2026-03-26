#define _GNU_SOURCE
/*
 * worker.c — worker thread lifecycle, connection pool initialization, and
 * public API (worker_init, worker_start, worker_stop, worker_join,
 * worker_destroy, worker_create_listener, worker_pool_capacity).
 *
 * The actual event loop logic lives in worker_proxy.c; helper subsystems
 * are in worker_accept.c, worker_backend.c, worker_cache.c, and
 * worker_compress.c.  Shared macros and forward declarations are in
 * worker_internal.h.
 */
#include "worker_internal.h"

static void *worker_thread(void *arg)
{
    struct worker *w = (struct worker *)arg;
    log_info("worker_start", "id=%d", w->worker_id);

    /* Init io_uring in this thread (required for SINGLE_ISSUER / COOP_TASKRUN) */
    if (uring_init(&w->uring, WORKER_URING_DEPTH, w->cfg->sqpoll) != 0) {
        log_error("worker_thread", "uring_init failed");
        return NULL;
    }

    /* Register fixed buffers — one iovec per recv/send slot.
     * recv_buf[cid] → index cid, send_buf[cid] → index (capacity + cid).
     * Skips per-op page-pinning on every recv/send in the hot path. */
    {
        uint32_t cap = w->pool.capacity;
        struct iovec *iovecs = malloc(2 * cap * sizeof(struct iovec));
        if (iovecs) {
            for (uint32_t i = 0; i < cap; i++) {
                iovecs[i].iov_base          = conn_recv_buf(&w->pool, i);
                iovecs[i].iov_len           = w->pool.buf_size;
                iovecs[cap + i].iov_base    = conn_send_buf(&w->pool, i);
                iovecs[cap + i].iov_len     = w->pool.buf_size;
            }
            uring_register_bufs(&w->uring, iovecs, 2 * cap);
            free(iovecs);
        }

        /* Fixed-file registration is intentionally disabled for now.
         * The hot path already falls back to normal fds when
         * files_registered=false, and teardown has been hanging in kernel
         * fixed-file unregister quiescing during service restarts. */

        /* Multishot recv buf ring — used for H2 client recv.
         * One buffer per connection slot (ring count = next power-of-two ≥ cap).
         * Independent of the fixed-buffer registration above. */
        if (uring_recv_ring_setup(&w->uring, w->pool.buf_size, cap, 0) != 0)
            log_warn("worker_thread",
                     "recv ring unavailable — H2 uses single-shot recv");
    }

    /* Queue the multishot accept — cid=0 means accept op */
    struct io_uring_sqe *asqe = io_uring_get_sqe(&w->uring.ring);
    if (!asqe) {
        log_error("worker_thread", "get_sqe for accept failed");
        uring_destroy(&w->uring);
        return NULL;
    }
    io_uring_prep_multishot_accept(asqe, w->listen_fd, NULL, NULL, 0);
    asqe->user_data = URING_UD_ENCODE(VORTEX_OP_ACCEPT, 0);

    /* Arm read on the TLS-done result pipe — wakes us when pool threads finish */
#ifdef VORTEX_PHASE_TLS
    if (w->tls_done_pipe_rd >= 0) {
        struct io_uring_sqe *psqe = io_uring_get_sqe(&w->uring.ring);
        if (psqe) {
            io_uring_prep_read(psqe, w->tls_done_pipe_rd,
                               w->tls_pipe_buf, sizeof(w->tls_pipe_buf), 0);
            psqe->user_data = URING_UD_ENCODE(VORTEX_OP_TLS_DONE, 0);
        }
    }
#endif
    uring_submit(&w->uring);

    while (!w->stop) {
        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned count = 0;

        /* Wait up to 1s so we can check stop flag for graceful shutdown */
        struct __kernel_timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        int ret = io_uring_wait_cqe_timeout(&w->uring.ring, &cqe, &ts);
        if (ret == -ETIME) {
            /* Periodic: drip more urandom garbage into tarpitted connections */
            if (w->urandom_fd >= 0 && w->tarpit_count > 0) {
                uint8_t noise[TARPIT_NOISE_DRIP];
                if (read(w->urandom_fd, noise, sizeof(noise)) == (ssize_t)sizeof(noise)) {
                    for (uint32_t ti = 0; ti < w->tarpit_count; ti++) {
                        int slot = (int)((w->tarpit_head + ti) % WORKER_TARPIT_MAX);
                        int tfd  = w->tarpit_fds[slot];
                        if (tfd < 0) continue;
                        if (send(tfd, noise, sizeof(noise),
                                 MSG_NOSIGNAL | MSG_DONTWAIT) < 0) {
                            close(tfd);
                            w->tarpit_fds[slot] = -1;
                        }
                    }
                }
            }
            /* Periodic: expire blocklist entries whose TTL has elapsed */
            if (w->blocked_count > 0) {
                time_t now_t = time(NULL);
                while (w->blocked_count > 0) {
                    struct blocked_entry *be =
                        &w->blocked_list[w->blocked_head];
                    if (be->expire_at > now_t) break;
                    bpf_blocklist_remove(be->ip_host);
                    w->blocked_head =
                        (w->blocked_head + 1) % WORKER_BLOCKED_MAX;
                    w->blocked_count--;
                }
            }
            /* Periodic: abort connections whose backend response deadline elapsed */
            {
                struct timespec _bt;
                clock_gettime(CLOCK_MONOTONIC_COARSE, &_bt);
                uint64_t now_ns = (uint64_t)_bt.tv_sec * 1000000000ULL + _bt.tv_nsec;
                for (uint32_t _i = 0; _i < w->pool.capacity; _i++) {
                    struct conn_hot *_h = &w->pool.hot[_i];
                    if (_h->state == CONN_STATE_FREE) continue;
                    struct conn_cold *_cold = conn_cold_ptr(&w->pool, _i);
                    if (_cold->backend_deadline_ns == 0) continue;
                    if (now_ns < _cold->backend_deadline_ns) continue;
                    /* Deadline breached — record CB failure, send 504, close */
                    int _ri = _h->route_idx, _bi = _h->backend_idx;
                    cb_record_failure(w, _ri, _bi, now_ns,
                        w->cfg->routes[_ri].health.fail_threshold,
                        w->cfg->routes[_ri].health.open_ms);
                    log_warn("backend_timeout",
                        "conn=%u route=%d backend=%d timed out", _i, _ri, _bi);
                    _cold->backend_deadline_ns = 0;
                    static const char r504[] =
                        "HTTP/1.1 504 Gateway Timeout\r\n"
                        "Content-Length: 15\r\nConnection: close\r\n\r\n"
                        "Gateway Timeout";
                    send(_h->client_fd, r504, sizeof(r504) - 1, MSG_NOSIGNAL);
                    conn_close(w, _i, false);
                }
            }
            continue;
        }
        if (ret < 0) {
            if (ret == -EINTR) continue;
            log_error("worker_loop", "io_uring_wait_cqe_timeout: %s", strerror(-ret));
            break;
        }

        /* Process all available completions */
        io_uring_for_each_cqe(&w->uring.ring, head, cqe) {
            handle_proxy_data(w, cqe);
            count++;
            (void)head;
        }
        io_uring_cq_advance(&w->uring.ring, count);
    }

    log_info("worker_stop", "id=%d accepted=%llu completed=%llu errors=%llu",
        w->worker_id,
        (unsigned long long)w->accepted,
        (unsigned long long)w->completed,
        (unsigned long long)w->errors);

    /* ---- Graceful ring drain ----
     * io_uring_unregister_buffers() (inside uring_destroy) blocks until all
     * in-flight fixed-buffer ops complete.  Close every live fd first so the
     * kernel auto-cancels their pending SQEs, then drain the CQ so the ring
     * is empty before we call uring_destroy.  This makes shutdown O(1)
     * instead of waiting for the last client or tarpit timeout to fire. */

    /* 1. Close active proxy connection fds */
    for (uint32_t i = 0; i < w->pool.capacity; i++) {
        struct conn_hot *h = &w->pool.hot[i];
        if (h->state == CONN_STATE_FREE) continue;
        if (h->client_fd  >= 0) { close(h->client_fd);  h->client_fd  = -1; }
        if (h->backend_fd >= 0) { close(h->backend_fd); h->backend_fd = -1; }
    }

    /* 2. Close tarpit fds */
    for (uint32_t i = 0; i < w->tarpit_count; i++) {
        int idx = (int)((w->tarpit_head + i) % WORKER_TARPIT_MAX);
        if (w->tarpit_fds[idx] >= 0) { close(w->tarpit_fds[idx]); w->tarpit_fds[idx] = -1; }
    }

    /* 3. Drain any cancellation CQEs the kernel posts after fd close */
    {
        struct io_uring_cqe *cqe;
        struct __kernel_timespec drain_ts = { .tv_sec = 0, .tv_nsec = 100000000L }; /* 100ms */
        while (io_uring_wait_cqe_timeout(&w->uring.ring, &cqe, &drain_ts) == 0) {
            io_uring_cqe_seen(&w->uring.ring, cqe);
        }
    }

    uring_destroy(&w->uring);
    return NULL;
}

int worker_create_listener(const char *addr, uint16_t port, int backlog, bool ipv4_only)
{
    struct sockaddr_storage ss;
    socklen_t               sslen;
    int                     domain;

    memset(&ss, 0, sizeof(ss));

    if (ipv4_only) {
        /* AF_INET: accepts only IPv4 connections.  bind_address must be a
         * dotted-quad or empty/invalid (falls back to INADDR_ANY). */
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
        sa4->sin_family = AF_INET;
        sa4->sin_port   = htons(port);
        if (inet_pton(AF_INET, addr, &sa4->sin_addr) <= 0)
            sa4->sin_addr.s_addr = INADDR_ANY;
        sslen  = sizeof(*sa4);
        domain = AF_INET;
    } else {
        /* AF_INET6 with IPV6_V6ONLY=0: dual-stack — accepts both IPv4-mapped
         * (::ffff:x.x.x.x) and native IPv6 on a single socket.
         * bind_address should be "::" for all interfaces; a dotted-quad is
         * silently converted to the IPv4-mapped form via inet_pton(AF_INET6). */
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port   = htons(port);
        if (inet_pton(AF_INET6, addr, &sa6->sin6_addr) <= 0)
            sa6->sin6_addr = in6addr_any;
        sslen  = sizeof(*sa6);
        domain = AF_INET6;
    }

    int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        log_error("create_listener", "socket: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    if (!ipv4_only) {
        /* Allow IPv4-mapped addresses on the IPv6 socket */
        int zero = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    }

    /* Don't wake accept until the client has sent data — saves a round-trip
     * on every new connection.  Kernel falls back gracefully if unsupported. */
    int defer_sec = 5;
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_sec, sizeof(defer_sec));

    if (bind(fd, (struct sockaddr *)&ss, sslen) < 0) {
        log_error("create_listener", "bind %s:%d: %s", addr, port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        log_error("create_listener", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_info("listener_ready", "addr=%s port=%d fd=%d mode=%s",
             addr, port, fd, ipv4_only ? "ipv4" : "dual-stack");
    return fd;
}

uint32_t worker_pool_capacity(int num_workers, double budget_pct)
{
    /* Read MemAvailable from /proc/meminfo */
    long avail_kb = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "MemAvailable:", 13) == 0) {
                avail_kb = atol(line + 13);
                break;
            }
        }
        fclose(f);
    }

    if (avail_kb <= 0) {
        log_warn("pool_capacity", "could not read MemAvailable, using default 256");
        return 256;
    }

    /* Budget: budget_pct of available memory across all workers,
     * each connection needs 2 × WORKER_BUF_SIZE bytes of pinned buffers. */
    long budget_kb     = (long)(avail_kb * budget_pct);
    long per_worker_kb = (num_workers > 0) ? budget_kb / num_workers : budget_kb;
    long capacity      = (per_worker_kb * 1024) / (2 * WORKER_BUF_SIZE);

    if (capacity < 1)   capacity = 1;
    if (capacity > WORKER_MAX_CONNS) capacity = WORKER_MAX_CONNS;

    log_info("pool_capacity",
        "avail=%ldMB budget=%.0f%% workers=%d capacity=%ld per_worker=%ldMB",
        avail_kb / 1024, budget_pct * 100, num_workers,
        capacity, per_worker_kb / 1024);

    return (uint32_t)capacity;
}

int worker_init(struct worker *w, int id, int listen_fd, uint32_t capacity,
                struct vortex_config *cfg, struct tls_ctx *tls,
                struct cache *shared_cache)
{
    memset(w, 0, sizeof(*w));
    w->worker_id = id;
    w->listen_fd = listen_fd;
    w->cfg       = cfg;
    w->cache     = shared_cache;
#ifdef VORTEX_PHASE_TLS
    w->tls       = tls;
    w->backend_tls_client_ctx = SSL_CTX_new(TLS_client_method());
    if (!w->backend_tls_client_ctx) {
        log_error("worker_init", "SSL_CTX_new(TLS_client_method) failed");
        return -1;
    }
    SSL_CTX_set_min_proto_version(w->backend_tls_client_ctx, cfg->tls.min_version);
    SSL_CTX_set_max_proto_version(w->backend_tls_client_ctx, cfg->tls.max_version);
    SSL_CTX_set_default_verify_paths(w->backend_tls_client_ctx);
#else
    (void)tls;
#endif

    /* io_uring is initialized inside the worker thread for SINGLE_ISSUER compat */

    for (int i = 0; i < WORKER_TARPIT_MAX; i++) w->tarpit_fds[i] = -1;

    /* Open /dev/urandom for tarpit noise */
    w->urandom_fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK);
    if (w->urandom_fd < 0)
        log_warn("worker_init", "cannot open /dev/urandom: %s", strerror(errno));

    /* Pipe for receiving TLS handshake results from the pool */
    {
        int pfd[2];
        if (pipe2(pfd, O_NONBLOCK | O_CLOEXEC) == 0) {
            w->tls_done_pipe_rd = pfd[0];
            w->tls_done_pipe_wr = pfd[1];
        } else {
            w->tls_done_pipe_rd = w->tls_done_pipe_wr = -1;
            log_warn("worker_init", "tls_done pipe creation failed: %s", strerror(errno));
        }
    }

    /* Open tarpit log */
    w->tarpit_log = fopen("/var/log/vortex/tarpit.log", "a");
    if (!w->tarpit_log)
        log_warn("worker_init", "cannot open tarpit log: %s", strerror(errno));

    if (conn_pool_init(&w->pool, capacity, WORKER_BUF_SIZE, cfg->hugepages) != 0) {
#ifdef VORTEX_PHASE_TLS
        if (w->backend_tls_client_ctx) {
            SSL_CTX_free(w->backend_tls_client_ctx);
            w->backend_tls_client_ctx = NULL;
        }
#endif
        return -1;
    }

    if (router_init(&w->router, cfg) != 0) {
        conn_pool_destroy(&w->pool);
#ifdef VORTEX_PHASE_TLS
        if (w->backend_tls_client_ctx) {
            SSL_CTX_free(w->backend_tls_client_ctx);
            w->backend_tls_client_ctx = NULL;
        }
#endif
        return -1;
    }

    return 0;
}

int worker_start(struct worker *w)
{
    int ret = pthread_create(&w->thread, NULL, worker_thread, w);
    if (ret != 0) return ret;

    /* Pin the worker thread to CPU worker_id (if that CPU is online).
     * This keeps the io_uring ring, TLS state, and connection pool hot in
     * the L1/L2 cache of one core, eliminating cross-CPU cache misses on
     * the hot accept/recv/send path.
     * If the CPU doesn't exist (e.g. fewer CPUs than workers) we skip
     * silently — the scheduler will place it wherever it fits. */
    if (w->cfg && w->cfg->cpu_affinity) {
        int ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
        int cpu   = w->worker_id % ncpus;
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);
        ret = pthread_setaffinity_np(w->thread, sizeof(cpuset), &cpuset);
        if (ret != 0)
            log_warn("worker_start", "id=%d cpu_affinity=%d failed: %s",
                     w->worker_id, cpu, strerror(ret));
        else
            log_info("worker_start", "id=%d pinned to CPU %d", w->worker_id, cpu);
    }
    return 0;
}

void worker_stop(struct worker *w)
{
    w->stop = 1;

    /* Wake the worker immediately instead of waiting for the 1s timeout.
     * This also cancels the multishot accept / TLS-done pipe SQEs before
     * uring_destroy(), avoiding stop-time hangs on still-open fds. */
    if (w->listen_fd >= 0) {
        close(w->listen_fd);
        w->listen_fd = -1;
    }
    if (w->tls_done_pipe_rd >= 0) {
        close(w->tls_done_pipe_rd);
        w->tls_done_pipe_rd = -1;
    }
    if (w->tls_done_pipe_wr >= 0) {
        close(w->tls_done_pipe_wr);
        w->tls_done_pipe_wr = -1;
    }
}

void worker_join(struct worker *w)
{
    pthread_join(w->thread, NULL);
}

void worker_destroy(struct worker *w)
{
    /* Close any held tarpit connections */
    for (uint32_t i = 0; i < w->tarpit_count; i++) {
        int idx = (int)((w->tarpit_head + i) % WORKER_TARPIT_MAX);
        if (w->tarpit_fds[idx] >= 0) { close(w->tarpit_fds[idx]); w->tarpit_fds[idx] = -1; }
    }
    if (w->tarpit_total)
        log_info("tarpit_stats", "worker=%d total=%llu active=%u blocked=%u",
            w->worker_id, (unsigned long long)w->tarpit_total,
            w->tarpit_count, w->blocked_count);

    /* Remove any still-live blocklist entries so they don't persist across restarts */
    for (uint32_t i = 0; i < w->blocked_count; i++) {
        uint32_t bi = (w->blocked_head + i) % WORKER_BLOCKED_MAX;
        bpf_blocklist_remove(w->blocked_list[bi].ip_host);
    }

    if (w->listen_fd >= 0) { close(w->listen_fd); w->listen_fd = -1; }
    if (w->urandom_fd >= 0) { close(w->urandom_fd); w->urandom_fd = -1; }
    if (w->tls_done_pipe_rd >= 0) { close(w->tls_done_pipe_rd); w->tls_done_pipe_rd = -1; }
    if (w->tls_done_pipe_wr >= 0) { close(w->tls_done_pipe_wr); w->tls_done_pipe_wr = -1; }
    if (w->tarpit_log)  { fclose(w->tarpit_log); w->tarpit_log = NULL; }
#ifdef VORTEX_PHASE_TLS
    if (w->backend_tls_client_ctx) {
        SSL_CTX_free(w->backend_tls_client_ctx);
        w->backend_tls_client_ctx = NULL;
    }
#endif

    router_destroy(&w->router);
    conn_pool_destroy(&w->pool);
    if (w->cache && w->cache->index && w->worker_id == 0) {
        log_info("cache_stats", "worker=%d hits=%llu misses=%llu stores=%llu evictions=%llu",
            w->worker_id,
            (unsigned long long)w->cache->hits,
            (unsigned long long)w->cache->misses,
            (unsigned long long)w->cache->stores,
            (unsigned long long)w->cache->evictions);
    }
    /* uring is destroyed inside the worker thread */
}
