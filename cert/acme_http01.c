#include "acme_http01.h"
#include "../src/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define CHALLENGE_PREFIX "/.well-known/acme-challenge/"
#define BUF_SZ 8192

static void handle_connection(struct acme_http01_server *srv, int cfd)
{
    char buf[BUF_SZ];
    ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(cfd); return; }
    buf[n] = '\0';

    /* Parse request line: METHOD PATH HTTP/x.y */
    char method[16], path[512];
    if (sscanf(buf, "%15s %511s", method, path) != 2) {
        close(cfd);
        return;
    }

    /* ACME challenge request? */
    if (strcmp(method, "GET") == 0 &&
        strncmp(path, CHALLENGE_PREFIX, strlen(CHALLENGE_PREFIX)) == 0)
    {
        const char *token = path + strlen(CHALLENGE_PREFIX);

        pthread_mutex_lock(&srv->challenge_lock);
        int match = (srv->challenge_token[0] != '\0' &&
                     strcmp(token, srv->challenge_token) == 0);
        char keyauth[512];
        strncpy(keyauth, srv->challenge_keyauth, sizeof(keyauth) - 1);
        keyauth[sizeof(keyauth)-1] = '\0';
        pthread_mutex_unlock(&srv->challenge_lock);

        if (match) {
            char resp[1024];
            int rlen = snprintf(resp, sizeof(resp),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/octet-stream\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                strlen(keyauth), keyauth);
            send(cfd, resp, (size_t)rlen, MSG_NOSIGNAL);
            log_info("acme_http01", "served challenge token=%s", token);
        } else {
            const char *not_found =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send(cfd, not_found, strlen(not_found), MSG_NOSIGNAL);
            log_debug("acme_http01", "unknown token=%s", token);
        }
    } else {
        /* Redirect everything else to HTTPS */
        char location[600] = "";
        /* Extract Host header */
        const char *host_hdr = strcasestr(buf, "\r\nHost:");
        if (host_hdr) {
            host_hdr += 7; /* skip "\r\nHost:" */
            while (*host_hdr == ' ') host_hdr++;
            const char *end = strstr(host_hdr, "\r\n");
            size_t hlen = end ? (size_t)(end - host_hdr) : strlen(host_hdr);
            if (hlen < sizeof(location) - 16) {
                snprintf(location, sizeof(location),
                    "https://%.*s%s", (int)hlen, host_hdr, path);
            }
        }

        char resp[700];
        int rlen;
        if (location[0]) {
            rlen = snprintf(resp, sizeof(resp),
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: %s\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n",
                location);
        } else {
            rlen = snprintf(resp, sizeof(resp),
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n");
        }
        send(cfd, resp, (size_t)rlen, MSG_NOSIGNAL);
    }

    close(cfd);
}

static void *server_thread(void *arg)
{
    struct acme_http01_server *srv = arg;

    while (srv->running) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(srv->listen_fd, &rset);
        FD_SET(srv->stop_pipe[0], &rset);
        int maxfd = (srv->listen_fd > srv->stop_pipe[0])
                  ? srv->listen_fd : srv->stop_pipe[0];

        struct timeval tv = { .tv_sec = 2 };
        int sel = select(maxfd + 1, &rset, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (sel == 0) continue;

        if (FD_ISSET(srv->stop_pipe[0], &rset)) break;

        if (FD_ISSET(srv->listen_fd, &rset)) {
            struct sockaddr_in ca;
            socklen_t calen = sizeof(ca);
            int cfd = accept(srv->listen_fd, (struct sockaddr *)&ca, &calen);
            if (cfd >= 0) {
                /* Set read/write timeout */
                struct timeval to = { .tv_sec = 5 };
                setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
                setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
                handle_connection(srv, cfd);
            }
        }
    }

    log_info("acme_http01", "server thread exiting");
    return NULL;
}

int acme_http01_start(struct acme_http01_server *srv, int port)
{
    memset(srv, 0, sizeof(*srv));
    srv->listen_fd = -1;
    srv->stop_pipe[0] = srv->stop_pipe[1] = -1;

    pthread_mutex_init(&srv->challenge_lock, NULL);

    if (pipe(srv->stop_pipe) < 0) {
        log_error("acme_http01", "pipe: %s", strerror(errno));
        return -1;
    }

    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) {
        log_error("acme_http01", "socket: %s", strerror(errno));
        goto err;
    }

    int one = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(srv->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_error("acme_http01", "bind port %d: %s", port, strerror(errno));
        goto err;
    }
    if (listen(srv->listen_fd, 16) < 0) {
        log_error("acme_http01", "listen: %s", strerror(errno));
        goto err;
    }

    srv->port    = port;
    srv->running = 1;
    if (pthread_create(&srv->thread, NULL, server_thread, srv) != 0) {
        log_error("acme_http01", "pthread_create: %s", strerror(errno));
        goto err;
    }

    log_info("acme_http01", "listening on port %d", port);
    return 0;

err:
    if (srv->listen_fd >= 0) { close(srv->listen_fd); srv->listen_fd = -1; }
    if (srv->stop_pipe[0] >= 0) { close(srv->stop_pipe[0]); close(srv->stop_pipe[1]); }
    return -1;
}

void acme_http01_set_challenge(struct acme_http01_server *srv,
                                const char *token, const char *key_auth)
{
    pthread_mutex_lock(&srv->challenge_lock);
    strncpy(srv->challenge_token,   token,    sizeof(srv->challenge_token)   - 1);
    strncpy(srv->challenge_keyauth, key_auth, sizeof(srv->challenge_keyauth) - 1);
    srv->challenge_token[sizeof(srv->challenge_token)-1]   = '\0';
    srv->challenge_keyauth[sizeof(srv->challenge_keyauth)-1] = '\0';
    pthread_mutex_unlock(&srv->challenge_lock);
}

void acme_http01_clear_challenge(struct acme_http01_server *srv)
{
    pthread_mutex_lock(&srv->challenge_lock);
    srv->challenge_token[0]   = '\0';
    srv->challenge_keyauth[0] = '\0';
    pthread_mutex_unlock(&srv->challenge_lock);
}

void acme_http01_stop(struct acme_http01_server *srv)
{
    if (!srv->running) return;
    srv->running = 0;
    if (srv->stop_pipe[1] >= 0) {
        write(srv->stop_pipe[1], "x", 1);
    }
    pthread_join(srv->thread, NULL);
    if (srv->listen_fd >= 0) { close(srv->listen_fd); srv->listen_fd = -1; }
    if (srv->stop_pipe[0] >= 0) { close(srv->stop_pipe[0]); srv->stop_pipe[0] = -1; }
    if (srv->stop_pipe[1] >= 0) { close(srv->stop_pipe[1]); srv->stop_pipe[1] = -1; }
    pthread_mutex_destroy(&srv->challenge_lock);
}
