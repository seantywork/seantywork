#include "h2.h"


#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
  }


/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
    size_t slen = strlen(s);
    size_t sublen = strlen(sub);
    if (slen < sublen) {
        return 0;
    }
    return memcmp(s + slen - sublen, sub, sublen) == 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
    if ('0' <= c && c <= '9') {
        return (uint8_t)(c - '0');
    }
    if ('A' <= c && c <= 'F') {
        return (uint8_t)(c - 'A' + 10);
    }
    if ('a' <= c && c <= 'f') {
        return (uint8_t)(c - 'a' + 10);
    }
    return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
    char *res;

    res = malloc(valuelen + 1);
    if (valuelen > 3) {
        size_t i, j;
        for (i = 0, j = 0; i < valuelen - 2;) {
        if (value[i] != '%' || !isxdigit(value[i + 1]) ||
            !isxdigit(value[i + 2])) {
            res[j++] = (char)value[i++];
            continue;
        }
        res[j++] =
            (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
        i += 3;
        }
        memcpy(&res[j], &value[i], 2);
        res[j + 2] = '\0';
    } else {
        memcpy(res, value, valuelen);
        res[valuelen] = '\0';
    }
    return res;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
    /* We don't like '\' in url. */
    return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
            strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
            !ends_with(path, "/..") && !ends_with(path, "/.");
}

static void add_stream(sess_info *session_data,
                       http2_stream_data *stream_data) {
    stream_data->next = session_data->root.next;
    session_data->root.next = stream_data;
    stream_data->prev = &session_data->root;
    if (stream_data->next) {
        stream_data->next->prev = stream_data;
    }
}

static void remove_stream(sess_info *session_data,
                          http2_stream_data *stream_data) {
    (void)session_data;

    stream_data->prev->next = stream_data->next;
    if (stream_data->next) {
        stream_data->next->prev = stream_data->prev;
    }
}

static http2_stream_data *create_http2_stream_data(sess_info *session_data, int32_t stream_id) {
    http2_stream_data *stream_data;
    stream_data = malloc(sizeof(http2_stream_data));
    memset(stream_data, 0, sizeof(http2_stream_data));
    stream_data->stream_id = stream_id;
    stream_data->fd = -1;

    add_stream(session_data, stream_data);
    return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
    if (stream_data->fd != -1) {
        close(stream_data->fd);
    }
    free(stream_data->request_path);
    free(stream_data);
}

static nghttp2_ssize send_callback(nghttp2_session *session,
                                   const uint8_t *data, size_t length,
                                   int flags, void *user_data) {
    sess_info *session_data = (sess_info *)user_data;
    int res = length;
    if(!res){
        printf("nothing to send\n");
        return (nghttp2_ssize)res;
    }
    printf("sending...\n");
    res = SSL_write(session_data->ssl, data, length);
    if(res < 1){
        printf("fatal: send callback: %d\n", res);
    } 
    printf("sent\n");
    return (nghttp2_ssize)res;
}

static nghttp2_ssize file_read_callback(nghttp2_session *session,
                                        int32_t stream_id, uint8_t *buf,
                                        size_t length, uint32_t *data_flags,
                                        nghttp2_data_source *source,
                                        void *user_data) {
    int fd = source->fd;
    ssize_t r;
    (void)session;
    (void)stream_id;
    (void)user_data;

    while ((r = read(fd, buf, length)) == -1 && errno == EINTR);
    if (r == -1) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (r == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (nghttp2_ssize)r;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd) {
    int rv;
    nghttp2_data_provider2 data_prd;
    data_prd.source.fd = fd;
    data_prd.read_callback = file_read_callback;

    rv = nghttp2_submit_response2(session, stream_id, nva, nvlen, &data_prd);
    if (rv != 0) {
        printf("fatal: send response: %s", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
                                 "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
    int rv;
    ssize_t writelen;
    int pipefd[2];
    nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

    rv = pipe(pipefd);
    if (rv != 0) {
        printf("could not create pipe\n");
        rv =
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                    stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
        if (rv != 0) {
            printf("fatal: error reply: %s", nghttp2_strerror(rv));
            return -1;
        }
        return 0;
    }

    writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
    close(pipefd[1]);

    if (writelen != sizeof(ERROR_HTML) - 1) {
        close(pipefd[0]);
        return -1;
    }

    stream_data->fd = pipefd[0];

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                        pipefd[0]) != 0) {
        close(pipefd[0]);
        return -1;
    }
    return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
    http2_stream_data *stream_data;
    const char PATH[] = ":path";
    (void)flags;
    (void)user_data;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
            break;
        }
        stream_data =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (!stream_data || stream_data->request_path) {
            break;
        }
        if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
            size_t j;
            for (j = 0; j < valuelen && value[j] != '?'; ++j);
            stream_data->request_path = percent_decode(value, j);
        }
        break;
    }
    return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
    sess_info *session_data = (sess_info *)user_data;
    http2_stream_data *stream_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                        stream_data);
    return 0;
}


static int on_request_recv(nghttp2_session *session,
                           sess_info *session_data,
                           http2_stream_data *stream_data) {
    int fd;
    nghttp2_nv hdrs[] = {MAKE_NV(":status", "200")};
    char *rel_path;

    if (!stream_data->request_path) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    fprintf(stderr, "GET %s\n", stream_data->request_path);
    if (!check_path(stream_data->request_path)) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path);
    fd = open(rel_path, O_RDONLY);
    if (fd == -1) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    stream_data->fd = fd;

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), fd) !=
        0) {
        close(fd);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
    sess_info *session_data = (sess_info *)user_data;
    http2_stream_data *stream_data;
    switch (frame->hd.type) {
    case NGHTTP2_DATA:
    case NGHTTP2_HEADERS:
        /* Check that the client request has finished */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream_data =
                nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            /* For DATA and HEADERS frame, this callback may be called after
                on_stream_close_callback. Check that stream still alive. */
            if (!stream_data) {
                return 0;
            }
            return on_request_recv(session, session_data, stream_data);
        }
        break;
    default:
        break;
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
    sess_info *session_data = (sess_info *)user_data;
    http2_stream_data *stream_data;
    (void)error_code;

    stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream_data) {
        return 0;
    }
    remove_stream(session_data, stream_data);
    delete_http2_stream_data(stream_data);
    return 0;
}




/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
int server_h2_send_connection_header(sess_info *session_data) {
    nghttp2_settings_entry iv[1] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    int rv;

    rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                                ARRLEN(iv));
    if (rv != 0) {
        printf("fatal: submit setting: %s\n", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}


void server_h2_initialize_nghttp2_session(sess_info *session_data) {
    nghttp2_session_callbacks *callbacks;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                        on_frame_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                    on_header_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);

    nghttp2_session_server_new(&session_data->session, callbacks, session_data);

    nghttp2_session_callbacks_del(callbacks);
}


int server_h2_alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
    int rv;
    (void)ssl;
    (void)arg;

    rv = nghttp2_select_alpn(out, outlen, in, inlen);

    if (rv != 1) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}


int server_h2_send(sess_info *session_data) {
    int rv;
    rv = nghttp2_session_send(session_data->session);
    if (rv != 0) {
        printf("fatal: session send: %s\n", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv2() may make
   additional pending frames, so call session_send() at the end of the
   function. */
int server_h2_recv(sess_info *session_data, unsigned char *data, size_t datalen) {
    nghttp2_ssize readlen;
    readlen = nghttp2_session_mem_recv2(session_data->session, data, datalen);
    if (readlen < 0) {
        printf("fatal: session recv: %s\n", nghttp2_strerror((int)readlen));
        return -1;
    }
    
    if (server_h2_send(session_data) != 0) {
        printf("fatal: session recv: send\n");
        return -1;
    }
    
    return 0;
}
