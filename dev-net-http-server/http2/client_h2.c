#include "h2.h"




#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))



static void print_header(FILE *f, const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen) {
    fwrite(name, 1, namelen, f);
    fprintf(f, ": ");
    fwrite(value, 1, valuelen, f);
    fprintf(f, "\n");
}

/* Print HTTP headers to |f|. Please note that this function does not
   take into account that header name and value are sequence of
   octets, therefore they may contain non-printable characters. */
static void print_headers(FILE *f, nghttp2_nv *nva, size_t nvlen) {
    size_t i;
    for (i = 0; i < nvlen; ++i) {
        print_header(f, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
    }
    fprintf(f, "\n");
}

/* nghttp2_send_callback2. Here we transmit the |data|, |length|
   bytes, to the network. Because we are using libevent bufferevent,
   we just write those bytes into bufferevent buffer. */
static nghttp2_ssize send_callback(nghttp2_session *session,
                                   const uint8_t *data, size_t length,
                                   int flags, void *user_data) {
    sess_info2 *session_data = (sess_info2 *)user_data;
    int res = length;
    if(!res){
        printf("nothing to send\n");
        return (nghttp2_ssize)res;
    }
    printf("sending...\n");
    for(int i = 0; i < length; i++){
        printf("%c", data[i]);
    }
    printf("\n");
    res = SSL_write(session_data->ssl, data, length);
    if(res < 1){
        printf("fatal: send callback: %d\n", res);
    } 
    printf("sent\n");
    return (nghttp2_ssize)res;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
    sess_info2 *session_data = (sess_info2 *)user_data;
    (void)session;
    (void)flags;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            session_data->stream_data->stream_id == frame->hd.stream_id) {
            /* Print response headers for the initiated request. */
            print_header(stderr, name, namelen, value, valuelen);
            break;
        }
        printf("recv: header0: %d,%d,%d\n", frame->headers.cat, session_data->stream_data->stream_id, frame->hd.stream_id);
    }
    return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
    sess_info2 *session_data = (sess_info2 *)user_data;
    (void)session;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            session_data->stream_data->stream_id == frame->hd.stream_id) {
            printf("Response headers for stream ID=%d:\n",
                frame->hd.stream_id);
        }
        printf("recv: header1: %d,%d,%d\n", frame->headers.cat, session_data->stream_data->stream_id, frame->hd.stream_id);
        break;
    }
    return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
    sess_info2 *session_data = (sess_info2 *)user_data;
    (void)session;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            session_data->stream_data->stream_id == frame->hd.stream_id) {
            printf("All headers received\n");
        }
        printf("recv: header2: %d,%d,%d\n", frame->headers.cat, session_data->stream_data->stream_id, frame->hd.stream_id);
        break;
    }
    return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
    sess_info2 *session_data = (sess_info2 *)user_data;
    (void)session;
    (void)flags;

    if (session_data->stream_data->stream_id == stream_id) {
        fwrite(data, 1, len, stdout);
    }
    return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
    sess_info2 *session_data = (sess_info2 *)user_data;
    int rv;

    if (session_data->stream_data->stream_id == stream_id) {
        fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id,
                error_code);
        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        if (rv != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}



void client_h2_initialize_nghttp2_session(sess_info2 *session_data) {
    nghttp2_session_callbacks *callbacks;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                        on_frame_recv_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, on_data_chunk_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                    on_header_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);

    nghttp2_session_client_new(&session_data->session, callbacks, session_data);

    nghttp2_session_callbacks_del(callbacks);
}

void client_h2_send_connection_header(sess_info2 *session_data) {
    nghttp2_settings_entry iv[1] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    int rv;

    /* client 24 bytes magic string will be sent by nghttp2 library */
    rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                                ARRLEN(iv));
    if (rv != 0) {
        printf("Could not submit SETTINGS: %s\n", nghttp2_strerror(rv));
    }
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE,     sizeof(NAME) - 1,                   \
    VALUELEN,        NGHTTP2_NV_FLAG_NONE,                                     \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
  }

/* Send HTTP request to the remote peer */
void client_h2_submit_request(sess_info2 *session_data) {
    int32_t stream_id;
    http2_stream_data2 *stream_data = session_data->stream_data;
    const char *uri = stream_data->uri;
    const urlparse_url *u = stream_data->u;
    nghttp2_nv hdrs[] = {
        MAKE_NV2(":method", "GET"),
        MAKE_NV(":scheme", &uri[u->field_data[URLPARSE_SCHEMA].off],
                u->field_data[URLPARSE_SCHEMA].len),
        MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
        MAKE_NV(":path", stream_data->path, stream_data->pathlen)};
    fprintf(stderr, "Request headers:\n");
    print_headers(stderr, hdrs, ARRLEN(hdrs));
    stream_id = nghttp2_submit_request2(session_data->session, NULL, hdrs,
                                        ARRLEN(hdrs), NULL, stream_data);
    if (stream_id < 0) {
        printf("Could not submit HTTP request: %s\n", nghttp2_strerror(stream_id));
    }
    printf("stream id: %d\n", stream_id);
    stream_data->stream_id = stream_id;
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
int client_h2_session_send(sess_info2 *session_data) {
    int rv;
    rv = nghttp2_session_send(session_data->session);
    if (rv != 0) {
        printf("Fatal error: session send: %s\n", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}


http2_stream_data2 *client_h2_create_http2_stream_data(const char *uri,
                                                   urlparse_url *u) {
    /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
    size_t extra = 7;
    http2_stream_data2 *stream_data = malloc(sizeof(http2_stream_data2));

    stream_data->uri = uri;
    stream_data->u = u;
    stream_data->stream_id = -1;

    stream_data->authoritylen = u->field_data[URLPARSE_HOST].len;
    stream_data->authority = malloc(stream_data->authoritylen + extra);
    memcpy(stream_data->authority, &uri[u->field_data[URLPARSE_HOST].off],
            u->field_data[URLPARSE_HOST].len);
    if (u->field_set & (1 << URLPARSE_PORT)) {
        stream_data->authoritylen += (size_t)snprintf(
        stream_data->authority + u->field_data[URLPARSE_HOST].len, extra, ":%u",
        u->port);
    }

    /* If we don't have path in URI, we use "/" as path. */
    stream_data->pathlen = 1;
    if (u->field_set & (1 << URLPARSE_PATH)) {
        stream_data->pathlen = u->field_data[URLPARSE_PATH].len;
    }
    if (u->field_set & (1 << URLPARSE_QUERY)) {
        /* +1 for '?' character */
        stream_data->pathlen += (size_t)(u->field_data[URLPARSE_QUERY].len + 1);
    }

    stream_data->path = malloc(stream_data->pathlen);
    if (u->field_set & (1 << URLPARSE_PATH)) {
        memcpy(stream_data->path, &uri[u->field_data[URLPARSE_PATH].off],
            u->field_data[URLPARSE_PATH].len);
    } else {
        stream_data->path[0] = '/';
    }
    if (u->field_set & (1 << URLPARSE_QUERY)) {
        stream_data
        ->path[stream_data->pathlen - u->field_data[URLPARSE_QUERY].len - 1] =
        '?';
        memcpy(stream_data->path + stream_data->pathlen -
                u->field_data[URLPARSE_QUERY].len,
            &uri[u->field_data[URLPARSE_QUERY].off],
            u->field_data[URLPARSE_QUERY].len);
    }

    return stream_data;
}

void client_h2_delete_http2_stream_data(http2_stream_data2 *stream_data) {
    free(stream_data->path);
    free(stream_data->authority);
    free(stream_data);
}