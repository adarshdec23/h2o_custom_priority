/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/http2_internal.h"
#include "h2o/http2_schedmode.h"
#include "h2o/http2_ua_id.h"

static const h2o_iovec_t CONNECTION_PREFACE = {H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")};

const h2o_http2_priority_t h2o_http2_default_priority = {
    0, /* exclusive */
    0, /* dependency */
    16 /* weight */
};

const h2o_http2_settings_t H2O_HTTP2_SETTINGS_HOST = {
    4096,     /* header_table_size */
    0,        /* enable_push (clients are never allowed to initiate server push; RFC 7540 Section 8.2) */
    100,      /* max_concurrent_streams */
    16777216, /* initial_window_size */
    16384     /* max_frame_size */
};

static const h2o_iovec_t SETTINGS_HOST_BIN = {H2O_STRLIT("\x00\x00\x0c"     /* frame size */
                                                         "\x04"             /* settings frame */
                                                         "\x00"             /* no flags */
                                                         "\x00\x00\x00\x00" /* stream id */
                                                         "\x00\x03"
                                                         "\x00\x00\x00\x64" /* max_concurrent_streams = 100 */
                                                         "\x00\x04"
                                                         "\x01\x00\x00\x00" /* initial_window_size = 16777216 */
                                                         )};

static __thread h2o_buffer_prototype_t wbuf_buffer_prototype = {{16}, {H2O_HTTP2_DEFAULT_OUTBUF_SIZE}};

static void initiate_graceful_shutdown(h2o_context_t *ctx);
static int close_connection(h2o_http2_conn_t *conn);
static ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
static void do_emit_writereq(h2o_http2_conn_t *conn);
static void on_read(h2o_socket_t *sock, const char *err);
static void push_path(h2o_req_t *src_req, const char *abspath, size_t abspath_len);
static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata);
static void stream_send_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum);

static int h2o_http2_update_headersframe_priority(const h2o_http2_conn_t *conn,
                                                  h2o_http2_headers_payload_t *headers_payload,
                                                  const sched_mode_t sched_mode);
static void set_priority(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream,
                         const h2o_http2_priority_t *priority, int scheduler_is_open);

const h2o_protocol_callbacks_t H2O_HTTP2_CALLBACKS = {initiate_graceful_shutdown, foreach_request};

//////////////////////////////////////////////////////////////////////////////
// Custom code
//////////////////////////////////////////////////////////////////////////////

static void custom_print_incoming_request(const uint32_t stream_id, const  h2o_http2_priority_t *priority);
static void custom_print_req(const uint32_t stream_id, const  h2o_http2_priority_t *priority);
/**
Called before the authors get a chance to change any priority information. This is the base we use to understand how browsers 
build their dependency tree
*/
void custom_print_incoming_request(const uint32_t stream_id, const  h2o_http2_priority_t *priority){

    for(int i=0; i<50; i++)
        printf("*");
    printf("\n");
    printf("*****+++++{'stream_id': %d, 'weight': %d, 'exclusive': %d, 'dependency': %d}\n", stream_id, priority->weight, priority->exclusive, priority->dependency);

}
void custom_print_req(const uint32_t stream_id, const  h2o_http2_priority_t *priority){
    //Do nothing
    return;
}

///////////////////////////////////////////////////////////////////////////////
// chrome_http2_parallel_img_download
///////////////////////////////////////////////////////////////////////////////

static const h2o_http2_stream_t* h2o_http2_scheduler_get_deepest_child(const h2o_http2_stream_t *root);
inline static int h2o_http2_scheduler_has_children(const h2o_http2_stream_t *root);
static int h2o_http2_update_priority_parallelism_serialization(const h2o_http2_conn_t *conn,
                                                               h2o_http2_priority_t *priority,
                                                               const useragent_id_t ua);

/**
 * The collection of idle/phantom streams that is created for every 
 * incoming HTTP/2 connection. These phantom streams will be exploited to 
 * introduce some level of parallelism in Chrome's H2 prioritization 
 * strategy or, conversely, to introduce some level of serialization in 
 * Firefox's H2 prioritization strategy.
 */
typedef struct st_h2o_http2_conn_phantom_streams_t {
    h2o_http2_conn_t *conn;
    /**
     * The idle/phantom stream that serves as root node of the serial 
     * branch of the H2 dep graph.
     */
    h2o_http2_stream_t *stream_phantom_serial;
    /**
     * The idle/phantom stream that will (non-exclusively) cluster all 
     * H2 streams belonging to Chrome's MEDIUM priority bucket (i.e., 
     * carrying H2 weight value 183) or the equivalent resource types 
     * in Firefox.
     */
    h2o_http2_stream_t *stream_phantom_w183;
    /**
     * The idle/phantom stream that will (non-exclusively) cluster all 
     * H2 streams belonging to Chrome's LOW or LOWEST priority bucket (i.e., 
     * carrying a weight value of 147 or lower) or the equivalent 
     * resource types in Firefox.
     */
    h2o_http2_stream_t *stream_phantom_w147;

    h2o_linklist_t conns;
} h2o_http2_conn_phantom_streams_t;

h2o_http2_conn_phantom_streams_t h2o_http2_conns_phantom_streams;
int h2o_http2_conns_phantom_streams_init_needed = 1;

const uint32_t H2O_HTTP2_STREAM_ID_PHANTOM_SERIAL = 4294967291U; // (1 << 32) - 5
const uint32_t H2O_HTTP2_STREAM_ID_PHANTOM_W183 = 4294967293U; // (1 << 32) - 3
const uint32_t H2O_HTTP2_STREAM_ID_PHANTOM_W147 = 4294967295U; // (1 << 32) - 1

/**
 * Initializes the <tt>h2o_http2_conns_phantom_streams</tt> data 
 * structure, if still needed
 */
void h2o_http2_conn_phantom_streams_init_datastructure()
{
    if (h2o_http2_conns_phantom_streams_init_needed == 1) {
        h2o_http2_conns_phantom_streams.conns = (h2o_linklist_t){ NULL };
        h2o_linklist_init_anchor(&h2o_http2_conns_phantom_streams.conns);

        h2o_http2_conns_phantom_streams_init_needed = 0;
    }
}

/**
 * @return The number of <tt>h2o_http2_conn_phantom_streams_t</tt> instances 
 *         that are stored in the <tt>h2o_http2_conns_phantom_streams</tt> 
 *         repository.
 */
size_t h2o_http2_conn_phantom_streams_num_records()
{
    size_t count = 0;
    
    h2o_http2_conn_phantom_streams_init_datastructure();

    if (h2o_linklist_is_empty(&h2o_http2_conns_phantom_streams.conns))
        return 0;

    h2o_linklist_t *node = &h2o_http2_conns_phantom_streams.conns;

    while ((h2o_linklist_is_linked(node)) && (node->next != &h2o_http2_conns_phantom_streams.conns)) {
        count++;
        node = node->next;
    }

    return count;
}

/**
 * @return The <tt>h2o_http2_conn_phantom_streams_t</tt> instance that is 
 *         related to the specifief HTTP/2 connection in the 
 *         <tt>h2o_http2_conns_phantom_streams</tt> repository, or 
 *         <tt>NULL</tt> if no such instance exists.
 */
h2o_http2_conn_phantom_streams_t* h2o_http2_conn_phantom_streams_get(const h2o_http2_conn_t *conn)
{
    h2o_http2_conn_phantom_streams_init_datastructure();

    if (h2o_linklist_is_empty(&h2o_http2_conns_phantom_streams.conns))
        return NULL;

    h2o_linklist_t *node = &h2o_http2_conns_phantom_streams.conns;
    h2o_http2_conn_phantom_streams_t *conn_phantom_streams = NULL;

    while ((h2o_linklist_is_linked(node)) && (node->next != &h2o_http2_conns_phantom_streams.conns)) {
        conn_phantom_streams = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_phantom_streams_t, conns, node->next);

        if (conn_phantom_streams->conn == conn)
            return conn_phantom_streams;

        node = node->next;
    }

    return NULL;
}

/**
 * Allocates and instantiates a <tt>h2o_http2_conn_phantom_streams_t</tt> 
 * record for the specified HTTP/2 connection, hereby creating the 
 * idle/phantom HTTP/2 streams that it encompasses, and then registers the 
 * new instance with the <tt>h2o_http2_conns_phantom_streams</tt> repository.
 */
void h2o_http2_conn_phantom_streams_generate(h2o_http2_conn_t *conn)
{
    static char remote_addr[NI_MAXHOST];
    static int32_t remote_port;

    get_remote_addr_and_port(conn, remote_addr, &remote_port);

    h2o_http2_conn_phantom_streams_init_datastructure();

    h2o_write_log_conditional("=== Generating idle/phantom streams for HTTP/2 connection %s:%i ...\n", remote_addr, remote_port);

    if (h2o_http2_conn_phantom_streams_get(conn) != NULL) {
        fprintf(stdout, "=== WARNING: Idle/phantom streams for HTTP/2 connection %s:%i already exist ...\n", remote_addr, remote_port);
        return;
    }

    h2o_http2_conn_phantom_streams_t *conn_phantom_streams;
    conn_phantom_streams = malloc(sizeof(h2o_http2_conn_phantom_streams_t));

    h2o_http2_priority_t priority = {
        0, /* exclusive */
        0, /* dependency */
        256 /* weight */
    };

    conn_phantom_streams->stream_phantom_serial = h2o_http2_stream_open(conn, H2O_HTTP2_STREAM_ID_PHANTOM_SERIAL, NULL, &priority);
    set_priority(conn, conn_phantom_streams->stream_phantom_serial, &priority, 0);

    priority.weight = 1;

    conn_phantom_streams->stream_phantom_w183 = h2o_http2_stream_open(conn, H2O_HTTP2_STREAM_ID_PHANTOM_W183, NULL, &priority);
    set_priority(conn, conn_phantom_streams->stream_phantom_w183, &priority, 0);
    
    conn_phantom_streams->stream_phantom_w147 = h2o_http2_stream_open(conn, H2O_HTTP2_STREAM_ID_PHANTOM_W147, NULL, &priority);
    set_priority(conn, conn_phantom_streams->stream_phantom_w147, &priority, 0);

    conn_phantom_streams->conn = conn;
    conn_phantom_streams->conns = (h2o_linklist_t){ NULL };

    h2o_linklist_insert(&h2o_http2_conns_phantom_streams.conns, &conn_phantom_streams->conns);

    h2o_write_log_conditional("=== New phantom streams record count = %u.\n", h2o_http2_conn_phantom_streams_num_records());
}

/**
 * Unregisters the <tt>h2o_http2_conn_phantom_streams_t</tt> record that 
 * is associated with the specified HTTP/2 connection from the 
 * <tt>h2o_http2_conns_phantom_streams</tt> repository, hereby optionally 
 * freeing the idle/phantom HTTP/2 streams that it encompasses
 *
 * @param close_phantom_streams controls whether the involved idle/phantom 
 *                              HTTP/2 streams must be closed and destroyed.
 * @return 1 on success, 0 on failure.
 */
int h2o_http2_conn_phantom_streams_dispose(const h2o_http2_conn_t *conn, const size_t close_phantom_streams)
{
    static char remote_addr[NI_MAXHOST];
    static int32_t remote_port;

    get_remote_addr_and_port(conn, remote_addr, &remote_port);

    h2o_http2_conn_phantom_streams_init_datastructure();

    h2o_write_log_conditional("=== Deleting idle/phantom streams for HTTP/2 connection %s:%i ...\n", remote_addr, remote_port);

    if (h2o_linklist_is_empty(&h2o_http2_conns_phantom_streams.conns))
        return 0;

    h2o_linklist_t *node = &h2o_http2_conns_phantom_streams.conns;
    h2o_http2_conn_phantom_streams_t *conn_phantom_streams = NULL;

    while ((h2o_linklist_is_linked(node)) && (node->next != &h2o_http2_conns_phantom_streams.conns)) {
        conn_phantom_streams = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_phantom_streams_t, conns, node->next);

        if (conn_phantom_streams->conn == conn) {
            if (close_phantom_streams >= 1) {
                h2o_http2_stream_close_internal(conn_phantom_streams->conn, conn_phantom_streams->stream_phantom_serial);
                h2o_http2_stream_close_internal(conn_phantom_streams->conn, conn_phantom_streams->stream_phantom_w183);
                h2o_http2_stream_close_internal(conn_phantom_streams->conn, conn_phantom_streams->stream_phantom_w147);
            }

            h2o_linklist_unlink(node->next);
            free(conn_phantom_streams);

            return 1;
        }

        node = node->next;
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////


static int is_idle_stream_id(h2o_http2_conn_t *conn, uint32_t stream_id)
{
    return (h2o_http2_stream_is_push(stream_id) ? conn->push_stream_ids.max_open : conn->pull_stream_ids.max_open) < stream_id;
}

static void enqueue_goaway(h2o_http2_conn_t *conn, int errnum, h2o_iovec_t additional_data)
{
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        /* http2 spec allows sending GOAWAY more than once (for one reason since errors may arise after sending the first one) */
        h2o_http2_encode_goaway_frame(&conn->_write.buf, conn->pull_stream_ids.max_open, errnum, additional_data);
        h2o_http2_conn_request_write(conn);
        conn->state = H2O_HTTP2_CONN_STATE_HALF_CLOSED;
    }
}

static void graceful_shutdown_resend_goaway(h2o_timeout_entry_t *entry)
{
    h2o_context_t *ctx = H2O_STRUCT_FROM_MEMBER(h2o_context_t, http2._graceful_shutdown_timeout, entry);
    h2o_linklist_t *node;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        if (conn->state < H2O_HTTP2_CONN_STATE_HALF_CLOSED)
            enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, (h2o_iovec_t){NULL});
    }
}

static void initiate_graceful_shutdown(h2o_context_t *ctx)
{
    /* draft-16 6.8
     * A server that is attempting to gracefully shut down a connection SHOULD send an initial GOAWAY frame with the last stream
     * identifier set to 231-1 and a NO_ERROR code. This signals to the client that a shutdown is imminent and that no further
     * requests can be initiated. After waiting at least one round trip time, the server can send another GOAWAY frame with an
     * updated last stream identifier. This ensures that a connection can be cleanly shut down without losing requests.
     */
    h2o_linklist_t *node;

    /* only doit once */
    if (ctx->http2._graceful_shutdown_timeout.cb != NULL)
        return;
    ctx->http2._graceful_shutdown_timeout.cb = graceful_shutdown_resend_goaway;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        if (conn->state < H2O_HTTP2_CONN_STATE_HALF_CLOSED) {
            h2o_http2_encode_goaway_frame(&conn->_write.buf, INT32_MAX, H2O_HTTP2_ERROR_NONE,
                                          (h2o_iovec_t){H2O_STRLIT("graceful shutdown")});
            h2o_http2_conn_request_write(conn);
        }
    }
    h2o_timeout_link(ctx->loop, &ctx->one_sec_timeout, &ctx->http2._graceful_shutdown_timeout);
}

static void on_idle_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _timeout_entry, entry);

    enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, h2o_iovec_init(H2O_STRLIT("idle timeout")));
    close_connection(conn);
}

static void update_idle_timeout(h2o_http2_conn_t *conn)
{
    h2o_timeout_unlink(&conn->_timeout_entry);

    if (conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed == 0) {
        assert(h2o_linklist_is_empty(&conn->_pending_reqs));
        conn->_timeout_entry.cb = on_idle_timeout;
        h2o_timeout_link(conn->super.ctx->loop, &conn->super.ctx->http2.idle_timeout, &conn->_timeout_entry);
    }
}

static int can_run_requests(h2o_http2_conn_t *conn)
{
    return conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed <
           conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection;
}

static void run_pending_requests(h2o_http2_conn_t *conn)
{
    while (!h2o_linklist_is_empty(&conn->_pending_reqs) && can_run_requests(conn)) {
        /* fetch and detach a pending stream */
        h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.link, conn->_pending_reqs.next);
        h2o_linklist_unlink(&stream->_refs.link);
        /* handle it */
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_SEND_HEADERS);
        if (!h2o_http2_stream_is_push(stream->stream_id) && conn->pull_stream_ids.max_processed < stream->stream_id)
            conn->pull_stream_ids.max_processed = stream->stream_id;
        h2o_process_request(&stream->req);
    }
}

static void execute_or_enqueue_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(stream->state < H2O_HTTP2_STREAM_STATE_REQ_PENDING);

    if (stream->_req_body != NULL && stream->_expected_content_length != SIZE_MAX &&
        stream->_req_body->size != stream->_expected_content_length) {
        stream_send_error(conn, stream->stream_id, H2O_HTTP2_ERROR_PROTOCOL);
        h2o_http2_stream_reset(conn, stream);
        return;
    }

    h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_REQ_PENDING);

    /* TODO schedule the pending reqs using the scheduler */
    h2o_linklist_insert(&conn->_pending_reqs, &stream->_refs.link);

    run_pending_requests(conn);
    update_idle_timeout(conn);
}

void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter;
    int r;

    iter = kh_put(h2o_http2_stream_t, conn->streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;
}

void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(h2o_http2_stream_t, conn->streams, iter);

    assert(h2o_http2_scheduler_is_open(&stream->_refs.scheduler));
    h2o_http2_scheduler_close(&stream->_refs.scheduler);

    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_IDLE:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        assert(!h2o_linklist_is_linked(&stream->_refs.link));
        break;
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        assert(h2o_linklist_is_linked(&stream->_refs.link));
        h2o_linklist_unlink(&stream->_refs.link);
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        if (h2o_linklist_is_linked(&stream->_refs.link))
            h2o_linklist_unlink(&stream->_refs.link);
        break;
    }
    if (stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM)
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_END_STREAM);

    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        run_pending_requests(conn);
        update_idle_timeout(conn);
    }
}

static void close_connection_now(h2o_http2_conn_t *conn)
{
    h2o_http2_stream_t *stream;

    assert(!h2o_timeout_is_linked(&conn->_write.timeout_entry));

    // Dispose of the data structure holding the idle/phantom streams for 
    // the HTTP/2 connection that is being torn down, without closing 
    // the idle/phantom streams themselves; this will happen in the 
    // kh_foreach_value instruction below
    h2o_http2_conn_phantom_streams_dispose(conn, 0);

    kh_foreach_value(conn->streams, stream, { h2o_http2_stream_close(conn, stream); });
    assert(conn->num_streams.pull.open == 0);
    assert(conn->num_streams.pull.half_closed == 0);
    assert(conn->num_streams.pull.send_body == 0);
    assert(conn->num_streams.push.half_closed == 0);
    assert(conn->num_streams.push.send_body == 0);
    assert(conn->num_streams.priority.open == 0);
    kh_destroy(h2o_http2_stream_t, conn->streams);
    assert(conn->_http1_req_input == NULL);
    h2o_hpack_dispose_header_table(&conn->_input_header_table);
    h2o_hpack_dispose_header_table(&conn->_output_header_table);
    assert(h2o_linklist_is_empty(&conn->_pending_reqs));
    h2o_timeout_unlink(&conn->_timeout_entry);
    h2o_buffer_dispose(&conn->_write.buf);
    if (conn->_write.buf_in_flight != NULL)
        h2o_buffer_dispose(&conn->_write.buf_in_flight);
    h2o_http2_scheduler_dispose(&conn->scheduler);
    assert(h2o_linklist_is_empty(&conn->_write.streams_to_proceed));
    assert(!h2o_timeout_is_linked(&conn->_write.timeout_entry));
    if (conn->_headers_unparsed != NULL)
        h2o_buffer_dispose(&conn->_headers_unparsed);
    if (conn->push_memo != NULL)
        h2o_cache_destroy(conn->push_memo);
    if (conn->casper != NULL)
        h2o_http2_casper_destroy(conn->casper);
    h2o_linklist_unlink(&conn->_conns);

    if (conn->sock != NULL)
        h2o_socket_close(conn->sock);
    free(conn);
}

int close_connection(h2o_http2_conn_t *conn)
{
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;

    if (conn->_write.buf_in_flight != NULL || h2o_timeout_is_linked(&conn->_write.timeout_entry)) {
        /* there is a pending write, let on_write_complete actually close the connection */
    } else {
        close_connection_now(conn);
        return -1;
    }
    return 0;
}

static void stream_send_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(stream_id != 0);
    assert(conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING);

    conn->super.ctx->http2.events.protocol_level_errors[-errnum]++;

    h2o_http2_encode_rst_stream_frame(&conn->_write.buf, stream_id, -errnum);
    h2o_http2_conn_request_write(conn);
}

static void request_gathered_write(h2o_http2_conn_t *conn)
{
    assert(conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING);
    if (conn->sock->_cb.write == NULL && !h2o_timeout_is_linked(&conn->_write.timeout_entry))
        h2o_timeout_link(conn->super.ctx->loop, &conn->super.ctx->zero_timeout, &conn->_write.timeout_entry);
}

static int update_stream_output_window(h2o_http2_stream_t *stream, ssize_t delta)
{
    ssize_t cur = h2o_http2_window_get_window(&stream->output_window);
    
    h2o_write_log_conditional("Updating the WINDOW_SIZE of stream %u from %zd to %zd.\n", stream->stream_id, cur, (cur + delta));
    
    if (h2o_http2_window_update(&stream->output_window, delta) != 0)
        return -1;
    if (cur <= 0 && h2o_http2_window_get_window(&stream->output_window) > 0 &&
        (h2o_http2_stream_has_pending_data(stream) || stream->state >= H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL)) {
        assert(!h2o_linklist_is_linked(&stream->_refs.link));
        h2o_http2_scheduler_activate(&stream->_refs.scheduler);
    }
    return 0;
}

static int handle_incoming_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    int ret, header_exists_map;

    printf("connection.c:handle_incoming_request start\n");

    assert(stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS);

    header_exists_map = 0;
    if ((ret = h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, src, len, &header_exists_map,
                                       &stream->_expected_content_length, &stream->cache_digests, err_desc)) != 0) {
        if (ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR) {
            /* fast forward the stream's state so that we can start sending the response */
            h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_REQ_PENDING);
            h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_SEND_HEADERS);
            h2o_send_error_400(&stream->req, "Invalid Headers", *err_desc, 0);
            return 0;
        }
        return ret;
    }

#define EXPECTED_MAP                                                                                                               \
    (H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS | H2O_HPACK_PARSE_HEADERS_PATH_EXISTS | H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS)
    if ((header_exists_map & EXPECTED_MAP) != EXPECTED_MAP) {
        ret = H2O_HTTP2_ERROR_PROTOCOL;
        goto SendRSTStream;
    }
#undef EXPECTED_MAP

    /* handle the request */
    if (conn->num_streams.pull.open > H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams) {
        ret = H2O_HTTP2_ERROR_REFUSED_STREAM;
        goto SendRSTStream;
    }

    if (stream->_req_body == NULL) {
        execute_or_enqueue_request(conn, stream);
    } else {
        h2o_http2_stream_set_state(conn, stream, H2O_HTTP2_STREAM_STATE_RECV_BODY);
    }
    return 0;

SendRSTStream:
    stream_send_error(conn, stream->stream_id, ret);
    h2o_http2_stream_reset(conn, stream);
    return 0;
}

static int handle_trailing_headers(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    size_t dummy_content_length;
    int ret;

    assert(stream->state == H2O_HTTP2_STREAM_STATE_RECV_BODY);

    if ((ret = h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, src, len, NULL, &dummy_content_length, NULL,
                                       err_desc)) != 0)
        return ret;

    execute_or_enqueue_request(conn, stream);
    return 0;
}

static ssize_t expect_continuation_of_headers(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    h2o_http2_stream_t *stream;
    int hret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST, err_desc)) < 0)
        return ret;
    if (frame.type != H2O_HTTP2_FRAME_TYPE_CONTINUATION) {
        *err_desc = "expected CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    if ((stream = h2o_http2_conn_get_stream(conn, frame.stream_id)) == NULL ||
        !(stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS || stream->state == H2O_HTTP2_STREAM_STATE_RECV_BODY)) {
        *err_desc = "unexpected stream id in CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    h2o_buffer_reserve(&conn->_headers_unparsed, frame.length);
    memcpy(conn->_headers_unparsed->bytes + conn->_headers_unparsed->size, frame.payload, frame.length);
    conn->_headers_unparsed->size += frame.length;

    if (conn->_headers_unparsed->size <= H2O_MAX_REQLEN) {
        if ((frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
            conn->_read_expect = expect_default;
            if (stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS) {
                hret = handle_incoming_request(conn, stream, (const uint8_t *)conn->_headers_unparsed->bytes,
                                               conn->_headers_unparsed->size, err_desc);
            } else {
                hret = handle_trailing_headers(conn, stream, (const uint8_t *)conn->_headers_unparsed->bytes,
                                               conn->_headers_unparsed->size, err_desc);
            }
            if (hret != 0)
                ret = hret;
            h2o_buffer_dispose(&conn->_headers_unparsed);
            conn->_headers_unparsed = NULL;
        }
    } else {
        /* request is too large (TODO log) */
        stream_send_error(conn, stream->stream_id, H2O_HTTP2_ERROR_REFUSED_STREAM);
        h2o_http2_stream_reset(conn, stream);
    }

    return ret;
}

static void update_input_window(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_http2_window_t *window, size_t consumed)
{
    h2o_http2_window_consume_window(window, consumed);
    if (h2o_http2_window_get_window(window) * 2 < H2O_HTTP2_SETTINGS_HOST.initial_window_size) {
        int32_t delta = (int32_t)(H2O_HTTP2_SETTINGS_HOST.initial_window_size - h2o_http2_window_get_window(window));
        h2o_http2_encode_window_update_frame(&conn->_write.buf, stream_id, delta);
        h2o_http2_conn_request_write(conn);
        h2o_http2_window_update(window, delta);
    }
}

static void set_priority(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const h2o_http2_priority_t *priority,
                         int scheduler_is_open)
{
    h2o_write_log_conditional("HTTP/2 prioritization: SID %u: " "%s" "exclusively depends on SID %u with weight %" PRIu16 "\n", stream->stream_id, (priority->exclusive ? "" : "non-"), priority->dependency, priority->weight);

    h2o_http2_scheduler_node_t *parent_sched;

    /* determine the parent */
    if (priority->dependency != 0) {
        h2o_http2_stream_t *parent_stream = h2o_http2_conn_get_stream(conn, priority->dependency);
        if (parent_stream != NULL) {
            parent_sched = &parent_stream->_refs.scheduler.node;
        } else {
            /* A dependency on a stream that is not currently in the tree - such as a stream in the "idle" state - results in that
             * stream being given a default priority. (RFC 7540 5.3.1)
             * It is possible for a stream to become closed while prioritization information that creates a dependency on that
             * stream is in transit. If a stream identified in a dependency has no associated priority information, then the
             * dependent stream is instead assigned a default priority. (RFC 7540 5.3.4)
             */
            parent_sched = &conn->scheduler;
            priority = &h2o_http2_default_priority;

            fprintf(stderr, "HTTP/2 prioritization: SID %u specifies a dependency on a non-existing SID; falling back to the default H2 priority ...\n", stream->stream_id);
        }
    } else {
        parent_sched = &conn->scheduler;
    }

//    h2o_write_log_conditional("Setting WEIGHT of stream %u to %" PRIu16 "\n", stream->stream_id, h2o_http2_scheduler_get_weight(&stream->_refs.scheduler));
    
    /* setup the scheduler */
    if (!scheduler_is_open) {
        h2o_http2_scheduler_open(&stream->_refs.scheduler, parent_sched, priority->weight, priority->exclusive);
    } else {
        h2o_http2_scheduler_rebind(&stream->_refs.scheduler, parent_sched, priority->weight, priority->exclusive);
    }

    h2o_write_log_conditional("set_priority: conn->scheduler._all_refs linked list H2 SIDs:\n");
    if (H2O_LOG_WORDY == 1)
        print_h2_dep_graph(conn);
}

static int handle_data_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_data_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_data_payload(&payload, frame, err_desc)) != 0)
        return ret;

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);

    /* save the input in the request body buffer, or send error (and close the stream) */
    if (stream == NULL) {
        if (frame->stream_id <= conn->pull_stream_ids.max_open) {
            stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        } else {
            *err_desc = "invalid DATA frame";
            return H2O_HTTP2_ERROR_PROTOCOL;
        }
    } else if (stream->state != H2O_HTTP2_STREAM_STATE_RECV_BODY) {
        stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        h2o_http2_stream_reset(conn, stream);
        stream = NULL;
    } else if (stream->_req_body->size + payload.length > conn->super.ctx->globalconf->max_request_entity_size) {
        stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_REFUSED_STREAM);
        h2o_http2_stream_reset(conn, stream);
        stream = NULL;
    } else {
        h2o_iovec_t buf = h2o_buffer_reserve(&stream->_req_body, payload.length);
        if (buf.base != NULL) {
            memcpy(buf.base, payload.data, payload.length);
            stream->_req_body->size += payload.length;
            /* handle request if request body is complete */
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) != 0) {
                stream->req.entity = h2o_iovec_init(stream->_req_body->bytes, stream->_req_body->size);
                execute_or_enqueue_request(conn, stream);
                stream = NULL; /* no need to send window update for this stream */
            }
        } else {
            /* memory allocation failed */
            stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
            h2o_http2_stream_reset(conn, stream);
            stream = NULL;
        }
    }

    /* consume buffer (and set window_update) */
    update_input_window(conn, 0, &conn->_input_window, frame->length);
    if (stream != NULL)
        update_input_window(conn, stream->stream_id, &stream->input_window, frame->length);

    return 0;
}
// Read a frame from a specific connection and get the associated stream from it.
// This function is of interest because this is where we can get the request url
static int handle_headers_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_headers_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;
    printf("connection.c:int handle_headers_frame start\n");
    printf("Received a frame\n");
    /* decode */
    if ((ret = h2o_http2_decode_headers_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if ((frame->stream_id & 1) == 0) {
        *err_desc = "invalid stream id in HEADERS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }
    if (!(conn->pull_stream_ids.max_open < frame->stream_id)) {
        if ((stream = h2o_http2_conn_get_stream(conn, frame->stream_id)) != NULL &&
            stream->state == H2O_HTTP2_STREAM_STATE_RECV_BODY) {
            /* is a trailer */
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0) {
                *err_desc = "trailing HEADERS frame MUST have END_STREAM flag set";
                return H2O_HTTP2_ERROR_PROTOCOL;
            }
            stream->req.entity = h2o_iovec_init(stream->_req_body->bytes, stream->_req_body->size);
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) == 0)
                goto PREPARE_FOR_CONTINUATION;
            return handle_trailing_headers(conn, stream, payload.headers, payload.headers_len, err_desc);
        } else if (!stream || stream->state != H2O_HTTP2_STREAM_STATE_IDLE) {
            /* it's legit that stream exists and is IDLE if a PRIORITY frame was received earlier */
            *err_desc = "invalid stream id in HEADERS frame";
            return H2O_HTTP2_ERROR_STREAM_CLOSED;
        }
    }
    // At this point we want to build the browsers default tree to see what that is like.
    // So let's log that information. We can then change it to print the tree.
    custom_print_req(frame->stream_id, &payload.priority);
    custom_print_incoming_request(frame->stream_id, &payload.priority);

    if (SCHED_MODE_H2_PRIO_AWARE() && (frame->stream_id == payload.priority.dependency)) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    // Implement the installed priority-agnostic scheduling strategy by 
    // adequately modifying the payload.priority struct
    if (SCHED_MODE_H2_PRIO_UNAWARE()) {
        if (h2o_http2_update_headersframe_priority(conn, &payload, H2O_SCHEDULING_MODE) == -1) {
            *err_desc = "could not update priority directives in HEADERS frame (cf. SCHED_MODE_H2_PRIO_UNAWARE mode)";
            return H2O_HTTP2_ERROR_INTERNAL;
        }
    }

    // Introduce some parallelism in Chrome's HTTP/2 prioritization 
    // strategy or, conversely, some serialization in Firefox's HTTP/2 
    // prioritization strategy
    if (h2o_http2_update_priority_parallelism_serialization(conn, &payload.priority, H2O_USERAGENT_EXPECTED) == -1) {
        *err_desc = "could not update priority directives in HEADERS frame (cf. parallelism/serialization mode)";
        return H2O_HTTP2_ERROR_INTERNAL;
    }

    /* open or determine the stream and prepare */
    if ((stream = h2o_http2_conn_get_stream(conn, frame->stream_id)) != NULL) {
        // Do NOT allow the user agent to install an (updated) priority 
        // for a previously opened H2 stream in case H2O has been 
        // configured to apply priority-agnostic scheduling
        if (SCHED_MODE_H2_PRIO_AWARE() && ((frame->flags & H2O_HTTP2_FRAME_FLAG_PRIORITY) != 0)) {
            set_priority(conn, stream, &payload.priority, 1);
            stream->received_priority = payload.priority;
        }
    } else {
        stream = h2o_http2_stream_open(conn, frame->stream_id, NULL, &payload.priority);
        set_priority(conn, stream, &payload.priority, 0);
    }

    // Appropriately update the weight value of the W183 phantom node (i.e., 
    // switch between a 1 and 256 weight value depending on whether the 
    // transfer of one or more higher-priority assets is ongoing)
    // NOTE: This action must be postponed up to this point in the code, as 
    //       it requires the HTTP/2 stream to which this HEADERS frame 
    //       applies to exist.
    h2o_http2_update_weight_parallelism_serialization(conn);

    h2o_http2_stream_prepare_for_request(conn, stream);

    /* setup container for request body if it is expected to arrive */
    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0)
        h2o_buffer_init(&stream->_req_body, &h2o_socket_buffer_prototype);

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
        /* request is complete, handle it */
        int res = handle_incoming_request(conn, stream, payload.headers, payload.headers_len, err_desc);

        if (res == 0) {
            static char remote_addr[NI_MAXHOST];
            static int32_t remote_port;

            get_remote_addr_and_port(conn, remote_addr, &remote_port);

            h2o_write_log_conditional("Initiating HTTP/2 stream with ID %u for URL %s (connection %s:%i)\n", stream->stream_id, stream->req.input.path.base, remote_addr, remote_port);
            printf("*****====={'stream_id':%u, 'url': %s}\n", stream->stream_id, stream->req.input.path.base);
        }
	return res;
    }

PREPARE_FOR_CONTINUATION:
    /* request is not complete, store in buffer */
    conn->_read_expect = expect_continuation_of_headers;
    h2o_buffer_init(&conn->_headers_unparsed, &h2o_socket_buffer_prototype);
    h2o_buffer_reserve(&conn->_headers_unparsed, payload.headers_len);
    memcpy(conn->_headers_unparsed->bytes, payload.headers, payload.headers_len);
    conn->_headers_unparsed->size = payload.headers_len;
    return 0;
}

static int handle_priority_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    // Ignore H2 PRIORITY frames when doing priority-agnostic scheduling
    if (SCHED_MODE_H2_PRIO_UNAWARE())
        return 0;

    h2o_http2_priority_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_priority_payload(&payload, frame, err_desc)) != 0)
        return ret;
    printf("Received a pritofy frame \n");
    custom_print_incoming_request(frame->stream_id, &payload);
    if (frame->stream_id == payload.dependency) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    // Introduce some parallelism in Chrome's HTTP/2 prioritization 
    // strategy or, conversely, some serialization in Firefox's HTTP/2 
    // prioritization strategy
    if (h2o_http2_update_priority_parallelism_serialization(conn, &payload, H2O_USERAGENT_EXPECTED) == -1) {
        *err_desc = "could not update priority directives in PRIORITY frame (cf. parallelism/serialization mode)";
        return H2O_HTTP2_ERROR_INTERNAL;
    }

    if ((stream = h2o_http2_conn_get_stream(conn, frame->stream_id)) != NULL) {
        stream->received_priority = payload;
        /* ignore priority changes to pushed streams with weight=257, since that is where we are trying to be smarter than the web
         * browsers
         */
        if (h2o_http2_scheduler_get_weight(&stream->_refs.scheduler) != 257)
            set_priority(conn, stream, &payload, 1);
        else
            h2o_write_log_conditional("Ignoring PRIORITY frame for PUSH stream %u\n", stream->stream_id);
    } else {
        if (h2o_http2_stream_is_push(frame->stream_id)) {
            /* Ignore PRIORITY frames for closed or idle pushed streams */
            return 0;
        } else {
            /* Ignore PRIORITY frames for closed pull streams */
            if (frame->stream_id <= conn->pull_stream_ids.max_open)
                return 0;
        }
        if (conn->num_streams.priority.open >= conn->super.ctx->globalconf->http2.max_streams_for_priority) {
            *err_desc = "too many streams in idle/closed state";
            /* RFC 7540 10.5: An endpoint MAY treat activity that is suspicious as a connection error (Section 5.4.1) of type
             * ENHANCE_YOUR_CALM.
             */
            return H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM;
        }
        stream = h2o_http2_stream_open(conn, frame->stream_id, NULL, &payload);
        set_priority(conn, stream, &payload, 0);
    }

    // Appropriately update the weight value of the W183 phantom node (i.e., 
    // switch between a 1 and 256 weight value depending on whether the 
    // transfer of one or more higher-priority assets is ongoing)
    // NOTE: This action must be postponed up to this point in the code, as 
    //       it requires the HTTP/2 stream to which this PRIORITY frame 
    //       applies to exist.
    h2o_http2_update_weight_parallelism_serialization(conn);

    return 0;
}

static void resume_send(h2o_http2_conn_t *conn)
{
    if (h2o_http2_conn_get_buffer_window(conn) <= 0)
        return;
#if 0 /* TODO reenable this check for performance? */
    if (conn->scheduler.list.size == 0)
        return;
#endif
    request_gathered_write(conn);
}

static int handle_settings_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    if (frame->stream_id != 0) {
        *err_desc = "invalid stream id in SETTINGS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0) {
            *err_desc = "invalid SETTINGS frame (+ACK)";
            return H2O_HTTP2_ERROR_FRAME_SIZE;
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        /* FIXME handle SETTINGS_HEADER_TABLE_SIZE */
        int ret = h2o_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length, err_desc);
        if (ret != 0)
            return ret;
        { /* schedule ack */
            h2o_iovec_t header_buf = h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE);
            h2o_http2_encode_frame_header((void *)header_buf.base, 0, H2O_HTTP2_FRAME_TYPE_SETTINGS, H2O_HTTP2_FRAME_FLAG_ACK, 0);
            conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE;
            h2o_http2_conn_request_write(conn);
        }
        /* apply the change to window size (to all the streams but not the connection, see 6.9.2 of draft-15) */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            h2o_http2_stream_t *stream;
            kh_foreach_value(conn->streams, stream, { update_stream_output_window(stream, delta); });
            resume_send(conn);
        }
    }

    return 0;
}

static int handle_window_update_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_window_update_payload_t payload;
    int ret, err_is_stream_level;

    if ((ret = h2o_http2_decode_window_update_payload(&payload, frame, err_desc, &err_is_stream_level)) != 0) {
        if (err_is_stream_level) {
            h2o_http2_stream_t *stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
            if (stream != NULL)
                h2o_http2_stream_reset(conn, stream);
            stream_send_error(conn, frame->stream_id, ret);
            return 0;
        } else {
            return ret;
        }
    }

    if (frame->stream_id == 0) {
        size_t winSizeOrig = conn->_write.window._avail;

        if (h2o_http2_window_update(&conn->_write.window, payload.window_size_increment) != 0) {
            *err_desc = "flow control window overflow";
            return H2O_HTTP2_ERROR_FLOW_CONTROL;
        }
        else {
            h2o_write_log_conditional("Updating the WINDOW_SIZE of the HTTP2 TCP connection from %zd to %zd.\n", winSizeOrig, (winSizeOrig + payload.window_size_increment));
        }
    } else if (!is_idle_stream_id(conn, frame->stream_id)) {
        h2o_http2_stream_t *stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            if (update_stream_output_window(stream, payload.window_size_increment) != 0) {
                h2o_http2_stream_reset(conn, stream);
                stream_send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_FLOW_CONTROL);
                return 0;
            }
        }
    } else {
        *err_desc = "invalid stream id in WINDOW_UPDATE frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    resume_send(conn);

    return 0;
}

static int handle_goaway_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_goaway_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_goaway_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* nothing to do, since we do not open new streams by ourselves */
    return 0;
}

static int handle_ping_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_ping_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_ping_payload(&payload, frame, err_desc)) != 0)
        return ret;

    h2o_http2_encode_ping_frame(&conn->_write.buf, 1, payload.data);
    h2o_http2_conn_request_write(conn);

    return 0;
}

static int handle_rst_stream_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_rst_stream_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_rst_stream_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (is_idle_stream_id(conn, frame->stream_id)) {
        *err_desc = "unexpected stream id in RST_STREAM frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        h2o_http2_stream_reset(conn, stream);
    }
    /* TODO log */

    return 0;
}

static int handle_push_promise_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received PUSH_PROMISE frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

static int handle_invalid_continuation_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received invalid CONTINUATION frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    static int (*FRAME_HANDLERS[])(h2o_http2_conn_t * conn, h2o_http2_frame_t * frame, const char **err_desc) = {
        handle_data_frame,                /* DATA */
        handle_headers_frame,             /* HEADERS */
        handle_priority_frame,            /* PRIORITY */
        handle_rst_stream_frame,          /* RST_STREAM */
        handle_settings_frame,            /* SETTINGS */
        handle_push_promise_frame,        /* PUSH_PROMISE */
        handle_ping_frame,                /* PING */
        handle_goaway_frame,              /* GOAWAY */
        handle_window_update_frame,       /* WINDOW_UPDATE */
        handle_invalid_continuation_frame /* CONTINUATION */
    };

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST, err_desc)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        int hret = FRAME_HANDLERS[frame.type](conn, &frame, err_desc);
        if (hret != 0)
            ret = hret;
    } else {
        fprintf(stderr, "skipping frame (type:%d)\n", frame.type);
    }

    return ret;
}

static ssize_t expect_preface(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    if (len < CONNECTION_PREFACE.len) {
        return H2O_HTTP2_ERROR_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;
    }

    { /* send SETTINGS */
        h2o_iovec_t vec = h2o_buffer_reserve(&conn->_write.buf, SETTINGS_HOST_BIN.len);
        memcpy(vec.base, SETTINGS_HOST_BIN.base, SETTINGS_HOST_BIN.len);
        conn->_write.buf->size += SETTINGS_HOST_BIN.len;
        h2o_http2_conn_request_write(conn);
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static int parse_input(h2o_http2_conn_t *conn)
{
    /* handle the input */
    while (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING && conn->sock->input->size != 0) {
        /* process a frame */
        const char *err_desc = NULL;
        ssize_t ret = conn->_read_expect(conn, (uint8_t *)conn->sock->input->bytes, conn->sock->input->size, &err_desc);
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            if (ret != H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY) {
                enqueue_goaway(conn, (int)ret,
                               err_desc != NULL ? (h2o_iovec_t){(char *)err_desc, strlen(err_desc)} : (h2o_iovec_t){NULL});
            }
            return close_connection(conn);
        }
        /* advance to the next frame */
        h2o_buffer_consume(&conn->sock->input, ret);
    }
    return 0;
}

static void on_read(h2o_socket_t *sock, const char *err)
{
    h2o_http2_conn_t *conn = sock->data;

    if (err != NULL) {
        conn->super.ctx->http2.events.read_closed++;
        h2o_socket_read_stop(conn->sock);
        close_connection(conn);
        return;
    }

    update_idle_timeout(conn);
    if (parse_input(conn) != 0)
        return;

    /* write immediately, if there is no write in flight and if pending write exists */
    if (h2o_timeout_is_linked(&conn->_write.timeout_entry)) {
        h2o_timeout_unlink(&conn->_write.timeout_entry);
        do_emit_writereq(conn);
    }
}

static void on_upgrade_complete(void *_conn, h2o_socket_t *sock, size_t reqsize)
{
    h2o_http2_conn_t *conn = _conn;

    if (sock == NULL) {
        close_connection(conn);
        return;
    }

    conn->sock = sock;
    sock->data = conn;
    conn->_http1_req_input = sock->input;
    h2o_buffer_init(&sock->input, &h2o_socket_buffer_prototype);

    /* setup inbound */
    h2o_socket_read_start(conn->sock, on_read);

    /* handle the request */
    execute_or_enqueue_request(conn, h2o_http2_conn_get_stream(conn, 1));

    if (conn->_http1_req_input->size > reqsize) {
        size_t remaining_bytes = conn->_http1_req_input->size - reqsize;
        h2o_buffer_reserve(&sock->input, remaining_bytes);
        memcpy(sock->input->bytes, conn->_http1_req_input->bytes + reqsize, remaining_bytes);
        sock->input->size += remaining_bytes;
        on_read(conn->sock, NULL);
    }
}

void h2o_http2_conn_request_write(h2o_http2_conn_t *conn)
{
    if (conn->state == H2O_HTTP2_CONN_STATE_IS_CLOSING)
        return;
    request_gathered_write(conn);
}

void h2o_http2_conn_register_for_proceed_callback(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_http2_conn_request_write(conn);

    if (h2o_http2_stream_has_pending_data(stream) || stream->state >= H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL) {
        if (h2o_http2_window_get_window(&stream->output_window) > 0) {
            assert(!h2o_linklist_is_linked(&stream->_refs.link));
            h2o_http2_scheduler_activate(&stream->_refs.scheduler);
        }
    } else {
        h2o_linklist_insert(&conn->_write.streams_to_proceed, &stream->_refs.link);
    }
}

static void on_notify_write(h2o_socket_t *sock, const char *err)
{
    h2o_http2_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection_now(conn);
        return;
    }
    do_emit_writereq(conn);
}

static void on_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_http2_conn_t *conn = sock->data;

    assert(conn->_write.buf_in_flight != NULL);

    /* close by error if necessary */
    if (err != NULL) {
        conn->super.ctx->http2.events.write_closed++;
        close_connection_now(conn);
        return;
    }

    /* reset the other memory pool */
    h2o_buffer_dispose(&conn->_write.buf_in_flight);
    assert(conn->_write.buf_in_flight == NULL);

    /* call the proceed callback of the streams that have been flushed (while unlinking them from the list) */
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        while (!h2o_linklist_is_empty(&conn->_write.streams_to_proceed)) {
            h2o_http2_stream_t *stream =
                H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.link, conn->_write.streams_to_proceed.next);
            assert(!h2o_http2_stream_has_pending_data(stream));
            h2o_linklist_unlink(&stream->_refs.link);
            h2o_http2_stream_proceed(conn, stream);
        }
    }

    /* cancel the write callback if scheduled (as the generator may have scheduled a write just before this function gets called) */
    if (h2o_timeout_is_linked(&conn->_write.timeout_entry))
        h2o_timeout_unlink(&conn->_write.timeout_entry);

#if !H2O_USE_LIBUV
    if (conn->state == H2O_HTTP2_CONN_STATE_OPEN) {
        if (conn->_write.buf->size != 0 || h2o_http2_scheduler_is_active(&conn->scheduler))
            h2o_socket_notify_write(sock, on_notify_write);
        return;
    }
#endif

    /* write more, if possible */
    do_emit_writereq(conn);
}

static int emit_writereq_of_openref(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg)
{
    h2o_http2_conn_t *conn = cb_arg;
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, ref);

    assert(h2o_http2_stream_has_pending_data(stream) || stream->state >= H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL);

    *still_is_active = 0;

    h2o_http2_stream_send_pending_data(conn, stream);
    if (h2o_http2_stream_has_pending_data(stream)) {
        if (h2o_http2_window_get_window(&stream->output_window) <= 0) {
            /* is blocked */
        } else {
            *still_is_active = 1;
        }
    } else {
        h2o_linklist_insert(&conn->_write.streams_to_proceed, &stream->_refs.link);
    }

    return h2o_http2_conn_get_buffer_window(conn) > 0 ? 0 : -1;
}

void do_emit_writereq(h2o_http2_conn_t *conn)
{
    assert(conn->_write.buf_in_flight == NULL);

    /* push DATA frames */
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING && h2o_http2_conn_get_buffer_window(conn) > 0)
        h2o_http2_scheduler_run(&conn->scheduler, emit_writereq_of_openref, conn);

    if (conn->_write.buf->size != 0) {
        /* write and wait for completion */
        h2o_iovec_t buf = {conn->_write.buf->bytes, conn->_write.buf->size};
        h2o_socket_write(conn->sock, &buf, 1, on_write_complete);
        conn->_write.buf_in_flight = conn->_write.buf;
        h2o_buffer_init(&conn->_write.buf, &wbuf_buffer_prototype);
    }

    /* close the connection if necessary */
    switch (conn->state) {
    case H2O_HTTP2_CONN_STATE_OPEN:
        break;
    case H2O_HTTP2_CONN_STATE_HALF_CLOSED:
        if (conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed != 0)
            break;
        conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;
    /* fall-thru */
    case H2O_HTTP2_CONN_STATE_IS_CLOSING:
        close_connection_now(conn);
        break;
    }
}

static void emit_writereq(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.timeout_entry, entry);

    do_emit_writereq(conn);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    h2o_http2_conn_t *conn = (void *)_conn;
    return h2o_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    h2o_http2_conn_t *conn = (void *)_conn;
    return h2o_socket_getpeername(conn->sock, sa);
}

static h2o_socket_t *get_socket(h2o_conn_t *_conn)
{
    h2o_http2_conn_t *conn = (void *)_conn;
    return conn->sock;
}

#define DEFINE_TLS_LOGGER(name)                                                                                                    \
    static h2o_iovec_t log_##name(h2o_req_t *req)                                                                                  \
    {                                                                                                                              \
        h2o_http2_conn_t *conn = (void *)req->conn;                                                                                \
        return h2o_socket_log_ssl_##name(conn->sock, &req->pool);                                                                  \
    }

DEFINE_TLS_LOGGER(protocol_version)
DEFINE_TLS_LOGGER(session_reused)
DEFINE_TLS_LOGGER(cipher)
DEFINE_TLS_LOGGER(cipher_bits)

#undef DEFINE_TLS_LOGGER

static h2o_iovec_t log_stream_id(h2o_req_t *req)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof(H2O_UINT32_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu32, stream->stream_id);
    return h2o_iovec_init(s, len);
}

static h2o_iovec_t log_priority_received(h2o_req_t *req)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof("1:" H2O_UINT32_LONGEST_STR ":" H2O_UINT16_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%c:%" PRIu32 ":%" PRIu16, stream->received_priority.exclusive ? '1' : '0',
                                 stream->received_priority.dependency, stream->received_priority.weight);
    return h2o_iovec_init(s, len);
}

static h2o_iovec_t log_priority_received_exclusive(h2o_req_t *req)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    return h2o_iovec_init(stream->received_priority.exclusive ? "1" : "0", 1);
}

static h2o_iovec_t log_priority_received_parent(h2o_req_t *req)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof(H2O_UINT32_LONGEST_STR));
    size_t len = sprintf(s, "%" PRIu32, stream->received_priority.dependency);
    return h2o_iovec_init(s, len);
}

static h2o_iovec_t log_priority_received_weight(h2o_req_t *req)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof(H2O_UINT16_LONGEST_STR));
    size_t len = sprintf(s, "%" PRIu16, stream->received_priority.weight);
    return h2o_iovec_init(s, len);
}

static uint32_t get_parent_stream_id(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_http2_scheduler_node_t *parent_sched = h2o_http2_scheduler_get_parent(&stream->_refs.scheduler);
    if (parent_sched == &conn->scheduler) {
        return 0;
    } else {
        h2o_http2_stream_t *parent_stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, parent_sched);
        return parent_stream->stream_id;
    }
}

static h2o_iovec_t log_priority_actual(h2o_req_t *req)
{
    h2o_http2_conn_t *conn = (void *)req->conn;
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof(H2O_UINT32_LONGEST_STR ":" H2O_UINT16_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu32 ":%" PRIu16, get_parent_stream_id(conn, stream),
                                 h2o_http2_scheduler_get_weight(&stream->_refs.scheduler));
    return h2o_iovec_init(s, len);
}

static h2o_iovec_t log_priority_actual_parent(h2o_req_t *req)
{
    h2o_http2_conn_t *conn = (void *)req->conn;
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof(H2O_UINT32_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu32, get_parent_stream_id(conn, stream));
    return h2o_iovec_init(s, len);
}

static h2o_iovec_t log_priority_actual_weight(h2o_req_t *req)
{
    h2o_http2_stream_t *stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, req);
    char *s = h2o_mem_alloc_pool(&stream->req.pool, sizeof(H2O_UINT16_LONGEST_STR));
    size_t len = (size_t)sprintf(s, "%" PRIu16, h2o_http2_scheduler_get_weight(&stream->_refs.scheduler));
    return h2o_iovec_init(s, len);
}

static h2o_http2_conn_t *create_conn(h2o_context_t *ctx, h2o_hostconf_t **hosts, h2o_socket_t *sock, struct timeval connected_at)
{
    static const h2o_conn_callbacks_t callbacks = {
        get_sockname,              /* stringify address */
        get_peername,              /* ditto */
        push_path,                 /* HTTP2 push */
        get_socket,                /* get underlying socket */
        h2o_http2_get_debug_state, /* get debug state */
        {{
            {log_protocol_version, log_session_reused, log_cipher, log_cipher_bits}, /* ssl */
            {NULL},                                                                  /* http1 */
            {log_stream_id, log_priority_received, log_priority_received_exclusive, log_priority_received_parent,
             log_priority_received_weight, log_priority_actual, log_priority_actual_parent, log_priority_actual_weight} /* http2 */
        }} /* loggers */
    };

    h2o_http2_conn_t *conn = (void *)h2o_create_connection(sizeof(*conn), ctx, hosts, connected_at, &callbacks);
 
    {
        static char remote_addr[NI_MAXHOST];
        static int32_t remote_port;
 
        conn->sock = sock;

        get_remote_addr_and_port(conn, remote_addr, &remote_port);
 
        h2o_write_log_conditional("Establishing a new HTTP2 connection with host %s:%i\n", remote_addr, remote_port);
    }

    memset((char *)conn + sizeof(conn->super), 0, sizeof(*conn) - sizeof(conn->super));
    conn->sock = sock;
    conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    conn->streams = kh_init(h2o_http2_stream_t);
    h2o_http2_scheduler_init(&conn->scheduler);
    conn->state = H2O_HTTP2_CONN_STATE_OPEN;
    h2o_linklist_insert(&ctx->http2._conns, &conn->_conns);
    conn->_read_expect = expect_preface;
    conn->_input_header_table.hpack_capacity = conn->_input_header_table.hpack_max_capacity =
        H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    h2o_http2_window_init(&conn->_input_window, &H2O_HTTP2_SETTINGS_DEFAULT);
    conn->_output_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_HOST.header_table_size;
    h2o_linklist_init_anchor(&conn->_pending_reqs);
    h2o_buffer_init(&conn->_write.buf, &wbuf_buffer_prototype);
    h2o_linklist_init_anchor(&conn->_write.streams_to_proceed);
    conn->_write.timeout_entry.cb = emit_writereq;
    h2o_http2_window_init(&conn->_write.window, &conn->peer_settings);

    // Initialize the idle/phantom streams for the new HTTP/2 connection 
    // that will allow us to introduce some level of parallelism in 
    // Chrome's HTTP/2 prioritization strategy or, conversely, some 
    // serialization in Firefox's HTTP/2 prioritization strategy
    h2o_http2_conn_phantom_streams_generate(conn);

    return conn;
}

static int update_push_memo(h2o_http2_conn_t *conn, h2o_req_t *src_req, const char *abspath, size_t abspath_len)
{

    if (conn->push_memo == NULL)
        conn->push_memo = h2o_cache_create(0, 1024, 1, NULL);

    /* uses the hash as the key */
    h2o_cache_hashcode_t url_hash = h2o_cache_calchash(src_req->input.scheme->name.base, src_req->input.scheme->name.len) ^
                                    h2o_cache_calchash(src_req->input.authority.base, src_req->input.authority.len) ^
                                    h2o_cache_calchash(abspath, abspath_len);
    return h2o_cache_set(conn->push_memo, 0, h2o_iovec_init(&url_hash, sizeof(url_hash)), url_hash, h2o_iovec_init(NULL, 0));
}

static void push_path(h2o_req_t *src_req, const char *abspath, size_t abspath_len)
{
    h2o_http2_conn_t *conn = (void *)src_req->conn;
    h2o_http2_stream_t *src_stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, src_req);

    /* RFC 7540 8.2.1: PUSH_PROMISE frames can be sent by the server in response to any client-initiated stream */
    if (h2o_http2_stream_is_push(src_stream->stream_id))
        return;

    if (!src_stream->req.hostconf->http2.push_preload || !conn->peer_settings.enable_push ||
        conn->num_streams.push.open >= conn->peer_settings.max_concurrent_streams)
        return;

    if (conn->push_stream_ids.max_open >= 0x7ffffff0)
        return;
    if (!(h2o_linklist_is_empty(&conn->_pending_reqs) && can_run_requests(conn)))
        return;

    if (h2o_find_header(&src_stream->req.headers, H2O_TOKEN_X_FORWARDED_FOR, -1) != -1)
        return;

    if (src_stream->cache_digests != NULL) {
        h2o_iovec_t url = h2o_concat(&src_stream->req.pool, src_stream->req.input.scheme->name, h2o_iovec_init(H2O_STRLIT("://")),
                                     src_stream->req.input.authority, h2o_iovec_init(abspath, abspath_len));
        if (h2o_cache_digests_lookup_by_url(src_stream->cache_digests, url.base, url.len) == H2O_CACHE_DIGESTS_STATE_FRESH)
            return;
    }

    /* delayed initialization of casper (cookie-based), that MAY be used together to cache-digests */
    if (src_stream->req.hostconf->http2.casper.capacity_bits != 0) {
        if (!src_stream->pull.casper_is_ready) {
            src_stream->pull.casper_is_ready = 1;
            if (conn->casper == NULL)
                h2o_http2_conn_init_casper(conn, src_stream->req.hostconf->http2.casper.capacity_bits);
            ssize_t header_index;
            for (header_index = -1;
                 (header_index = h2o_find_header(&src_stream->req.headers, H2O_TOKEN_COOKIE, header_index)) != -1;) {
                h2o_header_t *header = src_stream->req.headers.entries + header_index;
                h2o_http2_casper_consume_cookie(conn->casper, header->value.base, header->value.len);
            }
        }
    }

    /* update the push memo, and if it already pushed on the same connection, return */
    if (update_push_memo(conn, &src_stream->req, abspath, abspath_len))
        return;

    /* open the stream */
    h2o_http2_stream_t *stream = h2o_http2_stream_open(conn, conn->push_stream_ids.max_open + 2, NULL, &h2o_http2_default_priority);
    stream->received_priority.dependency = src_stream->stream_id;
    stream->push.parent_stream_id = src_stream->stream_id;
    h2o_http2_scheduler_open(&stream->_refs.scheduler, &src_stream->_refs.scheduler.node, 16, 0);
    h2o_http2_stream_prepare_for_request(conn, stream);

    /* setup request */
    stream->req.input.method = (h2o_iovec_t){H2O_STRLIT("GET")};
    stream->req.input.scheme = src_stream->req.input.scheme;
    stream->req.input.authority =
        h2o_strdup(&stream->req.pool, src_stream->req.input.authority.base, src_stream->req.input.authority.len);
    stream->req.input.path = h2o_strdup(&stream->req.pool, abspath, abspath_len);
    stream->req.version = 0x200;

    { /* copy headers that may affect the response (of a cacheable response) */
        size_t i;
        for (i = 0; i != src_stream->req.headers.size; ++i) {
            h2o_header_t *src_header = src_stream->req.headers.entries + i;
            if (h2o_iovec_is_token(src_header->name)) {
                h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, src_header->name);
                if (token->copy_for_push_request) {
                    h2o_add_header(&stream->req.pool, &stream->req.headers, token,
                                   h2o_strdup(&stream->req.pool, src_header->value.base, src_header->value.len).base,
                                   src_header->value.len);
                }
            }
        }
    }

    execute_or_enqueue_request(conn, stream);

    /* send push-promise ASAP (before the parent stream gets closed), even if execute_or_enqueue_request did not trigger the
     * invocation of send_headers */
    if (!stream->push.promise_sent && stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM)
        h2o_http2_stream_send_push_promise(conn, stream);
}

static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    h2o_linklist_t *node;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        h2o_http2_stream_t *stream;
        kh_foreach_value(conn->streams, stream, {
            int ret = cb(&stream->req, cbdata);
            if (ret != 0)
                return ret;
        });
    }
    return 0;
}

void h2o_http2_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    printf("connection.c: h2o_http2_accept start");
    h2o_http2_conn_t *conn = create_conn(ctx->ctx, ctx->hosts, sock, connected_at);
    sock->data = conn;
    h2o_socket_read_start(conn->sock, on_read);
    update_idle_timeout(conn);
    if (sock->input->size != 0)
        on_read(sock, 0);
    printf("connection.c: h2o_http2_accept end");
}

int h2o_http2_handle_upgrade(h2o_req_t *req, struct timeval connected_at)
{
    printf("connection.c: h2o_http2_handle_upgrade start");
    h2o_http2_conn_t *http2conn = create_conn(req->conn->ctx, req->conn->hosts, NULL, connected_at);
    h2o_http2_stream_t *stream;
    ssize_t connection_index, settings_index;
    h2o_iovec_t settings_decoded;
    const char *err_desc;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = h2o_find_header(&req->headers, H2O_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (!h2o_contains_token(req->headers.entries[connection_index].value.base, req->headers.entries[connection_index].value.len,
                            H2O_STRLIT("http2-settings"), ',')) {
        goto Error;
    }

    /* decode the settings */
    if ((settings_index = h2o_find_header(&req->headers, H2O_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        goto Error;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, req->headers.entries[settings_index].value.base,
                                                 req->headers.entries[settings_index].value.len))
            .base == NULL) {
        goto Error;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t *)settings_decoded.base, settings_decoded.len,
                                       &err_desc) != 0) {
        goto Error;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    stream = h2o_http2_stream_open(http2conn, 1, req, &h2o_http2_default_priority);
    h2o_http2_scheduler_open(&stream->_refs.scheduler, &http2conn->scheduler, h2o_http2_default_priority.weight, 0);
    h2o_http2_stream_prepare_for_request(http2conn, stream);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req, (h2o_iovec_t *)&SETTINGS_HOST_BIN, 1, on_upgrade_complete, http2conn);
    printf("connection.c: h2o_http2_handle_upgrade start");
    return 0;
Error:
    h2o_linklist_unlink(&http2conn->_conns);
    kh_destroy(h2o_http2_stream_t, http2conn->streams);
    free(http2conn);
    return -1;
}

/**
 * @return <tt>NULL</tt> if the HTTP/2 dependency graph currently only 
 *         consists of a root node (representing the underlying TCP 
 *         connection), or the HTTP/2 stream that is associated with the 
 *         left-most leaf in the HTTP/2 dependency graph.
 */
static const h2o_http2_stream_t* h2o_http2_scheduler_get_leaf_leftmost(const h2o_http2_conn_t *conn)
{
    const h2o_linklist_t *link = &conn->scheduler._all_refs;
    const h2o_http2_stream_t *stream = NULL;

    while (!h2o_linklist_is_empty(link)) {
        const h2o_http2_scheduler_openref_t *child_ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, link->next); // go to first child
        link = &child_ref->node._all_refs;

        stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, child_ref);
    }

    return stream;
}

/**
 * @return @a root if this HTTP/2 stream is childless in the HTTP/2 
 *         dependency graph, or the HTTP/2 stream that is associated with 
 *         the deepest (left-most) child of @a root in the HTTP/2 
 *         dependency graph.
 * NOTE: The <tt>h2o_http2_scheduler_get_leaf_leftmost</tt> and 
 *       <tt>h2o_http2_scheduler_get_deepest_child</tt> could be merged 
 *       into a single, unified function.
 */
static const h2o_http2_stream_t* h2o_http2_scheduler_get_deepest_child(const h2o_http2_stream_t *root)
{
    const h2o_linklist_t *link = &root->_refs.scheduler.node._all_refs;
    const h2o_http2_scheduler_openref_t *child_ref = NULL;

    while (!h2o_linklist_is_empty(link)) {
        child_ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, link->next); // go to first child
        link = &child_ref->node._all_refs;
    }

    return (child_ref == NULL) ? root : H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, child_ref);
}

/**
 * @return 0 in case the HTTP/2 dependency graph node that is associated 
 *         with @a root is childless, 1 otherwise.
 *
 * NOTE: The simplest implementation of this method would check whether 
 *       the specified @a root has any descendants in the H2 dep graph. 
 *       However, as we might configure H2O to postpone the cleanup of 
 *       closed HTTP/2 streams from the H2 dep graph, we need to resort 
 *       to a more elaborate implementation that also checks the state 
 *       of <a>root</a>'s descendants.
 * NOTE: This method assumes @a root to be the apex of a completely 
 *       linear branch in the H2 dep graph.
 */
inline static int h2o_http2_scheduler_has_children(const h2o_http2_stream_t *root)
{
//    return (h2o_http2_scheduler_get_deepest_child(root) != root) ? 1 : 0;

    const h2o_linklist_t *link = &root->_refs.scheduler.node._all_refs;
    const h2o_http2_scheduler_openref_t *child_ref = NULL;
    const h2o_http2_stream_t *stream = NULL;

    while (!h2o_linklist_is_empty(link)) {
        child_ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, link->next); // go to first child
        link = &child_ref->node._all_refs;

        stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, child_ref);
        if (stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM)
            return 1;
//        else
//            h2o_write_log_conditional("=== HTTP/2 stream with ID %u resides in the END_STREAM state ...\n", stream->stream_id);
    }

    return 0;
}

/**
 * @param[out] headers_payload representation of (the payload of) a HTTP/2 
 *                             HEADERS frame; the priority directives 
 *                             embedded in this frame will be updated 
 *                             so that the configured priority-agnostic 
 *                             scheduling mode (as communicated in the 
 *                             <em>sched_mode</em> argument) will be 
 *                             enforced by the H2O scheduler.
 * @return 0 on success, -1 on failure.
 */
static int h2o_http2_update_headersframe_priority(const h2o_http2_conn_t *conn, 
                                                  h2o_http2_headers_payload_t *headers_payload, 
                                                  const sched_mode_t sched_mode)
{
    if (sched_mode == SCHED_MODE_FLAG_FCFS) {
        // Apply First-Come-First-Served HTTP request servicing; this is 
        // achieved by constructing a completely linear H2 dep graph, with 
        // newly requested resources being made an (exclusive) child of the 
        // current leaf of the H2 dep graph.

        headers_payload->priority = h2o_http2_default_priority;
        headers_payload->priority.exclusive = 1;

        const h2o_http2_stream_t *stream_leaf = h2o_http2_scheduler_get_leaf_leftmost(conn);

        // Make dependent on root node if H2 dep currently is "empty", 
        // otherwise make dependent on leaf
        headers_payload->priority.dependency = (stream_leaf == NULL) ? 0 : stream_leaf->stream_id;
    } else if (sched_mode == SCHED_MODE_FLAG_RR) {
        // Apply fair Round-Robin HTTP request servicing; this is 
        // achieved by constructing a H2 dep graph where newly requested 
        // resources are made a non-exclusive child of the root node and 
        // are assigned an identical H2 weight value.
        
        // The "default" HTTP/2 priority directive consists of making the 
        // requested resource a non-exclusive child of the underlying TCP 
        // connection (i.e., the root of the H2 dep graph), with a static 
        // weight value of 16; as such, it perfectly suits RR scheduling needs
        headers_payload->priority = h2o_http2_default_priority;
    } else {
        return -1;
    }

    return 0;
}

/**
 * @param[out] priority representation of a HTTP/2 priority record (could 
 *                      originate from either a HEADERS or PRIORITY 
 *                      frame); the priority directives embedded in this 
 *                      record will be updated to introduce some level of 
 *                      parallelism in Chrome's H2 prioritization strategy 
 *                      or, conversely, to introduce some level of 
 *                      serialization in Firefox's H2 prioritization strategy.
 * @return 0 on success, -1 on failure.
 */
static int h2o_http2_update_priority_parallelism_serialization(const h2o_http2_conn_t *conn,
                                                               h2o_http2_priority_t *priority,
                                                               const useragent_id_t ua)
{
    static char remote_addr[NI_MAXHOST];
    static int32_t remote_port;
    
    get_remote_addr_and_port(conn, remote_addr, &remote_port);

    h2o_http2_conn_phantom_streams_t *conn_phantom_streams = h2o_http2_conn_phantom_streams_get(conn);

    if (conn_phantom_streams == NULL) {
        fprintf(stderr, "=== ERROR: Could not retrieve a handle to the idle/phantom streams for HTTP/2 connection %s:%i!\n", remote_addr, remote_port);
        return -1;
    }

    if (ua == UA_CHROME) {
        if (priority->weight > 183) {
            // Make high-priority resources exclusively dependent on 
            // phantom node SERIAL (i.e., preseve serial nature)
            priority->exclusive = 1;
            if (priority->dependency == 0)
                priority->dependency = conn_phantom_streams->stream_phantom_serial->stream_id;
        }
        else if (priority->weight == 183) {
            if (H2O_PARALLELIZE_SERIALIZE_ADVANCED) {
                // Make normal-priority resources (i.e., <body> JS) 
                // non-exclusively dependent on phantom node W183 to 
                // introduce an additional layer of parallelism
                priority->exclusive = 0;
                priority->dependency = conn_phantom_streams->stream_phantom_w183->stream_id;
            }
            else {
                // Preserve serial transfer of normal-priority resources
                priority->exclusive = 1;
                if (priority->dependency == 0)
                    priority->dependency = conn_phantom_streams->stream_phantom_serial->stream_id;
            }
        }
        else { // (priority-weight < 183)
            // Make low-priority resources non-exclusively dependent on 
            // phantom node W147; as such, parallelism is introduced in 
            // the delivery of resources belonging to Chrome's LOW and 
            // LOWEST priority buckets (e.g., images)
            priority->exclusive = 0;
            priority->dependency = conn_phantom_streams->stream_phantom_w147->stream_id;
        }
    }
    else if (ua == UA_FIREFOX) {
        if (priority->dependency == 0) {
            // Make Firefox's top-level phantom streams (non-exclusively) 
            // dependent on phantom node W147
            // FIXME: TODO: Will also impact pushed resources!
            priority->dependency = conn_phantom_streams->stream_phantom_w147->stream_id;
        }
        else if (((priority->dependency == 3) && (priority->weight > 22)) ||
                 ((priority->dependency == 11) && (priority->weight > 22))) {
            // Serialize the transfer of assets belonging to Firefox's 
            // "Leaders" category, and also serialize the transfer of 
            // HTML and font assets
            priority->dependency = h2o_http2_scheduler_get_deepest_child(conn_phantom_streams->stream_phantom_serial)->stream_id;
            priority->exclusive = 1;
        }

        if (H2O_PARALLELIZE_SERIALIZE_ADVANCED) {
            if ((priority->dependency == 5) && (priority->weight > 22)) {
                // Serialize the transfer of assets belonging to Firefox's 
                // "Unblocked" category (i.e., <body> JS, XHR) using 
                // phantom node W183
                priority->dependency = h2o_http2_scheduler_get_deepest_child(conn_phantom_streams->stream_phantom_w183)->stream_id;
                priority->exclusive = 1;
            }
        }
    }
    else {
        return -1;
    }

    return 0;
}

int h2o_http2_update_weight_parallelism_serialization(const h2o_http2_conn_t *conn)
{
    if (!H2O_PARALLELIZE_SERIALIZE_ADVANCED)
        return 0;

    static char remote_addr[NI_MAXHOST];
    static int32_t remote_port;
    static uint16_t weight_old;

    get_remote_addr_and_port(conn, remote_addr, &remote_port);

    h2o_http2_conn_phantom_streams_t *conn_phantom_streams = h2o_http2_conn_phantom_streams_get(conn);

    if (conn_phantom_streams == NULL) {
        fprintf(stderr, "=== ERROR: Could not retrieve a handle to the idle/phantom streams for HTTP/2 connection %s:%i!\n", remote_addr, remote_port);
        return -1;
    }

    // Appropriately update the weight value of the W183 phantom node (i.e., 
    // switch between a 1 and 256 weight value depending on whether the 
    // transfer of one or more higher-priority assets is ongoing)

    weight_old = conn_phantom_streams->stream_phantom_w183->_refs.scheduler.weight;
    conn_phantom_streams->stream_phantom_w183->_refs.scheduler.weight =
            h2o_http2_scheduler_has_children(conn_phantom_streams->stream_phantom_serial) ?
            1 : 256;
    
    // NOTE: An alternative approach to test the existence of pending 
    //       higher-priority assets could have been to verify the 
    //       scheduler._active_cnt value of phantom stream SERIAL, yet 
    //       this approach did not turn out to be feasible.

    if (H2O_LOG_WORDY && (weight_old != conn_phantom_streams->stream_phantom_w183->_refs.scheduler.weight))
        print_h2_dep_graph((h2o_http2_conn_t*) conn);

    return 0;
}

void print_h2_dep_graph(h2o_http2_conn_t *conn)
{
    printf("Printing the dependency graph \n");
    print_h2_dep_subgraph(&conn->scheduler, 0);
}

void print_h2_dep_subgraph(const h2o_http2_scheduler_node_t *scheduler, const size_t level)
{
    printf("Printing the dependency subgraph\n");
    const h2o_linklist_t *link;
    size_t i = 0;

    for (link = scheduler->_all_refs.next; link != &scheduler->_all_refs; link = link->next) {
        const h2o_http2_scheduler_openref_t *child_ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, link);
        const h2o_http2_stream_t *child_stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, child_ref);

        for (i = 0; i < level; i++)
            printf("\t");
        printf("%u (weight %u)\n", child_stream->stream_id, child_ref->weight);

        print_h2_dep_subgraph(&child_ref->node, (level + 1));
    }
}

int get_remote_addr_and_port(const h2o_http2_conn_t *conn, char *addr, int32_t *port)
{
    struct sockaddr_storage ss;
    socklen_t sslen;

    size_t remote_addr_len = SIZE_MAX;

    if ((sslen = get_peername((h2o_conn_t *)conn, (void *)&ss)) != 0) {
        remote_addr_len = h2o_socket_getnumerichost((void *)&ss, sslen, addr);
        *port = h2o_socket_getport((void *)&ss);
    }

    return (sslen != 0) ? 0 : -1;
}
