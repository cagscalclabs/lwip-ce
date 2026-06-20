#include <stdbool.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
    void *malloc(size_t size);
    void free(void *ptr);
    void *realloc(void *ptr, size_t size);
}
#define _EZCXX_STDLIB_H
extern "C"
{
#define class usb_class
#endif
#include <lwip.h>
#include <lwip/core/logging.h>
#ifdef __cplusplus
#undef class
}
#endif

#include "../../common/lwip_example.h"

#ifndef BROWSER_URL
#define BROWSER_URL "http://example.com/"
#endif

#define BROWSER_URL_MAX 128
#define BROWSER_HOST_MAX 96
#define BROWSER_PATH_MAX 160
#define BROWSER_BODY_MAX 512
#define BROWSER_RX_CHUNK 192
#define BROWSER_REQ_MAX 384
#define BROWSER_HISTORY_DEPTH 4
#define BROWSER_COLS 44
#define BROWSER_ROW_COLS 96
#define BROWSER_ELEMENT_RING 16
#define BROWSER_ELEMENT_TEXT_MAX 32
#define BROWSER_LINE_H 8
#define BROWSER_BAR_Y 0
#define BROWSER_BAR_H 12
#define BROWSER_URL_Y 2
#define BROWSER_BODY_Y 13
#define BROWSER_VISIBLE_ROWS ((LWIP_EXAMPLE_BOTTOM - BROWSER_BODY_Y) / BROWSER_LINE_H)
#define BROWSER_ROW_RING_ROWS BROWSER_VISIBLE_ROWS
#define BROWSER_ROW_STORE_MAX_BYTES 16384u
#define BROWSER_PAYLOAD_RING_MIN 1024u
#define BROWSER_RAW_CONTENT_MIN 1024u
#define BROWSER_NAME_RING_MIN 512u
#define BROWSER_RENDER_OBJECT_SLOTS 16u
#define BROWSER_OBJECT_NULL 0xFFFFu
#define BROWSER_DOM_STACK_MAX 16u
#define BROWSER_DOCUMENT_GROW 16
#define BROWSER_SOCKET_RX_MAX 8192
#define BROWSER_SOCKET_TIMEOUT_MS 60000u
#define BROWSER_NETWORK_WATCH_MS 1000u
#define BROWSER_CONNECT_WATCH_MS 1000u
#define BROWSER_CONNECT_WATCH_MAX_TICKS \
    ((BROWSER_SOCKET_TIMEOUT_MS + BROWSER_CONNECT_WATCH_MS - 1u) / \
     BROWSER_CONNECT_WATCH_MS)
#define BROWSER_CLOSE_DRAIN_TICKS 20
#define BROWSER_COLOR_URL_TEXT 0xFC
#define BROWSER_COLOR_LINK 0x03
#define BROWSER_COLOR_HEADING 0x10
#define BROWSER_COLOR_UNSUPPORTED 0xE0
#define BROWSER_STATUS_MAX 44

typedef enum
{
    BROWSER_STYLE_NORMAL = 0,
    BROWSER_STYLE_HEADING,
    BROWSER_STYLE_LINK,
    BROWSER_STYLE_UNSUPPORTED
} browser_style_t;

typedef enum
{
    BROWSER_DISPLAY_INLINE = 0,
    BROWSER_DISPLAY_BLOCK,
    BROWSER_DISPLAY_INLINE_BLOCK,
    BROWSER_DISPLAY_NONE
} browser_display_t;

typedef enum
{
    BROWSER_ELEMENT_TEXT = 0,
    BROWSER_ELEMENT_TAG,
    BROWSER_ELEMENT_BREAK
} browser_element_type_t;

typedef enum
{
    BROWSER_OBJECT_ELEMENT = 0,
    BROWSER_OBJECT_STYLE
} browser_object_kind_t;

typedef enum
{
    BROWSER_FLAG_READY = 1u << 0,
    BROWSER_FLAG_CONNECTED = 1u << 1,
    BROWSER_FLAG_ERROR = 1u << 2,
    BROWSER_FLAG_HAS_HTTP_RAW = 1u << 3
} browser_flags_t;

typedef enum
{
    BROWSER_HTML_UNKNOWN = 0,
    BROWSER_HTML_A,
    BROWSER_HTML_BODY,
    BROWSER_HTML_BR,
    BROWSER_HTML_DIV,
    BROWSER_HTML_HEAD,
    BROWSER_HTML_HTML,
    BROWSER_HTML_IMG,
    BROWSER_HTML_P,
    BROWSER_HTML_SCRIPT,
    BROWSER_HTML_STYLE,
    BROWSER_HTML_TITLE
} browser_html_tag_t;

typedef enum
{
    BROWSER_CONTENT_NONE = 0,
    BROWSER_CONTENT_STRING,
    BROWSER_CONTENT_IMAGE,
    BROWSER_CONTENT_UNSUPPORTED
} browser_content_type_t;

typedef enum
{
    BROWSER_CHUNK_SIZE = 0,
    BROWSER_CHUNK_DATA,
    BROWSER_CHUNK_DATA_CR,
    BROWSER_CHUNK_DATA_LF,
    BROWSER_CHUNK_DONE
} browser_chunk_state_t;

struct browser_style_metadata
{
    browser_display_t display;
    browser_style_t text_style;
    uint8_t color;
    uint8_t background_color;
    uint16_t width;
    uint16_t height;
};

struct browser_element
{
    uint16_t id;
    uint16_t count;
    browser_object_kind_t object_kind;
    browser_element_type_t type;
    bool styled;
    bool closing;
    bool self_closing;
    uint16_t class_name;
    uint16_t id_name;
    char tag[12];
    char text[BROWSER_ELEMENT_TEXT_MAX + 1];
    struct browser_style_metadata style;
};

struct browser_render_object
{
    uint16_t id;
    uint16_t parent;
    uint16_t first_child;
    uint16_t next_sibling;
    uint16_t last_child;
    uint16_t tag_id;
    browser_object_kind_t object_kind;
    browser_element_type_t element_type;
    bool closing;
    bool self_closing;
    browser_content_type_t content_type;
    uint32_t content_offset;
    uint16_t content_len;
    uint16_t class_name;
    uint16_t id_name;
    struct browser_style_metadata style;
};

struct browser_render_row
{
    char text[BROWSER_ROW_COLS + 1];
    uint8_t color;
};

struct browser_page
{
    struct browser_render_row *rows;
    uint16_t row_capacity;
    uint16_t row_count;
    uint16_t total_rows;
    uint8_t col;
    browser_style_t style;
    bool last_space;
    bool alloc_failed;
};

struct browser_parse_state
{
    bool skip;
    char skip_tag[8];
};

struct browser_stream_state
{
    struct browser_parse_state parse;
    char header_line[96];
    uint8_t header_line_len;
    bool headers_done;
    bool body_seen;
    bool body_done;
    bool content_length_seen;
    bool connection_close;
    bool chunked;
    bool chunk_size_ext;
    bool unsupported_encoding;
    size_t content_length;
    size_t body_bytes;
    size_t chunk_size;
    size_t chunk_remaining;
    browser_chunk_state_t chunk_state;
    bool in_tag;
    bool tag_ignore;
    bool tag_closing;
    bool tag_self_closing;
    bool tag_name_done;
    bool attr_want_value;
    bool attr_in_value;
    char attr_quote;
    uint8_t attr_target;
    char tag[12];
    uint8_t tag_len;
    char attr_name[8];
    uint8_t attr_name_len;
    char attr_value[32];
    uint8_t attr_value_len;
    uint16_t tag_class_name;
    uint16_t tag_id_name;
    bool in_entity;
    char entity[9];
    uint8_t entity_len;
    char text[BROWSER_ELEMENT_TEXT_MAX + 1];
    uint8_t text_len;
};

struct browser_request
{
    bool tls;
    char host[BROWSER_HOST_MAX];
    char path[BROWSER_PATH_MAX];
    uint16_t port;
};

struct browser_fetch_state
{
    struct browser_state *state;
    bool active;
    bool connected;
    bool sent;
    bool send_pending;
    bool readable;
    bool done;
    bool reusable;
    uint8_t settle_ticks;
    lwip_error_t err;
    uint16_t err_component;
    uint16_t err_operation;
    int raw_error;
    lwip_status_t last_status;
    const char *request;
    size_t request_len;
    struct browser_request req;
};

static void browser_set_body(struct browser_state *state, const char *text);
static void browser_fetch_cleanup(struct browser_state *state);
static bool browser_fetch_connect_socket(struct browser_state *state);
static void browser_fetch_send_request(struct lwip_socket *sock,
                                       struct browser_fetch_state *fetch);
static void browser_interpreter_body_byte(struct browser_state *state, char c);

class BrowserRingBuffer
{
public:
    bool init(size_t initial_size, size_t quantum, size_t min_size)
    {
        release();
        quantum_ = quantum ? quantum : 1u;
        min_size_ = min_size ? min_size : quantum_;
        if (initial_size < min_size_)
        {
            initial_size = min_size_;
        }
        initial_size = round_up(initial_size);
        data_ = (uint8_t *)mem_request(initial_size);
        if (!data_)
        {
            return false;
        }
        capacity_ = initial_size;
        head_ = 0;
        size_ = 0;
        return true;
    }

    void release(void)
    {
        if (data_)
        {
            mem_release(data_);
        }
        data_ = nullptr;
        capacity_ = 0;
        min_size_ = 0;
        quantum_ = 0;
        head_ = 0;
        size_ = 0;
    }

    void clear(void)
    {
        head_ = 0;
        size_ = 0;
    }

    bool push(const void *src, size_t len)
    {
        const uint8_t *bytes = (const uint8_t *)src;
        size_t tail;
        size_t first;

        if (!len)
        {
            return true;
        }
        if (!bytes || !reserve(size_ + len))
        {
            return false;
        }

        tail = (head_ + size_) % capacity_;
        first = capacity_ - tail;
        if (first > len)
        {
            first = len;
        }
        memcpy(data_ + tail, bytes, first);
        if (len > first)
        {
            memcpy(data_, bytes + first, len - first);
        }
        size_ += len;
        return true;
    }

    size_t pop(void *dst, size_t len)
    {
        uint8_t *bytes = (uint8_t *)dst;
        size_t first;

        if (len > size_)
        {
            len = size_;
        }
        if (!len)
        {
            return 0;
        }

        first = capacity_ - head_;
        if (first > len)
        {
            first = len;
        }
        if (bytes)
        {
            memcpy(bytes, data_ + head_, first);
            if (len > first)
            {
                memcpy(bytes + first, data_, len - first);
            }
        }
        head_ = (head_ + len) % capacity_;
        size_ -= len;
        if (!size_)
        {
            head_ = 0;
        }
        return len;
    }

    bool reserve(size_t needed)
    {
        size_t next_capacity;

        if (needed <= capacity_)
        {
            return true;
        }
        next_capacity = round_up(needed);
        return resize(next_capacity);
    }

    bool shrink_to_fit(void)
    {
        size_t target = round_up(size_);

        if (target < min_size_)
        {
            target = min_size_;
        }
        if (target >= capacity_)
        {
            return true;
        }
        return resize(target);
    }

    size_t size(void) const { return size_; }
    size_t capacity(void) const { return capacity_; }
    size_t available(void) const { return capacity_ - size_; }

    bool write_at(size_t offset, const void *src, size_t len)
    {
        const uint8_t *bytes = (const uint8_t *)src;
        size_t i;

        if (!bytes || offset + len > size_ || !data_)
        {
            return false;
        }
        for (i = 0; i < len; i++)
        {
            data_[(head_ + offset + i) % capacity_] = bytes[i];
        }
        return true;
    }

    bool read_at(size_t offset, void *dst, size_t len) const
    {
        uint8_t *bytes = (uint8_t *)dst;
        size_t i;

        if (!bytes || offset + len > size_ || !data_)
        {
            return false;
        }
        for (i = 0; i < len; i++)
        {
            bytes[i] = data_[(head_ + offset + i) % capacity_];
        }
        return true;
    }

private:
    size_t round_up(size_t value) const
    {
        size_t quantum = quantum_ ? quantum_ : 1u;
        size_t rem;

        if (value < min_size_)
        {
            value = min_size_;
        }
        rem = value % quantum;
        if (rem)
        {
            value += quantum - rem;
        }
        return value;
    }

    bool linearize(void)
    {
        uint8_t *scratch;
        size_t i;

        if (!head_ || !size_)
        {
            head_ = 0;
            return true;
        }

        scratch = (uint8_t *)mem_request(size_);
        if (!scratch)
        {
            return false;
        }
        for (i = 0; i < size_; i++)
        {
            scratch[i] = data_[(head_ + i) % capacity_];
        }
        memcpy(data_, scratch, size_);
        mem_release(scratch);
        head_ = 0;
        return true;
    }

    bool resize(size_t next_capacity)
    {
        void *next;

        if (!data_)
        {
            return false;
        }
        if (next_capacity < size_)
        {
            return false;
        }
        if (!linearize())
        {
            return false;
        }
        next = mem_resize(data_, next_capacity);
        if (!next)
        {
            return false;
        }
        data_ = (uint8_t *)next;
        capacity_ = next_capacity;
        return true;
    }

    uint8_t *data_;
    size_t capacity_;
    size_t min_size_;
    size_t quantum_;
    size_t head_;
    size_t size_;
};

class Browser;

class Interpreter
{
public:
    void init(Browser *browser) { browser_ = browser; }
    void run(struct browser_state *state);

private:
    Browser *browser_;
};

class Styler
{
public:
    void init(Browser *browser) { browser_ = browser; }

private:
    Browser *browser_;
};

class Browser
{
public:
    bool init(void)
    {
        const size_t render_quantum =
            sizeof(struct browser_render_object) * BROWSER_RENDER_OBJECT_SLOTS;

        if (initialized_)
        {
            release();
        }
        if (!start_network())
        {
            return false;
        }
        network_started_ = true;
        flags_ = 0;
        state_ = nullptr;
        service_requested_mask_ = 0;
        service_up_mask_ = 0;
        service_failed_ = false;
        service_timed_out_ = false;
        connect_watch_ticks_ = 0;
        network_watch_active_ = false;
        connect_watch_active_ = false;
        interpreter_watch_active_ = false;
        reset_page_objects();
        flags_ |= BROWSER_FLAG_READY;

        if (!payload_in.init(BROWSER_PAYLOAD_RING_MIN,
                             BROWSER_PAYLOAD_RING_MIN,
                             BROWSER_PAYLOAD_RING_MIN))
        {
            release();
            return false;
        }
        if (!render_object.init(render_quantum,
                                render_quantum,
                                render_quantum))
        {
            release();
            return false;
        }
        if (!raw_content.init(BROWSER_RAW_CONTENT_MIN,
                              BROWSER_RAW_CONTENT_MIN,
                              BROWSER_RAW_CONTENT_MIN))
        {
            release();
            return false;
        }
        if (!class_names.init(BROWSER_NAME_RING_MIN,
                              BROWSER_NAME_RING_MIN,
                              BROWSER_NAME_RING_MIN))
        {
            release();
            return false;
        }
        if (!id_names.init(BROWSER_NAME_RING_MIN,
                           BROWSER_NAME_RING_MIN,
                           BROWSER_NAME_RING_MIN))
        {
            release();
            return false;
        }

        interpreter.init(this);
        styler.init(this);
        initialized_ = true;
        return true;
    }

    void release(void)
    {
        sys_untimeout(network_watch_timeout, this);
        sys_untimeout(connect_watch_timeout, this);
        sys_untimeout(interpreter_timeout, this);
        network_watch_active_ = false;
        connect_watch_active_ = false;
        interpreter_watch_active_ = false;
        id_names.release();
        class_names.release();
        raw_content.release();
        render_object.release();
        payload_in.release();
        state_ = nullptr;
        initialized_ = false;
        if (network_started_)
        {
            network_started_ = false;
            lwip_stop();
        }
        lwip_example_gfx_stop();
    }

    void attach_state(struct browser_state *state) { state_ = state; }
    bool connect(struct browser_state *state);
    bool close(struct browser_state *state);
    bool fetch(struct browser_state *state);
    bool receive_http_payload(struct browser_state *state,
                              const char *data,
                              size_t len);
    void interpret(struct browser_state *state);
    bool emit_object(struct browser_state *state,
                     const struct browser_element *element);
    void reset_page_objects(void);
    uint16_t render_object_count(void) const { return object_count_; }
    bool render_object_at(uint16_t index,
                          struct browser_render_object *object) const
    {
        return read_render_object(index, object);
    }
    bool raw_content_at(uint16_t offset, void *dst, size_t len) const
    {
        return raw_content.read_at(offset, dst, len);
    }
    uint16_t append_class_name(const char *data, size_t len);
    uint16_t append_id_name(const char *data, size_t len);

    bool ready(void) const { return (flags_ & BROWSER_FLAG_READY) != 0; }
    bool connected(void) const
    {
        return (flags_ & BROWSER_FLAG_CONNECTED) != 0;
    }
    bool error(void) const { return (flags_ & BROWSER_FLAG_ERROR) != 0; }

    BrowserRingBuffer render_object;
    BrowserRingBuffer payload_in;
    BrowserRingBuffer raw_content;
    BrowserRingBuffer class_names;
    BrowserRingBuffer id_names;
    Interpreter interpreter;
    Styler styler;

private:
    static void netif_service_callback(struct netif *netif,
                                       void *arg,
                                       uint8_t service_id,
                                       lwip_netif_service_status_t status);
    static void network_watch_timeout(void *arg);
    static void connect_watch_timeout(void *arg);
    static void interpreter_timeout(void *arg);

    void schedule_network_watch(void)
    {
        if (!network_watch_active_)
        {
            network_watch_active_ = true;
            sys_timeout(BROWSER_NETWORK_WATCH_MS,
                        network_watch_timeout, this);
        }
    }

    void schedule_connect_watch(void)
    {
        if (!connect_watch_active_)
        {
            connect_watch_active_ = true;
            sys_timeout(BROWSER_CONNECT_WATCH_MS,
                        connect_watch_timeout, this);
        }
    }

    void network_watch_step(void);
    void connect_watch_step(void);
    void schedule_interpreter(void)
    {
        if (!interpreter_watch_active_)
        {
            interpreter_watch_active_ = true;
            sys_timeout(1u, interpreter_timeout, this);
        }
    }

    uint16_t append_raw_content(const char *data, size_t len);
    uint16_t find_name(const BrowserRingBuffer &names,
                       const char *data,
                       size_t len) const;
    bool read_render_object(uint16_t index,
                            struct browser_render_object *object) const;
    bool write_render_object(uint16_t index,
                             const struct browser_render_object *object);
    uint16_t append_render_object(const struct browser_render_object *object);
    uint16_t tag_id_for_name(const char *tag) const;

    bool start_network(void)
    {
        lwip_example_gfx_start();
        lwip_example_show("lwIP runtime", (const char *)nullptr);

        if (!lwip_start_with_crt((void *)malloc,
                                 (void *)free,
                                 (void *)realloc))
        {
            lwip_example_show_and_wait("lwIP failed",
                                       lwip_get_start_errstring());
            lwip_example_gfx_stop();
            return false;
        }
        lwip_example_gfx_blit_start();

        lwip_example_show("lwIP network up", (const char *)nullptr);
        if (!lwip_network_up())
        {
            switch (lwip_start_last_error())
            {
            case 1:
                lwip_example_show_and_wait("lwIP failed", "start init");
                break;
            case 2:
                lwip_example_show_and_wait("lwIP failed", "start usb");
                break;
            default:
                lwip_example_show_and_wait("lwIP failed", "start");
                break;
            }
            lwip_stop();
            lwip_example_gfx_stop();
            return false;
        }

        lwip_example_draw_mem_stats();
        return true;
    }

    bool initialized_;
    bool network_started_;
    uint8_t flags_;
    uint8_t service_requested_mask_;
    uint8_t service_up_mask_;
    bool service_failed_;
    bool service_timed_out_;
    bool network_watch_active_;
    bool connect_watch_active_;
    bool interpreter_watch_active_;
    uint16_t connect_watch_ticks_;
    uint16_t next_object_id_;
    uint16_t object_count_;
    uint16_t dom_stack_[BROWSER_DOM_STACK_MAX];
    uint8_t dom_depth_;
    struct browser_state *state_;
};

struct browser_state
{
    char url[BROWSER_URL_MAX];
    char edit_url[BROWSER_URL_MAX];
    char history[BROWSER_HISTORY_DEPTH][BROWSER_URL_MAX];
    char forward_history[BROWSER_HISTORY_DEPTH][BROWSER_URL_MAX];
    uint8_t history_count;
    uint8_t forward_count;
    bool editing;
    uint8_t input_mode;
    bool input_upper_once;
    uint16_t scroll_line;
    uint8_t scroll_col;
    char body[BROWSER_BODY_MAX];
    size_t body_len;
    char request[BROWSER_REQ_MAX];
    char rx_chunk[BROWSER_RX_CHUNK];
    struct lwip_socket *sock;
    Browser *browser;
    struct browser_fetch_state fetch;
    struct browser_request socket_req;
    bool socket_valid;
    bool closing_for_navigation;
    bool close_pending;
    bool pending_navigation;
    char pending_url[BROWSER_URL_MAX];
    struct browser_page page;
    struct browser_element *document;
    uint16_t document_count;
    uint16_t document_capacity;
    bool document_alloc_failed;
    bool page_dirty;
    struct browser_stream_state stream;
    struct browser_element elements[BROWSER_ELEMENT_RING];
    uint8_t element_head;
    uint8_t element_count;
    uint16_t next_element_id;
    bool interpreter_working;
    browser_style_t styler_text_style;
    char event_line[BROWSER_STATUS_MAX + 1];
    bool event_dirty;
};

static struct browser_state *browser_event_state;

static void browser_parse_html(struct browser_state *state);
static void browser_stream_flush_text(struct browser_state *state);
static void browser_stream_flush_style_text(struct browser_state *state);
static bool browser_fetch_start(struct browser_state *state);
static void browser_document_release(struct browser_state *state);
static void browser_on_event(struct lwip_socket *sock,
                             lwip_socket_event_type_t type,
                             const void *ev_data,
                             void *arg);
static bool browser_tag_is_media(const char *tag);
static void browser_stream_attr_reset(struct browser_stream_state *stream);

static bool browser_starts_with(const char *text, const char *prefix)
{
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static void browser_copy(char *dst, size_t dst_len, const char *src)
{
    snprintf(dst, dst_len, "%s", src ? src : "");
}

static void browser_set_event_line(struct browser_state *state,
                                   const char *text)
{
    if (!state)
    {
        return;
    }
    browser_copy(state->event_line, sizeof(state->event_line), text);
    state->event_dirty = true;
}

static void browser_lwip_event_cb(const struct lwip_event *ev)
{
    struct browser_state *state = browser_event_state;

    if (!state || !ev || ev->module != LWIP_DBG_MOD_TLS)
    {
        return;
    }

    if (ev->kind == LWIP_EV_INFO)
    {
        browser_set_event_line(state, ev->data.msg);
    }
    else if (ev->kind == LWIP_EV_WARN || ev->kind == LWIP_EV_ERROR)
    {
        char line[BROWSER_STATUS_MAX + 1];
        snprintf(line, sizeof(line), "%s %s:%u",
                 ev->kind == LWIP_EV_WARN ? "warn" : "err",
                 lwip_debug_file_name(
                     LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                 (unsigned)LWIP_EVENT_CODE_LINE(ev->data.code.loc));
        browser_set_event_line(state, line);
    }
}

static void browser_set_body(struct browser_state *state, const char *text)
{
    browser_document_release(state);
    if (state->browser)
    {
        state->browser->reset_page_objects();
    }
    state->page_dirty = false;
    state->body_len = strlen(text);
    if (state->body_len >= sizeof(state->body))
    {
        state->body_len = sizeof(state->body) - 1;
    }
    memcpy(state->body, text, state->body_len);
    state->body[state->body_len] = '\0';
    browser_parse_html(state);
}

static void browser_trace_append(char *buf, size_t buf_len, size_t *used)
{
    const struct lwip_traceback_entry *trace;
    uint8_t count = 0;

    if (!buf || !used || *used >= buf_len)
    {
        return;
    }

    trace = lwip_get_traceback(&count);
    for (uint8_t i = 0; i < count && i < 16u; i++)
    {
        const struct lwip_traceback_entry *entry = &trace[i];
        size_t remaining = buf_len - *used;
        int n;

        if (remaining <= 1u)
        {
            break;
        }

        if (entry->file)
        {
            n = snprintf(buf + *used, remaining,
                         "\n%u %s %s:%u x%u",
                         (unsigned)i,
                         lwip_debug_module_name(entry->module),
                         lwip_debug_file_name(entry->file),
                         (unsigned)entry->line,
                         (unsigned)entry->extra);
        }
        else
        {
            n = snprintf(buf + *used, remaining,
                         "\n%u sock c%u o%u r%d e%u s%u",
                         (unsigned)i,
                         (unsigned)entry->component,
                         (unsigned)entry->operation,
                         entry->raw_error,
                         (unsigned)entry->mapped_error,
                         (unsigned)entry->status);
        }

        if (n < 0)
        {
            break;
        }
        if ((size_t)n >= remaining)
        {
            *used = buf_len - 1u;
            buf[*used] = '\0';
            break;
        }
        *used += (size_t)n;
    }
}

static void browser_set_fetch_error_body(struct browser_state *state,
                                         const struct browser_fetch_state *fetch)
{
    char msg[BROWSER_BODY_MAX];
    int n;
    size_t used;

    if (!state || !fetch)
    {
        return;
    }

    n = snprintf(msg, sizeof(msg), "Fetch e%u c%u o%u r%d",
                 (unsigned)fetch->err,
                 (unsigned)fetch->err_component,
                 (unsigned)fetch->err_operation,
                 fetch->raw_error);
    if (n < 0)
    {
        msg[0] = '\0';
        used = 0;
    }
    else if ((size_t)n >= sizeof(msg))
    {
        used = sizeof(msg) - 1u;
        msg[used] = '\0';
    }
    else
    {
        used = (size_t)n;
    }

    browser_trace_append(msg, sizeof(msg), &used);
    browser_set_body(state, msg);
}

static void browser_normalize_url(char *url, size_t url_len)
{
    char tmp[BROWSER_URL_MAX];

    if (!url || !url[0])
    {
        browser_copy(url, url_len, BROWSER_URL);
        return;
    }
    if (browser_starts_with(url, "http://") ||
        browser_starts_with(url, "https://"))
    {
        return;
    }
    snprintf(tmp, sizeof(tmp), "http://%s", url);
    browser_copy(url, url_len, tmp);
}

static bool browser_parse_port(const char *text, size_t len, uint16_t *port)
{
    uint32_t value = 0;
    size_t i;

    if (!text || !len)
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        if (text[i] < '0' || text[i] > '9')
        {
            return false;
        }
        value = value * 10u + (uint32_t)(text[i] - '0');
        if (value > 65535u)
        {
            return false;
        }
    }
    *port = (uint16_t)value;
    return true;
}

static bool browser_parse_url(const char *url, struct browser_request *req)
{
    const char *p = url;
    const char *path;
    const char *colon = nullptr;
    size_t authority_len;
    size_t host_len;
    size_t i;

    memset(req, 0, sizeof(*req));
    req->port = 80;

    if (browser_starts_with(p, "https://"))
    {
        req->tls = true;
        req->port = 443;
        p += 8;
    }
    else if (browser_starts_with(p, "http://"))
    {
        p += 7;
    }

    path = strchr(p, '/');
    authority_len = path ? (size_t)(path - p) : strlen(p);
    if (authority_len == 0)
    {
        return false;
    }

    for (i = 0; i < authority_len; i++)
    {
        if (p[i] == ':')
        {
            colon = p + i;
            break;
        }
    }

    host_len = colon ? (size_t)(colon - p) : authority_len;
    if (host_len == 0 || host_len >= sizeof(req->host))
    {
        return false;
    }
    memcpy(req->host, p, host_len);
    req->host[host_len] = '\0';

    if (colon)
    {
        if (!browser_parse_port(colon + 1,
                                authority_len - host_len - 1u,
                                &req->port))
        {
            return false;
        }
    }

    browser_copy(req->path, sizeof(req->path), path ? path : "/");
    return true;
}

static bool browser_same_origin(const struct browser_request *a,
                                const struct browser_request *b)
{
    return a && b &&
        a->tls == b->tls &&
        a->port == b->port &&
        strcmp(a->host, b->host) == 0;
}

static char browser_printable(char c)
{
    if (c == '\t')
    {
        return ' ';
    }
    return (c >= 32 && c <= 126) ? c : '.';
}

static char browser_key_to_url_char(uint8_t key, uint8_t mode)
{
    char c = key_to_char(key, mode);

    if (c)
    {
        return c;
    }

    switch (key)
    {
    case sk_DecPnt: return '.';
    case sk_Div: return '/';
    case sk_Sub: return '-';
    case sk_Chs: return '-';
    case sk_Store: return '>';
    default: return '\0';
    }
}

static uint8_t browser_style_color(browser_style_t style)
{
    switch (style)
    {
    case BROWSER_STYLE_HEADING: return BROWSER_COLOR_HEADING;
    case BROWSER_STYLE_LINK: return BROWSER_COLOR_LINK;
    case BROWSER_STYLE_UNSUPPORTED: return BROWSER_COLOR_UNSUPPORTED;
    case BROWSER_STYLE_NORMAL:
    default: return LWIP_EXAMPLE_COLOR_FG;
    }
}

static void browser_page_release(struct browser_state *state)
{
    if (state->page.rows)
    {
        mem_release(state->page.rows);
    }
    memset(&state->page, 0, sizeof(state->page));
}

static uint16_t browser_page_row_cap(void)
{
    size_t max_rows = BROWSER_ROW_STORE_MAX_BYTES /
        sizeof(struct browser_render_row);

    if (max_rows < BROWSER_VISIBLE_ROWS)
    {
        return BROWSER_VISIBLE_ROWS;
    }
    if (max_rows > UINT16_MAX)
    {
        return UINT16_MAX;
    }
    return (uint16_t)max_rows;
}

static void browser_page_init_rows(struct browser_render_row *rows,
                                   uint16_t from,
                                   uint16_t to)
{
    uint16_t i;

    for (i = from; i < to; i++)
    {
        rows[i].text[0] = '\0';
        rows[i].color = browser_style_color(BROWSER_STYLE_NORMAL);
    }
}

static bool browser_page_resize_rows(struct browser_state *state,
                                     uint16_t rows)
{
    struct browser_page *page = &state->page;
    void *next;

    if (rows < BROWSER_VISIBLE_ROWS)
    {
        rows = BROWSER_VISIBLE_ROWS;
    }
    if (rows > browser_page_row_cap())
    {
        rows = browser_page_row_cap();
    }
    if (page->row_capacity == rows && page->rows)
    {
        return true;
    }

    if (page->rows)
    {
        next = mem_resize(page->rows,
                          sizeof(struct browser_render_row) * rows);
    }
    else
    {
        next = mem_request(sizeof(struct browser_render_row) * rows);
    }
    if (!next)
    {
        page->alloc_failed = true;
        return false;
    }
    page->rows = (struct browser_render_row *)next;
    if (rows > page->row_capacity)
    {
        browser_page_init_rows(page->rows, page->row_capacity, rows);
    }
    page->row_capacity = rows;
    return true;
}

static bool browser_page_alloc(struct browser_state *state)
{
    return browser_page_resize_rows(state, BROWSER_VISIBLE_ROWS);
}

static void browser_page_shrink_to_fit(struct browser_state *state)
{
    uint16_t target = state->page.row_count;

    if (target < BROWSER_VISIBLE_ROWS)
    {
        target = BROWSER_VISIBLE_ROWS;
    }
    if (state->page.row_capacity > target)
    {
        (void)browser_page_resize_rows(state, target);
    }
}

static struct browser_render_row *browser_page_row(struct browser_state *state,
                                                   uint16_t row)
{
    struct browser_page *page = &state->page;

    if (!page->rows || row >= page->row_count)
    {
        return nullptr;
    }
    return &page->rows[row];
}

static struct browser_render_row *browser_page_append_row(
    struct browser_state *state)
{
    struct browser_page *page = &state->page;
    struct browser_render_row *row;

    if (!browser_page_alloc(state))
    {
        return nullptr;
    }

    if (page->row_count == page->row_capacity)
    {
        uint16_t next_capacity = (uint16_t)(page->row_capacity * 2u);
        if (next_capacity <= page->row_capacity)
        {
            next_capacity = (uint16_t)(page->row_capacity + 1u);
        }
        if (!browser_page_resize_rows(state, next_capacity) ||
            page->row_count == page->row_capacity)
        {
            page->alloc_failed = true;
            return nullptr;
        }
    }

    row = &page->rows[page->row_count++];
    row->text[0] = '\0';
    row->color = browser_style_color(page->style);
    page->total_rows++;
    return row;
}

static struct browser_render_row *browser_page_current_row(
    struct browser_state *state)
{
    if (state->page.total_rows == 0)
    {
        return browser_page_append_row(state);
    }
    return browser_page_row(state, (uint16_t)(state->page.total_rows - 1u));
}

static void browser_page_reset(struct browser_state *state)
{
    browser_page_release(state);
    state->page.style = BROWSER_STYLE_NORMAL;
    state->scroll_line = 0;
    state->scroll_col = 0;
}

static void browser_page_newline(struct browser_state *state)
{
    if (state->page.col || state->page.total_rows == 0)
    {
        (void)browser_page_append_row(state);
    }
    state->page.col = 0;
    state->page.last_space = false;
}

static void browser_page_blank_line(struct browser_state *state)
{
    struct browser_render_row *row;

    if (state->page.col)
    {
        browser_page_newline(state);
    }
    row = browser_page_current_row(state);
    if (row && row->text[0] == '\0')
    {
        return;
    }
    browser_page_newline(state);
}

static void browser_page_append_char(struct browser_state *state, char c)
{
    struct browser_render_row *row;

    if (c == '\r')
    {
        return;
    }
    if (c == '\n')
    {
        browser_page_newline(state);
        return;
    }
    if ((unsigned char)c <= ' ')
    {
        c = ' ';
    }
    if (c == ' ' && state->page.col == 0)
    {
        return;
    }
    if (c == ' ' && state->page.last_space)
    {
        return;
    }
    if (state->page.col >= BROWSER_ROW_COLS)
    {
        browser_page_newline(state);
    }
    row = browser_page_current_row(state);
    if (!row)
    {
        return;
    }
    row->text[state->page.col++] = browser_printable(c);
    row->text[state->page.col] = '\0';
    row->color = browser_style_color(state->page.style);
    state->page.last_space = c == ' ';
}

static void browser_document_release(struct browser_state *state)
{
    if (state->document)
    {
        mem_release(state->document);
    }
    state->document = nullptr;
    state->document_count = 0;
    state->document_capacity = 0;
    state->document_alloc_failed = false;
    state->page_dirty = true;
}

static uint8_t browser_element_index(const struct browser_state *state,
                                     uint8_t offset)
{
    return (uint8_t)((state->element_head + offset) % BROWSER_ELEMENT_RING);
}

static void browser_renderer_step(struct browser_state *state, uint8_t budget);
static void browser_styler_step(struct browser_state *state, uint8_t budget);

static bool browser_element_emit(struct browser_state *state,
                                 const struct browser_element *src)
{
    struct browser_element *dst;
    uint8_t idx;

    if (state->element_count == BROWSER_ELEMENT_RING)
    {
        browser_styler_step(state, BROWSER_ELEMENT_RING);
        browser_renderer_step(state, BROWSER_ELEMENT_RING);
    }
    if (state->element_count == BROWSER_ELEMENT_RING)
    {
        return false;
    }

    idx = browser_element_index(state, state->element_count);
    dst = &state->elements[idx];
    *dst = *src;
    dst->id = state->next_element_id++;
    if (!dst->count)
    {
        dst->count = 1;
    }
    dst->styled = false;
    state->element_count++;
    return true;
}

static bool browser_element_emit_text(struct browser_state *state,
                                      const char *text,
                                      size_t len)
{
    struct browser_element element;

    if (!len)
    {
        return true;
    }
    memset(&element, 0, sizeof(element));
    element.object_kind = BROWSER_OBJECT_ELEMENT;
    element.count = 1;
    element.type = BROWSER_ELEMENT_TEXT;
    element.class_name = BROWSER_OBJECT_NULL;
    element.id_name = BROWSER_OBJECT_NULL;
    if (len > BROWSER_ELEMENT_TEXT_MAX)
    {
        len = BROWSER_ELEMENT_TEXT_MAX;
    }
    memcpy(element.text, text, len);
    element.text[len] = '\0';
    return browser_element_emit(state, &element);
}

static bool browser_element_emit_tag_with_names(struct browser_state *state,
                                                const char *tag,
                                                bool closing,
                                                bool self_closing,
                                                uint16_t class_name,
                                                uint16_t id_name)
{
    struct browser_element element;

    memset(&element, 0, sizeof(element));
    element.object_kind = BROWSER_OBJECT_ELEMENT;
    element.count = 1;
    element.type = BROWSER_ELEMENT_TAG;
    element.closing = closing;
    element.self_closing = self_closing;
    element.class_name = class_name;
    element.id_name = id_name;
    browser_copy(element.tag, sizeof(element.tag), tag);
    return browser_element_emit(state, &element);
}

static bool browser_element_emit_break(struct browser_state *state)
{
    struct browser_element element;

    memset(&element, 0, sizeof(element));
    element.object_kind = BROWSER_OBJECT_ELEMENT;
    element.count = 1;
    element.type = BROWSER_ELEMENT_BREAK;
    element.class_name = BROWSER_OBJECT_NULL;
    element.id_name = BROWSER_OBJECT_NULL;
    return browser_element_emit(state, &element);
}

static bool browser_element_emit_style_tag(struct browser_state *state,
                                           bool closing)
{
    struct browser_element element;

    memset(&element, 0, sizeof(element));
    element.object_kind = BROWSER_OBJECT_STYLE;
    element.count = 1;
    element.type = BROWSER_ELEMENT_TAG;
    element.closing = closing;
    element.class_name = BROWSER_OBJECT_NULL;
    element.id_name = BROWSER_OBJECT_NULL;
    browser_copy(element.tag, sizeof(element.tag), "style");
    return browser_element_emit(state, &element);
}

static bool browser_element_emit_style_text(struct browser_state *state,
                                            const char *text,
                                            size_t len)
{
    struct browser_element element;

    if (!len)
    {
        return true;
    }
    memset(&element, 0, sizeof(element));
    element.object_kind = BROWSER_OBJECT_STYLE;
    element.count = 1;
    element.type = BROWSER_ELEMENT_TEXT;
    element.class_name = BROWSER_OBJECT_NULL;
    element.id_name = BROWSER_OBJECT_NULL;
    if (len > BROWSER_ELEMENT_TEXT_MAX)
    {
        len = BROWSER_ELEMENT_TEXT_MAX;
    }
    memcpy(element.text, text, len);
    element.text[len] = '\0';
    return browser_element_emit(state, &element);
}

static char browser_entity_char(const char *entity, size_t len)
{
    if (len == 2 && strncmp(entity, "lt", len) == 0) return '<';
    if (len == 2 && strncmp(entity, "gt", len) == 0) return '>';
    if (len == 3 && strncmp(entity, "amp", len) == 0) return '&';
    if (len == 4 && strncmp(entity, "quot", len) == 0) return '"';
    if (len == 4 && strncmp(entity, "nbsp", len) == 0) return ' ';
    return '\0';
}

static void browser_page_finish(struct browser_state *state)
{
    (void)state;
}

typedef void (*browser_tag_fn)(struct browser_state *state,
                               struct browser_parse_state *parse,
                               bool closing,
                               bool self_closing);

struct browser_page_rule
{
    const char *tag;
    browser_tag_fn fn;
};

static void browser_rule_block(struct browser_state *state,
                               struct browser_parse_state *parse,
                               bool closing,
                               bool self_closing)
{
    (void)parse;
    (void)closing;
    (void)self_closing;
    browser_page_blank_line(state);
}

static void browser_rule_break(struct browser_state *state,
                               struct browser_parse_state *parse,
                               bool closing,
                               bool self_closing)
{
    (void)parse;
    (void)closing;
    (void)self_closing;
    browser_page_newline(state);
}

static void browser_rule_heading(struct browser_state *state,
                                 struct browser_parse_state *parse,
                                 bool closing,
                                 bool self_closing)
{
    (void)parse;
    (void)self_closing;
    if (closing)
    {
        state->page.style = BROWSER_STYLE_NORMAL;
        browser_page_blank_line(state);
    }
    else
    {
        browser_page_blank_line(state);
        state->page.style = BROWSER_STYLE_HEADING;
    }
}

static void browser_rule_link(struct browser_state *state,
                              struct browser_parse_state *parse,
                              bool closing,
                              bool self_closing)
{
    (void)parse;
    (void)self_closing;
    state->page.style = closing ? BROWSER_STYLE_NORMAL : BROWSER_STYLE_LINK;
}

static void browser_rule_skip(struct browser_state *state,
                              struct browser_parse_state *parse,
                              bool closing,
                              bool self_closing)
{
    (void)state;
    (void)self_closing;
    if (closing)
    {
        parse->skip = false;
        parse->skip_tag[0] = '\0';
    }
}

static void browser_rule_media(struct browser_state *state,
                               struct browser_parse_state *parse,
                               bool closing,
                               bool self_closing)
{
    (void)state;
    (void)parse;
    (void)closing;
    (void)self_closing;
}

static const struct browser_page_rule browser_rules[] = {
    {"a", browser_rule_link},
    {"article", browser_rule_block},
    {"audio", browser_rule_media},
    {"br", browser_rule_break},
    {"button", browser_rule_block},
    {"canvas", browser_rule_media},
    {"div", browser_rule_block},
    {"footer", browser_rule_block},
    {"form", browser_rule_block},
    {"h1", browser_rule_heading},
    {"h2", browser_rule_heading},
    {"h3", browser_rule_heading},
    {"h4", browser_rule_heading},
    {"h5", browser_rule_heading},
    {"h6", browser_rule_heading},
    {"head", browser_rule_skip},
    {"header", browser_rule_block},
    {"hr", browser_rule_block},
    {"iframe", browser_rule_media},
    {"img", browser_rule_media},
    {"input", browser_rule_block},
    {"li", browser_rule_break},
    {"main", browser_rule_block},
    {"nav", browser_rule_block},
    {"ol", browser_rule_block},
    {"p", browser_rule_block},
    {"pre", browser_rule_block},
    {"script", browser_rule_skip},
    {"section", browser_rule_block},
    {"select", browser_rule_block},
    {"style", browser_rule_skip},
    {"table", browser_rule_block},
    {"td", browser_rule_block},
    {"textarea", browser_rule_block},
    {"th", browser_rule_block},
    {"title", browser_rule_skip},
    {"tr", browser_rule_break},
    {"ul", browser_rule_block},
    {"video", browser_rule_media},
};

static bool browser_tag_in_list(const char *tag, const char *const *list,
                                size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
    {
        if (strcmp(tag, list[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

static browser_display_t browser_default_display(const char *tag)
{
    static const char *const block_tags[] = {
        "article", "body", "div", "footer", "form", "h1", "h2", "h3",
        "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol",
        "p", "pre", "section", "table", "tbody", "td", "textarea", "th",
        "thead", "tr", "ul"
    };
    static const char *const inline_block_tags[] = {
        "audio", "button", "canvas", "iframe", "img", "input", "select",
        "video"
    };
    static const char *const none_tags[] = {
        "head", "script", "style", "title"
    };

    if (browser_tag_in_list(tag, none_tags,
                            sizeof(none_tags) / sizeof(none_tags[0])))
    {
        return BROWSER_DISPLAY_NONE;
    }
    if (browser_tag_in_list(tag, block_tags,
                            sizeof(block_tags) / sizeof(block_tags[0])))
    {
        return BROWSER_DISPLAY_BLOCK;
    }
    if (browser_tag_in_list(tag, inline_block_tags,
                            sizeof(inline_block_tags) /
                            sizeof(inline_block_tags[0])))
    {
        return BROWSER_DISPLAY_INLINE_BLOCK;
    }
    return BROWSER_DISPLAY_INLINE;
}

static bool browser_tag_is_media(const char *tag)
{
    static const char *const media_tags[] = {
        "audio", "canvas", "iframe", "img", "video"
    };

    return browser_tag_in_list(tag, media_tags,
                               sizeof(media_tags) / sizeof(media_tags[0]));
}

static bool browser_tag_id_is_media(uint16_t tag_id)
{
    return tag_id == BROWSER_HTML_IMG;
}

static bool browser_tag_is_heading(const char *tag)
{
    return tag[0] == 'h' && tag[1] >= '1' && tag[1] <= '6' && tag[2] == '\0';
}

static bool browser_tag_suppresses_content(const char *tag)
{
    return strcmp(tag, "head") == 0 ||
        strcmp(tag, "script") == 0 ||
        strcmp(tag, "style") == 0 ||
        strcmp(tag, "title") == 0;
}

static void browser_styler_apply(struct browser_state *state,
                                 struct browser_element *element)
{
    if (element->object_kind == BROWSER_OBJECT_STYLE)
    {
        element->styled = true;
        return;
    }

    element->style.display = BROWSER_DISPLAY_INLINE;
    element->style.text_style = state->styler_text_style;
    element->style.color = browser_style_color(element->style.text_style);
    element->style.background_color = LWIP_EXAMPLE_COLOR_BG;
    element->style.width = 0;
    element->style.height = 0;

    if (element->type == BROWSER_ELEMENT_BREAK)
    {
        element->style.display = BROWSER_DISPLAY_BLOCK;
        element->styled = true;
        return;
    }
    if (element->type == BROWSER_ELEMENT_TEXT)
    {
        element->styled = true;
        return;
    }

    element->style.display = browser_default_display(element->tag);
    if (browser_tag_is_heading(element->tag))
    {
        if (element->closing)
        {
            state->styler_text_style = BROWSER_STYLE_NORMAL;
        }
        else
        {
            state->styler_text_style = BROWSER_STYLE_HEADING;
        }
    }
    else if (strcmp(element->tag, "a") == 0)
    {
        state->styler_text_style = element->closing
            ? BROWSER_STYLE_NORMAL
            : BROWSER_STYLE_LINK;
    }
    if (browser_tag_is_media(element->tag))
    {
        element->style.text_style = BROWSER_STYLE_UNSUPPORTED;
        element->style.color = browser_style_color(BROWSER_STYLE_UNSUPPORTED);
    }
    else
    {
        element->style.text_style = state->styler_text_style;
        element->style.color = browser_style_color(element->style.text_style);
    }
    element->styled = true;
}

static void browser_styler_step(struct browser_state *state, uint8_t budget)
{
    uint8_t offset;

    for (offset = 0; offset < state->element_count && budget; offset++)
    {
        struct browser_element *element =
            &state->elements[browser_element_index(state, offset)];
        if (!element->styled)
        {
            browser_styler_apply(state, element);
            budget--;
        }
    }
}

static void browser_renderer_pop(struct browser_state *state)
{
    memset(&state->elements[state->element_head], 0,
           sizeof(state->elements[state->element_head]));
    state->element_head = (uint8_t)((state->element_head + 1u) %
                                   BROWSER_ELEMENT_RING);
    state->element_count--;
}

static void browser_renderer_step(struct browser_state *state, uint8_t budget)
{
    while (state->element_count && budget)
    {
        struct browser_element *element = &state->elements[state->element_head];
        bool ok = true;

        if (!element->styled)
        {
            return;
        }
        if (state->browser)
        {
            ok = state->browser->emit_object(state, element);
            if (ok)
            {
                state->page_dirty = true;
            }
        }
        if (!ok && !state->document_alloc_failed)
        {
            return;
        }
        browser_renderer_pop(state);
        budget--;
    }
}

static bool browser_tag_name_match(const char *tag, const char *name)
{
    return strcmp(tag, name) == 0;
}

static void browser_handle_tag(struct browser_state *state,
                               struct browser_parse_state *parse,
                               const char *tag,
                               bool closing,
                               bool self_closing)
{
    size_t i;

    if (!tag[0])
    {
        return;
    }
    if (parse->skip)
    {
        if (closing && browser_tag_name_match(tag, parse->skip_tag))
        {
            parse->skip = false;
            parse->skip_tag[0] = '\0';
        }
        return;
    }
    for (i = 0; i < sizeof(browser_rules) / sizeof(browser_rules[0]); i++)
    {
        if (browser_tag_name_match(tag, browser_rules[i].tag))
        {
            if (browser_rules[i].fn == browser_rule_skip && !closing)
            {
                parse->skip = true;
                browser_copy(parse->skip_tag, sizeof(parse->skip_tag), tag);
                return;
            }
            browser_rules[i].fn(state, parse, closing, self_closing);
            return;
        }
    }
}

static size_t browser_parse_tag(const char *html, size_t len, size_t i,
                                char *tag, size_t tag_len,
                                bool *closing,
                                bool *self_closing)
{
    size_t n = 0;

    *closing = false;
    *self_closing = false;
    tag[0] = '\0';

    i++;
    if (i < len && html[i] == '!')
    {
        while (i < len && html[i] != '>')
        {
            i++;
        }
        return i < len ? i + 1u : i;
    }
    while (i < len && isspace((unsigned char)html[i]))
    {
        i++;
    }
    if (i < len && html[i] == '/')
    {
        *closing = true;
        i++;
    }
    while (i < len && isspace((unsigned char)html[i]))
    {
        i++;
    }
    while (i < len && n + 1u < tag_len)
    {
        unsigned char c = (unsigned char)html[i];

        if (!isalnum(c))
        {
            break;
        }
        tag[n++] = (char)tolower(c);
        i++;
    }
    tag[n] = '\0';
    while (i < len && html[i] != '>')
    {
        if (html[i] == '/')
        {
            *self_closing = true;
        }
        i++;
    }
    return i < len ? i + 1u : i;
}

static size_t browser_parse_entity(struct browser_state *state,
                                   const char *html,
                                   size_t len,
                                   size_t i)
{
    size_t start = i + 1u;
    size_t end = start;
    char c;

    while (end < len && end - start < 8u && html[end] != ';')
    {
        end++;
    }
    if (end >= len || html[end] != ';')
    {
        browser_page_append_char(state, '&');
        return i + 1u;
    }
    c = browser_entity_char(html + start, end - start);
    if (c)
    {
        browser_page_append_char(state, c);
    }
    return end + 1u;
}

static void browser_parse_html(struct browser_state *state)
{
    struct browser_parse_state parse = {0};
    size_t i = 0;

    browser_page_reset(state);
    while (i < state->body_len)
    {
        char c = state->body[i];

        if (c == '<')
        {
            char tag[12];
            bool closing;
            bool self_closing;
            i = browser_parse_tag(state->body, state->body_len, i, tag,
                                  sizeof(tag), &closing, &self_closing);
            browser_handle_tag(state, &parse, tag, closing, self_closing);
            continue;
        }
        if (!parse.skip)
        {
            if (c == '&')
            {
                i = browser_parse_entity(state, state->body,
                                         state->body_len, i);
                continue;
            }
            browser_page_append_char(state, c);
        }
        i++;
    }
    browser_page_finish(state);
}

static void browser_stream_reset(struct browser_state *state)
{
    memset(&state->stream, 0, sizeof(state->stream));
    if (state->browser)
    {
        state->browser->reset_page_objects();
    }
    memset(state->elements, 0, sizeof(state->elements));
    state->element_head = 0;
    state->element_count = 0;
    state->next_element_id = 1;
    state->interpreter_working = true;
    state->styler_text_style = BROWSER_STYLE_NORMAL;
    browser_page_reset(state);
}

static void browser_stream_finish(struct browser_state *state)
{
    if (state->browser)
    {
        state->browser->interpret(state);
    }
    browser_stream_flush_text(state);
    state->interpreter_working = false;
}

static bool browser_header_starts_with(const char *line, const char *prefix)
{
    while (*prefix)
    {
        if (tolower((unsigned char)*line) !=
            tolower((unsigned char)*prefix))
        {
            return false;
        }
        line++;
        prefix++;
    }
    return true;
}

static bool browser_header_contains_token(const char *line, const char *token)
{
    size_t token_len = strlen(token);

    while (*line)
    {
        size_t i;

        for (i = 0; i < token_len; i++)
        {
            if (!line[i] ||
                tolower((unsigned char)line[i]) !=
                    tolower((unsigned char)token[i]))
            {
                break;
            }
        }
        if (i == token_len)
        {
            return true;
        }
        line++;
    }
    return false;
}

static void browser_stream_process_header_line(
    struct browser_stream_state *stream)
{
    const char *line = stream->header_line;

    if (browser_header_starts_with(line, "content-length:"))
    {
        const char *p = line + 15;
        size_t value = 0;

        while (*p == ' ' || *p == '\t')
        {
            p++;
        }
        while (*p >= '0' && *p <= '9')
        {
            value = value * 10u + (size_t)(*p - '0');
            p++;
        }
        stream->content_length = value;
        stream->content_length_seen = true;
    }
    else if (browser_header_starts_with(line, "connection:") &&
             browser_header_contains_token(line + 11, "close"))
    {
        stream->connection_close = true;
    }
    else if (browser_header_starts_with(line, "transfer-encoding:") &&
             browser_header_contains_token(line + 18, "chunked"))
    {
        stream->chunked = true;
        stream->chunk_state = BROWSER_CHUNK_SIZE;
    }
    else if (browser_header_starts_with(line, "content-encoding:") &&
             !browser_header_contains_token(line + 17, "identity"))
    {
        stream->unsupported_encoding = true;
        stream->connection_close = true;
    }
}

static bool browser_stream_header_byte(struct browser_stream_state *stream,
                                       char c)
{
    if (c == '\r')
    {
        return false;
    }
    if (c == '\n')
    {
        stream->header_line[stream->header_line_len] = '\0';
        if (!stream->header_line_len)
        {
            return true;
        }
        browser_stream_process_header_line(stream);
        stream->header_line_len = 0;
        stream->header_line[0] = '\0';
        return false;
    }
    if (stream->header_line_len + 1u < sizeof(stream->header_line))
    {
        stream->header_line[stream->header_line_len++] = c;
    }
    return false;
}

static void browser_stream_finish_tag(struct browser_state *state)
{
    struct browser_stream_state *stream = &state->stream;

    stream->tag[stream->tag_len] = '\0';
    if (!stream->tag_ignore && stream->tag[0])
    {
        if (strcmp(stream->tag, "body") == 0 && !stream->tag_closing)
        {
            stream->parse.skip = false;
            stream->parse.skip_tag[0] = '\0';
            (void)browser_element_emit_tag_with_names(
                state, stream->tag, stream->tag_closing,
                stream->tag_self_closing, stream->tag_class_name,
                stream->tag_id_name);
        }
        else if (strcmp(stream->tag, "style") == 0)
        {
            if (stream->tag_closing)
            {
                browser_stream_flush_style_text(state);
            }
            (void)browser_element_emit_style_tag(state, stream->tag_closing);
            if (stream->tag_closing)
            {
                stream->parse.skip = false;
                stream->parse.skip_tag[0] = '\0';
            }
            else
            {
                stream->parse.skip = true;
                browser_copy(stream->parse.skip_tag,
                             sizeof(stream->parse.skip_tag),
                             stream->tag);
            }
        }
        else if (stream->parse.skip)
        {
            if (stream->tag_closing &&
                browser_tag_name_match(stream->tag,
                                       stream->parse.skip_tag))
            {
                stream->parse.skip = false;
                stream->parse.skip_tag[0] = '\0';
            }
        }
        else if (browser_tag_suppresses_content(stream->tag) &&
                 !stream->tag_closing)
        {
            stream->parse.skip = true;
            browser_copy(stream->parse.skip_tag,
                         sizeof(stream->parse.skip_tag),
                         stream->tag);
        }
        else if (strcmp(stream->tag, "br") == 0)
        {
            (void)browser_element_emit_break(state);
        }
        else
        {
            (void)browser_element_emit_tag_with_names(
                state, stream->tag, stream->tag_closing,
                stream->tag_self_closing, stream->tag_class_name,
                stream->tag_id_name);
        }
    }
    stream->in_tag = false;
    stream->tag_ignore = false;
    stream->tag_closing = false;
    stream->tag_self_closing = false;
    stream->tag_name_done = false;
    stream->tag_len = 0;
    stream->tag_class_name = BROWSER_OBJECT_NULL;
    stream->tag_id_name = BROWSER_OBJECT_NULL;
    browser_stream_attr_reset(stream);
}

static void browser_stream_flush_text(struct browser_state *state)
{
    struct browser_stream_state *stream = &state->stream;

    if (!stream->text_len)
    {
        return;
    }
    (void)browser_element_emit_text(state, stream->text, stream->text_len);
    stream->text_len = 0;
    stream->text[0] = '\0';
}

static void browser_stream_flush_style_text(struct browser_state *state)
{
    struct browser_stream_state *stream = &state->stream;

    if (!stream->text_len)
    {
        return;
    }
    (void)browser_element_emit_style_text(state, stream->text,
                                          stream->text_len);
    stream->text_len = 0;
    stream->text[0] = '\0';
}

static void browser_stream_emit_text_char(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    stream->text[stream->text_len++] = c;
    stream->text[stream->text_len] = '\0';
    if (stream->text_len == BROWSER_ELEMENT_TEXT_MAX)
    {
        browser_stream_flush_text(state);
    }
}

static void browser_stream_emit_style_char(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    stream->text[stream->text_len++] = c;
    stream->text[stream->text_len] = '\0';
    if (stream->text_len == BROWSER_ELEMENT_TEXT_MAX)
    {
        browser_stream_flush_style_text(state);
    }
}

static void browser_stream_text_char(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    if (stream->parse.skip)
    {
        if (strcmp(stream->parse.skip_tag, "style") == 0)
        {
            browser_stream_emit_style_char(state, c);
        }
        return;
    }
    if (stream->in_entity)
    {
        if (c == ';')
        {
            char out = browser_entity_char(stream->entity,
                                           stream->entity_len);
            if (out)
            {
                browser_stream_emit_text_char(state, out);
            }
            stream->in_entity = false;
            stream->entity_len = 0;
            return;
        }
        if (stream->entity_len < sizeof(stream->entity) - 1u &&
            (isalnum((unsigned char)c) || c == '#'))
        {
            stream->entity[stream->entity_len++] = c;
            stream->entity[stream->entity_len] = '\0';
            return;
        }
        browser_stream_emit_text_char(state, '&');
        for (uint8_t i = 0; i < stream->entity_len; i++)
        {
            browser_stream_emit_text_char(state, stream->entity[i]);
        }
        stream->in_entity = false;
        stream->entity_len = 0;
    }
    if (c == '&')
    {
        stream->in_entity = true;
        stream->entity_len = 0;
        stream->entity[0] = '\0';
        return;
    }
    browser_stream_emit_text_char(state, c);
}

static int8_t browser_hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return (int8_t)(c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return (int8_t)(10 + c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return (int8_t)(10 + c - 'A');
    }
    return -1;
}

static void browser_stream_attr_reset(struct browser_stream_state *stream)
{
    stream->attr_want_value = false;
    stream->attr_in_value = false;
    stream->attr_quote = '\0';
    stream->attr_target = 0;
    stream->attr_name_len = 0;
    stream->attr_name[0] = '\0';
    stream->attr_value_len = 0;
    stream->attr_value[0] = '\0';
}

static void browser_stream_attr_commit(struct browser_state *state)
{
    struct browser_stream_state *stream = &state->stream;

    if (!stream->attr_target || !stream->attr_value_len || !state->browser)
    {
        browser_stream_attr_reset(stream);
        return;
    }

    if (stream->attr_target == 1)
    {
        stream->tag_id_name =
            state->browser->append_id_name(stream->attr_value,
                                           stream->attr_value_len);
    }
    else if (stream->attr_target == 2)
    {
        stream->tag_class_name =
            state->browser->append_class_name(stream->attr_value,
                                              stream->attr_value_len);
    }
    browser_stream_attr_reset(stream);
}

static void browser_stream_tag_attr_char(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    if (stream->attr_in_value)
    {
        if ((stream->attr_quote && c == stream->attr_quote) ||
            (!stream->attr_quote && isspace((unsigned char)c)))
        {
            browser_stream_attr_commit(state);
            return;
        }
        if (stream->attr_value_len + 1u < sizeof(stream->attr_value))
        {
            stream->attr_value[stream->attr_value_len++] = c;
            stream->attr_value[stream->attr_value_len] = '\0';
        }
        return;
    }

    if (stream->attr_want_value)
    {
        if (isspace((unsigned char)c))
        {
            return;
        }
        if (c == '"' || c == '\'')
        {
            stream->attr_quote = c;
            stream->attr_in_value = true;
            return;
        }
        stream->attr_quote = '\0';
        stream->attr_in_value = true;
        browser_stream_tag_attr_char(state, c);
        return;
    }

    if (isspace((unsigned char)c) || c == '/')
    {
        browser_stream_attr_reset(stream);
        return;
    }
    if (c == '=')
    {
        stream->attr_name[stream->attr_name_len] = '\0';
        if (strcmp(stream->attr_name, "id") == 0)
        {
            stream->attr_target = 1;
        }
        else if (strcmp(stream->attr_name, "class") == 0)
        {
            stream->attr_target = 2;
        }
        else
        {
            stream->attr_target = 0;
        }
        stream->attr_want_value = true;
        return;
    }
    if (isalnum((unsigned char)c) || c == '-')
    {
        if (stream->attr_name_len + 1u < sizeof(stream->attr_name))
        {
            stream->attr_name[stream->attr_name_len++] =
                (char)tolower((unsigned char)c);
            stream->attr_name[stream->attr_name_len] = '\0';
        }
    }
}

static void browser_interpreter_body_byte(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    if (stream->in_tag)
    {
        if (c == '>')
        {
            browser_stream_attr_commit(state);
            browser_stream_finish_tag(state);
            goto maybe_done;
        }
        if (stream->tag_len == 0 && !stream->tag_closing &&
            !stream->tag_name_done)
        {
            if (c == '!')
            {
                stream->tag_ignore = true;
                goto maybe_done;
            }
            if (c == '/')
            {
                stream->tag_closing = true;
                goto maybe_done;
            }
            if (isspace((unsigned char)c))
            {
                goto maybe_done;
            }
        }
        if (c == '/')
        {
            stream->tag_self_closing = true;
        }
        if (!stream->tag_name_done)
        {
            if (isalnum((unsigned char)c))
            {
                if (stream->tag_len + 1u < sizeof(stream->tag))
                {
                    stream->tag[stream->tag_len++] =
                        (char)tolower((unsigned char)c);
                }
            }
            else if (stream->tag_len)
            {
                stream->tag_name_done = true;
            }
        }
        else
        {
            browser_stream_tag_attr_char(state, c);
        }
        goto maybe_done;
    }

    if (c == '<')
    {
        browser_stream_flush_text(state);
        stream->in_tag = true;
        stream->tag_ignore = false;
        stream->tag_closing = false;
        stream->tag_self_closing = false;
        stream->tag_name_done = false;
        stream->tag_len = 0;
        stream->tag[0] = '\0';
        stream->tag_class_name = BROWSER_OBJECT_NULL;
        stream->tag_id_name = BROWSER_OBJECT_NULL;
        browser_stream_attr_reset(stream);
        goto maybe_done;
    }
    browser_stream_text_char(state, c);

maybe_done:
    return;
}

static void browser_stream_body_byte(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    stream->body_seen = true;
    stream->body_bytes++;
    if (state->browser &&
        !state->browser->receive_http_payload(state, &c, 1u))
    {
        state->document_alloc_failed = true;
    }

    if (!stream->chunked &&
        stream->content_length_seen &&
        stream->body_bytes >= stream->content_length)
    {
        stream->body_done = true;
    }
}

static void browser_stream_chunk_byte(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    switch (stream->chunk_state)
    {
    case BROWSER_CHUNK_SIZE:
        if (c == '\r')
        {
            return;
        }
        if (c == '\n')
        {
            if (stream->chunk_size == 0)
            {
                stream->chunk_state = BROWSER_CHUNK_DONE;
                browser_stream_flush_text(state);
                stream->header_line_len = 0;
                stream->header_line[0] = '\0';
                return;
            }
            stream->chunk_remaining = stream->chunk_size;
            stream->chunk_size = 0;
            stream->chunk_size_ext = false;
            stream->chunk_state = BROWSER_CHUNK_DATA;
            return;
        }
        if (c == ';')
        {
            stream->chunk_size_ext = true;
            return;
        }
        if (!stream->chunk_size_ext)
        {
            int8_t value = browser_hex_value(c);
            if (value >= 0)
            {
                stream->chunk_size =
                    (stream->chunk_size << 4) + (size_t)value;
            }
        }
        return;

    case BROWSER_CHUNK_DATA:
        if (stream->chunk_remaining)
        {
            browser_stream_body_byte(state, c);
            stream->chunk_remaining--;
            if (!stream->chunk_remaining)
            {
                stream->chunk_state = BROWSER_CHUNK_DATA_CR;
            }
        }
        return;

    case BROWSER_CHUNK_DATA_CR:
        if (c == '\n')
        {
            stream->chunk_state = BROWSER_CHUNK_SIZE;
        }
        else if (c == '\r')
        {
            stream->chunk_state = BROWSER_CHUNK_DATA_LF;
        }
        else
        {
            stream->chunk_state = BROWSER_CHUNK_SIZE;
        }
        return;

    case BROWSER_CHUNK_DATA_LF:
        stream->chunk_state = BROWSER_CHUNK_SIZE;
        return;

    case BROWSER_CHUNK_DONE:
        if (c == '\r')
        {
            return;
        }
        if (c == '\n')
        {
            if (!stream->header_line_len)
            {
                stream->body_done = true;
                return;
            }
            stream->header_line_len = 0;
            stream->header_line[0] = '\0';
            return;
        }
        if (stream->header_line_len + 1u < sizeof(stream->header_line))
        {
            stream->header_line[stream->header_line_len++] = c;
            stream->header_line[stream->header_line_len] = '\0';
        }
        return;
    default:
        return;
    }
}

static void browser_stream_parse_byte(struct browser_state *state, char c)
{
    struct browser_stream_state *stream = &state->stream;

    if (!stream->headers_done)
    {
        stream->headers_done = browser_stream_header_byte(stream, c);
        if (stream->headers_done && stream->unsupported_encoding)
        {
            (void)browser_element_emit_text(
                state, "Unsupported content encoding",
                sizeof("Unsupported content encoding") - 1u);
            stream->body_done = true;
        }
        if (stream->headers_done && stream->content_length_seen &&
            stream->content_length == 0)
        {
            stream->body_done = true;
        }
        return;
    }
    if (stream->body_done)
    {
        return;
    }
    if (stream->chunked)
    {
        browser_stream_chunk_byte(state, c);
        return;
    }
    browser_stream_body_byte(state, c);
}

static void browser_stream_parse(struct browser_state *state,
                                 const char *data,
                                 size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        browser_stream_parse_byte(state, data[i]);
    }
}

struct browser_layout
{
    uint16_t row;
    uint8_t col;
    browser_style_t style;
    bool last_space;
    bool any;
};

static bool browser_view_prepare(struct browser_state *state)
{
    if (!browser_page_alloc(state))
    {
        return false;
    }
    browser_page_init_rows(state->page.rows, 0, state->page.row_capacity);
    state->page.row_count = 0;
    state->page.total_rows = 0;
    state->page.col = 0;
    state->page.last_space = false;
    state->page.style = BROWSER_STYLE_NORMAL;
    return true;
}

static struct browser_render_row *browser_layout_row(
    struct browser_state *state,
    const struct browser_layout *layout)
{
    struct browser_page *page = &state->page;

    while (page->row_count <= layout->row)
    {
        if (!browser_page_append_row(state))
        {
            return nullptr;
        }
    }
    return &page->rows[layout->row];
}

static void browser_layout_newline(struct browser_layout *layout)
{
    if (layout->col || !layout->any)
    {
        layout->row++;
    }
    layout->col = 0;
    layout->last_space = false;
}

static void browser_layout_char(struct browser_state *state,
                                struct browser_layout *layout,
                                char c)
{
    struct browser_render_row *row;

    if (c == '\r')
    {
        return;
    }
    if (c == '\n')
    {
        browser_layout_newline(layout);
        return;
    }
    if ((unsigned char)c <= ' ')
    {
        c = ' ';
    }
    if (c == ' ' && layout->col == 0)
    {
        return;
    }
    if (c == ' ' && layout->last_space)
    {
        return;
    }
    if (layout->col >= BROWSER_ROW_COLS)
    {
        browser_layout_newline(layout);
    }

    row = browser_layout_row(state, layout);
    if (row && layout->col < BROWSER_ROW_COLS)
    {
        row->text[layout->col] = browser_printable(c);
        row->text[layout->col + 1u] = '\0';
        row->color = browser_style_color(layout->style);
    }
    layout->col++;
    layout->last_space = c == ' ';
    layout->any = true;
}

static void browser_layout_text(struct browser_state *state,
                                struct browser_layout *layout,
                                const char *text)
{
    while (text && *text)
    {
        browser_layout_char(state, layout, *text++);
    }
}

static void browser_layout_tag(struct browser_state *state,
                               struct browser_layout *layout,
                               const struct browser_element *element)
{
    browser_display_t display = element->style.display;

    if (display == BROWSER_DISPLAY_NONE)
    {
        return;
    }
    if (strcmp(element->tag, "br") == 0)
    {
        browser_layout_newline(layout);
        return;
    }
    if (browser_tag_is_media(element->tag) && !element->closing)
    {
        (void)state;
        return;
    }
    if (display == BROWSER_DISPLAY_BLOCK)
    {
        if (element->closing || element->self_closing)
        {
            browser_layout_newline(layout);
        }
        else if (layout->col)
        {
            browser_layout_newline(layout);
        }
    }
}

static void browser_layout_object_tag(struct browser_state *state,
                                      struct browser_layout *layout,
                                      const struct browser_render_object *object)
{
    browser_display_t display = object->style.display;

    if (display == BROWSER_DISPLAY_NONE)
    {
        return;
    }
    if (object->tag_id == BROWSER_HTML_BR)
    {
        browser_layout_newline(layout);
        return;
    }
    if (object->content_type == BROWSER_CONTENT_UNSUPPORTED ||
        browser_tag_id_is_media(object->tag_id))
    {
        (void)state;
        return;
    }
    if (display == BROWSER_DISPLAY_BLOCK)
    {
        if (object->closing || object->self_closing)
        {
            browser_layout_newline(layout);
        }
        else if (layout->col)
        {
            browser_layout_newline(layout);
        }
    }
}

static void browser_layout_object_text(struct browser_state *state,
                                       struct browser_layout *layout,
                                       const struct browser_render_object *object)
{
    char buf[BROWSER_ELEMENT_TEXT_MAX + 1];
    uint32_t offset = object->content_offset;
    uint16_t remaining = object->content_len;
    browser_style_t old_style = layout->style;

    if (!state->browser || object->content_type != BROWSER_CONTENT_STRING ||
        object->content_offset > UINT16_MAX)
    {
        return;
    }

    layout->style = object->style.text_style;
    while (remaining)
    {
        size_t chunk = remaining;
        if (chunk > BROWSER_ELEMENT_TEXT_MAX)
        {
            chunk = BROWSER_ELEMENT_TEXT_MAX;
        }
        if (!state->browser->raw_content_at((uint16_t)offset, buf, chunk))
        {
            break;
        }
        buf[chunk] = '\0';
        browser_layout_text(state, layout, buf);
        offset += (uint32_t)chunk;
        remaining = (uint16_t)(remaining - chunk);
    }
    layout->style = old_style;
}

static bool browser_layout_render_objects(struct browser_state *state,
                                          struct browser_layout *layout)
{
    uint16_t count;

    if (!state->browser)
    {
        return false;
    }
    count = state->browser->render_object_count();
    if (!count)
    {
        return false;
    }

    for (uint16_t i = 0; i < count; i++)
    {
        struct browser_render_object object;

        if (!state->browser->render_object_at(i, &object))
        {
            return true;
        }
        if (object.object_kind == BROWSER_OBJECT_STYLE)
        {
            continue;
        }
        if (object.element_type == BROWSER_ELEMENT_TEXT)
        {
            browser_layout_object_text(state, layout, &object);
        }
        else if (object.element_type == BROWSER_ELEMENT_BREAK)
        {
            browser_layout_newline(layout);
        }
        else if (object.element_type == BROWSER_ELEMENT_TAG)
        {
            browser_layout_object_tag(state, layout, &object);
        }
    }

    return true;
}

static void browser_layout_document(struct browser_state *state)
{
    struct browser_layout layout = {0};
    uint16_t i;
    bool rendered_objects;

    if (!state->page_dirty)
    {
        return;
    }
    if (!browser_view_prepare(state))
    {
        return;
    }

    layout.style = BROWSER_STYLE_NORMAL;
    rendered_objects = browser_layout_render_objects(state, &layout);
    for (i = 0; !rendered_objects && i < state->document_count; i++)
    {
        const struct browser_element *element = &state->document[i];

        if (element->type == BROWSER_ELEMENT_TEXT)
        {
            browser_style_t old_style = layout.style;
            layout.style = element->style.text_style;
            browser_layout_text(state, &layout, element->text);
            layout.style = old_style;
        }
        else if (element->type == BROWSER_ELEMENT_BREAK)
        {
            browser_layout_newline(&layout);
        }
        else
        {
            browser_layout_tag(state, &layout, element);
        }
    }

    state->page.total_rows = layout.any ? (uint16_t)(layout.row + 1u) : 0;
    if (state->page.total_rows > state->page.row_count)
    {
        state->page.total_rows = state->page.row_count;
    }
    browser_page_shrink_to_fit(state);
    if (state->scroll_line >= state->page.total_rows &&
        state->page.total_rows)
    {
        state->scroll_line = state->page.total_rows - 1u;
        state->page_dirty = true;
        browser_layout_document(state);
        return;
    }
    state->page_dirty = false;
}

static void browser_draw_row(uint8_t row, const char *text, uint8_t color,
                             uint8_t x_offset)
{
    uint8_t y = (uint8_t)(BROWSER_BODY_Y + row * BROWSER_LINE_H);
    const char *start = text ? text : "";
    char visible[BROWSER_COLS + 1];
    size_t len;

    gfx_SetColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_FillRectangle(0, y, LWIP_EXAMPLE_LCD_W, BROWSER_LINE_H);
    gfx_SetTextFGColor(color);
    if (strlen(start) > x_offset)
    {
        start += x_offset;
    }
    else
    {
        start = "";
    }
    len = strlen(start);
    if (len > BROWSER_COLS)
    {
        len = BROWSER_COLS;
    }
    memcpy(visible, start, len);
    visible[len] = '\0';
    gfx_PrintStringXY(visible, 0, y);
}

static char browser_mode_char(const struct browser_state *state)
{
    if (state->input_upper_once)
    {
        return 'A';
    }
    switch ((lwip_example_chat_input_mode_t)state->input_mode)
    {
    case LWIP_EXAMPLE_CHAT_MODE_UPPER: return 'A';
    case LWIP_EXAMPLE_CHAT_MODE_NUMERIC: return '0';
    case LWIP_EXAMPLE_CHAT_MODE_LOWER:
    default: return 'a';
    }
}

static void browser_draw_url(const struct browser_state *state)
{
    const char *url = state->editing ? state->edit_url : state->url;
    char line[BROWSER_COLS + 1];
    size_t len;

    if (state->editing)
    {
        char edit[BROWSER_URL_MAX + 3];
        const char *tail;

        snprintf(edit, sizeof(edit), "%c>%s", browser_mode_char(state), url);
        len = strlen(edit);
        if (len + 1u < sizeof(line))
        {
            snprintf(line, sizeof(line), "%s", edit);
            len = strlen(line);
            line[len++] = '_';
            line[len] = '\0';
        }
        else
        {
            tail = edit + (len - (sizeof(line) - 1u));
            snprintf(line, sizeof(line), "%s", tail);
            line[sizeof(line) - 2u] = '_';
            line[sizeof(line) - 1u] = '\0';
        }
    }
    else
    {
        snprintf(line, sizeof(line), "%s", url);
    }
    gfx_SetColor(state->editing ? LWIP_EXAMPLE_COLOR_SYSTEM
                                : LWIP_EXAMPLE_COLOR_FG);
    gfx_FillRectangle(0, BROWSER_BAR_Y, LWIP_EXAMPLE_LCD_W, BROWSER_BAR_H);
    gfx_SetTextFGColor(BROWSER_COLOR_URL_TEXT);
    gfx_PrintStringXY(line, 0, BROWSER_URL_Y);
}

static void browser_draw_body(const struct browser_state *state)
{
    uint8_t drawn = 0;

    if (state->fetch.active && !state->stream.headers_done &&
        state->event_line[0])
    {
        browser_draw_row(drawn++, state->event_line,
                         BROWSER_COLOR_HEADING, 0);
    }

    if (!state->page.rows || !state->page.row_count)
    {
        while (drawn < BROWSER_VISIBLE_ROWS)
        {
            browser_draw_row(drawn++, "", LWIP_EXAMPLE_COLOR_FG, 0);
        }
        return;
    }

    while (drawn < BROWSER_VISIBLE_ROWS)
    {
        uint16_t page_row = (uint16_t)(state->scroll_line + drawn);
        if (page_row < state->page.row_count)
        {
            browser_draw_row(drawn, state->page.rows[page_row].text,
                             state->page.rows[page_row].color,
                             state->scroll_col);
        }
        else
        {
            browser_draw_row(drawn, "", LWIP_EXAMPLE_COLOR_FG, 0);
        }
        drawn++;
    }
}

static void browser_render(struct browser_state *state)
{
    browser_layout_document(state);
    gfx_SetColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_FillScreen(LWIP_EXAMPLE_COLOR_BG);
    browser_draw_url(state);
    browser_draw_body(state);
    lwip_example_draw_mem_stats();
    lwip_example_present();
}

static void browser_history_push(struct browser_state *state, const char *url)
{
    uint8_t i;

    if (!url || !url[0])
    {
        return;
    }
    if (state->history_count &&
        strcmp(state->history[state->history_count - 1u], url) == 0)
    {
        return;
    }
    if (state->history_count == BROWSER_HISTORY_DEPTH)
    {
        for (i = 1; i < BROWSER_HISTORY_DEPTH; i++)
        {
            browser_copy(state->history[i - 1], sizeof(state->history[0]),
                         state->history[i]);
        }
        state->history_count--;
    }
    browser_copy(state->history[state->history_count++],
                 sizeof(state->history[0]), url);
}

static void browser_forward_push(struct browser_state *state, const char *url)
{
    uint8_t i;

    if (!url || !url[0])
    {
        return;
    }
    if (state->forward_count &&
        strcmp(state->forward_history[state->forward_count - 1u], url) == 0)
    {
        return;
    }
    if (state->forward_count == BROWSER_HISTORY_DEPTH)
    {
        for (i = 1; i < BROWSER_HISTORY_DEPTH; i++)
        {
            browser_copy(state->forward_history[i - 1],
                         sizeof(state->forward_history[0]),
                         state->forward_history[i]);
        }
        state->forward_count--;
    }
    browser_copy(state->forward_history[state->forward_count++],
                 sizeof(state->forward_history[0]), url);
}

static bool browser_history_back(struct browser_state *state)
{
    if (!state->history_count)
    {
        return false;
    }
    browser_forward_push(state, state->url);
    state->history_count--;
    browser_copy(state->url, sizeof(state->url),
                 state->history[state->history_count]);
    return true;
}

static bool browser_history_forward(struct browser_state *state)
{
    if (!state->forward_count)
    {
        return false;
    }
    browser_history_push(state, state->url);
    state->forward_count--;
    browser_copy(state->url, sizeof(state->url),
                 state->forward_history[state->forward_count]);
    return true;
}

static void browser_fetch_drain(struct lwip_socket *sock,
                                struct browser_fetch_state *fetch)
{
    struct browser_state *state;

    if (!sock || !fetch || !fetch->state)
    {
        return;
    }

    state = fetch->state;
    while (!state->stream.body_done && lwip_socket_available(sock))
    {
        size_t avail = lwip_socket_available(sock);
        if (avail > sizeof(state->rx_chunk))
        {
            avail = sizeof(state->rx_chunk);
        }
        avail = lwip_socket_read(sock, (uint8_t *)state->rx_chunk, avail);
        if (!avail)
        {
            break;
        }
        browser_stream_parse(state, state->rx_chunk, avail);
    }
    fetch->readable = false;
}

static void browser_fetch_send_request(struct lwip_socket *sock,
                                       struct browser_fetch_state *fetch)
{
    lwip_error_t err;

    if (!sock || !fetch || !fetch->send_pending || fetch->sent)
    {
        return;
    }

    err = lwip_socket_write(sock, (const uint8_t *)fetch->request,
                            fetch->request_len);
    if (err == LWIP_OK)
    {
        fetch->sent = true;
        fetch->send_pending = false;
        return;
    }
    if (err == LWIP_ERR_MEM)
    {
        return;
    }

    fetch->err = err;
    fetch->err_component = LWIP_SOCKET_ERR_COMP_SOCKET;
    fetch->err_operation = LWIP_SOCKET_ERR_OP_WRITE;
    fetch->raw_error = 0;
    fetch->send_pending = false;
    fetch->done = true;
}

static bool browser_fetch_connect_socket(struct browser_state *state)
{
    lwip_error_t err;

    if (!state->sock)
    {
        browser_set_body(state, "Socket unavailable");
        return false;
    }
    memset(state->sock, 0, sizeof(*state->sock));
    err = lwip_socket_create_ex(state->sock,
                                state->fetch.req.tls
                                    ? LWIP_SOCKET_ALTCP_TLS
                                    : LWIP_SOCKET_TCP,
                                LWIP_NETIF_EXT, nullptr,
                                BROWSER_SOCKET_TIMEOUT_MS,
                                BROWSER_SOCKET_RX_MAX);
    if (err != LWIP_OK)
    {
        browser_set_body(state, "Socket create failed");
        browser_fetch_cleanup(state);
        return false;
    }

    lwip_socket_on_event(state->sock, LWIP_SOCKET_EVENTF_ALL,
                         browser_on_event, &state->fetch);

    state->socket_valid = true;
    state->socket_req = state->fetch.req;
    browser_stream_reset(state);

    err = lwip_socket_connect(state->sock,
                              state->fetch.req.host,
                              state->fetch.req.port);
    if (err != LWIP_OK)
    {
        char msg[56];
        snprintf(msg, sizeof(msg), "Connect err %u st %s",
                 (unsigned)err,
                 lwip_example_socket_status_name(
                     lwip_socket_status(state->sock)));
        browser_set_body(state, msg);
        browser_fetch_cleanup(state);
        return false;
    }

    return true;
}

void Browser::netif_service_callback(struct netif *netif,
                                     void *arg,
                                     uint8_t service_id,
                                     lwip_netif_service_status_t status)
{
    Browser *browser = (Browser *)arg;

    (void)netif;
    if (!browser)
    {
        return;
    }
    if (status == LWIP_NETIF_SERVICE_UP)
    {
        browser->service_up_mask_ |= service_id;
    }
    else if (status == LWIP_NETIF_SERVICE_TIMEOUT)
    {
        browser->service_timed_out_ = true;
    }
    else
    {
        browser->service_failed_ = true;
    }
}

void Browser::network_watch_timeout(void *arg)
{
    Browser *browser = (Browser *)arg;

    if (!browser)
    {
        return;
    }
    browser->network_watch_active_ = false;
    browser->network_watch_step();
}

void Browser::connect_watch_timeout(void *arg)
{
    Browser *browser = (Browser *)arg;

    if (!browser)
    {
        return;
    }
    browser->connect_watch_active_ = false;
    browser->connect_watch_step();
}

void Browser::network_watch_step(void)
{
    if (flags_ & BROWSER_FLAG_ERROR)
    {
        return;
    }

    if (service_failed_ || service_timed_out_)
    {
        flags_ |= BROWSER_FLAG_ERROR;
        if (state_ && state_->fetch.active && !state_->socket_valid)
        {
            state_->fetch.err = LWIP_ERR_NETIF;
            state_->fetch.err_component = LWIP_SOCKET_ERR_COMP_NETIF;
            state_->fetch.err_operation = LWIP_SOCKET_ERR_OP_SERVICE_WAIT;
            state_->fetch.raw_error = service_timed_out_ ? -1 : 0;
            state_->fetch.done = true;
        }
        return;
    }

    if ((service_up_mask_ & service_requested_mask_) == service_requested_mask_)
    {
        flags_ |= BROWSER_FLAG_READY;
        if (state_ && state_->fetch.active && !state_->socket_valid)
        {
            (void)connect(state_);
        }
        return;
    }

    schedule_network_watch();
}

void Browser::connect_watch_step(void)
{
    lwip_status_t status;

    if (!state_ || !state_->fetch.active || !state_->sock)
    {
        return;
    }

    status = lwip_socket_status(state_->sock);
    if (state_->fetch.connected || status == LWIP_STATUS_CONNECTED)
    {
        flags_ |= BROWSER_FLAG_CONNECTED;
        state_->fetch.connected = true;
        (void)fetch(state_);
        return;
    }

    if (status == LWIP_STATUS_CLOSED ||
        status == LWIP_STATUS_RESET ||
        status == LWIP_STATUS_ERROR ||
        state_->fetch.done ||
        state_->fetch.err != LWIP_OK)
    {
        flags_ |= BROWSER_FLAG_ERROR;
        return;
    }

    connect_watch_ticks_++;
    if (connect_watch_ticks_ >= BROWSER_CONNECT_WATCH_MAX_TICKS)
    {
        flags_ |= BROWSER_FLAG_ERROR;
        state_->fetch.err = LWIP_ERR_CONNECT;
        state_->fetch.err_component = LWIP_SOCKET_ERR_COMP_SOCKET;
        state_->fetch.err_operation = LWIP_SOCKET_ERR_OP_CONNECT;
        state_->fetch.raw_error = -1;
        state_->fetch.done = true;
        return;
    }

    schedule_connect_watch();
}

bool Browser::connect(struct browser_state *state)
{
    state_ = state;
    flags_ &= (uint8_t)~BROWSER_FLAG_CONNECTED;
    if (!service_failed_ && !service_timed_out_)
    {
        flags_ &= (uint8_t)~BROWSER_FLAG_ERROR;
    }

    if (!state)
    {
        flags_ |= BROWSER_FLAG_ERROR;
        return false;
    }
    if (flags_ & BROWSER_FLAG_ERROR)
    {
        state->fetch.err = LWIP_ERR_NETIF;
        state->fetch.err_component = LWIP_SOCKET_ERR_COMP_NETIF;
        state->fetch.err_operation = LWIP_SOCKET_ERR_OP_SERVICE_WAIT;
        state->fetch.done = true;
        return false;
    }
    if (!(flags_ & BROWSER_FLAG_READY))
    {
        browser_set_body(state, "Waiting for network");
        schedule_network_watch();
        return true;
    }
    connect_watch_ticks_ = 0;
    if (!browser_fetch_connect_socket(state))
    {
        flags_ |= BROWSER_FLAG_ERROR;
        return false;
    }
    schedule_connect_watch();
    return true;
}

bool Browser::close(struct browser_state *state)
{
    lwip_status_t status;
    lwip_error_t err;

    flags_ &= (uint8_t)~BROWSER_FLAG_CONNECTED;
    sys_untimeout(connect_watch_timeout, this);
    connect_watch_active_ = false;

    if (!state || !state->socket_valid || !state->sock)
    {
        return true;
    }

    status = lwip_socket_status(state->sock);
    if (status == LWIP_STATUS_CONNECTED || status == LWIP_STATUS_CLOSING)
    {
        err = lwip_socket_close(state->sock);
        if (err == LWIP_OK || err == LWIP_ERR_CLOSED)
        {
            return true;
        }
        if (err == LWIP_ERR_MEM || err == LWIP_ERR_STATE)
        {
            return false;
        }
        browser_fetch_cleanup(state);
        return true;
    }

    return true;
}

bool Browser::fetch(struct browser_state *state)
{
    if (!state || !state->sock || !state->fetch.active ||
        !state->fetch.connected || state->fetch.sent)
    {
        return false;
    }
    state->fetch.send_pending = true;
    browser_fetch_send_request(state->sock, &state->fetch);
    return state->fetch.sent;
}

uint16_t Browser::tag_id_for_name(const char *tag) const
{
    if (!tag || !tag[0]) return BROWSER_HTML_UNKNOWN;
    if (strcmp(tag, "a") == 0) return BROWSER_HTML_A;
    if (strcmp(tag, "body") == 0) return BROWSER_HTML_BODY;
    if (strcmp(tag, "br") == 0) return BROWSER_HTML_BR;
    if (strcmp(tag, "div") == 0) return BROWSER_HTML_DIV;
    if (strcmp(tag, "head") == 0) return BROWSER_HTML_HEAD;
    if (strcmp(tag, "html") == 0) return BROWSER_HTML_HTML;
    if (strcmp(tag, "img") == 0) return BROWSER_HTML_IMG;
    if (strcmp(tag, "p") == 0) return BROWSER_HTML_P;
    if (strcmp(tag, "script") == 0) return BROWSER_HTML_SCRIPT;
    if (strcmp(tag, "style") == 0) return BROWSER_HTML_STYLE;
    if (strcmp(tag, "title") == 0) return BROWSER_HTML_TITLE;
    return BROWSER_HTML_UNKNOWN;
}

uint16_t Browser::append_raw_content(const char *data, size_t len)
{
    uint16_t offset;
    char nul = '\0';

    if (!data || raw_content.size() > UINT16_MAX ||
        raw_content.size() + len + 1u > UINT16_MAX)
    {
        return BROWSER_OBJECT_NULL;
    }
    offset = (uint16_t)raw_content.size();
    if (!raw_content.push(data, len) || !raw_content.push(&nul, 1u))
    {
        return BROWSER_OBJECT_NULL;
    }
    return offset;
}

uint16_t Browser::find_name(const BrowserRingBuffer &names,
                            const char *data,
                            size_t len) const
{
    size_t offset = 0;
    size_t used = names.size();

    if (!data || len > UINT16_MAX)
    {
        return BROWSER_OBJECT_NULL;
    }

    while (offset < used)
    {
        size_t name_len = 0;
        bool match = true;
        char c = '\0';

        while (offset + name_len < used)
        {
            if (!names.read_at(offset + name_len, &c, 1u))
            {
                return BROWSER_OBJECT_NULL;
            }
            if (c == '\0')
            {
                break;
            }
            if (name_len >= len || c != data[name_len])
            {
                match = false;
            }
            name_len++;
        }

        if (offset + name_len >= used)
        {
            return BROWSER_OBJECT_NULL;
        }
        if (match && name_len == len)
        {
            return (uint16_t)offset;
        }
        offset += name_len + 1u;
    }

    return BROWSER_OBJECT_NULL;
}

uint16_t Browser::append_class_name(const char *data, size_t len)
{
    uint16_t offset;
    char nul = '\0';

    if (!data || class_names.size() > UINT16_MAX ||
        class_names.size() + len + 1u > UINT16_MAX)
    {
        return BROWSER_OBJECT_NULL;
    }
    offset = find_name(class_names, data, len);
    if (offset != BROWSER_OBJECT_NULL)
    {
        return offset;
    }
    offset = (uint16_t)class_names.size();
    if (!class_names.push(data, len) || !class_names.push(&nul, 1u))
    {
        return BROWSER_OBJECT_NULL;
    }
    return offset;
}

uint16_t Browser::append_id_name(const char *data, size_t len)
{
    uint16_t offset;
    char nul = '\0';

    if (!data || id_names.size() > UINT16_MAX ||
        id_names.size() + len + 1u > UINT16_MAX)
    {
        return BROWSER_OBJECT_NULL;
    }
    offset = find_name(id_names, data, len);
    if (offset != BROWSER_OBJECT_NULL)
    {
        return offset;
    }
    offset = (uint16_t)id_names.size();
    if (!id_names.push(data, len) || !id_names.push(&nul, 1u))
    {
        return BROWSER_OBJECT_NULL;
    }
    return offset;
}

bool Browser::read_render_object(uint16_t index,
                                 struct browser_render_object *object) const
{
    return index < object_count_ &&
        render_object.read_at((size_t)index * sizeof(*object),
                              object, sizeof(*object));
}

bool Browser::write_render_object(
    uint16_t index,
    const struct browser_render_object *object)
{
    return index < object_count_ &&
        render_object.write_at((size_t)index * sizeof(*object),
                               object, sizeof(*object));
}

uint16_t Browser::append_render_object(
    const struct browser_render_object *object)
{
    if (!object || object_count_ == BROWSER_OBJECT_NULL)
    {
        return BROWSER_OBJECT_NULL;
    }
    if (!render_object.push(object, sizeof(*object)))
    {
        return BROWSER_OBJECT_NULL;
    }
    return object_count_++;
}

void Browser::reset_page_objects(void)
{
    payload_in.clear();
    render_object.clear();
    raw_content.clear();
    class_names.clear();
    id_names.clear();
    object_count_ = 0;
    next_object_id_ = 1;
    dom_depth_ = 0;
    for (uint8_t i = 0; i < BROWSER_DOM_STACK_MAX; i++)
    {
        dom_stack_[i] = BROWSER_OBJECT_NULL;
    }
    flags_ &= (uint8_t)~BROWSER_FLAG_HAS_HTTP_RAW;
}

bool Browser::emit_object(struct browser_state *state,
                          const struct browser_element *element)
{
    struct browser_render_object object;
    uint16_t index;
    uint16_t parent = dom_depth_ ? dom_stack_[dom_depth_ - 1u]
                                 : BROWSER_OBJECT_NULL;

    (void)state;
    if (!element)
    {
        return false;
    }
    if (element->type == BROWSER_ELEMENT_TAG && browser_tag_is_media(element->tag))
    {
        return true;
    }

    memset(&object, 0, sizeof(object));
    object.id = next_object_id_++;
    object.parent = parent;
    object.first_child = BROWSER_OBJECT_NULL;
    object.next_sibling = BROWSER_OBJECT_NULL;
    object.last_child = BROWSER_OBJECT_NULL;
    object.tag_id = element->type == BROWSER_ELEMENT_TAG
        ? tag_id_for_name(element->tag)
        : BROWSER_HTML_UNKNOWN;
    object.object_kind = element->object_kind;
    object.element_type = element->type;
    object.closing = element->closing;
    object.self_closing = element->self_closing;
    object.content_type = BROWSER_CONTENT_NONE;
    object.content_offset = BROWSER_OBJECT_NULL;
    object.content_len = 0;
    object.class_name = element->class_name;
    object.id_name = element->id_name;
    object.style = element->style;

    if (element->type == BROWSER_ELEMENT_TEXT)
    {
        size_t len = strlen(element->text);
        uint16_t offset = append_raw_content(element->text, len);
        if (offset == BROWSER_OBJECT_NULL)
        {
            return false;
        }
        object.content_type = BROWSER_CONTENT_STRING;
        object.content_offset = offset;
        object.content_len = (uint16_t)len;
    }
    else if (browser_tag_is_media(element->tag))
    {
        object.content_type = BROWSER_CONTENT_UNSUPPORTED;
    }

    index = append_render_object(&object);
    if (index == BROWSER_OBJECT_NULL)
    {
        return false;
    }

    if (parent != BROWSER_OBJECT_NULL && !element->closing)
    {
        struct browser_render_object parent_object;
        if (read_render_object(parent, &parent_object))
        {
            if (parent_object.first_child == BROWSER_OBJECT_NULL)
            {
                parent_object.first_child = index;
            }
            else if (parent_object.last_child != BROWSER_OBJECT_NULL)
            {
                struct browser_render_object sibling;
                if (read_render_object(parent_object.last_child, &sibling))
                {
                    sibling.next_sibling = index;
                    (void)write_render_object(parent_object.last_child,
                                              &sibling);
                }
            }
            parent_object.last_child = index;
            (void)write_render_object(parent, &parent_object);
        }
    }

    if (element->type == BROWSER_ELEMENT_TAG && element->closing)
    {
        if (dom_depth_)
        {
            dom_depth_--;
        }
    }
    else if (element->type == BROWSER_ELEMENT_TAG && !element->self_closing &&
        !browser_tag_is_media(element->tag) && dom_depth_ < BROWSER_DOM_STACK_MAX)
    {
        dom_stack_[dom_depth_++] = index;
    }

    return true;
}

bool Browser::receive_http_payload(struct browser_state *state,
                                   const char *data,
                                   size_t len)
{
    (void)state;
    if (!payload_in.push(data, len))
    {
        flags_ |= BROWSER_FLAG_ERROR;
        return false;
    }
    flags_ |= BROWSER_FLAG_HAS_HTTP_RAW;
    schedule_interpreter();
    return true;
}

void Interpreter::run(struct browser_state *state)
{
    char c;

    if (!browser_ || !state)
    {
        return;
    }
    while (browser_->payload_in.pop(&c, 1u) == 1u)
    {
        browser_interpreter_body_byte(state, c);
    }
}

void Browser::interpret(struct browser_state *state)
{
    interpreter.run(state);
    if (!payload_in.size())
    {
        flags_ &= (uint8_t)~BROWSER_FLAG_HAS_HTTP_RAW;
    }
}

void Browser::interpreter_timeout(void *arg)
{
    Browser *browser = (Browser *)arg;

    if (!browser)
    {
        return;
    }
    browser->interpreter_watch_active_ = false;
    if (browser->state_ && (browser->flags_ & BROWSER_FLAG_HAS_HTTP_RAW))
    {
        browser->interpret(browser->state_);
        if (browser->payload_in.size())
        {
            browser->schedule_interpreter();
        }
    }
}

static void browser_fetch_step(struct browser_state *state)
{
    struct browser_fetch_state *fetch = &state->fetch;

    if (!fetch->active && !state->interpreter_working &&
        !state->element_count)
    {
        return;
    }
    if (fetch->active && !fetch->sent && state->sock &&
        (fetch->connected ||
         lwip_socket_status(state->sock) == LWIP_STATUS_CONNECTED))
    {
        fetch->connected = true;
        fetch->send_pending = true;
        browser_fetch_send_request(state->sock, fetch);
    }
    if (fetch->active && fetch->readable)
    {
        browser_fetch_drain(state->sock, fetch);
    }
    if (fetch->active && fetch->send_pending)
    {
        if (state->browser)
        {
            state->browser->fetch(state);
        }
    }
    if (state->interpreter_working || state->element_count)
    {
        browser_styler_step(state, 16);
        browser_renderer_step(state, 16);
    }
}

static void browser_on_event(struct lwip_socket *sock,
                             lwip_socket_event_type_t type,
                             const void *ev_data,
                             void *arg)
{
    struct browser_fetch_state *fetch = (struct browser_fetch_state *)arg;

    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st =
            (const lwip_socket_state_data_t *)ev_data;
        if (st)
        {
            fetch->last_status = st->current;
            if (st->current == LWIP_STATUS_CONNECTED)
            {
                fetch->connected = true;
                fetch->send_pending = true;
                browser_fetch_send_request(sock, fetch);
            }
            else if (st->current == LWIP_STATUS_CLOSED ||
                     st->current == LWIP_STATUS_RESET ||
                     st->current == LWIP_STATUS_ERROR)
            {
                fetch->readable = true;
                fetch->done = true;
                fetch->settle_ticks = BROWSER_CLOSE_DRAIN_TICKS;
            }
        }
        return;
    }

    if (type == LWIP_SOCKET_EV_IO)
    {
        const lwip_socket_io_data_t *io =
            (const lwip_socket_io_data_t *)ev_data;
        if (io && (io->flags & LWIP_SOCKET_IO_READABLE))
        {
            fetch->readable = true;
        }
        if (io && (io->flags & (LWIP_SOCKET_IO_WRITABLE | LWIP_SOCKET_IO_POLL)))
        {
            fetch->send_pending = fetch->send_pending && !fetch->sent;
        }
        return;
    }

    if (type == LWIP_SOCKET_EV_ERROR)
    {
        const lwip_socket_error_data_t *err =
            (const lwip_socket_error_data_t *)ev_data;
        if (err)
        {
            fetch->err = err->err;
            fetch->err_component = (uint16_t)err->component;
            fetch->err_operation = (uint16_t)err->operation;
            fetch->raw_error = err->raw_error;
        }
        else
        {
            fetch->err = sock->last_error;
        }
        fetch->done = true;
        fetch->settle_ticks = BROWSER_CLOSE_DRAIN_TICKS;
    }
}

static void browser_fetch_cleanup(struct browser_state *state)
{
    if (state->sock)
    {
        lwip_socket_destroy(state->sock);
        memset(state->sock, 0, sizeof(*state->sock));
    }
    memset(&state->fetch, 0, sizeof(state->fetch));
    memset(&state->socket_req, 0, sizeof(state->socket_req));
    state->socket_valid = false;
    state->closing_for_navigation = false;
    state->close_pending = false;
    memset(&state->stream, 0, sizeof(state->stream));
    memset(state->elements, 0, sizeof(state->elements));
    state->element_head = 0;
    state->element_count = 0;
    state->interpreter_working = false;
    state->event_line[0] = '\0';
    state->event_dirty = true;
}

static void browser_transient_clear(struct browser_state *state)
{
    browser_document_release(state);
    if (state->browser)
    {
        state->browser->reset_page_objects();
    }
    browser_page_reset(state);
    state->body_len = 0;
    state->body[0] = '\0';
    state->scroll_line = 0;
    state->scroll_col = 0;
    memset(&state->stream, 0, sizeof(state->stream));
    memset(state->elements, 0, sizeof(state->elements));
    state->element_head = 0;
    state->element_count = 0;
    state->next_element_id = 1;
    state->interpreter_working = false;
    state->styler_text_style = BROWSER_STYLE_NORMAL;
    state->page_dirty = true;
}

static bool browser_socket_reusable(const struct browser_state *state,
                                    const struct browser_request *req)
{
    return state->socket_valid &&
        !state->fetch.active &&
        state->sock &&
        lwip_socket_status(state->sock) == LWIP_STATUS_CONNECTED &&
        browser_same_origin(&state->socket_req, req);
}

static void browser_socket_close_for_navigation(struct browser_state *state,
                                                const char *url)
{
    browser_copy(state->pending_url, sizeof(state->pending_url), url);
    browser_normalize_url(state->pending_url, sizeof(state->pending_url));
    state->pending_navigation = true;
    state->closing_for_navigation = true;
    state->close_pending = true;
    state->fetch.active = false;
    state->fetch.send_pending = false;
    state->fetch.readable = false;

    if (!state->socket_valid)
    {
        state->close_pending = false;
        return;
    }

    if (state->browser && state->browser->close(state))
    {
        state->close_pending = false;
    }
    else if (!state->browser)
    {
        state->close_pending = false;
    }
}

static bool browser_navigation_step(struct browser_state *state)
{
    if (!state->pending_navigation)
    {
        if (state->socket_valid && !state->fetch.active &&
            state->sock &&
            !lwip_socket_is_active(state->sock))
        {
            browser_fetch_cleanup(state);
        }
        return false;
    }
    if (state->fetch.active && !state->closing_for_navigation)
    {
        return false;
    }

    if (!state->closing_for_navigation)
    {
        char url[BROWSER_URL_MAX];

        browser_copy(url, sizeof(url), state->pending_url);
        state->pending_navigation = false;
        state->pending_url[0] = '\0';
        browser_copy(state->url, sizeof(state->url), url);
        (void)browser_fetch_start(state);
        return true;
    }

    if (state->closing_for_navigation && state->socket_valid)
    {
        lwip_status_t status = state->sock
            ? lwip_socket_status(state->sock)
            : LWIP_STATUS_CLOSED;

        if (state->close_pending &&
            (status == LWIP_STATUS_CONNECTED ||
             status == LWIP_STATUS_CLOSING))
        {
            if (state->browser && state->browser->close(state))
            {
                state->close_pending = false;
            }
            else if (!state->browser)
            {
                state->close_pending = false;
            }
        }

        if (state->sock && lwip_socket_is_active(state->sock))
        {
            return false;
        }
        browser_fetch_cleanup(state);
        browser_transient_clear(state);
        state->closing_for_navigation = false;
        return true;
    }

    state->closing_for_navigation = false;
    return false;
}

static void browser_fetch_cancel(struct browser_state *state)
{
    if (state->fetch.active)
    {
        browser_fetch_cleanup(state);
    }
    browser_set_body(state, "Cancelled");
}

static bool browser_fetch_finish(struct browser_state *state)
{
    struct browser_fetch_state *fetch = &state->fetch;

    if (!fetch->active)
    {
        return false;
    }

    if (!state->stream.body_done &&
        state->sock &&
        lwip_socket_status(state->sock) == LWIP_STATUS_CONNECTED)
    {
        return false;
    }

    if (!fetch->done && !state->stream.body_done &&
        state->sock &&
        lwip_socket_is_active(state->sock))
    {
        return false;
    }

    browser_fetch_drain(state->sock, fetch);
    if (!state->stream.body_done && fetch->done && fetch->settle_ticks)
    {
        fetch->settle_ticks--;
        return false;
    }

    browser_stream_finish(state);
    while (state->element_count)
    {
        uint8_t before = state->element_count;
        browser_styler_step(state, BROWSER_ELEMENT_RING);
        browser_renderer_step(state, BROWSER_ELEMENT_RING);
        if (state->element_count == before)
        {
            break;
        }
    }

    if (fetch->err != LWIP_OK)
    {
        char msg[BROWSER_BODY_MAX];

        browser_set_fetch_error_body(state, fetch);
        snprintf(msg, sizeof(msg), "%s", state->body);
        browser_fetch_cleanup(state);
        browser_set_body(state, msg);
        return true;
    }

    if (!state->stream.headers_done)
    {
        char msg[56];
        snprintf(msg, sizeof(msg), "No response st %s sent %u",
                 lwip_example_socket_status_name(fetch->last_status),
                 fetch->sent ? 1u : 0u);
        browser_fetch_cleanup(state);
        browser_set_body(state, msg);
        return true;
    }

    browser_page_finish(state);
    fetch->reusable = state->stream.body_done &&
        (state->stream.content_length_seen || state->stream.chunked) &&
        !state->stream.connection_close &&
        state->sock &&
        lwip_socket_status(state->sock) == LWIP_STATUS_CONNECTED;
    if (fetch->reusable)
    {
        memset(&state->fetch, 0, sizeof(state->fetch));
        state->fetch.state = state;
    }
    else
    {
        browser_fetch_cleanup(state);
    }
    if (state->pending_navigation)
    {
        (void)browser_navigation_step(state);
    }
    return true;
}

static bool browser_fetch_start(struct browser_state *state)
{
    struct browser_request req;
    char host_header[BROWSER_HOST_MAX + 8];
    bool reuse_socket;

    if (state->fetch.active)
    {
        return false;
    }

    if (!browser_parse_url(state->url, &req))
    {
        browser_set_body(state, "Invalid URL");
        return false;
    }
    reuse_socket = browser_socket_reusable(state, &req);
    if (state->socket_valid && !reuse_socket)
    {
        browser_fetch_cleanup(state);
    }

    browser_document_release(state);
    browser_page_reset(state);
    state->body_len = 0;
    state->body[0] = '\0';

    if ((req.tls && req.port != 443u) || (!req.tls && req.port != 80u))
    {
        snprintf(host_header, sizeof(host_header), "%s:%u",
                 req.host, (unsigned)req.port);
    }
    else
    {
        browser_copy(host_header, sizeof(host_header), req.host);
    }

    snprintf(state->request, sizeof(state->request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: lwip-ce-browser/1.0 (TI-84+ CE)\r\n"
             "Accept: text/html,*/*\r\n"
             "Accept-Encoding: identity\r\n"
             "Connection: keep-alive\r\n"
             "\r\n",
             req.path, host_header);

    memset(&state->fetch, 0, sizeof(state->fetch));
    state->fetch.state = state;
    state->fetch.active = true;
    state->fetch.request = state->request;
    state->fetch.request_len = strlen(state->request);
    state->fetch.last_status = LWIP_STATUS_INIT;
    state->fetch.req = req;

    if (reuse_socket)
    {
        state->fetch.connected = true;
        state->fetch.last_status = LWIP_STATUS_CONNECTED;
        browser_stream_reset(state);
        if (state->browser)
        {
            (void)state->browser->fetch(state);
        }
        return true;
    }

    return state->browser ? state->browser->connect(state) : false;
}

static uint8_t browser_max_horizontal_scroll(const struct browser_state *state);

static void browser_scroll(struct browser_state *state, int delta)
{
    uint16_t max_scroll = 0;
    uint16_t before = state->scroll_line;

    browser_layout_document(state);
    if (state->page.total_rows > BROWSER_VISIBLE_ROWS)
    {
        max_scroll = (uint16_t)(state->page.total_rows -
                                BROWSER_VISIBLE_ROWS);
    }

    if (delta < 0)
    {
        uint16_t amount = (uint16_t)(-delta);
        if (amount > state->scroll_line)
        {
            state->scroll_line = 0;
        }
        else
        {
            state->scroll_line = (uint16_t)(state->scroll_line - amount);
        }
    }
    else if (delta > 0)
    {
        state->scroll_line = (uint16_t)(state->scroll_line + delta);
        if (state->scroll_line > max_scroll)
        {
            state->scroll_line = max_scroll;
        }
    }
    (void)before;
    if (state->scroll_col > browser_max_horizontal_scroll(state))
    {
        state->scroll_col = browser_max_horizontal_scroll(state);
    }
}

static uint8_t browser_max_horizontal_scroll(const struct browser_state *state)
{
    uint8_t max_scroll = 0;
    uint8_t row;

    if (!state->page.rows || !state->page.row_count)
    {
        return 0;
    }
    for (row = 0; row < BROWSER_VISIBLE_ROWS; row++)
    {
        uint16_t page_row = (uint16_t)(state->scroll_line + row);
        size_t len;
        if (page_row >= state->page.row_count)
        {
            break;
        }
        len = strlen(state->page.rows[page_row].text);
        if (len > BROWSER_COLS && len - BROWSER_COLS > max_scroll)
        {
            max_scroll = (uint8_t)(len - BROWSER_COLS);
        }
    }
    return max_scroll;
}

static void browser_scroll_horizontal(struct browser_state *state, int delta)
{
    uint8_t max_scroll;

    browser_layout_document(state);
    if (delta < 0)
    {
        uint8_t amount = (uint8_t)(-delta);
        state->scroll_col = amount > state->scroll_col
            ? 0
            : (uint8_t)(state->scroll_col - amount);
        return;
    }
    if (delta <= 0)
    {
        return;
    }
    max_scroll = browser_max_horizontal_scroll(state);
    state->scroll_col = (uint8_t)(state->scroll_col + delta);
    if (state->scroll_col > max_scroll)
    {
        state->scroll_col = max_scroll;
    }
}

static void browser_edit_append(struct browser_state *state, char c)
{
    size_t len;

    if (!c || c == ' ')
    {
        return;
    }
    len = strlen(state->edit_url);
    if (len + 1u >= sizeof(state->edit_url))
    {
        return;
    }
    state->edit_url[len++] = c;
    state->edit_url[len] = '\0';
}

static void browser_edit_backspace(struct browser_state *state)
{
    size_t len = strlen(state->edit_url);

    if (len)
    {
        state->edit_url[len - 1u] = '\0';
    }
}

static void browser_goto_internal(struct browser_state *state, const char *url,
                                  bool record_history)
{
    char previous[BROWSER_URL_MAX];
    char target[BROWSER_URL_MAX];
    struct browser_request req;
    bool parsed;

    browser_copy(previous, sizeof(previous), state->url);
    browser_copy(target, sizeof(target), url);
    browser_copy(state->url, sizeof(state->url), target);
    browser_normalize_url(state->url, sizeof(state->url));
    parsed = browser_parse_url(state->url, &req);
    if (record_history && strcmp(previous, state->url) != 0)
    {
        browser_history_push(state, previous);
        state->forward_count = 0;
    }

    if (!parsed)
    {
        (void)browser_fetch_start(state);
        return;
    }

    if (state->fetch.active)
    {
        browser_copy(state->pending_url, sizeof(state->pending_url),
                     state->url);
        state->pending_navigation = true;
        if (!browser_same_origin(&state->fetch.req, &req))
        {
            browser_socket_close_for_navigation(state, state->url);
        }
        return;
    }

    if (state->socket_valid && !browser_same_origin(&state->socket_req, &req))
    {
        browser_socket_close_for_navigation(state, state->url);
        return;
    }

    (void)browser_fetch_start(state);
}

static void browser_goto(struct browser_state *state, const char *url)
{
    browser_goto_internal(state, url, true);
}

static void browser_reload(struct browser_state *state)
{
    browser_goto_internal(state, state->url, false);
}

static void browser_state_release(struct browser_state *state)
{
    if (!state)
    {
        return;
    }
    if (state->fetch.active || state->socket_valid)
    {
        browser_fetch_cleanup(state);
    }
    browser_event_state = nullptr;
    lwip_set_event_cb(nullptr);
    browser_document_release(state);
    browser_page_release(state);
    if (state->browser)
    {
        state->browser->release();
        state->browser = nullptr;
    }
    mem_release(state);
}

int main(void)
{
    static Browser browser;
    static struct lwip_socket sock;
    struct browser_state *state;
    bool redraw = true;

    if (!browser.init())
    {
        return 1;
    }

    state = (struct browser_state *)mem_request(sizeof(*state));
    if (!state)
    {
        lwip_example_show_and_wait("browser mem", "failed");
        browser.release();
        return 1;
    }
    memset(state, 0, sizeof(*state));
    state->browser = &browser;
    browser.attach_state(state);
    state->sock = &sock;
    memset(state->sock, 0, sizeof(*state->sock));
    browser_copy(state->url, sizeof(state->url), BROWSER_URL);
    browser_normalize_url(state->url, sizeof(state->url));
    browser_copy(state->edit_url, sizeof(state->edit_url), state->url);
    state->editing = true;
    state->input_mode = LWIP_EXAMPLE_CHAT_MODE_LOWER;
    browser_set_body(state, "");
    browser_event_state = state;
    lwip_set_event_cb(browser_lwip_event_cb);

    while (true)
    {
        uint8_t key;

        lwip_service_events();
        key = os_GetCSC();
        if (lwip_example_mem_stats_tick(key))
        {
            redraw = true;
        }
        if (state->fetch.active && lwip_example_cancelled(key))
        {
            browser_fetch_cancel(state);
            key = 0;
            redraw = true;
        }
        {
            uint16_t objects_before = state->browser
                ? state->browser->render_object_count()
                : state->document_count;
            bool dirty_before = state->page_dirty;
            browser_fetch_step(state);
            uint16_t objects_after = state->browser
                ? state->browser->render_object_count()
                : state->document_count;
            if (dirty_before || state->page_dirty || state->event_dirty ||
                objects_before != objects_after)
            {
                redraw = true;
                state->event_dirty = false;
            }
        }
        if (browser_fetch_finish(state))
        {
            redraw = true;
        }
        if (browser_navigation_step(state))
        {
            redraw = true;
        }

        if (state->editing)
        {
            switch (key)
            {
            case sk_Clear:
                state->editing = false;
                state->input_upper_once = false;
                redraw = true;
                break;
            case sk_Enter:
                state->editing = false;
                state->input_upper_once = false;
                browser_goto(state, state->edit_url);
                redraw = true;
                break;
            case sk_Del:
                browser_edit_backspace(state);
                redraw = true;
                break;
            case sk_Alpha:
                state->input_mode = (uint8_t)((state->input_mode + 1u) % 3u);
                state->input_upper_once = false;
                redraw = true;
                break;
            case sk_GraphVar:
                state->input_upper_once = true;
                redraw = true;
                break;
            default:
            {
                uint8_t input_mode = state->input_upper_once
                                         ? (uint8_t)LWIP_EXAMPLE_CHAT_MODE_UPPER
                                         : state->input_mode;
                char c = browser_key_to_url_char(key, input_mode);
                if (c)
                {
                    state->input_upper_once = false;
                    browser_edit_append(state, c);
                    redraw = true;
                }
            }
            break;
            }
        }
        else
        {
            switch (key)
            {
            case sk_Clear:
                browser_state_release(state);
                return 0;
            case sk_Yequ:
                if (browser_history_back(state))
                {
                    browser_goto_internal(state, state->url, false);
                    redraw = true;
                }
                break;
            case sk_Graph:
                if (browser_history_forward(state))
                {
                    browser_goto_internal(state, state->url, false);
                    redraw = true;
                }
                break;
            case sk_Window:
                browser_copy(state->edit_url, sizeof(state->edit_url),
                             state->url);
                state->editing = true;
                state->input_upper_once = false;
                redraw = true;
                break;
            case sk_Zoom:
                browser_reload(state);
                redraw = true;
                break;
            case sk_Left:
                browser_scroll_horizontal(state, -4);
                redraw = true;
                break;
            case sk_Right:
                browser_scroll_horizontal(state, 4);
                redraw = true;
                break;
            case sk_Up:
                browser_scroll(state, -1);
                redraw = true;
                break;
            case sk_Down:
                browser_scroll(state, 1);
                redraw = true;
                break;
            default:
                break;
            }
        }

        if (redraw)
        {
            browser_render(state);
            redraw = false;
        }
    }
}
