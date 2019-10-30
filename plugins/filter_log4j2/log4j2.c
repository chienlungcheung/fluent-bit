/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_regex.h>
#include <msgpack.h>
#include "log4j2.h"

static struct flb_regex *log_regex = NULL;

static void cb_parse_regex_search_result(const char *name, const char *value,
                                         size_t vlen, void *data) {
    struct LogMessage *logMessage = data;

    if (vlen == 0) {
        return;
    }

    if (logMessage->ts == NULL && strcmp(name, "ts") == 0) {
        logMessage->ts = flb_strndup(value, vlen);
        logMessage->ts_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->thread == NULL && strcmp(name, "thread") == 0) {
        logMessage->thread = flb_strndup(value, vlen);
        logMessage->thread_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->level == NULL && strcmp(name, "level") == 0) {
        logMessage->level = flb_strndup(value, vlen);
        logMessage->level_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->location == NULL && strcmp(name, "location") == 0) {
        logMessage->location = flb_strndup(value, vlen);
        logMessage->location_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->msg == NULL && strcmp(name, "msg") == 0) {
        logMessage->msg = flb_strndup(value, vlen);
        logMessage->msg_len = vlen;
        logMessage->fileds++;
    } else {
        flb_warn("[log4j2] not supported filed, name = %s, value = %s, vlen = %d", name, value, vlen);
    }
    return;
}

static int packLogMessage(msgpack_packer *packer, msgpack_object *ts, struct LogMessage *logMessage) {
    if (packer == NULL || logMessage == NULL || logMessage->fileds == 0) {
        return -1;
    }

    // * Record array init(2)
    msgpack_pack_array(packer, 2);

    // * * Record array item 1/2
    msgpack_pack_object(packer, *ts);

    // * * Record array item 2/2
    msgpack_pack_map(packer, logMessage->fileds);

    if (logMessage->ts != NULL && logMessage->ts_len != 0) {
        const char *key = "ts";
        const size_t key_len = strlen(key);
        const char *value = logMessage->ts;
        const size_t value_len = logMessage->ts_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->thread != NULL && logMessage->thread_len != 0) {
        const char *key = "thread";
        const size_t key_len = strlen(key);
        const char *value = logMessage->thread;
        const size_t value_len = logMessage->thread_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->level != NULL && logMessage->level_len != 0) {
        const char *key = "level";
        const size_t key_len = strlen(key);
        const char *value = logMessage->level;
        const size_t value_len = logMessage->level_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->location != NULL && logMessage->location_len != 0) {
        const char *key = "location";
        const size_t key_len = strlen(key);
        const char *value = logMessage->location;
        const size_t value_len = logMessage->location_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->msg != NULL && logMessage->msg_len != 0) {
        const char *key = "msg";
        const size_t key_len = strlen(key);
        const char *value = logMessage->msg;
        const size_t value_len = logMessage->msg_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    return 0;
}

static inline int split_log_content_and_pack_it(msgpack_packer *packer,
                                                msgpack_object *root) {
    if (packer == NULL || root == NULL) {
        return FLB_FILTER_NOTOUCH;
    }
    msgpack_object ts = root->via.array.ptr[0];
    msgpack_object map = root->via.array.ptr[1];
    const char *log_content = map.via.map.ptr[0].val.via.str.ptr;
    struct flb_regex_search result;
    // do match
    int n = flb_regex_do(log_regex, log_content, strlen(log_content), &result);
    if (n <= 0) {
        flb_warn("[filter_log4j2] invalid pattern = %s for given log_content =  %s", pattern, log_content);
        return FLB_FILTER_NOTOUCH;
    } else {
        struct LogMessage logMessge;
        memset(&logMessge, '\0', sizeof(struct LogMessage));
        // parse the regex results
        int ret = flb_regex_parse(log_regex, &result, cb_parse_regex_search_result, &logMessge);
        if (ret < 0) {
            return FLB_FILTER_NOTOUCH;
        } else {
            packLogMessage(packer, &ts, &logMessge);
            return FLB_FILTER_MODIFIED;
        }
    }
}

static int cb_log4j2_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data) {
    // initialize flb-regrex module
    flb_regex_init();
    pattern = "(?<ts>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{3})\\s*\\[\\s*(?<thread>.+?)\\s*\\]\\s*\\[\\s*(?<level>\\w+?)\\s*\\]\\s*\\[(?<location>.+?)\\]\\s*(?<msg>.+)";
    log_regex = flb_regex_create(pattern);
    if (log_regex == NULL) {
        flb_error("Could not compile regex. pattern = %s", pattern);
        return -1;
    }
    return 0;
}

static int cb_log4j2_filter(const void *data,                  /* msgpack buffer   */
                            size_t bytes,                      /* msgpack size     */
                            const char *tag, int tag_len,      /* input tag        */
                            void **out_buf,                    /* new data         */
                            size_t *out_size,                 /* new data size    */
                            struct flb_filter_instance *f_ins, /* filter instance  */
                            void *context,                     /* filter priv data */
                            struct flb_config *config) {
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    (void) out_buf;
    (void) out_size;
    (void) f_ins;
    (void) context;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

    if (strcmp(tag, "log4j2") != 0) {
        flb_error("[filter] could not filter non-log4j2 text. "
                  "Skipping filtering.");
        return FLB_FILTER_NOTOUCH;
    }

    // out buffer
    msgpack_sbuffer buffer;
    msgpack_sbuffer_init(&buffer);

    msgpack_packer packer;
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    int modified = 0;
    // Iterate item of array
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            // 2019-10-28 19:00:05.851 [ service-task-12 ] [ ERROR ] [com.iflytek.gnome.adx.downplat.BaseDownPlatHandler] MAB 算法模型异常
            if (FLB_FILTER_NOTOUCH == split_log_content_and_pack_it(&packer, &result.data)) {
//                flb_warn("[log4j2] somehow event not touched");
                msgpack_pack_object(&packer, result.data);
            } else {
                modified++;
            }
        } else {
//            flb_warn("[log4j2] event type not array");
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);
    if (modified == 0) {
//        flb_warn("[log4j2] somehow all event not touched");
        msgpack_sbuffer_destroy(&buffer);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_log4j2_exit(void *data, struct flb_config *config) {
    if (log_regex != NULL) {
        flb_regex_destroy(log_regex);
    }
    // exit flb-regex module
    flb_regex_exit();
    return 0;
}

struct flb_filter_plugin filter_log4j2_plugin = {
        .name         = "log4j2",
        .description  = "Convert log4j2 log to json",
        .cb_init      = cb_log4j2_init,
        .cb_filter    = cb_log4j2_filter,
        .cb_exit      = cb_log4j2_exit,
        .flags        = 0
};
