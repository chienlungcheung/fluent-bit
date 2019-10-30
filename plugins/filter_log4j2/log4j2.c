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
#include <regex.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

static inline int split_log_content_and_pack_it(const char *log_content,
                                                const char *pattern,
                                                msgpack_packer *packer) {
    regex_t regex;
    int ret;
    char msgbuf[100];

    /* Compile regular expression */
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        flb_error("Could not compile regex");
        return FLB_FILTER_NOTOUCH;
    }

    const int MATCHES = 5;
    regmatch_t group[MATCHES + 1];
    const char* keys[5] = {"ts", "thread", "level", "location", "msg"};
    /* Execute regular expression */
    log_content = "2019-10-29 15:20:03.000 [ service-task-2 ] [ ERROR ] [com.iflytek?+.gnome.adx.downplat.media.DownPlat00001_IflyMediaApi] 广告位ID不存在。请检查数据表T_ADUNIT_INFO的ADUNIT_SHOW_ID。 adUnitShowId = 2D7D9B851545AC10BF90B69C4C950652\t, sid = ace3ae2e-1259-4e87-b747-10b4a60e2c61-1572333603000";
    ret = regexec(&regex, log_content, MATCHES, group, 0);
    if (ret == 0) {
        for (int i = 1; i <= MATCHES; i++) {
            int begin = group[i].rm_so;
            if (begin < 0) {
                flb_error("malformed log %s", log_content);
                return FLB_FILTER_NOTOUCH;
            }
            const char *key = keys[i];
            const char *value = mk_string_copy_substr(log_content, begin, group[i].rm_eo);
            // pack key
            msgpack_pack_str(packer, strlen(key));
            msgpack_pack_str_body(packer, key, strlen(key));
            // pack value
            msgpack_pack_str(packer, group[i].rm_eo - begin);
            msgpack_pack_str_body(packer, value, group[i].rm_eo - begin);
        }
    }
    else if (ret == REG_NOMATCH) {
        flb_error("malformed log = %s, pattern = %s", log_content, pattern);
        return FLB_FILTER_NOTOUCH;
    }
    else {
        regerror(ret, &regex, msgbuf, sizeof(msgbuf));
        flb_error("Regex match failed: %s", msgbuf);
        return FLB_FILTER_NOTOUCH;
    }
    /* Free memory allocated to the pattern buffer by regcomp() */
    regfree(&regex);
    return FLB_FILTER_MODIFIED;
}

static int cb_log4j2_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    (void) f_ins;
    (void) config;
    (void) data;

    return 0;
}

static int cb_log4j2_filter(const void *data,                  /* msgpack buffer   */
                            size_t bytes,                      /* msgpack size     */
                            const char *tag, int tag_len,      /* input tag        */
                            void **out_buf,                    /* new data         */
                            size_t * out_size,                 /* new data size    */
                            struct flb_filter_instance *f_ins, /* filter instance  */
                            void *context,                     /* filter priv data */
                            struct flb_config *config)
{
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
    int modified = 1;
    // Iterate item of array
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            flb_error("event type not array");
            modified = 0;
            break;
        }
        // get timestamp and pack it into new buffer
        msgpack_object *ts = &result.data.via.array.ptr[0];
        msgpack_pack_object(&packer, *ts);
        // get log4j2 log kv
        // 2019-10-28 19:00:05.851 [ service-task-12 ] [ ERROR ] [com.iflytek.gnome.adx.downplat.BaseDownPlatHandler] MAB 算法模型异常
        msgpack_object *map = &result.data.via.array.ptr[1];
        // split log into msgpack_object array
        const char *log_content = map->via.map.ptr[0].val.via.str.ptr;
//        const char *pattern = "(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{3}) \\[ (.+?) \\] \\[ (\\w+?) \\] \\[(.+?)\\] (.+?)";
        const char *pattern = "\\[ ER[A-Z].*\\? \\]";
        if (FLB_FILTER_NOTOUCH == split_log_content_and_pack_it(log_content, pattern, &packer)) {
            modified = 0;
            break;
        }
    }
    msgpack_unpacked_destroy(&result);
    if (modified == 0) {
        msgpack_sbuffer_destroy(&buffer);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}


struct flb_filter_plugin filter_log4j2_plugin = {
    .name         = "log4j2",
    .description  = "Convert log4j2 log to json",
    .cb_init      = cb_log4j2_init,
    .cb_filter    = cb_log4j2_filter,
    .cb_exit      = NULL,
    .flags        = 0
};
