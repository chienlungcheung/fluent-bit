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
#include "log4business.h"

static struct flb_regex *log_regex = NULL;
static struct flb_regex *err_regex = NULL;

static void cb_parse_regex_search_result(const char *name, const char *value,
                                         size_t vlen, void *data) {
    struct BusinessLogMessage *logMessage = data;

    if (vlen == 0) {
        return;
    }

    if (logMessage->ts == NULL && strcmp(name, "ts") == 0) {
        logMessage->ts = flb_strndup(value, vlen);
        logMessage->ts_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->adunit == NULL && strcmp(name, "adunit") == 0) {
        logMessage->adunit = flb_strndup(value, vlen);
        logMessage->adunit_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->app == NULL && strcmp(name, "app") == 0) {
        logMessage->app = flb_strndup(value, vlen);
        logMessage->app_len = vlen;
        logMessage->fileds++;
    } else if (logMessage->ip == NULL && strcmp(name, "ip") == 0) {
        logMessage->ip = flb_strndup(value, vlen);
        logMessage->ip_len = vlen;
        logMessage->fileds++;
    }  else if (logMessage->err == NULL && strcmp(name, "err") == 0) {
        logMessage->err = flb_strndup(value, vlen);
        logMessage->err_len = vlen;
        logMessage->fileds++;
    } else {
        flb_warn("[log4business] not supported filed, name = %s, value = %s, vlen = %d", name, value, vlen);
    }
    return;
}

static int packLogMessage(msgpack_packer *packer, msgpack_object *ts, struct BusinessLogMessage *logMessage) {
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

    if (logMessage->adunit != NULL && logMessage->adunit_len != 0) {
        const char *key = "adunit";
        const size_t key_len = strlen(key);
        const char *value = logMessage->adunit;
        const size_t value_len = logMessage->adunit_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->app != NULL && logMessage->app_len != 0) {
        const char *key = "app";
        const size_t key_len = strlen(key);
        const char *value = logMessage->app;
        const size_t value_len = logMessage->app_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->ip != NULL && logMessage->ip_len != 0) {
        const char *key = "ip";
        const size_t key_len = strlen(key);
        const char *value = logMessage->ip;
        const size_t value_len = logMessage->ip_len;
        // pack key
        msgpack_pack_str(packer, key_len);
        msgpack_pack_str_body(packer, key, key_len);
        // pack value
        msgpack_pack_str(packer, value_len);
        msgpack_pack_str_body(packer, value, value_len);
    }

    if (logMessage->err != NULL && logMessage->err_len != 0) {
        const char *key = "err";
        const size_t key_len = strlen(key);
        const char *value = logMessage->err;
        const size_t value_len = logMessage->err_len;
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
    // do log match
    int n = flb_regex_do(log_regex, log_content, strlen(log_content), &result);
    if (n <= 0) {
        flb_warn("[filter_log4business] invalid pattern = %s for given log_content =  %s", pattern, log_content);
        // do err match
        n = flb_regex_do(err_regex, log_content, strlen(log_content), &result);
        if (n <= 0) {
            flb_warn("[filter_log4business] invalid pattern = %s for given log_content =  %s", err_pattern, log_content);
            return FLB_FILTER_NOTOUCH;
        } else {
            struct BusinessLogMessage logMessge;
            memset(&logMessge, '\0', sizeof(struct BusinessLogMessage));
            // parse the regex results
            int ret = flb_regex_parse(err_regex, &result, cb_parse_regex_search_result, &logMessge);
            if (ret < 0) {
                return FLB_FILTER_NOTOUCH;
            } else {
                packLogMessage(packer, &ts, &logMessge);
                return FLB_FILTER_MODIFIED;
            }
        }
    } else {
        struct BusinessLogMessage logMessge;
        memset(&logMessge, '\0', sizeof(struct BusinessLogMessage));
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

static int cb_log4business_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data) {
    // initialize flb-regrex module
    flb_regex_init();
    pattern = ".*\\{.*\"millRecvReq\":(?<ts>\\d{10,13}).*\"adUnitId\":(?<adunit>\\d+).*\"app\":\\{.*\"name\":\"(?<app>.+?)\".*\\}.*\"device\":\\{.*\"ip\":\"(?<ip>.+?)\".*\\}.*\\}";
    err_pattern = "\\{\"handle_request_fail_reason\":(?<err>\\[.*?\\])\\}";
    log_regex = flb_regex_create(pattern);
    err_regex = flb_regex_create(err_pattern);
    if (log_regex == NULL) {
        flb_error("Could not compile regex. pattern = %s", pattern);
        return -1;
    }
    if (err_regex == NULL) {
        flb_error("Could not compile regex. pattern = %s", err_pattern);
        return -1;
    }
    return 0;
}

static int cb_log4business_filter(const void *data,                  /* msgpack buffer   */
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

    if (strcmp(tag, "business-log") != 0) {
        flb_error("[filter] could not filter non-log4business text. "
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
            // 2019/11/09 15:00:00 {"ac":0,"convert":0,"replaceId":0,"tfc":false,"predictScore":-2.0,"predictSign":-3,"mediaLogicVersion":3,"isTrafficFromServer":false,"ocpc":false,"firstRoundAdpIdList":[131,37,134],"winnerPlatId":-1,"winnerDealAmountType":0,"traceInfo":{},"httpSupportStatus":3,"nginxTime":1573282800004,"reqRealIp":"125.254.135.4","localIp":"172.21.52.34","endTime":1573282800016,"adUnitStatus":2,"adTemplates":[3],"dLStatus":[1,2],"downRspHasDirectDeeplink":0,"downType":1,"incomeType":2,"income":0.1,"mediaErrInfo":{"errCode":0,"errMsg":"默认正常状态"},"sid":"fc753fdf-d907-4071-828d-c59d8dd8ac5c-1573282800004","millRecvReq":1573282800004,"downPlatId":31,"realDownPlatId":0,"mapUpPlatInfo":{"131":{"discountRatio":1.0,"errInfos":[],"replaceId":0,"bidfloor":4.0,"priceAdjustmentStrategy":0,"ipFilterRedisStatus":1,"platAdUnitId":"93D469E110C95C2A9C571300C3EB7621","httpRspCode":204,"lstInnerMateriel":[],"reqTime":1573282800005,"rspTime":1573282800008,"originalUpPlatHttpStatus":204,"pdbRequestDealInfo":{},"nativeAdMType":0,"dmSign":0,"debugClues":{}},"37":{"discountRatio":1.0,"errInfos":[],"replaceId":0,"bidfloor":0.102,"priceAdjustmentStrategy":2,"ipFilterRedisStatus":0,"platAdUnitId":"93D469E110C95C2A9C571300C3EB7621","httpRspCode":204,"lstInnerMateriel":[],"reqTime":1573282800005,"rspTime":1573282800008,"originalUpPlatHttpStatus":204,"pdbRequestDealInfo":{},"nativeAdMType":0,"dmSign":0,"debugClues":{}},"134":{"discountRatio":1.0,"errInfos":[],"replaceId":0,"bidfloor":2.0,"priceAdjustmentStrategy":0,"ipFilterRedisStatus":0,"platAdUnitId":"93D469E110C95C2A9C571300C3EB7621","httpRspCode":204,"lstInnerMateriel":[],"reqTime":1573282800005,"rspTime":1573282800015,"originalUpPlatHttpStatus":204,"pdbRequestDealInfo":{},"nativeAdMType":0,"dmSign":0,"debugClues":{}}},"adUnitId":42678,"request":{"requestid":"ba301827824d49e5808d82c645f31775","imp":[{"id":"2a101d2002ec421db30bab114952d5d3","bidfloor":9.25,"adunitEffectiveExtCreativeIds":["9","10"],"isboot":0}],"app":{"id":"133966_134815","name":"小哥哥别走3D","bundle":"com.renyouwangluo.xggbz","ver":""},"device":{"ua":"Dalvik/2.1.0 (Linux; U; Android 8.1.0; PBAT00 Build/OPM1.171019.026)","ip":"113.220.89.112","devicetype":2,"make":"OPPO","model":"PBAT00","os":"android","osv":"8.1.0","h":1520,"w":720,"carrier":"46001","connectiontype":2,"imeimd5":"2049990a440852de72142746fecf7900","orientation":0}},"downRspCode":0,"isVoiceAd":false}
            if (FLB_FILTER_NOTOUCH == split_log_content_and_pack_it(&packer, &result.data)) {
//                flb_warn("[log4business] somehow event not touched");
                msgpack_pack_object(&packer, result.data);
            } else {
                modified++;
            }
        } else {
//            flb_warn("[log4business] event type not array");
            msgpack_pack_object(&packer, result.data);
        }
    }
    msgpack_unpacked_destroy(&result);
    if (modified == 0) {
//        flb_warn("[log4business] somehow all event not touched");
        msgpack_sbuffer_destroy(&buffer);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_log4business_exit(void *data, struct flb_config *config) {
    if (log_regex != NULL) {
        flb_regex_destroy(log_regex);
    }
    if (err_regex != NULL) {
        flb_regex_destroy(err_regex);
    }
    // exit flb-regex module
    flb_regex_exit();
    return 0;
}

struct flb_filter_plugin filter_log4business_plugin = {
        .name         = "log4business",
        .description  = "Extract interesting fields from business logs",
        .cb_init      = cb_log4business_init,
        .cb_filter    = cb_log4business_filter,
        .cb_exit      = cb_log4business_exit,
        .flags        = 0
};
