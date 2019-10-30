//
// Created by hari on 2019/10/30.
//

#ifndef FLUENT_BIT_LOG4J2_H
#define FLUENT_BIT_LOG4J2_H


struct LogMessage {
  const char *ts;
  const char *thread;
  const char *level;
  const char *location;
  const char *msg;

  size_t ts_len;
  size_t thread_len;
  size_t level_len;
  size_t location_len;
  size_t msg_len;

  size_t fileds;
};

static char *pattern;

#endif //FLUENT_BIT_LOG4J2_H
