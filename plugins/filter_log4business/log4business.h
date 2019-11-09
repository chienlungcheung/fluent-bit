//
// Created by chienlungcheung on 2019/10/31.
//

#ifndef FLUENT_BIT_LOG4J2_H
#define FLUENT_BIT_LOG4J2_H


static struct BusinessLogMessage {
  const char *ts;
  const char *adunit;
  const char *app;
  const char *ip;

  size_t ts_len;
  size_t adunit_len;
  size_t app_len;
  size_t ip_len;

  size_t fileds;
};

static char *pattern;

#endif //FLUENT_BIT_LOG4J2_H
