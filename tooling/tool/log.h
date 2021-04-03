#ifndef LOG_H
#define LOG_H 1

#include <stdio.h>
#define LOG_INFO(fmt, ...) log_to_stream_(stdout, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) log_to_stream_(stderr, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

void log_init();
void log_to_stream_(FILE *stream, const char *src, const char *file, const int line, const char *fmt, ...);

#endif
