#ifndef LOG_H
#define LOG_H 1
#define LOG_INFO(fmt, ...) log_info_(__func__, __FILE__,__LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) log_err_(__func__, __FILE__,__LINE__, fmt, ##__VA_ARGS__)

void log_init();
void log_info_(const char *src, const char *file, const int line,  const char *fmt, ...);
void log_err_(const char *src, const char *file, const int line, const char *fmt, ...);

#endif
