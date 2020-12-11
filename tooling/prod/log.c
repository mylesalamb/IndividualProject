
#include <stdio.h>
#include <time.h>


clock_t begin;

void log_init()
{
    begin = clock();
}

void log_info_(const char *src, const int line, const char *fmt, ...)
{
    va_list args;
    float curr_time = ((float)clock() - begin) / CLOCKS_PER_SEC;
    
    printf("[ %08.2f ] %s.%d: ", curr_time, src, line);
    
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

void log_err_(const char *src, const int line, const char *fmt, ...)
{

    va_list args;
    float curr_time = ((float)clock() - begin) / CLOCKS_PER_SEC;
    
    fprintf(stderr, "[ %08.2f ] %s: ", curr_time, src);
    
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

}