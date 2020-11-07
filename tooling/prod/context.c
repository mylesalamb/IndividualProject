#include <stdlib.h>
#include <string.h>

#include "context.h"

/**
 * Get a string that represents a connection context
 * formatted wrt each protocol implemented
 */
char *get_context_str(struct connection_context_t *ctx)
{
        char *ret;
        
        if (!ctx)
                return NULL;
        

        /* absolute maximum filename */
        ret = malloc(sizeof(char) * 256);
        if(!ret)
        {
                perror("context.c:malloc context str");
        }




}