/**
 * Simple util to restrict static functions except when we are testing
 * 
 */

#ifndef TEST_CONFIG_H

    #ifdef UNIT_TEST

    #define unit_static

    #else

    #define unit_static static

    #endif

#endif