#include <stdio.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "parser.h"

#define CHECK_ERR(x)                           \
        do                                     \
        {                                      \
                if (x == NULL)                 \
                {                              \
                        CU_cleanup_registry(); \
                        return CU_get_error(); \
                }                              \
        } while (0)

void test_parse_line(void) {}

int main(void)
{
        CU_pSuite suite = NULL;

        if (CUE_SUCCESS != CU_initialize_registry())
        {
                return CU_get_error();
        }

        /* add a suite to the registry */
        suite = CU_add_suite("Parser", NULL, NULL);
        if (NULL == suite)
        {
                CU_cleanup_registry();
                return CU_get_error();
        }

        void *ret;
        ret = CU_add_test(suite, "test of func", test_parse_line);
        CHECK_ERR(ret);

        /* Run all tests using the CUnit Basic interface */
        CU_basic_set_mode(CU_BRM_VERBOSE);
        CU_basic_run_tests();
        CU_cleanup_registry();
        return CU_get_error();
}