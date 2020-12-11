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

void test_parse_gibberish_line(void)
{
        struct transaction_node_t *transac;

        char gibberish[] = "thisisnot A_ValidLine\n\n\n";
        transac = parse_transaction(gibberish);
        CU_ASSERT_PTR_NULL(transac);
}

void test_parse_line_web(void)
{

        struct transaction_node_t *transac;

        char web_norm_buff[] = "192.168.0.1 WEB example.io\n";
        transac = parse_transaction(web_norm_buff);
        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_EQUAL(WEB, transac->type)
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NOT_NULL_FATAL(transac->request);
        CU_ASSERT_STRING_EQUAL("example.io", transac->request);
        transaction_node_free(transac);

        char web_mal_buff[] = "192.168.0.1  WEB example.io     ";
        transac = parse_transaction(web_mal_buff);

        CU_ASSERT_PTR_NOT_NULL_FATAL(transac);
        CU_ASSERT_EQUAL(WEB, transac->type);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NOT_NULL_FATAL(transac->request);
        CU_ASSERT_STRING_EQUAL("example.io", transac->request);
        transaction_node_free(transac);
}

void test_parse_line_dns(void)
{
        struct transaction_node_t *transac;

        char dns_norm_buff[] = "192.168.0.1 DNS example.io\n";
        transac = parse_transaction(dns_norm_buff);
        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_EQUAL(DNS, transac->type)
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NOT_NULL_FATAL(transac->request);
        CU_ASSERT_STRING_EQUAL("example.io", transac->request);
        transaction_node_free(transac);

        char dns_mal_buff[] = "192.168.0.1  DNS example.io     ";
        transac = parse_transaction(dns_mal_buff);

        CU_ASSERT_PTR_NOT_NULL_FATAL(transac);
        CU_ASSERT_EQUAL(DNS, transac->type);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NOT_NULL_FATAL(transac->request);
        CU_ASSERT_STRING_EQUAL("example.io", transac->request);
        transaction_node_free(transac);
}

void test_parse_line_ntp(void)
{
        struct transaction_node_t *transac;

        char dns_norm_buff[] = "192.168.0.1 NTP\n";
        transac = parse_transaction(dns_norm_buff);
        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_EQUAL(NTP, transac->type)
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NULL(transac->request);
        transaction_node_free(transac);

        char dns_mal_buff[] = "192.168.0.1  NTP     ";
        transac = parse_transaction(dns_mal_buff);

        CU_ASSERT_PTR_NOT_NULL_FATAL(transac);
        CU_ASSERT_EQUAL(NTP, transac->type);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NULL(transac->request);
        transaction_node_free(transac);
}

void test_parse_line_comment(void)
{
        struct transaction_node_t *transac;
        char buff[] = "#some comment\n";

        transac = parse_transaction(buff);

        CU_ASSERT_PTR_NULL(transac);
}

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
        ret = CU_add_test(suite, "test of parse line (web)\n", test_parse_line_web);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (dns)\n", test_parse_line_dns);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (ntp)\n", test_parse_line_ntp);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (comment)\n", test_parse_line_comment);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (gibberish)\n", test_parse_gibberish_line);
        CHECK_ERR(ret);

        /* Run all tests using the CUnit Basic interface */
        CU_basic_set_mode(CU_BRM_VERBOSE);
        CU_basic_run_tests();
        CU_cleanup_registry();
        return CU_get_number_of_tests_failed();
}