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

void test_parse_gibberish_line(void){
        struct transaction_node_t *transac;

        char gibberish[] = "thisisnot A_ValidLine\n\n\n";
        transac = parse_transaction(gibberish);
        CU_ASSERT_PTR_NULL(transac);
}

void test_parse_line_ntp(void) {
        
        struct transaction_node_t *transac;
        
        
        char ntp_norm_buff[] = "192.168.0.1 02 NTP\n";
        transac = parse_transaction(ntp_norm_buff);
        printf("check non null\n");
        CU_ASSERT_PTR_NOT_NULL(transac);
        printf("check non null done\n");
        CU_ASSERT_TRUE(transac->ctx->flags == 0x02);
        CU_ASSERT_STRING_EQUAL("NTP", transac->ctx->proto);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NULL(transac->request);
        transaction_node_free(transac);
        

        char ntp_mal_buff[] = "192.168.0.1     02      NTP     ";
        transac = parse_transaction(ntp_mal_buff);

        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_TRUE(transac->ctx->flags == 0x02);
        CU_ASSERT_STRING_EQUAL("NTP", transac->ctx->proto);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NULL(transac->request);
        transaction_node_free(transac);
}

void test_parse_line_dns(void) {
        
        struct transaction_node_t *transac;
        

        char dns_norm_buff[] = "192.168.0.1 02 DNS bbc.co.uk\n";
        transac = parse_transaction(dns_norm_buff);

        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_TRUE(transac->ctx->flags == 0x02);
        CU_ASSERT_STRING_EQUAL("DNS", transac->ctx->proto);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_STRING_EQUAL(transac->request, "bbc.co.uk");
        
        transaction_node_free(transac);
        

        char dns_mal_buff[] = "192.168.0.1     02      DNS   bbc.co.uk   ";
        transac = parse_transaction(dns_mal_buff);

        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_TRUE(transac->ctx->flags == 0x02);
        CU_ASSERT_STRING_EQUAL("DNS", transac->ctx->proto);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_STRING_EQUAL(transac->request, "bbc.co.uk");
        transaction_node_free(transac);

        char dns_missing_host[] = "192.168.0.1 02 DNS";
        transac = parse_transaction(dns_missing_host);
        CU_ASSERT_PTR_NULL(transac);
}

void test_parse_line_http(void) {
        
        struct transaction_node_t *transac;
        

        char tcp_norm_buff[] = "192.168.0.1 00 TCP www.bbc.co.uk\n";
        transac = parse_transaction(tcp_norm_buff);

        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_TRUE(transac->ctx->flags == 0x00);
        CU_ASSERT_STRING_EQUAL("TCP", transac->ctx->proto);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NOT_NULL(strstr(transac->request, "www.bbc.co.uk"));
        transaction_node_free(transac);
        

        char tcp_mal_buff[] = "192.168.0.1   00      TCP   www.bbc.co.uk  ";
        transac = parse_transaction(tcp_mal_buff);

        CU_ASSERT_PTR_NOT_NULL(transac);
        CU_ASSERT_TRUE(transac->ctx->flags == 0x00);
        CU_ASSERT_STRING_EQUAL("TCP", transac->ctx->proto);
        CU_ASSERT_STRING_EQUAL("192.168.0.1", transac->ctx->host);
        CU_ASSERT_PTR_NOT_NULL(strstr(transac->request, "www.bbc.co.uk"));
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
        ret = CU_add_test(suite, "test of parse line (ntp)\n", test_parse_line_ntp);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (dns)\n", test_parse_line_dns);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (http)\n", test_parse_line_http);
        CHECK_ERR(ret);

        ret = CU_add_test(suite, "test of parse line (comment)\n", test_parse_line_comment);
        CHECK_ERR(ret);

        // ret = CU_add_test(suite, "test of parse line (gibberish)\n", test_parse_gibberish_line);
        // CHECK_ERR(ret);

        /* Run all tests using the CUnit Basic interface */
        CU_basic_set_mode(CU_BRM_VERBOSE);
        CU_basic_run_tests();
        CU_cleanup_registry();
        return CU_get_number_of_tests_failed();
}