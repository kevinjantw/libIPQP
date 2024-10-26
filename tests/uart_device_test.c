#include "ipqp_common.h"
#include "test_common.h"
#include "kat.h"

void test_apdu_uart_status_check(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t status[2] = {0x00, 0x00};
    int ret = apdu_uart_status_check(uart_conf, status);

    printf("test_apdu_uart_status_check(): %d\r\n", ret);
    printf("status: %02X %02X\r\n", status[0], status[1]);

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber512_keypair(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_512_length_public_key];
    memset(pk, 0x00, IPQP_KEM_kyber_512_length_public_key);
    uint8_t sk[IPQP_KEM_kyber_512_length_secret_key];
    memset(sk, 0x00, IPQP_KEM_kyber_512_length_secret_key);

    int ret = apdu_uart_kem_keypair(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)pk, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber512 public key:\r\n");
        print_arr(pk, IPQP_KEM_kyber_512_length_public_key, 32, "PK");
        printf("\r\n");

        printf("Kyber512 secret key:\r\n");
        print_arr(sk, IPQP_KEM_kyber_512_length_secret_key, 32, "SK");
        printf("\r\n");

        if (memcmp(pk, kat_kyber_512_pk, IPQP_KEM_kyber_512_length_public_key) == 0)
            printf("The Kyber512 public key and KAT are the same\r\n");
        else
            printf("The Kyber512 public key and KAT are NOT the same\r\n");

        if (memcmp(sk, kat_kyber_512_sk, IPQP_KEM_kyber_512_length_secret_key) == 0)
            printf("The Kyber512 secret key and KAT are the same\r\n");
        else
            printf("The Kyber512 secret key and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to generate kyber 512 keypair: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber768_keypair(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_768_length_public_key];
    memset(pk, 0x00, IPQP_KEM_kyber_768_length_public_key);
    uint8_t sk[IPQP_KEM_kyber_768_length_secret_key];
    memset(sk, 0x00, IPQP_KEM_kyber_768_length_secret_key);

    int ret = apdu_uart_kem_keypair(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)pk, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber768 public key:\r\n");
        print_arr(pk, IPQP_KEM_kyber_768_length_public_key, 32, "PK");
        printf("\r\n");

        printf("Kyber768 secret key:\r\n");
        print_arr(sk, IPQP_KEM_kyber_768_length_secret_key, 32, "SK");
        printf("\r\n");

        if (memcmp(pk, kat_kyber_768_pk, IPQP_KEM_kyber_768_length_public_key) == 0)
            printf("The Kyber768 public key and KAT are the same\r\n");
        else
            printf("The Kyber768 public key and KAT are NOT the same\r\n");

        if (memcmp(sk, kat_kyber_768_sk, IPQP_KEM_kyber_768_length_secret_key) == 0)
            printf("The Kyber768 secret key and KAT are the same\r\n");
        else
            printf("The Kyber768 secret key and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to generate kyber 768 keypair: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber1024_keypair(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_1024_length_public_key];
    memset(pk, 0x00, IPQP_KEM_kyber_1024_length_public_key);
    uint8_t sk[IPQP_KEM_kyber_1024_length_secret_key];
    memset(sk, 0x00, IPQP_KEM_kyber_1024_length_secret_key);

    int ret = apdu_uart_kem_keypair(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)pk, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber1024 public key:\r\n");
        print_arr(pk, IPQP_KEM_kyber_1024_length_public_key, 32, "PK");
        printf("\r\n");

        printf("Kyber1024 secret key:\r\n");
        print_arr(sk, IPQP_KEM_kyber_1024_length_secret_key, 32, "SK");
        printf("\r\n");

        if (memcmp(pk, kat_kyber_1024_pk, IPQP_KEM_kyber_1024_length_public_key) == 0)
            printf("The Kyber1024 public key and KAT are the same\r\n");
        else
            printf("The Kyber1024 public key and KAT are NOT the same\r\n");

        if (memcmp(sk, kat_kyber_1024_sk, IPQP_KEM_kyber_1024_length_secret_key) == 0)
            printf("The Kyber1024 secret key and KAT are the same\r\n");
        else
            printf("The Kyber1024 secret key and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to generate kyber 1024 keypair: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber512_encap(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_512_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_512_pk, IPQP_KEM_kyber_512_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_512_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_512_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_512_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_512_length_ciphertext);

    int ret = apdu_uart_kem_encap(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber512 Ciphertext:\r\n");
        print_arr(ct, IPQP_KEM_kyber_512_length_ciphertext, 32, "CT");
        printf("\r\n");

        printf("Kyber512 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_512_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ct, kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext) == 0)
            printf("The Kyber512 ciphertext and KAT are the same\r\n");
        else
        {
            printf("The Kyber512 ciphertext and KAT are NOT the same\r\n");
            print_arr(kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext, 32, "CT_KAT");
            printf("\r\n");
        }

        if (memcmp(ss, kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret) == 0)
            printf("The Kyber512 shared sceret and KAT are the same\r\n");
        else
        {
            printf("The Kyber512 shared sceret and KAT are NOT the same\r\n");
            print_arr(kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret, 32, "SS_KAT");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber512_encap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber768_encap(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_768_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_768_pk, IPQP_KEM_kyber_768_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_768_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_768_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_768_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_768_length_ciphertext);

    int ret = apdu_uart_kem_encap(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber768 Ciphertext:\r\n");
        print_arr(ct, IPQP_KEM_kyber_768_length_ciphertext, 32, "CT");
        printf("\r\n");

        printf("Kyber768 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_768_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ct, kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext) == 0)
            printf("The Kyber768 ciphertext and KAT are the same\r\n");
        else
        {
            printf("The Kyber768 ciphertext and KAT are NOT the same\r\n");
            print_arr(kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext, 32, "CT_KAT");
            printf("\r\n");
        }

        if (memcmp(ss, kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret) == 0)
            printf("The Kyber768 shared sceret and KAT are the same\r\n");
        else
        {
            printf("The Kyber768 shared sceret and KAT are NOT the same\r\n");
            print_arr(kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret, 32, "SS_KAT");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber768_encap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber1024_encap(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_1024_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_1024_pk, IPQP_KEM_kyber_1024_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_1024_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_1024_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_1024_length_ciphertext);

    int ret = apdu_uart_kem_encap(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber1024 Ciphertext:\r\n");
        print_arr(ct, IPQP_KEM_kyber_1024_length_ciphertext, 32, "CT");
        printf("\r\n");

        printf("Kyber1024 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ct, kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext) == 0)
            printf("The Kyber1024 ciphertext and KAT are the same\r\n");
        else
        {
            printf("The Kyber1024 ciphertext and KAT are NOT the same\r\n");
            print_arr(kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext, 32, "CT_KAT");
            printf("\r\n");
        }

        if (memcmp(ss, kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret) == 0)
            printf("The Kyber1024 shared sceret and KAT are the same\r\n");
        else
        {
            printf("The Kyber1024 shared sceret and KAT are NOT the same\r\n");
            print_arr(kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "SS_KAT");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber1024_encap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber512_decap(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_512_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_512_sk, IPQP_KEM_kyber_512_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_512_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_512_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_512_length_shared_secret);

    print_arr(sk, IPQP_KEM_kyber_512_length_secret_key, 32, "Kyber512 scetet key");
    printf("\r\n");

    print_arr(ct, IPQP_KEM_kyber_512_length_ciphertext, 32, "Kyber512 ciphertext");
    printf("\r\n");

    int ret = apdu_uart_kem_decap(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber512 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_512_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ss, kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret) == 0)
            printf("The Kyber512 shared scetet and KAT are the same\r\n");
        else
            printf("The Kyber512 shared scetet and KAT are NOT the same\r\n");
    }
    else
    {
        printf("apdu_kem_kyber512_decap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber768_decap(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_768_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_768_sk, IPQP_KEM_kyber_768_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_768_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_768_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_768_length_shared_secret);

    int ret = apdu_uart_kem_decap(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber768 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_768_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ss, kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret) == 0)
            printf("The Kyber768 shared scetet and KAT are the same\r\n");
        else
            printf("The Kyber768 shared scetet and KAT are NOT the same\r\n");
    }
    else
    {
        printf("apdu_kem_kyber768_decap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber1024_decap(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_1024_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_1024_sk, IPQP_KEM_kyber_1024_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_1024_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_1024_length_shared_secret);

    int ret = apdu_uart_kem_decap(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber1024 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ss, kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret) == 0)
            printf("The Kyber1024 shared scetet and KAT are the same\r\n");
        else
        {
            printf("The Kyber1024 shared scetet and KAT are NOT the same\r\n");
            printf("KAT Kyber1024 shared scetet:\r\n");
            print_arr(kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "KAT_SS");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber1024_decap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_512_encap_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_512_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_512_pk, IPQP_KEM_kyber_512_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_512_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_512_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_512_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_512_length_ciphertext);

    int ret = apdu_uart_kem_encap_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber512 Ciphertext:\r\n");
        print_arr(ct, IPQP_KEM_kyber_512_length_ciphertext, 32, "CT");
        printf("\r\n");

        printf("Kyber512 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_512_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ct, kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext) == 0)
            printf("The Kyber512 ciphertext and KAT are the same\r\n");
        else
        {
            printf("The Kyber512 ciphertext and KAT are NOT the same\r\n");
            print_arr(kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext, 32, "CT_KAT");
            printf("\r\n");
        }

        if (memcmp(ss, kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret) == 0)
            printf("The Kyber512 shared sceret and KAT are the same\r\n");
        else
        {
            printf("The Kyber512 shared sceret and KAT are NOT the same\r\n");
            print_arr(kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret, 32, "SS_KAT");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber512_encap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_768_encap_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_768_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_768_pk, IPQP_KEM_kyber_768_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_768_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_768_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_768_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_768_length_ciphertext);

    int ret = apdu_uart_kem_encap_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber768 Ciphertext:\r\n");
        print_arr(ct, IPQP_KEM_kyber_768_length_ciphertext, 32, "CT");
        printf("\r\n");

        printf("Kyber768 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_768_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ct, kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext) == 0)
            printf("The Kyber768 ciphertext and KAT are the same\r\n");
        else
        {
            printf("The Kyber768 ciphertext and KAT are NOT the same\r\n");
            print_arr(kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext, 32, "CT_KAT");
            printf("\r\n");
        }

        if (memcmp(ss, kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret) == 0)
            printf("The Kyber768 shared sceret and KAT are the same\r\n");
        else
        {
            printf("The Kyber768 shared sceret and KAT are NOT the same\r\n");
            print_arr(kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret, 32, "SS_KAT");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber768_encap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_1024_encap_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_1024_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_1024_pk, IPQP_KEM_kyber_1024_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_1024_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_1024_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_1024_length_ciphertext);

    int ret = apdu_uart_kem_encap_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber1024 Ciphertext:\r\n");
        print_arr(ct, IPQP_KEM_kyber_1024_length_ciphertext, 32, "CT");
        printf("\r\n");

        printf("Kyber1024 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ct, kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext) == 0)
            printf("The Kyber1024 ciphertext and KAT are the same\r\n");
        else
        {
            printf("The Kyber1024 ciphertext and KAT are NOT the same\r\n");
            print_arr(kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext, 32, "CT_KAT");
            printf("\r\n");
        }

        if (memcmp(ss, kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret) == 0)
            printf("The Kyber1024 shared sceret and KAT are the same\r\n");
        else
        {
            printf("The Kyber1024 shared sceret and KAT are NOT the same\r\n");
            print_arr(kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "SS_KAT");
            printf("\r\n");
        }
    }
    else
    {
        printf("apdu_kem_kyber1024_encap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_512_decap_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_512_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_512_sk, IPQP_KEM_kyber_512_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_512_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_512_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_512_length_shared_secret);

    print_arr(sk, IPQP_KEM_kyber_512_length_secret_key, 32, "Kyber512 scetet key");
    printf("\r\n");

    print_arr(ct, IPQP_KEM_kyber_512_length_ciphertext, 32, "Kyber512 ciphertext");
    printf("\r\n");

    int ret = apdu_uart_kem_decap_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber512 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_512_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ss, kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret) == 0)
            printf("The Kyber512 shared scetet and KAT are the same\r\n");
        else
            printf("The Kyber512 shared scetet and KAT are NOT the same\r\n");
    }
    else
    {
        printf("apdu_kem_kyber512_decap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_768_decap_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_768_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_768_sk, IPQP_KEM_kyber_768_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_768_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_768_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_768_length_shared_secret);

    int ret = apdu_uart_kem_decap_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber768 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_768_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ss, kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret) == 0)
            printf("The Kyber768 shared scetet and KAT are the same\r\n");
        else
            printf("The Kyber768 shared scetet and KAT are NOT the same\r\n");
    }
    else
    {
        printf("apdu_kem_kyber768_decap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_1024_decap_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_1024_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_1024_sk, IPQP_KEM_kyber_1024_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_1024_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_1024_length_shared_secret);

    int ret = apdu_uart_kem_decap_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("Kyber1024 shared scetet:\r\n");
        print_arr(ss, IPQP_KEM_kyber_1024_length_shared_secret, 32, "SS");
        printf("\r\n");

        if (memcmp(ss, kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret) == 0)
            printf("The Kyber1024 shared scetet and KAT are the same\r\n");
        else
            printf("The Kyber1024 shared scetet and KAT are NOT the same\r\n");
    }
    else
    {
        printf("apdu_kem_kyber1024_decap() failed: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_keypair(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_2_length_public_key];
    memset(pk, 0x00, IPQP_DSA_dilithium_2_length_public_key);

    uint8_t sk[IPQP_DSA_dilithium_2_length_secret_key];
    memset(sk, 0x00, IPQP_DSA_dilithium_2_length_secret_key);

    int ret = apdu_uart_dsa_keypair(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)pk, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 public key:\r\n");
        print_arr(pk, IPQP_DSA_dilithium_2_length_public_key, 32, "PK");
        printf("\r\n");

        printf("dilithium2 secret key:\r\n");
        print_arr(sk, IPQP_DSA_dilithium_2_length_secret_key, 32, "SK");
        printf("\r\n");

        if (memcmp(pk, kat_dilithium2_pk, IPQP_DSA_dilithium_2_length_public_key) == 0)
            printf("The dilithium2 public key and KAT are the same\r\n");
        else
            printf("The dilithium2 public key and KAT are NOT the same\r\n");

        if (memcmp(sk, kat_dilithium2_sk, IPQP_DSA_dilithium_2_length_secret_key) == 0)
            printf("The dilithium2 secret key and KAT are the same\r\n");
        else
            printf("The dilithium2 secret key and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to generate dilithium2 keypair: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_keypair(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_3_length_public_key];
    memset(pk, 0x00, IPQP_DSA_dilithium_3_length_public_key);

    uint8_t sk[IPQP_DSA_dilithium_3_length_secret_key];
    memset(sk, 0x00, IPQP_DSA_dilithium_3_length_secret_key);

    int ret = apdu_uart_dsa_keypair(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)pk, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 public key:\r\n");
        print_arr(pk, IPQP_DSA_dilithium_3_length_public_key, 32, "PK");
        printf("\r\n");

        printf("dilithium3 secret key:\r\n");
        print_arr(sk, IPQP_DSA_dilithium_3_length_secret_key, 32, "SK");
        printf("\r\n");

        if (memcmp(pk, kat_dilithium3_pk, IPQP_DSA_dilithium_3_length_public_key) == 0)
            printf("The dilithium3 public key and KAT are the same\r\n");
        else
            printf("The dilithium3 public key and KAT are NOT the same\r\n");

        if (memcmp(sk, kat_dilithium3_sk, IPQP_DSA_dilithium_3_length_secret_key) == 0)
            printf("The dilithium3 secret key and KAT are the same\r\n");
        else
            printf("The dilithium3 secret key and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to dilithium3 keypair: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_keypair(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_5_length_public_key];
    memset(pk, 0x00, IPQP_DSA_dilithium_5_length_public_key);

    uint8_t sk[IPQP_DSA_dilithium_5_length_secret_key];
    memset(sk, 0x00, IPQP_DSA_dilithium_5_length_secret_key);

    int ret = apdu_uart_dsa_keypair(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)pk, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 public key:\r\n");
        print_arr(pk, IPQP_DSA_dilithium_5_length_public_key, 32, "PK");
        printf("\r\n");

        printf("dilithium5 secret key:\r\n");
        print_arr(sk, IPQP_DSA_dilithium_5_length_secret_key, 32, "SK");
        printf("\r\n");

        if (memcmp(pk, kat_dilithium5_pk, IPQP_DSA_dilithium_5_length_public_key) == 0)
            printf("The dilithium5 public key and KAT are the same\r\n");
        else
            printf("The dilithium5 public key and KAT are NOT the same\r\n");

        if (memcmp(sk, kat_dilithium5_sk, IPQP_DSA_dilithium_5_length_secret_key) == 0)
            printf("The dilithium5 secret key and KAT are the same\r\n");
        else
            printf("The dilithium5 secret key and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to generate dilithium5 keypair: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_sign(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_2_length_secret_key];
    memcpy(sk, kat_dilithium2_sk, IPQP_DSA_dilithium_2_length_secret_key);

    uint8_t msg[KAT_DILITHIUM2_MLEN];
    memcpy(msg, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_uart_dsa_sign(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM2_MLEN, (uint8_t *)sm, &smlen);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 signature(" PRINT_SIZE_FMT "):\r\n", smlen);
        print_arr(sm, smlen, 32, "SM");
        printf("\r\n");

        if ((memcmp(sm, kat_dilithium2_sm, smlen) == 0) && (smlen == IPQP_DSA_dilithium_2_length_signature))
            printf("The dilithium2 signature and KAT are the same\r\n");
        else
            printf("The dilithium2 signature and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to sign the message: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_sign(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_3_length_secret_key];
    memcpy(sk, kat_dilithium3_sk, IPQP_DSA_dilithium_3_length_secret_key);

    uint8_t msg[KAT_DILITHIUM3_MLEN];
    memcpy(msg, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_uart_dsa_sign(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM3_MLEN, (uint8_t *)sm, &smlen);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 signature(" PRINT_SIZE_FMT "):\r\n", smlen);
        print_arr(sm, smlen, 32, "SM");
        printf("\r\n");

        if ((memcmp(sm, kat_dilithium3_sm, smlen) == 0) && (smlen == IPQP_DSA_dilithium_3_length_signature))
            printf("The dilithium3 signature and KAT are the same\r\n");
        else
            printf("The dilithium3 signature and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to sign the message: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_sign(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_5_length_secret_key];
    memcpy(sk, kat_dilithium5_sk, IPQP_DSA_dilithium_5_length_secret_key);

    uint8_t msg[KAT_DILITHIUM5_MLEN];
    memcpy(msg, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_uart_dsa_sign(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM5_MLEN, (uint8_t *)sm, &smlen);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 signature(" PRINT_SIZE_FMT "):\r\n", smlen);
        print_arr(sm, smlen, 32, "SM");
        printf("\r\n");

        if ((memcmp(sm, kat_dilithium5_sm, smlen) == 0) && (smlen == IPQP_DSA_dilithium_5_length_signature))
            printf("The dilithium5 signature and KAT are the same\r\n");
        else
            printf("The dilithium5 signature and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to sign the message: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_verify(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_2_length_public_key];
    memcpy(pk, kat_dilithium2_pk, IPQP_DSA_dilithium_2_length_public_key);

    uint8_t msg[KAT_DILITHIUM2_MLEN];
    memcpy(msg, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);

    uint8_t sm[KAT_DILITHIUM2_SMLEN];
    memcpy(sm, kat_dilithium2_sm, KAT_DILITHIUM2_SMLEN);

    bool verified = false;

    int ret = apdu_uart_dsa_verify(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM2_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM2_SMLEN, &verified);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 signature verified(%s):\r\n", (verified) ? "true" : "false");
    }
    else
    {
        printf("failed to verified the signature: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_verify(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_3_length_public_key];
    memcpy(pk, kat_dilithium3_pk, IPQP_DSA_dilithium_3_length_public_key);

    uint8_t msg[KAT_DILITHIUM3_MLEN];
    memcpy(msg, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);

    uint8_t sm[KAT_DILITHIUM3_SMLEN];
    memcpy(sm, kat_dilithium3_sm, KAT_DILITHIUM3_SMLEN);

    bool verified = false;

    int ret = apdu_uart_dsa_verify(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM3_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM3_SMLEN, &verified);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 signature verified(%s):\r\n", (verified) ? "true" : "false");
    }
    else
    {
        printf("failed to verified the signature: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_verify(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_5_length_public_key];
    memcpy(pk, kat_dilithium5_pk, IPQP_DSA_dilithium_5_length_public_key);

    uint8_t msg[KAT_DILITHIUM5_MLEN];
    memcpy(msg, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);

    uint8_t sm[KAT_DILITHIUM5_SMLEN];
    memcpy(sm, kat_dilithium5_sm, KAT_DILITHIUM5_SMLEN);

    bool verified = false;

    int ret = apdu_uart_dsa_verify(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM5_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM5_SMLEN, &verified);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 signature verified(%s):\r\n", (verified) ? "true" : "false");
    }
    else
    {
        printf("failed to verified the signature: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_sign_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_2_length_secret_key];
    memcpy(sk, kat_dilithium2_sk, IPQP_DSA_dilithium_2_length_secret_key);

    uint8_t msg[KAT_DILITHIUM2_MLEN];
    memcpy(msg, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_uart_dsa_sign_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM2_MLEN, (uint8_t *)sm, &smlen);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 signature(" PRINT_SIZE_FMT "):\r\n", smlen);
        print_arr(sm, smlen, 32, "SM");
        printf("\r\n");

        if ((memcmp(sm, kat_dilithium2_sm, smlen) == 0) && (smlen == IPQP_DSA_dilithium_2_length_signature))
            printf("The dilithium2 signature and KAT are the same\r\n");
        else
            printf("The dilithium2 signature and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to sign the message: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_sign_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_3_length_secret_key];
    memcpy(sk, kat_dilithium3_sk, IPQP_DSA_dilithium_3_length_secret_key);

    uint8_t msg[KAT_DILITHIUM3_MLEN];
    memcpy(msg, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_uart_dsa_sign_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM3_MLEN, (uint8_t *)sm, &smlen);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 signature(" PRINT_SIZE_FMT "):\r\n", smlen);
        print_arr(sm, smlen, 32, "SM");
        printf("\r\n");

        if ((memcmp(sm, kat_dilithium3_sm, smlen) == 0) && (smlen == IPQP_DSA_dilithium_3_length_signature))
            printf("The dilithium3 signature and KAT are the same\r\n");
        else
            printf("The dilithium3 signature and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to sign the message: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_sign_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_5_length_secret_key];
    memcpy(sk, kat_dilithium5_sk, IPQP_DSA_dilithium_5_length_secret_key);

    uint8_t msg[KAT_DILITHIUM5_MLEN];
    memcpy(msg, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_uart_dsa_sign_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM5_MLEN, (uint8_t *)sm, &smlen);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 signature(" PRINT_SIZE_FMT "):\r\n", smlen);
        print_arr(sm, smlen, 32, "SM");
        printf("\r\n");

        if ((memcmp(sm, kat_dilithium5_sm, smlen) == 0) && (smlen == IPQP_DSA_dilithium_5_length_signature))
            printf("The dilithium5 signature and KAT are the same\r\n");
        else
            printf("The dilithium5 signature and KAT are NOT the same\r\n");
    }
    else
    {
        printf("failed to sign the message: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_verify_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_2_length_public_key];
    memcpy(pk, kat_dilithium2_pk, IPQP_DSA_dilithium_2_length_public_key);

    uint8_t msg[KAT_DILITHIUM2_MLEN];
    memcpy(msg, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);

    uint8_t sm[KAT_DILITHIUM2_SMLEN];
    memcpy(sm, kat_dilithium2_sm, KAT_DILITHIUM2_SMLEN);

    bool verified = false;

    int ret = apdu_uart_dsa_verify_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM2_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM2_SMLEN, &verified);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 signature verified(%s):\r\n", (verified) ? "true" : "false");
    }
    else
    {
        printf("failed to verified the signature: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_verify_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_3_length_public_key];
    memcpy(pk, kat_dilithium3_pk, IPQP_DSA_dilithium_3_length_public_key);

    uint8_t msg[KAT_DILITHIUM3_MLEN];
    memcpy(msg, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);

    uint8_t sm[KAT_DILITHIUM3_SMLEN];
    memcpy(sm, kat_dilithium3_sm, KAT_DILITHIUM3_SMLEN);

    bool verified = false;

    int ret = apdu_uart_dsa_verify_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM3_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM3_SMLEN, &verified);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 signature verified(%s):\r\n", (verified) ? "true" : "false");
    }
    else
    {
        printf("failed to verified the signature: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_verify_cmd(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_5_length_public_key];
    memcpy(pk, kat_dilithium5_pk, IPQP_DSA_dilithium_5_length_public_key);

    uint8_t msg[KAT_DILITHIUM5_MLEN];
    memcpy(msg, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);

    uint8_t sm[KAT_DILITHIUM5_SMLEN];
    memcpy(sm, kat_dilithium5_sm, KAT_DILITHIUM5_SMLEN);

    bool verified = false;

    int ret = apdu_uart_dsa_verify_cmd(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM5_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM5_SMLEN, &verified);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 signature verified(%s):\r\n", (verified) ? "true" : "false");
    }
    else
    {
        printf("failed to verified the signature: %d\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_assign_public_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_2_length_public_key];
    memcpy(pk, kat_dilithium2_pk, IPQP_DSA_dilithium_2_length_public_key);

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, APDU_CMD_P1_ASSIGN_DSA_PK, (uint8_t *)pk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("dilithium2 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_assign_public_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_3_length_public_key];
    memcpy(pk, kat_dilithium3_pk, IPQP_DSA_dilithium_3_length_public_key);

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, APDU_CMD_P1_ASSIGN_DSA_PK, (uint8_t *)pk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("dilithium3 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_assign_public_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_5_length_public_key];
    memcpy(pk, kat_dilithium5_pk, IPQP_DSA_dilithium_5_length_public_key);

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, APDU_CMD_P1_ASSIGN_DSA_PK, (uint8_t *)pk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("dilithium5 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium2_assign_secret_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_2_length_secret_key];
    memcpy(sk, kat_dilithium2_sk, IPQP_DSA_dilithium_2_length_secret_key);

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, APDU_CMD_P1_ASSIGN_DSA_SK, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium2 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("dilithium2 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium3_assign_secret_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_3_length_secret_key];
    memcpy(sk, kat_dilithium3_sk, IPQP_DSA_dilithium_3_length_secret_key);

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, APDU_CMD_P1_ASSIGN_DSA_SK, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium3 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("dilithium3 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_dsa_dilithium5_assign_secret_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_5_length_secret_key];
    memcpy(sk, kat_dilithium5_sk, IPQP_DSA_dilithium_5_length_secret_key);

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, APDU_CMD_P1_ASSIGN_DSA_SK, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("dilithium5 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("dilithium5 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_512_assign_secret_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_512_length_secret_key];
    memcpy(sk, kat_kyber_512_sk, IPQP_KEM_kyber_512_length_secret_key);

    print_arr(sk, IPQP_KEM_kyber_512_length_secret_key, 32, "SK");

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, APDU_CMD_P1_ASSIGN_KEM_SK, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 512 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("kyber 512 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_768_assign_secret_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_768_length_secret_key];
    memcpy(sk, kat_kyber_768_sk, IPQP_KEM_kyber_768_length_secret_key);

    print_arr(sk, IPQP_KEM_kyber_768_length_secret_key, 32, "SK");

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, APDU_CMD_P1_ASSIGN_KEM_SK, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 768 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("kyber 768 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_1024_assign_secret_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_1024_length_secret_key];
    memcpy(sk, kat_kyber_1024_sk, IPQP_KEM_kyber_1024_length_secret_key);
    // memset(sk, 0xAB, IPQP_KEM_kyber_1024_length_secret_key);

    print_arr(sk, IPQP_KEM_kyber_1024_length_secret_key, 32, "SK");

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, APDU_CMD_P1_ASSIGN_KEM_SK, (uint8_t *)sk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 1024 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("kyber 1024 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_512_assign_public_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_512_length_public_key];
    memcpy(pk, kat_kyber_512_pk, IPQP_KEM_kyber_512_length_public_key);

    print_arr(pk, IPQP_KEM_kyber_512_length_public_key, 32, "PK");

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, APDU_CMD_P1_ASSIGN_KEM_PK, (uint8_t *)pk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 512 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("kyber 512 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_768_assign_public_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_768_length_public_key];
    memcpy(pk, kat_kyber_768_pk, IPQP_KEM_kyber_768_length_public_key);

    print_arr(pk, IPQP_KEM_kyber_768_length_public_key, 32, "PK");

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, APDU_CMD_P1_ASSIGN_KEM_PK, (uint8_t *)pk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 768 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("kyber 768 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_1024_assign_public_key(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_1024_length_public_key];
    memcpy(pk, kat_kyber_1024_pk, IPQP_KEM_kyber_1024_length_public_key);
    // memset(pk, 0xCD, IPQP_KEM_kyber_1024_length_public_key);

    print_arr(pk, IPQP_KEM_kyber_1024_length_public_key, 32, "PK");

    int ret = apdu_uart_assign_key(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, APDU_CMD_P1_ASSIGN_KEM_PK, (uint8_t *)pk);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 1024 apdu_uart_assign_key() success.\r\n");
    }
    else
    {
        printf("kyber 1024 apdu_uart_assign_key() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_512_assign_ciphertext(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t ct[IPQP_KEM_kyber_512_length_public_key];
    memcpy(ct, kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext);

    print_arr(ct, IPQP_KEM_kyber_512_length_public_key, 32, "CT");

    int ret = apdu_uart_kem_assign_ciphertext(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, APDU_CMD_P1_ASSIGN_KEM_CT, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 512 apdu_uart_kem_assign_ciphertext() success.\r\n");
    }
    else
    {
        printf("kyber 512 apdu_uart_kem_assign_ciphertext() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_768_assign_ciphertext(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t ct[IPQP_KEM_kyber_768_length_public_key];
    memcpy(ct, kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext);

    print_arr(ct, IPQP_KEM_kyber_768_length_ciphertext, 32, "CT");

    int ret = apdu_uart_kem_assign_ciphertext(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, APDU_CMD_P1_ASSIGN_KEM_CT, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 768 apdu_uart_kem_assign_ciphertext() success.\r\n");
    }
    else
    {
        printf("kyber 768 apdu_uart_kem_assign_ciphertext() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

void test_apdu_uart_kem_kyber_1024_assign_ciphertext(uart_conf_t *uart_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memcpy(ct, kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext);
    // memset(ct, 0xEF, IPQP_KEM_kyber_1024_length_ciphertext);

    print_arr(ct, IPQP_KEM_kyber_1024_length_ciphertext, 32, "CT");

    int ret = apdu_uart_kem_assign_ciphertext(uart_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, APDU_CMD_P1_ASSIGN_KEM_CT, (uint8_t *)ct);
    if (ret == IPQP_EC_SUCCESS)
    {
        printf("kyber 1024 apdu_uart_kem_assign_ciphertext() success.\r\n");
    }
    else
    {
        printf("kyber 1024 apdu_uart_kem_assign_ciphertext() failed. (%d)\r\n", ret);
    }

    printf("[E N D]: %s()\r\n", __func__);
}

int main(int argc, char *argv[])
{
    printf("===== [START] =====\r\n");
    int flag = -1;

    char device[32] = UART_DEV_NAME;
    uart_conf_t uart_conf = {
        .fd = -1,
        .name = device,
        .open_flags = UART_OPEN_FLAGS,
        .input_mode_flags = UART_INPUT_MODE_FLAGS,
        .output_mode_flags = UART_OUTPUT_MODE_FLAGS,
        .control_mode_flags = UART_CONTROL_MODE_FLAGS,
        .local_mode_flags = UART_LOCAL_MODE_FLAGS};

    prepare_kat_data();

    if (argc > 1)
        flag = atoi(argv[1]);

    void (*test_function)(uart_conf_t *uart_conf);
    test_function = NULL;

    switch (flag)
    {
    case 0:
        test_function = &test_apdu_uart_status_check;
        break;

    case 1:
        test_function = &test_apdu_uart_kem_kyber512_keypair;
        break;

    case 2:
        test_function = &test_apdu_uart_kem_kyber768_keypair;
        break;

    case 3:
        test_function = &test_apdu_uart_kem_kyber1024_keypair;
        break;

    case 11:
        test_function = &test_apdu_uart_kem_kyber512_encap;
        break;

    case 12:
        test_function = &test_apdu_uart_kem_kyber768_encap;
        break;

    case 13:
        test_function = &test_apdu_uart_kem_kyber1024_encap;
        break;

    case 21:
        test_function = &test_apdu_uart_kem_kyber512_decap;
        break;

    case 22:
        test_function = &test_apdu_uart_kem_kyber768_decap;
        break;

    case 23:
        test_function = &test_apdu_uart_kem_kyber1024_decap;
        break;

    case 31:
        test_function = &test_apdu_uart_dsa_dilithium2_keypair;
        break;

    case 32:
        test_function = &test_apdu_uart_dsa_dilithium3_keypair;
        break;

    case 33:
        test_function = &test_apdu_uart_dsa_dilithium5_keypair;
        break;

    case 41:
        test_function = &test_apdu_uart_dsa_dilithium2_sign;
        break;

    case 42:
        test_function = &test_apdu_uart_dsa_dilithium3_sign;
        break;

    case 43:
        test_function = &test_apdu_uart_dsa_dilithium5_sign;
        break;

    case 51:
        test_function = &test_apdu_uart_dsa_dilithium2_verify;
        break;

    case 52:
        test_function = &test_apdu_uart_dsa_dilithium3_verify;
        break;

    case 53:
        test_function = &test_apdu_uart_dsa_dilithium5_verify;
        break;

    case 61:
        test_function = &test_apdu_uart_dsa_dilithium2_assign_public_key;
        break;

    case 62:
        test_function = &test_apdu_uart_dsa_dilithium3_assign_public_key;
        break;

    case 63:
        test_function = &test_apdu_uart_dsa_dilithium5_assign_public_key;
        break;

    case 71:
        test_function = &test_apdu_uart_dsa_dilithium2_assign_secret_key;
        break;

    case 72:
        test_function = &test_apdu_uart_dsa_dilithium3_assign_secret_key;
        break;

    case 73:
        test_function = &test_apdu_uart_dsa_dilithium5_assign_secret_key;
        break;

    case 81:
        test_function = &test_apdu_uart_kem_kyber_512_assign_secret_key;
        break;

    case 91:
        test_function = &test_apdu_uart_kem_kyber_512_assign_public_key;
        break;

    case 101:
        test_function = &test_apdu_uart_kem_kyber_512_assign_ciphertext;
        break;

    case 111:
        test_function = &test_apdu_uart_kem_kyber_512_encap_cmd;
        break;

    case 121:
        test_function = &test_apdu_uart_kem_kyber_512_decap_cmd;
        break;

    case 82:
        test_function = &test_apdu_uart_kem_kyber_768_assign_secret_key;
        break;

    case 92:
        test_function = &test_apdu_uart_kem_kyber_768_assign_public_key;
        break;

    case 102:
        test_function = &test_apdu_uart_kem_kyber_768_assign_ciphertext;
        break;

    case 112:
        test_function = &test_apdu_uart_kem_kyber_768_encap_cmd;
        break;

    case 122:
        test_function = &test_apdu_uart_kem_kyber_768_decap_cmd;
        break;

    case 83:
        test_function = &test_apdu_uart_kem_kyber_1024_assign_secret_key;
        break;

    case 93:
        test_function = &test_apdu_uart_kem_kyber_1024_assign_public_key;
        break;

    case 103:
        test_function = &test_apdu_uart_kem_kyber_1024_assign_ciphertext;
        break;

    case 113:
        test_function = &test_apdu_uart_kem_kyber_1024_encap_cmd;
        break;

    case 123:
        test_function = &test_apdu_uart_kem_kyber_1024_decap_cmd;
        break;

    case 131:
        test_function = &test_apdu_uart_dsa_dilithium2_sign_cmd;
        break;

    case 132:
        test_function = &test_apdu_uart_dsa_dilithium3_sign_cmd;
        break;

    case 133:
        test_function = &test_apdu_uart_dsa_dilithium5_sign_cmd;
        break;

    case 141:
        test_function = &test_apdu_uart_dsa_dilithium2_verify_cmd;
        break;

    case 142:
        test_function = &test_apdu_uart_dsa_dilithium3_verify_cmd;
        break;

    case 143:
        test_function = &test_apdu_uart_dsa_dilithium5_verify_cmd;
        break;

    default:
        printf("-----------------------------------\r\n");
        printf("  0:: test_apdu_uart_status_check()\r\n\r\n");

        printf("  1:: test_apdu_uart_kem_kyber512_keypair()\r\n");
        printf("  2:: test_apdu_uart_kem_kyber768_keypair();\r\n");
        printf("  3:: test_apdu_uart_kem_kyber1024_keypair();\r\n\r\n");

        printf(" 11:: test_apdu_uart_kem_kyber512_encap();\r\n");
        printf(" 12:: test_apdu_uart_kem_kyber768_encap();\r\n");
        printf(" 13:: test_apdu_uart_kem_kyber1024_encap();\r\n\r\n");

        printf(" 21:: test_apdu_uart_kem_kyber512_decap();\r\n");
        printf(" 22:: test_apdu_uart_kem_kyber768_encap();\r\n");
        printf(" 23:: test_apdu_uart_kem_kyber1024_decap();\r\n\r\n");

        printf(" 31:: test_apdu_uart_dsa_dilithium2_keypair();\r\n");
        printf(" 32:: test_apdu_uart_dsa_dilithium3_keypair();\r\n");
        printf(" 33:: test_apdu_uart_dsa_dilithium5_keypair();\r\n\r\n");

        printf(" 41:: test_apdu_uart_dsa_dilithium2_sign();\r\n");
        printf(" 42:: test_apdu_uart_dsa_dilithium3_sign();\r\n");
        printf(" 43:: test_apdu_uart_dsa_dilithium5_sign();\r\n\r\n");

        printf(" 51:: test_apdu_uart_dsa_dilithium2_verify();\r\n");
        printf(" 52:: test_apdu_uart_dsa_dilithium3_verify();\r\n");
        printf(" 53:: test_apdu_uart_dsa_dilithium5_verify();\r\n\r\n");

        printf(" 61:: test_apdu_uart_dsa_dilithium2_assign_public_key();\r\n");
        printf(" 71:: test_apdu_uart_dsa_dilithium2_assign_secret_key();\r\n");
        printf("131:: test_apdu_uart_dsa_dilithium2_sign_cmd();\r\n");
        printf("141:: test_apdu_uart_dsa_dilithium2_verify_cmd();\r\n\r\n");

        printf(" 62:: test_apdu_uart_dsa_dilithium3_assign_public_key();\r\n");
        printf(" 72:: test_apdu_uart_dsa_dilithium3_assign_secret_key();\r\n");
        printf("132:: test_apdu_uart_dsa_dilithium3_sign_cmd();\r\n");
        printf("142:: test_apdu_uart_dsa_dilithium3_verify_cmd();\r\n\r\n");

        printf(" 63:: test_apdu_uart_dsa_dilithium5_assign_public_key();\r\n");
        printf(" 73:: test_apdu_uart_dsa_dilithium5_assign_secret_key();\r\n");
        printf("133:: test_apdu_uart_dsa_dilithium5_sign_cmd();\r\n");
        printf("143:: test_apdu_uart_dsa_dilithium5_verify_cmd();\r\n\r\n");

        printf(" 81:: test_apdu_uart_kem_kyber_512_assign_secret_key();\r\n");
        printf(" 91:: test_apdu_uart_kem_kyber_512_assign_public_key();\r\n");
        printf("101:: test_apdu_uart_kem_kyber_512_assign_ciphertext();\r\n");
        printf("111:: test_apdu_uart_kem_kyber_512_encap_cmd();\r\n");
        printf("121:: test_apdu_uart_kem_kyber_512_decap_cmd();\r\n\r\n");

        printf(" 82:: test_apdu_uart_kem_kyber_768_assign_secret_key();\r\n");
        printf(" 92:: test_apdu_uart_kem_kyber_768_assign_public_key();\r\n");
        printf("102:: test_apdu_uart_kem_kyber_768_assign_ciphertext();\r\n");
        printf("112:: test_apdu_uart_kem_kyber_768_encap_cmd();\r\n");
        printf("122:: test_apdu_uart_kem_kyber_768_decap_cmd();\r\n\r\n");

        printf(" 83:: test_apdu_uart_kem_kyber_1024_assign_secret_key();\r\n");
        printf(" 93:: test_apdu_uart_kem_kyber_1024_assign_public_key();\r\n");
        printf("103:: test_apdu_uart_kem_kyber_1024_assign_ciphertext();\r\n");
        printf("113:: test_apdu_uart_kem_kyber_1024_encap_cmd();\r\n");
        printf("123:: test_apdu_uart_kem_kyber_1024_decap_cmd();\r\n\r\n");

        printf("-----------------------------------\r\n");
        return EXIT_SUCCESS;
    }

    if (test_function != NULL)
    {
        if (uart_open(&uart_conf) < 0)
        {
            printf("fali to open interface.\r\n");
            return EXIT_FAILURE;
        }

        test_function(&uart_conf);

        if (uart_conf.fd >= 0)
            uart_close(&uart_conf);
    }

    printf("===== [E N D] =====\r\n");
    return EXIT_SUCCESS;
}
