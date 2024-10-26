#include "ipqp_common.h"
#include "test_common.h"
#include "kat.h"

void test_apdu_tcp_kem_kyber512_keypair(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_512_length_public_key];
    memset(pk, 0x00, IPQP_KEM_kyber_512_length_public_key);
    uint8_t sk[IPQP_KEM_kyber_512_length_secret_key];
    memset(sk, 0x00, IPQP_KEM_kyber_512_length_secret_key);

    int ret = apdu_tcp_kem_keypair(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)pk, (uint8_t *)sk);
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

void test_apdu_tcp_kem_kyber768_keypair(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_768_length_public_key];
    memset(pk, 0x00, IPQP_KEM_kyber_768_length_public_key);
    uint8_t sk[IPQP_KEM_kyber_768_length_secret_key];
    memset(sk, 0x00, IPQP_KEM_kyber_768_length_secret_key);

    int ret = apdu_tcp_kem_keypair(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)pk, (uint8_t *)sk);
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

void test_apdu_tcp_kem_kyber1024_keypair(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_1024_length_public_key];
    memset(pk, 0x00, IPQP_KEM_kyber_1024_length_public_key);
    uint8_t sk[IPQP_KEM_kyber_1024_length_secret_key];
    memset(sk, 0x00, IPQP_KEM_kyber_1024_length_secret_key);

    int ret = apdu_tcp_kem_keypair(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)pk, (uint8_t *)sk);
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

void test_apdu_tcp_kem_kyber512_encap(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_512_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_512_pk, IPQP_KEM_kyber_512_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_512_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_512_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_512_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_512_length_ciphertext);

    int ret = apdu_tcp_kem_encap(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
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

void test_apdu_tcp_kem_kyber768_encap(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_768_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_768_pk, IPQP_KEM_kyber_768_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_768_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_768_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_768_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_768_length_ciphertext);

    int ret = apdu_tcp_kem_encap(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
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

void test_apdu_tcp_kem_kyber1024_encap(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_KEM_kyber_1024_length_public_key];
    memcpy((uint8_t *)pk, (uint8_t *)kat_kyber_1024_pk, IPQP_KEM_kyber_1024_length_public_key);

    uint8_t ss[IPQP_KEM_kyber_1024_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_1024_length_shared_secret);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memset((uint8_t *)ct, 0x00, IPQP_KEM_kyber_1024_length_ciphertext);

    int ret = apdu_tcp_kem_encap(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
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

void test_apdu_tcp_kem_kyber512_decap(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_512_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_512_sk, IPQP_KEM_kyber_512_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_512_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_512_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_512_length_shared_secret);

    int ret = apdu_tcp_kem_decap(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_512, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
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

void test_apdu_tcp_kem_kyber768_decap(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_768_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_768_sk, IPQP_KEM_kyber_768_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_768_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_768_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_768_length_shared_secret);

    int ret = apdu_tcp_kem_decap(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_768, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
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

void test_apdu_tcp_kem_kyber1024_decap(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_KEM_kyber_1024_length_secret_key];
    memcpy((uint8_t *)sk, (uint8_t *)kat_kyber_1024_sk, IPQP_KEM_kyber_1024_length_secret_key);

    uint8_t ct[IPQP_KEM_kyber_1024_length_ciphertext];
    memcpy((uint8_t *)ct, (uint8_t *)kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext);

    uint8_t ss[IPQP_KEM_kyber_1024_length_shared_secret];
    memset((uint8_t *)ss, 0x00, IPQP_KEM_kyber_1024_length_shared_secret);

    int ret = apdu_tcp_kem_decap(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_KYBER_1024, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
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

void test_apdu_tcp_dsa_dilithium2_keypair(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_2_length_public_key];
    memset(pk, 0x00, IPQP_DSA_dilithium_2_length_public_key);

    uint8_t sk[IPQP_DSA_dilithium_2_length_secret_key];
    memset(sk, 0x00, IPQP_DSA_dilithium_2_length_secret_key);

    int ret = apdu_tcp_dsa_keypair(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)pk, (uint8_t *)sk);
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

void test_apdu_tcp_dsa_dilithium3_keypair(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_3_length_public_key];
    memset(pk, 0x00, IPQP_DSA_dilithium_3_length_public_key);

    uint8_t sk[IPQP_DSA_dilithium_3_length_secret_key];
    memset(sk, 0x00, IPQP_DSA_dilithium_3_length_secret_key);

    int ret = apdu_tcp_dsa_keypair(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)pk, (uint8_t *)sk);
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

void test_apdu_tcp_dsa_dilithium5_keypair(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_5_length_public_key];
    memset(pk, 0x00, IPQP_DSA_dilithium_5_length_public_key);

    uint8_t sk[IPQP_DSA_dilithium_5_length_secret_key];
    memset(sk, 0x00, IPQP_DSA_dilithium_5_length_secret_key);

    int ret = apdu_tcp_dsa_keypair(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)pk, (uint8_t *)sk);
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

void test_apdu_tcp_dsa_dilithium2_sign(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_2_length_secret_key];
    memcpy(sk, kat_dilithium2_sk, IPQP_DSA_dilithium_2_length_secret_key);

    uint8_t msg[KAT_DILITHIUM2_MLEN];
    memcpy(msg, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_tcp_dsa_sign(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM2_MLEN, (uint8_t *)sm, &smlen);
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

void test_apdu_tcp_dsa_dilithium3_sign(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_3_length_secret_key];
    memcpy(sk, kat_dilithium3_sk, IPQP_DSA_dilithium_3_length_secret_key);

    uint8_t msg[KAT_DILITHIUM3_MLEN];
    memcpy(msg, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_tcp_dsa_sign(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM3_MLEN, (uint8_t *)sm, &smlen);
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

void test_apdu_tcp_dsa_dilithium5_sign(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t sk[IPQP_DSA_dilithium_5_length_secret_key];
    memcpy(sk, kat_dilithium5_sk, IPQP_DSA_dilithium_5_length_secret_key);

    uint8_t msg[KAT_DILITHIUM5_MLEN];
    memcpy(msg, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);

    uint8_t sm[5120];
    memset(sm, 0x00, 5120);

    size_t smlen = 0;

    int ret = apdu_tcp_dsa_sign(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)sk, (uint8_t *)msg, KAT_DILITHIUM5_MLEN, (uint8_t *)sm, &smlen);
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

void test_apdu_tcp_dsa_dilithium2_verify(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_2_length_public_key];
    memcpy(pk, kat_dilithium2_pk, IPQP_DSA_dilithium_2_length_public_key);

    uint8_t msg[KAT_DILITHIUM2_MLEN];
    memcpy(msg, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);

    uint8_t sm[KAT_DILITHIUM2_SMLEN];
    memcpy(sm, kat_dilithium2_sm, KAT_DILITHIUM2_SMLEN);

    bool verified = false;

    int ret = apdu_tcp_dsa_verify(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_2, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM2_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM2_SMLEN, &verified);
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

void test_apdu_tcp_dsa_dilithium3_verify(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_3_length_public_key];
    memcpy(pk, kat_dilithium3_pk, IPQP_DSA_dilithium_3_length_public_key);

    uint8_t msg[KAT_DILITHIUM3_MLEN];
    memcpy(msg, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);

    uint8_t sm[KAT_DILITHIUM3_SMLEN];
    memcpy(sm, kat_dilithium3_sm, KAT_DILITHIUM3_SMLEN);

    bool verified = false;

    int ret = apdu_tcp_dsa_verify(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_3, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM3_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM3_SMLEN, &verified);
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

void test_apdu_tcp_dsa_dilithium5_verify(tcp_conf_t *tcp_conf)
{
    printf("[START]: %s()\r\n", __func__);

    uint8_t pk[IPQP_DSA_dilithium_5_length_public_key];
    memcpy(pk, kat_dilithium5_pk, IPQP_DSA_dilithium_5_length_public_key);

    uint8_t msg[KAT_DILITHIUM5_MLEN];
    memcpy(msg, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);

    uint8_t sm[KAT_DILITHIUM5_SMLEN];
    memcpy(sm, kat_dilithium5_sm, KAT_DILITHIUM5_SMLEN);

    bool verified = false;

    int ret = apdu_tcp_dsa_verify(tcp_conf, APDU_CLA_ITRI, APDU_CMD_INS_ALGO_DILITHIUM_5, (uint8_t *)pk, (uint8_t *)msg, (size_t)KAT_DILITHIUM5_MLEN, (uint8_t *)sm, (size_t)KAT_DILITHIUM5_SMLEN, &verified);
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

int main(int argc, char *argv[])
{
    printf("===== [START] =====\r\n");
    int flag = -1;

    char ip[32] = TCP_DEV_IP;
    uint16_t port = TCP_DEV_PORT;
    tcp_conf_t tcp_conf = {
        .fd = -1,
        .ip = ip,
        .port = port,
        .timeout_sec = TCP_TIMEOUT_SEC,
        .retries_on_failure = TCP_RETRIES_ON_FAILURE};

    if (argc > 1)
        flag = atoi(argv[1]);

    void (*test_function)(tcp_conf_t *tcp_conf);
    test_function = NULL;

    switch (flag)
    {
    case 1:
        test_function = &test_apdu_tcp_kem_kyber512_keypair;
        break;

    case 2:
        test_function = &test_apdu_tcp_kem_kyber768_keypair;
        break;

    case 3:
        test_function = &test_apdu_tcp_kem_kyber1024_keypair;
        break;

    case 11:
        test_function = &test_apdu_tcp_kem_kyber512_encap;
        break;

    case 12:
        test_function = &test_apdu_tcp_kem_kyber768_encap;
        break;

    case 13:
        test_function = &test_apdu_tcp_kem_kyber1024_encap;
        break;

    case 21:
        test_function = &test_apdu_tcp_kem_kyber512_decap;
        break;

    case 22:
        test_function = &test_apdu_tcp_kem_kyber768_decap;
        break;

    case 23:
        test_function = &test_apdu_tcp_kem_kyber1024_decap;
        break;

    case 31:
        test_function = &test_apdu_tcp_dsa_dilithium2_keypair;
        break;

    case 32:
        test_function = &test_apdu_tcp_dsa_dilithium3_keypair;
        break;

    case 33:
        test_function = &test_apdu_tcp_dsa_dilithium5_keypair;
        break;

    case 41:
        test_function = &test_apdu_tcp_dsa_dilithium2_sign;
        break;

    case 42:
        test_function = &test_apdu_tcp_dsa_dilithium3_sign;
        break;

    case 43:
        test_function = &test_apdu_tcp_dsa_dilithium5_sign;
        break;

    case 51:
        test_function = &test_apdu_tcp_dsa_dilithium2_verify;
        break;

    case 52:
        test_function = &test_apdu_tcp_dsa_dilithium3_verify;
        break;

    case 53:
        test_function = &test_apdu_tcp_dsa_dilithium5_verify;
        break;

    default:
        printf("-----------------------------------\r\n\r\n");

        printf("  1:: test_apdu_tcp_kem_kyber512_keypair()\r\n");
        printf("  2:: test_apdu_tcp_kem_kyber768_keypair();\r\n");
        printf("  3:: test_apdu_tcp_kem_kyber1024_keypair();\r\n\r\n");

        printf(" 11:: test_apdu_tcp_kem_kyber512_encap();\r\n");
        printf(" 12:: test_apdu_tcp_kem_kyber768_encap();\r\n");
        printf(" 13:: test_apdu_tcp_kem_kyber1024_encap();\r\n\r\n");

        printf(" 21:: test_apdu_tcp_kem_kyber512_decap();\r\n");
        printf(" 22:: test_apdu_tcp_kem_kyber768_encap();\r\n");
        printf(" 23:: test_apdu_tcp_kem_kyber1024_decap();\r\n\r\n");

        printf(" 31:: test_apdu_tcp_dsa_dilithium2_keypair();\r\n");
        printf(" 32:: test_apdu_tcp_dsa_dilithium3_keypair();\r\n");
        printf(" 33:: test_apdu_tcp_dsa_dilithium5_keypair();\r\n\r\n");

        printf(" 41:: test_apdu_tcp_dsa_dilithium2_sign();\r\n");
        printf(" 42:: test_apdu_tcp_dsa_dilithium3_sign();\r\n");
        printf(" 43:: test_apdu_tcp_dsa_dilithium5_sign();\r\n\r\n");

        printf(" 51:: test_apdu_tcp_dsa_dilithium2_verify();\r\n");
        printf(" 52:: test_apdu_tcp_dsa_dilithium3_verify();\r\n");
        printf(" 53:: test_apdu_tcp_dsa_dilithium5_verify();\r\n\r\n");

        printf("-----------------------------------\r\n");
    }

    if (test_function != NULL)
    {
        prepare_kat_data();

        if (tcp_open(&tcp_conf) < 0)
        {
            printf("fali to open interface.\r\n");
            return EXIT_FAILURE;
        }

        test_function(&tcp_conf);

        if (tcp_conf.fd >= 0)
            tcp_close(&tcp_conf);
    }

    printf("===== [E N D] =====\r\n");
    return EXIT_SUCCESS;
}
