#include "ipqp_common.h"
#include "test_common.h"

void clear_buff(const char *algo, uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss_e, uint8_t *ss_d)
{
    if (strncasecmp(algo, "kyber_512", 9) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_KEM_kyber_512_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_KEM_kyber_512_length_secret_key);
        OQS_MEM_cleanse(ct, IPQP_KEM_kyber_512_length_ciphertext);
        OQS_MEM_cleanse(ss_e, IPQP_KEM_kyber_512_length_shared_secret);
        OQS_MEM_cleanse(ss_d, IPQP_KEM_kyber_512_length_shared_secret);
    }
    else if (strncasecmp(algo, "kyber_768", 9) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_KEM_kyber_768_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_KEM_kyber_768_length_secret_key);
        OQS_MEM_cleanse(ct, IPQP_KEM_kyber_768_length_ciphertext);
        OQS_MEM_cleanse(ss_e, IPQP_KEM_kyber_768_length_shared_secret);
        OQS_MEM_cleanse(ss_d, IPQP_KEM_kyber_768_length_shared_secret);
    }
    else if (strncasecmp(algo, "kyber_1024", 10) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_KEM_kyber_1024_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_KEM_kyber_1024_length_secret_key);
        OQS_MEM_cleanse(ct, IPQP_KEM_kyber_1024_length_ciphertext);
        OQS_MEM_cleanse(ss_e, IPQP_KEM_kyber_1024_length_shared_secret);
        OQS_MEM_cleanse(ss_d, IPQP_KEM_kyber_1024_length_shared_secret);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        SKIP_n_EXIT;
    }

    if (strncasecmp(argv[1], "kyber_512", 9) == 0)
    {
        uint8_t public_key[IPQP_KEM_kyber_512_length_public_key];
        uint8_t secret_key[IPQP_KEM_kyber_512_length_secret_key];
        uint8_t ciphertext[IPQP_KEM_kyber_512_length_ciphertext];
        uint8_t shared_secret_e[IPQP_KEM_kyber_512_length_shared_secret];
        uint8_t shared_secret_d[IPQP_KEM_kyber_512_length_shared_secret];

        /* Config IPQP */
        char spi_dev_name[256] = SPI_DEV_NAME;
        spi_conf_t spi_conf = {
            .fd = -1,
            .mode = SPI_MODE,
            .bits_per_word = SPI_BITS_PER_WORD,
            .speed = SPI_MAX_SPEED_HZ,
            .lsb = SPI_LSB_FIRST,
            .name = spi_dev_name};

        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_SPI_ITRI, &spi_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Generate keypair */
        printf(" --- Kyber 512 keygen ---\r\n");
        ec = IPQP_kem_keypair(IPQP_ALGO_KYBER_512, (uint8_t *)public_key, (uint8_t *)secret_key);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_512_keypair failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("Public Key[%d]:\r\n", IPQP_KEM_kyber_512_length_public_key);
        print_arr((uint8_t *)public_key, IPQP_KEM_kyber_512_length_public_key, 32, NULL);

        printf("Private Key[%d]:\r\n", IPQP_KEM_kyber_512_length_secret_key);
        print_arr((uint8_t *)secret_key, IPQP_KEM_kyber_512_length_secret_key, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        ec = IPQP_config(IPQP_PROV_LIBOQS);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Encapsulate shared secret with public key */
        printf(" --- Kyber 512 key-encapsulation ---\r\n");
        ec = IPQP_kem_encap(IPQP_ALGO_KYBER_512, (uint8_t *)public_key, (uint8_t *)shared_secret_e, (uint8_t *)ciphertext);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_512_encaps failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("shared_secret_e[%d]:\r\n", IPQP_KEM_kyber_512_length_shared_secret);
        print_arr((uint8_t *)shared_secret_e, IPQP_KEM_kyber_512_length_shared_secret, 32, NULL);

        printf("Ciphertext[%d]:\r\n", IPQP_KEM_kyber_512_length_ciphertext);
        print_arr((uint8_t *)ciphertext, IPQP_KEM_kyber_512_length_ciphertext, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        ec = IPQP_config(IPQP_PROV_LIBOQS);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Decapsulate ciphertext with secret key */
        printf(" --- Kyber 512 key-decapsulation ---\r\n");
        ec = IPQP_kem_decap(IPQP_ALGO_KYBER_512, (uint8_t *)secret_key, (uint8_t *)ciphertext, (uint8_t *)shared_secret_d);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_512_decaps failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("shared_secret_d[%d]:\r\n", IPQP_KEM_kyber_512_length_shared_secret);
        print_arr((uint8_t *)shared_secret_d, IPQP_KEM_kyber_512_length_shared_secret, 32, NULL);

        /* ====================================================================== */

        /* Compare shared_sectet_e and shared_secret_d */
        int res = memcmp(shared_secret_e, shared_secret_d, IPQP_KEM_kyber_512_length_shared_secret);
        if (res != 0)
        {
            printf("ERROR: Shared secrets are not te same!\r\n");
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }
        clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
    }
    else if (strncasecmp(argv[1], "kyber_768", 9) == 0)
    {
        uint8_t public_key[IPQP_KEM_kyber_768_length_public_key];
        uint8_t secret_key[IPQP_KEM_kyber_768_length_secret_key];
        uint8_t ciphertext[IPQP_KEM_kyber_768_length_ciphertext];
        uint8_t shared_secret_e[IPQP_KEM_kyber_768_length_shared_secret];
        uint8_t shared_secret_d[IPQP_KEM_kyber_768_length_shared_secret];

        /* Config IPQP */
        char spi_dev_name[256] = SPI_DEV_NAME;
        spi_conf_t spi_conf = {
            .fd = -1,
            .mode = SPI_MODE,
            .bits_per_word = SPI_BITS_PER_WORD,
            .speed = SPI_MAX_SPEED_HZ,
            .lsb = SPI_LSB_FIRST,
            .name = spi_dev_name};

        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_SPI_ITRI, &spi_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Generate keypair */
        printf(" --- Kyber 768 keygen ---\r\n");
        ec = IPQP_kem_keypair(IPQP_ALGO_KYBER_768, (uint8_t *)public_key, (uint8_t *)secret_key);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_768_keypair failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("Public Key[%d]:\r\n", IPQP_KEM_kyber_768_length_public_key);
        print_arr((uint8_t *)public_key, IPQP_KEM_kyber_768_length_public_key, 32, NULL);

        printf("Private Key[%d]:\r\n", IPQP_KEM_kyber_768_length_secret_key);
        print_arr((uint8_t *)secret_key, IPQP_KEM_kyber_768_length_secret_key, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        ec = IPQP_config(IPQP_PROV_LIBOQS);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Encapsulate shared secret with public key */
        printf(" --- Kyber 768 key-encapsulation ---\r\n");
        ec = IPQP_kem_encap(IPQP_ALGO_KYBER_768, (uint8_t *)public_key, (uint8_t *)shared_secret_e, (uint8_t *)ciphertext);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_768_encaps failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("shared_secret_e[%d]:\r\n", IPQP_KEM_kyber_768_length_shared_secret);
        print_arr((uint8_t *)shared_secret_e, IPQP_KEM_kyber_768_length_shared_secret, 32, NULL);

        printf("Ciphertext[%d]:\r\n", IPQP_KEM_kyber_768_length_ciphertext);
        print_arr((uint8_t *)ciphertext, IPQP_KEM_kyber_768_length_ciphertext, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        ec = IPQP_config(IPQP_PROV_LIBOQS);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Decapsulate ciphertext with secret key */
        printf(" --- Kyber 768 key-decapsulation ---\r\n");
        ec = IPQP_kem_decap(IPQP_ALGO_KYBER_768, (uint8_t *)secret_key, (uint8_t *)ciphertext, (uint8_t *)shared_secret_d);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_768_decaps failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("shared_secret_d[%d]:\r\n", IPQP_KEM_kyber_768_length_shared_secret);
        print_arr((uint8_t *)shared_secret_d, IPQP_KEM_kyber_768_length_shared_secret, 32, NULL);

        /* ====================================================================== */

        /* Compare shared_sectet_e and shared_secret_d */
        int res = memcmp(shared_secret_e, shared_secret_d, IPQP_KEM_kyber_768_length_shared_secret);
        if (res != 0)
        {
            printf("ERROR: Shared secrets are not te same!\r\n");
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }
        clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
    }
    else if (strncasecmp(argv[1], "kyber_1024", 10) == 0)
    {
        uint8_t public_key[IPQP_KEM_kyber_1024_length_public_key];
        uint8_t secret_key[IPQP_KEM_kyber_1024_length_secret_key];
        uint8_t ciphertext[IPQP_KEM_kyber_1024_length_ciphertext];
        uint8_t shared_secret_e[IPQP_KEM_kyber_1024_length_shared_secret];
        uint8_t shared_secret_d[IPQP_KEM_kyber_1024_length_shared_secret];

        /* Config IPQP */
        char spi_dev_name[256] = SPI_DEV_NAME;
        spi_conf_t spi_conf = {
            .fd = -1,
            .mode = SPI_MODE,
            .bits_per_word = SPI_BITS_PER_WORD,
            .speed = SPI_MAX_SPEED_HZ,
            .lsb = SPI_LSB_FIRST,
            .name = spi_dev_name};

        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_SPI_ITRI, &spi_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Generate keypair */
        printf(" --- Kyber 1024 keygen ---\r\n");
        ec = IPQP_kem_keypair(IPQP_ALGO_KYBER_1024, (uint8_t *)public_key, (uint8_t *)secret_key);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_1024_keypair failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("Public Key[%d]:\r\n", IPQP_KEM_kyber_1024_length_public_key);
        print_arr((uint8_t *)public_key, IPQP_KEM_kyber_1024_length_public_key, 32, NULL);

        printf("Private Key[%d]:\r\n", IPQP_KEM_kyber_1024_length_secret_key);
        print_arr((uint8_t *)secret_key, IPQP_KEM_kyber_1024_length_secret_key, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        ec = IPQP_config(IPQP_PROV_LIBOQS);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Encapsulate shared secret with public key */
        printf(" --- Kyber 1024 key-encapsulation ---\r\n");
        ec = IPQP_kem_encap(IPQP_ALGO_KYBER_1024, (uint8_t *)public_key, (uint8_t *)shared_secret_e, (uint8_t *)ciphertext);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_1024_encaps failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("shared_secret_e[%d]:\r\n", IPQP_KEM_kyber_1024_length_shared_secret);
        print_arr((uint8_t *)shared_secret_e, IPQP_KEM_kyber_1024_length_shared_secret, 32, NULL);

        printf("Ciphertext[%d]:\r\n", IPQP_KEM_kyber_1024_length_ciphertext);
        print_arr((uint8_t *)ciphertext, IPQP_KEM_kyber_1024_length_ciphertext, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        ec = IPQP_config(IPQP_PROV_LIBOQS);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Decapsulate ciphertext with secret key */
        printf(" --- Kyber 1024 key-decapsulation ---\r\n");
        ec = IPQP_kem_decap(IPQP_ALGO_KYBER_1024, (uint8_t *)secret_key, (uint8_t *)ciphertext, (uint8_t *)shared_secret_d);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_KEM_kyber_1024_decaps failed! (%d)\r\n", ec);
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }

        printf("shared_secret_d[%d]:\r\n", IPQP_KEM_kyber_1024_length_shared_secret);
        print_arr((uint8_t *)shared_secret_d, IPQP_KEM_kyber_1024_length_shared_secret, 32, NULL);

        /* ====================================================================== */

        /* Compare shared_sectet_e and shared_secret_d */
        int res = memcmp(shared_secret_e, shared_secret_d, IPQP_KEM_kyber_1024_length_shared_secret);
        if (res != 0)
        {
            printf("ERROR: Shared secrets are not te same!\r\n");
            clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
            FAIL_n_EXIT;
        }
        clear_buff(argv[1], public_key, secret_key, ciphertext, shared_secret_e, shared_secret_d);
    }
    else
    {
        SKIP_n_EXIT;
    }

    PASS_n_EXIT;
}
