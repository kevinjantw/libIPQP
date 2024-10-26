#include "ipqp_common.h"
#include "test_common.h"
#include "kat.h"

void clear_buff(const char *algo, uint8_t *pk, uint8_t *sk, uint8_t *sig, uint8_t *msg)
{
    if (strncasecmp(algo, "dilithium_2", 11) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_DSA_dilithium_2_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_DSA_dilithium_2_length_secret_key);
        OQS_MEM_cleanse(sig, IPQP_DSA_dilithium_2_length_signature);
        OQS_MEM_cleanse(msg, KAT_DILITHIUM2_MLEN);
    }
    else if (strncasecmp(algo, "dilithium_3", 11) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_DSA_dilithium_3_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_DSA_dilithium_3_length_secret_key);
        OQS_MEM_cleanse(sig, IPQP_DSA_dilithium_3_length_signature);
        OQS_MEM_cleanse(msg, KAT_DILITHIUM3_MLEN);
    }
    else if (strncasecmp(algo, "dilithium_5", 11) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_DSA_dilithium_5_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_DSA_dilithium_5_length_secret_key);
        OQS_MEM_cleanse(sig, IPQP_DSA_dilithium_5_length_signature);
        OQS_MEM_cleanse(msg, KAT_DILITHIUM5_MLEN);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        SKIP_n_EXIT;
    }

    prepare_kat_data();

    if (strncasecmp(argv[1], "dilithium_2", 11) == 0)
    {
        uint8_t public_key[IPQP_DSA_dilithium_2_length_public_key];
        uint8_t secret_key[IPQP_DSA_dilithium_2_length_secret_key];
        uint8_t message[KAT_DILITHIUM2_MLEN];
        uint8_t signature[IPQP_DSA_dilithium_2_length_signature];
        size_t message_len = KAT_DILITHIUM2_MLEN;
        size_t signature_len;

        /* Create a random test message to sign */
        // OQS_randombytes(message, message_len);
        memcpy((uint8_t *)message, (uint8_t *)kat_dilithium2_msg, message_len);

        printf("Message[" PRINT_SIZE_FMT "]:\r\n", message_len);
        print_arr((uint8_t *)message, message_len, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        char i2c_dev_name[32] = I2C_DEV_NAME;
        i2c_conf_t i2c_conf = {
            .fd = -1,
            .name = i2c_dev_name,
            .open_flags = I2C_OPEN_FLAGS,
            .ten_bits = I2C_TENBITS_ADDR,
            .slave_addr = I2C_SLAVE_ADDRESS};

        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Generate keypair */
        printf(" --- Dilithium 2 keygen --- \r\n");
        ec = IPQP_dsa_keypair(IPQP_ALGO_DILITHIUM_2, (uint8_t *)public_key, (uint8_t *)secret_key);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_2_keypair failed! (%d)\r\n", ec);
            clear_buff("dilithium_2", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }

        printf("Public Key[%d]:\r\n", IPQP_DSA_dilithium_2_length_public_key);
        print_arr((uint8_t *)public_key, IPQP_DSA_dilithium_2_length_public_key, 32, NULL);

        printf("Private Key[%d]:\r\n", IPQP_DSA_dilithium_2_length_secret_key);
        print_arr((uint8_t *)secret_key, IPQP_DSA_dilithium_2_length_secret_key, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        i2c_conf.fd = -1;
        i2c_conf.name = i2c_dev_name;
        i2c_conf.open_flags = I2C_OPEN_FLAGS;
        i2c_conf.ten_bits = I2C_TENBITS_ADDR;
        i2c_conf.slave_addr = I2C_SLAVE_ADDRESS;

        ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Sign the message */
        printf(" --- Dilithium 2 signing --- \r\n");
        ec = IPQP_dsa_sign(IPQP_ALGO_DILITHIUM_2, (uint8_t *)secret_key, (uint8_t *)message, (size_t)message_len, (uint8_t *)signature, (size_t *)&signature_len);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_2_sign failed! (%d)\r\n", ec);
            clear_buff("dilithium_2", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }

        printf("Message[" PRINT_SIZE_FMT "]:\r\n", message_len);
        print_arr((uint8_t *)message, message_len, 32, NULL);

        printf("Signature[" PRINT_SIZE_FMT "]:\r\n", signature_len);
        print_arr((uint8_t *)signature, signature_len, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        i2c_conf.fd = -1;
        i2c_conf.name = i2c_dev_name;
        i2c_conf.open_flags = I2C_OPEN_FLAGS;
        i2c_conf.ten_bits = I2C_TENBITS_ADDR;
        i2c_conf.slave_addr = I2C_SLAVE_ADDRESS;

        ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Verify the signature */
        printf(" --- Dilithium 2 verification --- \r\n");
        bool verified = false;
        ec = IPQP_dsa_verify(IPQP_ALGO_DILITHIUM_2, (uint8_t *)public_key, (uint8_t *)message, (size_t)message_len, (uint8_t *)signature, (size_t)signature_len, (bool *)&verified);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_2_verify failed! (%d)\r\n", ec);
            clear_buff("dilithium_2", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }
        clear_buff("dilithium_2", public_key, secret_key, signature, message);

        if (!verified)
        {
            FAIL_n_EXIT;
        }
    }
    else if (strncasecmp(argv[1], "dilithium_3", 11) == 0)
    {
        uint8_t public_key[IPQP_DSA_dilithium_3_length_public_key];
        uint8_t secret_key[IPQP_DSA_dilithium_3_length_secret_key];
        uint8_t message[KAT_DILITHIUM3_MLEN];
        uint8_t signature[IPQP_DSA_dilithium_3_length_signature];
        size_t message_len = KAT_DILITHIUM3_MLEN;
        size_t signature_len;

        /* Create a random test message to sign */
        // OQS_randombytes(message, message_len);
        memcpy((uint8_t *)message, (uint8_t *)kat_dilithium3_msg, message_len);

        printf("Message[" PRINT_SIZE_FMT "]:\r\n", message_len);
        print_arr((uint8_t *)message, message_len, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        char i2c_dev_name[32] = I2C_DEV_NAME;
        i2c_conf_t i2c_conf = {
            .fd = -1,
            .name = i2c_dev_name,
            .open_flags = I2C_OPEN_FLAGS,
            .ten_bits = I2C_TENBITS_ADDR,
            .slave_addr = I2C_SLAVE_ADDRESS};

        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Generate keypair */
        printf(" --- Dilithium 3 keygen --- \r\n");
        ec = IPQP_dsa_keypair(IPQP_ALGO_DILITHIUM_3, (uint8_t *)public_key, (uint8_t *)secret_key);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_3_keypair failed! (%d)\r\n", ec);
            clear_buff("dilithium_3", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }

        printf("Public Key[%d]:\r\n", IPQP_DSA_dilithium_3_length_public_key);
        print_arr((uint8_t *)public_key, IPQP_DSA_dilithium_3_length_public_key, 32, NULL);

        printf("Private Key[%d]:\r\n", IPQP_DSA_dilithium_3_length_secret_key);
        print_arr((uint8_t *)secret_key, IPQP_DSA_dilithium_3_length_secret_key, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        i2c_conf.fd = -1;
        i2c_conf.name = i2c_dev_name;
        i2c_conf.open_flags = I2C_OPEN_FLAGS;
        i2c_conf.ten_bits = I2C_TENBITS_ADDR;
        i2c_conf.slave_addr = I2C_SLAVE_ADDRESS;

        ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Sign the message */
        printf(" --- Dilithium 3 signing --- \r\n");
        ec = IPQP_dsa_sign(IPQP_ALGO_DILITHIUM_3, (uint8_t *)secret_key, (uint8_t *)message, (size_t)message_len, (uint8_t *)signature, (size_t *)&signature_len);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_3_sign failed! (%d)\r\n", ec);
            clear_buff("dilithium_3", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }

        printf("Signature[%d]:\r\n", IPQP_DSA_dilithium_3_length_signature);
        print_arr((uint8_t *)signature, IPQP_DSA_dilithium_3_length_signature, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        i2c_conf.fd = -1;
        i2c_conf.name = i2c_dev_name;
        i2c_conf.open_flags = I2C_OPEN_FLAGS;
        i2c_conf.ten_bits = I2C_TENBITS_ADDR;
        i2c_conf.slave_addr = I2C_SLAVE_ADDRESS;

        ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Verify the signature */
        printf(" --- Dilithium 3 verification --- \r\n");
        bool verified = false;
        ec = IPQP_dsa_verify(IPQP_ALGO_DILITHIUM_3, (uint8_t *)public_key, (uint8_t *)message, (size_t)message_len, (uint8_t *)signature, (size_t)signature_len, (bool *)&verified);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_3_verify failed! (%d)\r\n", ec);
            clear_buff("dilithium_3", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }
        clear_buff("dilithium_3", public_key, secret_key, signature, message);

        if (!verified)
        {
            FAIL_n_EXIT;
        }
    }
    else if (strncasecmp(argv[1], "dilithium_5", 11) == 0)
    {
        uint8_t public_key[IPQP_DSA_dilithium_5_length_public_key];
        uint8_t secret_key[IPQP_DSA_dilithium_5_length_secret_key];
        uint8_t message[KAT_DILITHIUM5_MLEN];
        uint8_t signature[IPQP_DSA_dilithium_5_length_signature];
        size_t message_len = KAT_DILITHIUM5_MLEN;
        size_t signature_len;

        /* Create a random test message to sign */
        // OQS_randombytes(message, message_len);
        memcpy((uint8_t *)message, (uint8_t *)kat_dilithium5_msg, message_len);

        printf("Message[" PRINT_SIZE_FMT "]:\r\n", message_len);
        print_arr((uint8_t *)message, message_len, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        char i2c_dev_name[32] = I2C_DEV_NAME;
        i2c_conf_t i2c_conf = {
            .fd = -1,
            .name = i2c_dev_name,
            .open_flags = I2C_OPEN_FLAGS,
            .ten_bits = I2C_TENBITS_ADDR,
            .slave_addr = I2C_SLAVE_ADDRESS};

        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Generate keypair */
        printf(" --- Dilithium 5 keygen --- \r\n");
        ec = IPQP_dsa_keypair(IPQP_ALGO_DILITHIUM_5, (uint8_t *)public_key, (uint8_t *)secret_key);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_5_keypair failed! (%d)\r\n", ec);
            clear_buff("dilithium_5", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }

        printf("Public Key[%d]:\r\n", IPQP_DSA_dilithium_5_length_public_key);
        print_arr((uint8_t *)public_key, IPQP_DSA_dilithium_5_length_public_key, 32, NULL);

        printf("Private Key[%d]:\r\n", IPQP_DSA_dilithium_5_length_secret_key);
        print_arr((uint8_t *)secret_key, IPQP_DSA_dilithium_5_length_secret_key, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        i2c_conf.fd = -1;
        i2c_conf.name = i2c_dev_name;
        i2c_conf.open_flags = I2C_OPEN_FLAGS;
        i2c_conf.ten_bits = I2C_TENBITS_ADDR;
        i2c_conf.slave_addr = I2C_SLAVE_ADDRESS;

        ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Sign the message */
        printf(" --- Dilithium 5 signing --- \r\n");
        ec = IPQP_dsa_sign(IPQP_ALGO_DILITHIUM_5, (uint8_t *)secret_key, (uint8_t *)message, (size_t)message_len, (uint8_t *)signature, (size_t *)&signature_len);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_5_sign failed! (%d)\r\n", ec);
            clear_buff("dilithium_5", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }

        printf("Message[" PRINT_SIZE_FMT "]:\r\n", message_len);
        print_arr((uint8_t *)message, message_len, 32, NULL);

        printf("Signature[" PRINT_SIZE_FMT "]:\r\n", signature_len);
        print_arr((uint8_t *)signature, signature_len, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        i2c_conf.fd = -1;
        i2c_conf.name = i2c_dev_name;
        i2c_conf.open_flags = I2C_OPEN_FLAGS;
        i2c_conf.ten_bits = I2C_TENBITS_ADDR;
        i2c_conf.slave_addr = I2C_SLAVE_ADDRESS;

        ec = IPQP_config(IPQP_PROV_I2C_ITRI, &i2c_conf);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: Failed to config IPQP. (%d)\r\n", ec);
            FAIL_n_EXIT;
        }

        /* Verify the signature */
        printf(" --- Dilithium 5 verification --- \r\n");
        bool verified = false;
        ec = IPQP_dsa_verify(IPQP_ALGO_DILITHIUM_5, (uint8_t *)public_key, (uint8_t *)message, (size_t)message_len, (uint8_t *)signature, (size_t)signature_len, (bool *)&verified);
        if (ec != IPQP_EC_SUCCESS)
        {
            printf("ERROR: OQS_SIG_dilithium_5_verify failed! (%d)\r\n", ec);
            clear_buff("dilithium_5", public_key, secret_key, signature, message);
            FAIL_n_EXIT;
        }
        clear_buff("dilithium_5", public_key, secret_key, signature, message);

        if (!verified)
        {
            FAIL_n_EXIT;
        }
    }
    else
    {
        SKIP_n_EXIT;
    }

    PASS_n_EXIT;
}
