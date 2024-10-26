#include "ipqp_common.h"
#include "test_common.h"

#define MESSAGE_LEN 64

void clear_buff(const char *algo, uint8_t *pk, uint8_t *sk, uint8_t *sig, uint8_t *msg)
{
    if (strncasecmp(algo, "dilithium_2", 11) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_DSA_dilithium_2_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_DSA_dilithium_2_length_secret_key);
        OQS_MEM_cleanse(sig, IPQP_DSA_dilithium_2_length_signature);
        OQS_MEM_cleanse(msg, MESSAGE_LEN);
    }
    else if (strncasecmp(algo, "dilithium_3", 11) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_DSA_dilithium_3_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_DSA_dilithium_3_length_secret_key);
        OQS_MEM_cleanse(sig, IPQP_DSA_dilithium_3_length_signature);
        OQS_MEM_cleanse(msg, MESSAGE_LEN);
    }
    else if (strncasecmp(algo, "dilithium_5", 11) == 0)
    {
        OQS_MEM_cleanse(pk, IPQP_DSA_dilithium_5_length_public_key);
        OQS_MEM_cleanse(sk, IPQP_DSA_dilithium_5_length_secret_key);
        OQS_MEM_cleanse(sig, IPQP_DSA_dilithium_5_length_signature);
        OQS_MEM_cleanse(msg, MESSAGE_LEN);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        SKIP_n_EXIT;
    }

    if (strncasecmp(argv[1], "dilithium_2", 11) == 0)
    {
        uint8_t public_key[IPQP_DSA_dilithium_2_length_public_key];
        uint8_t secret_key[IPQP_DSA_dilithium_2_length_secret_key];
        uint8_t message[MESSAGE_LEN];
        uint8_t signature[IPQP_DSA_dilithium_2_length_signature];
        size_t message_len = MESSAGE_LEN;
        size_t signature_len;

        /* Create a random test message to sign */
        OQS_randombytes(message, message_len);

        printf("Message[%d]:\r\n", MESSAGE_LEN);
        print_arr((uint8_t *)message, MESSAGE_LEN, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_LIBOQS);
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
        ec = IPQP_config(IPQP_PROV_LIBOQS);
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

        printf("Signature[%d]:\r\n", IPQP_DSA_dilithium_2_length_signature);
        print_arr((uint8_t *)signature, IPQP_DSA_dilithium_2_length_signature, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        char uart_dev_name[32] = UART_DEV_NAME;
        uart_conf_t uart_conf = {
            .fd = -1,
            .name = uart_dev_name,
            .open_flags = UART_OPEN_FLAGS,
            .input_mode_flags = UART_INPUT_MODE_FLAGS,
            .output_mode_flags = UART_OUTPUT_MODE_FLAGS,
            .control_mode_flags = UART_CONTROL_MODE_FLAGS,
            .local_mode_flags = UART_LOCAL_MODE_FLAGS};

        ec = IPQP_config(IPQP_PROV_UART_ITRI, &uart_conf);
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
        uint8_t message[MESSAGE_LEN];
        uint8_t signature[IPQP_DSA_dilithium_3_length_signature];
        size_t message_len = MESSAGE_LEN;
        size_t signature_len;

        /* Create a random test message to sign */
        OQS_randombytes(message, message_len);

        printf("Message[%d]:\r\n", MESSAGE_LEN);
        print_arr((uint8_t *)message, MESSAGE_LEN, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_LIBOQS);
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
        ec = IPQP_config(IPQP_PROV_LIBOQS);
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
        char uart_dev_name[32] = UART_DEV_NAME;
        uart_conf_t uart_conf = {
            .fd = -1,
            .name = uart_dev_name,
            .open_flags = UART_OPEN_FLAGS,
            .input_mode_flags = UART_INPUT_MODE_FLAGS,
            .output_mode_flags = UART_OUTPUT_MODE_FLAGS,
            .control_mode_flags = UART_CONTROL_MODE_FLAGS,
            .local_mode_flags = UART_LOCAL_MODE_FLAGS};

        ec = IPQP_config(IPQP_PROV_UART_ITRI, &uart_conf);
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
        uint8_t message[MESSAGE_LEN];
        uint8_t signature[IPQP_DSA_dilithium_5_length_signature];
        size_t message_len = MESSAGE_LEN;
        size_t signature_len;

        /* Create a random test message to sign */
        OQS_randombytes(message, message_len);

        printf("Message[%d]:\r\n", MESSAGE_LEN);
        print_arr((uint8_t *)message, MESSAGE_LEN, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        IPQP_ErrorCode ec = IPQP_config(IPQP_PROV_LIBOQS);
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
        ec = IPQP_config(IPQP_PROV_LIBOQS);
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

        printf("Signature[%d]:\r\n", IPQP_DSA_dilithium_5_length_signature);
        print_arr((uint8_t *)signature, IPQP_DSA_dilithium_5_length_signature, 32, NULL);

        /* ====================================================================== */

        /* Config IPQP */
        char uart_dev_name[32] = UART_DEV_NAME;
        uart_conf_t uart_conf = {
            .fd = -1,
            .name = uart_dev_name,
            .open_flags = UART_OPEN_FLAGS,
            .input_mode_flags = UART_INPUT_MODE_FLAGS,
            .output_mode_flags = UART_OUTPUT_MODE_FLAGS,
            .control_mode_flags = UART_CONTROL_MODE_FLAGS,
            .local_mode_flags = UART_LOCAL_MODE_FLAGS};

        ec = IPQP_config(IPQP_PROV_UART_ITRI, &uart_conf);
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
