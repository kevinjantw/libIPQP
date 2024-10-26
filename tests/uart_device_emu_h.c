#include "ipqp_common.h"
#include "test_common.h"

int receive_apdu_command(uart_conf_t *uart_conf, apdu_t *rcvd_apdu, uint8_t **ret_data);

int main(int argc, char *argv[])
{
    char uart_name[16] = UART_DEV_NAME;
    char *uart_iface_name = uart_name;
    if (argc > 1)
        uart_iface_name = argv[1];

    printf("UART: %s\r\n", uart_iface_name);

    uart_conf_t uart_conf = {
        -1,
        uart_iface_name,
        UART_OPEN_FLAGS,
        UART_INPUT_MODE_FLAGS,
        UART_OUTPUT_MODE_FLAGS,
        UART_CONTROL_MODE_FLAGS,
        UART_LOCAL_MODE_FLAGS};

    if (uart_open(&uart_conf) < 0)
    {
        PRINTF("[ERROR]:: fail to open uart iface %s\r\n", uart_conf.name);
        FAIL_n_EXIT;
    }

    printf("%s Listening...\r\n", uart_name);
    while (true)
    {
        apdu_t rcvd_apdu;
        bzero(&rcvd_apdu, sizeof(rcvd_apdu));
        rcvd_apdu.data = NULL;

        uint8_t *snd_buff = NULL;

        // receive apdu command
        if (receive_apdu_command(&uart_conf, &rcvd_apdu, &snd_buff) < 0)
        {
            printf("[ERROR]: receive_apdu_command()\r\n");
            uart_close(&uart_conf);
            break;
        }
        PRINTF("receive_apdu_command():: Success\r\n");

        printf("apdu.cla: 0x%02X\r\n", rcvd_apdu.cla);
        printf("apdu.ins: 0x%02X\r\n", rcvd_apdu.ins);
        printf("apdu.p1: 0x%02X\r\n", rcvd_apdu.p1);
        printf("apdu.p2: 0x%02X\r\n", rcvd_apdu.p2);
        printf("apdu.lc: 0x%06X (%d)\r\n", rcvd_apdu.lc, rcvd_apdu.lc);
        printf("apdu.le: 0x%06X (%d)\r\n", rcvd_apdu.le, rcvd_apdu.le);
        if (rcvd_apdu.lc > 0)
            print_arr(rcvd_apdu.data, rcvd_apdu.lc, 32, "apdu.data");
        else
            printf("apdu.data: NULL\r\n");

        if (rcvd_apdu.le > 0)
        {
            print_arr(snd_buff, rcvd_apdu.le, 32, "return data");
            ssize_t snt_data_len = uart_write(&uart_conf, snd_buff, rcvd_apdu.le);

            if (snd_buff != NULL)
            {
                free(snd_buff);
                snd_buff = NULL;
            }

            if (snt_data_len != rcvd_apdu.le)
            {
                printf("[ERROR]: uart_write() \r\n");
                break;
            }
        }

        if (rcvd_apdu.data != NULL)
            free(rcvd_apdu.data);

        if (snd_buff != NULL)
            free(snd_buff);
    }

    if (uart_close(&uart_conf) < 0)
    {
        PRINTF("[ERROR]:: fail to close uart iface %s\r\n", uart_conf.name);
        FAIL_n_EXIT;
    }

    PASS_n_EXIT;
}

#define IPQP_EC_CHECK(ipqp_ec, buff, err_log) \
    if (ipqp_ec != IPQP_EC_SUCCESS)           \
    {                                         \
        if (strlen(err_log) > 1)              \
            printf(err_log);                  \
        if (buff != NULL)                     \
        {                                     \
            free(buff);                       \
            buff = NULL;                      \
        }                                     \
        return -1;                            \
    }

int receive_apdu_command(uart_conf_t *uart_conf, apdu_t *rcvd_apdu, uint8_t **ret_data)
{
    // receive apdu header (cla -> lc)
    uint8_t buff[7];
    IPQP_ErrorCode ipqp_ec = IPQP_EC_SUCCESS;

    // read apdu header
    printf("read apdu header\r\n");
    ipqp_ec = uart_read_packet(uart_conf, buff, 7);
    IPQP_EC_CHECK(ipqp_ec, *ret_data, "[ERROR]: uart_read_packet()::apdu_header(7)\r\n");

    rcvd_apdu->cla = buff[0];
    rcvd_apdu->ins = buff[1];
    rcvd_apdu->p1 = buff[2];
    rcvd_apdu->p2 = buff[3];
    rcvd_apdu->lc = ((buff[5] << 8) | (buff[6]));

    printf("read apdu data\r\n");
    if (rcvd_apdu->lc > 0)
    {
        // receive apdu data
        rcvd_apdu->data = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->lc);

        switch (rcvd_apdu->p1)
        {
        case APDU_CMD_P1_KEM_KEYPAIR:
        case APDU_CMD_P1_DSA_KEYPAIR:
        {
            // do nothing
            break;
        }

        case APDU_CMD_P1_KEM_ENCAP:
        {
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                pk_len = IPQP_KEM_kyber_512_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                pk_len = IPQP_KEM_kyber_768_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                pk_len = IPQP_KEM_kyber_1024_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            // read pk(pk_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data, pk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::pk(pk_len)\r\n");

            break;
        }

        case APDU_CMD_P1_KEM_DECAP:
        {
            size_t sk_len = 0;
            size_t ct_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                sk_len = IPQP_KEM_kyber_512_length_secret_key;
                ct_len = IPQP_KEM_kyber_512_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                sk_len = IPQP_KEM_kyber_768_length_secret_key;
                ct_len = IPQP_KEM_kyber_768_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                sk_len = IPQP_KEM_kyber_1024_length_secret_key;
                ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            // read ct(ct_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data, ct_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::ct(ct_len)\r\n");

            // read sk(sk_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data + ct_len, sk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::sk(sk_len)\r\n");

            break;
        }

        case APDU_CMD_P1_DSA_SIGN:
        {
            // read msg_len_val(2)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data, 2);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::msg_len_val(2)\r\n");

            uint16_t msg_len = *(&(rcvd_apdu->data[0]));
            printf("msg_len_val: %u\n", msg_len);

            // read msg(msg_len_val)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data + 2, (size_t)msg_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::msg(msg_len_val)\r\n");

            size_t sk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                sk_len = IPQP_DSA_dilithium_2_length_secret_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                sk_len = IPQP_DSA_dilithium_3_length_secret_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                sk_len = IPQP_DSA_dilithium_5_length_secret_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            // read sk(sk_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data + 2 + msg_len, sk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::sk(sk_len)\r\n");

            break;
        }

        case APDU_CMD_P1_DSA_VERIFY:
        {
            // read sm_n_msg_len_val(2)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data, 2);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::sm_n_msg_len_val(2)\r\n");

            uint16_t sm_n_msg_len_val = *((uint16_t *)rcvd_apdu->data);
            printf("sm_n_msg_len_val: %u\n", sm_n_msg_len_val);

            size_t sm_len = 0;
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                sm_len = IPQP_DSA_dilithium_2_length_signature;
                pk_len = IPQP_DSA_dilithium_2_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                sm_len = IPQP_DSA_dilithium_3_length_signature;
                pk_len = IPQP_DSA_dilithium_3_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                sm_len = IPQP_DSA_dilithium_5_length_signature;
                pk_len = IPQP_DSA_dilithium_5_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            size_t msg_len = sm_n_msg_len_val - sm_len;

            // read sm(sm_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data + 2, sm_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::sm(sm_len)\r\n");

            // read msg(msg_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data + 2 + sm_len, msg_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::msg(msg_len)\r\n");

            // read pk(pk_len)
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data + 2 + sm_len + msg_len, pk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()::pk(pk_len)\r\n");

            break;
        }

        default:
        {
            ipqp_ec = uart_read_packet(uart_conf, rcvd_apdu->data, rcvd_apdu->lc);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: uart_read_packet()\r\n");

            break;
        }
        }
    }

    // read apdu footer (le)
    printf("read apdu footer\r\n");
    ipqp_ec = uart_read_packet(uart_conf, buff, 3);
    IPQP_EC_CHECK(ipqp_ec, *ret_data, "[ERROR]: uart_read_packet()::apdu_footer(3)\r\n");

    rcvd_apdu->le = ((buff[1] << 8) | (buff[2]));

    printf("prepare return data\r\n");
    if (rcvd_apdu->le > 0)
    {
        switch (rcvd_apdu->p1)
        {

        case APDU_CMD_P1_KEM_KEYPAIR:
        {
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                pk_len = IPQP_KEM_kyber_512_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                pk_len = IPQP_KEM_kyber_768_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                pk_len = IPQP_KEM_kyber_1024_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            ipqp_ec = IPQP_kem_keypair(rcvd_apdu->ins, (uint8_t *)(*ret_data), (uint8_t *)((*ret_data) + pk_len));
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_kem_keypair()\r\n");

            break;
        }

        case APDU_CMD_P1_KEM_ENCAP:
        {
            uint16_t ss_len = 0;
            uint16_t ct_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                ss_len = IPQP_KEM_kyber_512_length_shared_secret;
                ct_len = IPQP_KEM_kyber_512_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                ss_len = IPQP_KEM_kyber_768_length_shared_secret;
                ct_len = IPQP_KEM_kyber_768_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
                ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
                break;
            default:
                IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
                return IPQP_EC_ALGO_MISSING;
            }

            uint8_t *pk = rcvd_apdu->data;

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *ss = (*ret_data) + 2 + 2 + ct_len;
            uint8_t *ct = (*ret_data) + 2 + 2;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_kem_encap(rcvd_apdu->ins, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_kem_encap()\r\n");

            (*ret_data)[0] = ((uint8_t *)&ct_len)[0];
            (*ret_data)[1] = ((uint8_t *)&ct_len)[1];

            (*ret_data)[2] = ((uint8_t *)&ss_len)[0];
            (*ret_data)[3] = ((uint8_t *)&ss_len)[1];

            break;
        }

        case APDU_CMD_P1_KEM_DECAP:
        {
            uint16_t ss_len = 0;
            uint16_t ct_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                ss_len = IPQP_KEM_kyber_512_length_shared_secret;
                ct_len = IPQP_KEM_kyber_512_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                ss_len = IPQP_KEM_kyber_768_length_shared_secret;
                ct_len = IPQP_KEM_kyber_768_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
                ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
                break;
            default:
                IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
                return IPQP_EC_ALGO_MISSING;
            }

            uint8_t *ct = rcvd_apdu->data;
            uint8_t *sk = rcvd_apdu->data + ct_len;

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *ss = (*ret_data) + 2;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_kem_decap(rcvd_apdu->ins, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_kem_decap()\r\n");

            (*ret_data)[0] = ((uint8_t *)&ss_len)[0];
            (*ret_data)[1] = ((uint8_t *)&ss_len)[1];

            break;
        }

        case APDU_CMD_P1_DSA_KEYPAIR:
        {
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                pk_len = IPQP_DSA_dilithium_2_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                pk_len = IPQP_DSA_dilithium_3_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                pk_len = IPQP_DSA_dilithium_5_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *pk = (*ret_data);
            uint8_t *sk = (*ret_data) + pk_len;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_dsa_keypair(rcvd_apdu->ins, (uint8_t *)pk, (uint8_t *)sk);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_dsa_keypair()\r\n");

            break;
        }

        case APDU_CMD_P1_DSA_SIGN:
        {
            size_t sm_len = 0;
            uint16_t msg_len = *(&(rcvd_apdu->data[0]));
            uint8_t *msg = rcvd_apdu->data + 2;
            uint8_t *sk = rcvd_apdu->data + 2 + msg_len;

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *sm = (*ret_data) + 2;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_dsa_sign(rcvd_apdu->ins, (uint8_t *)sk, (uint8_t *)msg, (size_t)msg_len, (uint8_t *)sm, (size_t *)&sm_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_dsa_sign()\r\n");

            uint8_t *msg_o = (*ret_data) + 2 + sm_len;
            memcpy(msg_o, msg, msg_len);

            uint16_t sm_n_msg_len_16 = (uint16_t)(sm_len + msg_len);
            (*ret_data)[0] = ((uint8_t *)&sm_n_msg_len_16)[0];
            (*ret_data)[1] = ((uint8_t *)&sm_n_msg_len_16)[1];

            break;
        }
        case APDU_CMD_P1_DSA_VERIFY:
        {
            size_t sm_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                sm_len = IPQP_DSA_dilithium_2_length_signature;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                sm_len = IPQP_DSA_dilithium_3_length_signature;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                sm_len = IPQP_DSA_dilithium_5_length_signature;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            uint16_t sm_n_msg_len = *((uint16_t *)rcvd_apdu->data);
            uint16_t msg_len = sm_n_msg_len - sm_len;

            uint8_t *sm = rcvd_apdu->data + 2;
            uint8_t *msg = rcvd_apdu->data + 2 + sm_len;
            uint8_t *pk = rcvd_apdu->data + 2 + sm_len + msg_len;

            bool verified = false;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_dsa_verify(rcvd_apdu->ins, (uint8_t *)pk, (uint8_t *)msg, (size_t)msg_len, (uint8_t *)sm, (size_t)sm_len, (bool *)&verified);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_dsa_verify()\r\n");

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            if (verified)
            {
                (*ret_data)[0] = ((uint8_t *)&msg_len)[0];
                (*ret_data)[1] = ((uint8_t *)&msg_len)[1];
                memcpy((*ret_data) + 2, msg, rcvd_apdu->le - 2);
            }
            else
            {
                (*ret_data)[0] = ((uint8_t *)&msg_len)[0];
                (*ret_data)[1] = ((uint8_t *)&msg_len)[1];
                memset((*ret_data) + 2, 0xFF, msg_len);
            }

            break;
        }
        default:
        {

            if (rcvd_apdu->le > 0)
            {
                (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);

                for (int i = 0; i < rcvd_apdu->le; i++)
                    (*ret_data)[i] = 0xFF;

                (*ret_data)[0] = ((uint8_t *)&(rcvd_apdu->le))[0];
                (*ret_data)[1] = ((uint8_t *)&(rcvd_apdu->le))[1];
            }
            else
            {
                *ret_data = NULL;
            }
        }
        }
    }
    else
        *ret_data = NULL;

    return 0;
}
