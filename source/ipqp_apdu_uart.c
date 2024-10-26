#include "ipqp_apdu.h"

#ifndef WORKAROUND_DELAY
#define WORKAROUND_DELAY usleep(1800000);
#endif

IPQP_ErrorCode apdu_uart_kem_assign_ciphertext(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t i_ct_type, uint8_t *i_ct)
{
    // parameters validation
    if ((i_uart_conf == NULL) || (i_ct == NULL))
        return IPQP_EC_NULL_POINTER;

    // assign key lengths according to algorithm
    size_t ct_len = 0;
    switch (i_kem_algo)
    {
    case APDU_CMD_INS_ALGO_KYBER_512:
        ct_len = IPQP_KEM_kyber_512_length_ciphertext;
        break;
    case APDU_CMD_INS_ALGO_KYBER_768:
        ct_len = IPQP_KEM_kyber_768_length_ciphertext;
        break;
    case APDU_CMD_INS_ALGO_KYBER_1024:
        ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
        break;
    default:
        return IPQP_EC_ALGO_MISSING;
    }

    switch (i_ct_type)
    {
    case APDU_CMD_P1_ASSIGN_KEM_CT:
        break;
    default:
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = ct_len; // ct(ct_len)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // expected data length
    size_t rsp_data_full_size = 0; // null(0)
    PRINTF("expected response size: " PRINT_SIZE_FMT "\n", rsp_data_full_size);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = i_ct_type;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the apdu command header
    size_t cmd_pkt_size = 7;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_header");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_header\r\n");

    // send the apdu command data
    // send apdu_data::ct(ct_len)
    cmd_pkt_size = ct_len;
    if (uart_write(i_uart_conf, (uint8_t *)i_ct, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::ct(ct_len)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::ct(ct_len)\r\n");

    // send the apdu command footer
    cmd_pkt_size = 3;
    if (uart_write(i_uart_conf, uart_buff + 7, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_footer");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_footer\r\n");

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_assign_key(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_kem_algo, uint8_t i_key_type, uint8_t *i_key)
{
    // parameters validation
    if ((i_uart_conf == NULL) || (i_key == NULL))
        return IPQP_EC_NULL_POINTER;

    // assign key lengths according to algorithm
    size_t pk_len = 0;
    size_t sk_len = 0;
    bool is_dsa_algo = false;
    switch (i_dsa_kem_algo)
    {
    case APDU_CMD_INS_ALGO_DILITHIUM_2:
        pk_len = IPQP_DSA_dilithium_2_length_public_key;
        sk_len = IPQP_DSA_dilithium_2_length_secret_key;
        is_dsa_algo = true;
        break;
    case APDU_CMD_INS_ALGO_DILITHIUM_3:
        pk_len = IPQP_DSA_dilithium_3_length_public_key;
        sk_len = IPQP_DSA_dilithium_3_length_secret_key;
        is_dsa_algo = true;
        break;
    case APDU_CMD_INS_ALGO_DILITHIUM_5:
        pk_len = IPQP_DSA_dilithium_5_length_public_key;
        sk_len = IPQP_DSA_dilithium_5_length_secret_key;
        is_dsa_algo = true;
        break;
    case APDU_CMD_INS_ALGO_KYBER_512:
        pk_len = IPQP_KEM_kyber_512_length_public_key;
        sk_len = IPQP_KEM_kyber_512_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_KYBER_768:
        pk_len = IPQP_KEM_kyber_768_length_public_key;
        sk_len = IPQP_KEM_kyber_768_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_KYBER_1024:
        pk_len = IPQP_KEM_kyber_1024_length_public_key;
        sk_len = IPQP_KEM_kyber_1024_length_secret_key;
        break;
    default:
        return IPQP_EC_ALGO_MISSING;
    }

    size_t key_len = 0;
    if (is_dsa_algo)
    {
        switch (i_key_type)
        {
        case APDU_CMD_P1_ASSIGN_DSA_PK:
            key_len = pk_len;
            break;
        case APDU_CMD_P1_ASSIGN_DSA_SK:
            key_len = sk_len;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }
    }
    else
    {
        switch (i_key_type)
        {
        case APDU_CMD_P1_ASSIGN_KEM_PK:
            key_len = pk_len;
            break;
        case APDU_CMD_P1_ASSIGN_KEM_SK:
            key_len = sk_len;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = key_len; // key(key_len)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // expected data length
    size_t rsp_data_full_size = 0; // null(0)
    PRINTF("expected response size: " PRINT_SIZE_FMT "\n", rsp_data_full_size);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_kem_algo;
    apdu_cmd.p1 = i_key_type;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the apdu command header
    size_t cmd_pkt_size = 7;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_header");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_header\r\n");

    // send the apdu command data
    // send apdu_data::key(key_len)
    cmd_pkt_size = key_len;
    if (uart_write(i_uart_conf, (uint8_t *)i_key, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::key(key_len)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::key(key_len)\r\n");

    // send the apdu command footer
    cmd_pkt_size = 3;
    if (uart_write(i_uart_conf, uart_buff + 7, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_footer");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_footer\r\n");

    // PRINT_ARR(i_key, key_len, 32, "Written KEY");

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_kem_keypair(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_uart_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign key lengths according to algorithm
    size_t pk_len = 0;
    size_t sk_len = 0;
    switch (i_kem_algo)
    {
    case APDU_CMD_INS_ALGO_KYBER_512:
        pk_len = IPQP_KEM_kyber_512_length_public_key;
        sk_len = IPQP_KEM_kyber_512_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_KYBER_768:
        pk_len = IPQP_KEM_kyber_768_length_public_key;
        sk_len = IPQP_KEM_kyber_768_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_KYBER_1024:
        pk_len = IPQP_KEM_kyber_1024_length_public_key;
        sk_len = IPQP_KEM_kyber_1024_length_secret_key;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int rsp_data_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // send KEM keypair generation command to the UART device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()\r\n");

    // fetching response data from the UART device
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;

    int total_rcvd_data_len = 0;
    int retries = 0;

    while ((total_rcvd_data_len < rsp_data_full_size) && (retries < 1000))
    {
        // reset tx/rx buffer
        memset(uart_buff, 0x00, UART_BUFFER_SIZE);

        ssize_t rcvd_data_len = uart_read(i_uart_conf, (uint8_t *)uart_buff, (size_t)UART_BUFFER_SIZE);
        if (rcvd_data_len > 0)
        {
            // fill the key buffer
            for (int i = 0; i < rcvd_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = uart_buff[i];

                    if ((rcv_buff == o_pk) && (rcv_buff_idx == pk_len))
                    {
                        rcv_buff = o_sk;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == o_sk) && (rcv_buff_idx == sk_len))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcvd_data_len += rcvd_data_len;
            retries = 0;

            /*
            PRINT_ARR(uart_buff, apdu_le, 32, "RX");
            PRINTF("\r\n");
            */
        }
        else
        {
            usleep(10000);
            retries++;
        }
    }

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_kem_encap(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if (apdu_uart_assign_key(i_uart_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_PK, i_pk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign kem public key.");
        return IPQP_EC_FAIL;
    }

    return apdu_uart_kem_encap_cmd(i_uart_conf, i_rtl_src, i_kem_algo, i_pk, o_ss, o_ct);
}

IPQP_ErrorCode apdu_uart_kem_encap_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if ((i_uart_conf == NULL) || (i_pk == NULL) || (o_ss == NULL) || (o_ct == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign data lengths according to algorithm
    size_t ss_len = 0;
    size_t ct_len = 0;
    switch (i_kem_algo)
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

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    memset(o_ct, 0x00, ct_len);

    // data size for apdu command
    size_t cmd_data_full_size = 0; // null(0)
    PRINTF("command data size: " PRINT_SIZE_FMT "\n", cmd_data_full_size);

    // expected data length
    size_t rsp_data_full_size = 2 + 2 + ct_len + ss_len; // ct_len(2) + ss_len(2) + ct(ct_len) + ss(ss_len)
    PRINTF("expected response size: " PRINT_SIZE_FMT "\n", rsp_data_full_size);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_ENCAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the full apdu command
    size_t cmd_pkt_size = 10;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_cmd");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_cmd\r\n");

    uint16_t ct_len_val = 0;
    uint16_t ss_len_val = 0;
    uint8_t ct_len_data[2] = {0x00, 0x00};
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the UART device
    uint8_t *rcv_buff = (uint8_t *)ct_len_data;
    int rcv_buff_idx = 0;

    int total_rcvd_data_len = 0;
    int retries = 0;

    while ((total_rcvd_data_len < rsp_data_full_size) && (retries < 1000))
    {
        // reset tx/rx buffer
        memset(uart_buff, 0x00, UART_BUFFER_SIZE);

        ssize_t rcvd_data_len = uart_read(i_uart_conf, (uint8_t *)uart_buff, (size_t)UART_BUFFER_SIZE);
        if (rcvd_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcvd_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = uart_buff[i];

                    if ((rcv_buff == (uint8_t *)ct_len_data) && (rcv_buff_idx == 2))
                    {
                        // ct_len_val = ((((uint16_t)ct_len_data[1]) & 0xFF) << 8) | (((uint16_t)ct_len_data[0]) & 0xFF);
                        ct_len_val = ((uint16_t *)ct_len_data)[0];
                        rcv_buff = (uint8_t *)ss_len_data;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)ss_len_data) && (rcv_buff_idx == 2))
                    {
                        // ss_len_val = ((((uint16_t)ss_len_data[1]) & 0xFF) << 8) | (((uint16_t)ss_len_data[0]) & 0xFF);
                        ss_len_val = ((uint16_t *)ss_len_data)[0];
                        rcv_buff = (uint8_t *)o_ct;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == o_ct) && (rcv_buff_idx == ct_len_val))
                    {
                        rcv_buff = (uint8_t *)o_ss;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)o_ss) && (rcv_buff_idx == ss_len_val))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcvd_data_len += rcvd_data_len;
            retries = 0;

            /*
            PRINT_ARR(uart_buff, apdu_le, 32, "RX");
            PRINTF("\r\n");
            */
        }
        else
        {
            usleep(10000);
            retries++;
        }
    }

    /*
    PRINTF("ct_len_data: %d\r\n", ct_len_val);
    PRINT_ARR(ct_len_data, 2, 32, "CT_LEN");
    PRINTF("ss_len_data: %d\r\n", ss_len_val);
    PRINT_ARR(ss_len_data, 2, 32, "SS_LEN");
    */

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_kem_decap(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    if (apdu_uart_assign_key(i_uart_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_SK, i_sk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign kem secert key.");
        return IPQP_EC_FAIL;
    }

    if (apdu_uart_kem_assign_ciphertext(i_uart_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_CT, i_ct) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign ciphertext.");
        return IPQP_EC_FAIL;
    }

    return apdu_uart_kem_decap_cmd(i_uart_conf, i_rtl_src, i_kem_algo, i_sk, i_ct, o_ss);
}

IPQP_ErrorCode apdu_uart_kem_decap_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    if ((i_uart_conf == NULL) || (i_sk == NULL) || (i_ct == NULL) || (o_ss == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign data lengths according to algorithm
    size_t ss_len = 0;
    switch (i_kem_algo)
    {
    case APDU_CMD_INS_ALGO_KYBER_512:
        ss_len = IPQP_KEM_kyber_512_length_shared_secret;
        break;
    case APDU_CMD_INS_ALGO_KYBER_768:
        ss_len = IPQP_KEM_kyber_768_length_shared_secret;
        break;
    case APDU_CMD_INS_ALGO_KYBER_1024:
        ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    memset(o_ss, 0x00, ss_len);

    // data size for apdu command
    size_t cmd_data_full_size = 0; // null(0))
    PRINTF("command data size: " PRINT_SIZE_FMT "\n", cmd_data_full_size);

    // expected data length
    size_t rsp_data_full_size = 2 + ss_len; // ss_len_val(2) + ss(ss_len_val)
    PRINTF("expected response size: " PRINT_SIZE_FMT "\n", rsp_data_full_size);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_DECAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the full apdu command
    size_t cmd_pkt_size = 10;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_cmd");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_cmd\r\n");

    uint16_t ss_len_val = 0;
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the UART device
    uint8_t *rcv_buff = (uint8_t *)ss_len_data;
    int rcv_buff_idx = 0;

    int total_rcvd_data_len = 0;
    int retries = 0;

    while ((total_rcvd_data_len < rsp_data_full_size) && (retries < 1000))
    {
        // reset tx/rx buffer
        memset(uart_buff, 0x00, UART_BUFFER_SIZE);

        ssize_t rcvd_data_len = uart_read(i_uart_conf, (uint8_t *)uart_buff, (size_t)UART_BUFFER_SIZE);
        if (rcvd_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcvd_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = uart_buff[i];

                    if ((rcv_buff == (uint8_t *)ss_len_data) && (rcv_buff_idx == 2))
                    {
                        ss_len_val = ((uint16_t *)ss_len_data)[0];
                        rcv_buff = (uint8_t *)o_ss;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)o_ss) && (rcv_buff_idx == ss_len_val))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcvd_data_len += rcvd_data_len;
            retries = 0;

            /*
            PRINT_ARR(uart_buff, apdu_le, 32, "RX");
            PRINTF("\r\n");
            */
        }
        else
        {
            usleep(10000);
            retries++;
        }
    }

    /*
    PRINTF("ss_len_data: %d\r\n", ss_len_val);
    PRINT_ARR(ss_len_data, 2, 32, "SS_LEN");
    */

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_dsa_keypair(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_uart_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign key lengths according to algorithm
    size_t pk_len = 0;
    size_t sk_len = 0;
    switch (i_dsa_algo)
    {
    case APDU_CMD_INS_ALGO_DILITHIUM_2:
        pk_len = IPQP_DSA_dilithium_2_length_public_key;
        sk_len = IPQP_DSA_dilithium_2_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_DILITHIUM_3:
        pk_len = IPQP_DSA_dilithium_3_length_public_key;
        sk_len = IPQP_DSA_dilithium_3_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_DILITHIUM_5:
        pk_len = IPQP_DSA_dilithium_5_length_public_key;
        sk_len = IPQP_DSA_dilithium_5_length_secret_key;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int rsp_data_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // send DSA keypair generation command to the SPI device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // PRINT_ARR(uart_buff, 10, 32, "APDU command");
    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_cmd");
        return IPQP_EC_UART_IO;
    }

    // fetching response data from the UART device
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;

    int total_rcvd_data_len = 0;
    int retries = 0;

    while ((total_rcvd_data_len < rsp_data_full_size) && (retries < 1000))
    {
        // reset tx/rx buffer
        memset(uart_buff, 0x00, UART_BUFFER_SIZE);

        ssize_t rcvd_data_len = uart_read(i_uart_conf, (uint8_t *)uart_buff, (size_t)UART_BUFFER_SIZE);
        if (rcvd_data_len > 0)
        {
            // fill the key buffer
            for (int i = 0; i < rcvd_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = uart_buff[i];

                    if ((rcv_buff == o_pk) && (rcv_buff_idx == pk_len))
                    {
                        rcv_buff = o_sk;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == o_sk) && (rcv_buff_idx == sk_len))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcvd_data_len += rcvd_data_len;
            retries = 0;

            /*
            PRINT_ARR(uart_buff, apdu_le, 32, "RX");
            PRINTF("\r\n");
            */
        }
        else
        {
            usleep(10000);
            retries++;
        }
    }

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_dsa_sign(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if (apdu_uart_assign_key(i_uart_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_SK, i_sk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign dsa secret key.");
        return IPQP_EC_FAIL;
    }

    return apdu_uart_dsa_sign_cmd(i_uart_conf, i_rtl_src, i_dsa_algo, i_sk, i_msg, i_msg_len, o_sm, o_sm_len);
}

IPQP_ErrorCode apdu_uart_dsa_sign_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if ((i_uart_conf == NULL) || (i_sk == NULL) || (i_msg == NULL) || (o_sm == NULL) || (o_sm_len == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign key lengths according to algorithm
    size_t sm_len = 0;
    switch (i_dsa_algo)
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
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    // data size for apdu command
    size_t cmd_data_full_size = 2 + i_msg_len; // msg_len_val(2) + msg(msg_len_val)
    PRINTF("command data size: " PRINT_SIZE_FMT "\n", cmd_data_full_size);

    // expected data length
    size_t rsp_data_full_size = 2 + (sm_len + i_msg_len); // sm_n_msg_len_val(2) + [sm + msg](sm_n_msg_len_val)
    PRINTF("expected response size: " PRINT_SIZE_FMT "\n", rsp_data_full_size);
    PRINTF("sm_len: " PRINT_SIZE_FMT "\r\n", sm_len);
    PRINTF("i_msg_len: " PRINT_SIZE_FMT "\r\n", i_msg_len);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_SIGN;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the apdu command header
    size_t cmd_pkt_size = 7;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_header");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_header\r\n");

    // send the apdu command data
    // send apdu_data::msg_len_val(2)
    cmd_pkt_size = 2;
    if (uart_write(i_uart_conf, (uint8_t *)&i_msg_len, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::msg_len_val(2)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::msg_len_val(2)\r\n");

    // send apdu_data::msg(msg_len_val)
    cmd_pkt_size = i_msg_len;
    if (uart_write(i_uart_conf, (uint8_t *)i_msg, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::msg(msg_len_val)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::msg(msg_len_val)\r\n");

    // send the apdu command footer
    cmd_pkt_size = 3;
    if (uart_write(i_uart_conf, uart_buff + 7, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_footer");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_footer\r\n");

    *o_sm_len = 0;
    uint8_t sm_n_msg_len_data[2] = {0x00, 0x00};
    size_t sm_n_msg_len_val = 0;

    // fetching response data from the UART device
    uint8_t *rcv_buff = (uint8_t *)sm_n_msg_len_data;
    int rcv_buff_idx = 0;

    int total_rcvd_data_len = 0;
    int retries = 0;

    while ((total_rcvd_data_len < rsp_data_full_size) && (retries < 2000))
    {
        // reset tx/rx buffer
        memset(uart_buff, 0x00, UART_BUFFER_SIZE);

        ssize_t rcvd_data_len = uart_read(i_uart_conf, (uint8_t *)uart_buff, (size_t)UART_BUFFER_SIZE);
        if (rcvd_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcvd_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = uart_buff[i];

                    if ((rcv_buff == (uint8_t *)sm_n_msg_len_data) && (rcv_buff_idx == 2))
                    {
                        sm_n_msg_len_val = (size_t)(((uint16_t *)(sm_n_msg_len_data))[0]);
                        *o_sm_len = (size_t)(sm_n_msg_len_val - i_msg_len);
                        rcv_buff = (uint8_t *)o_sm;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)o_sm) && (rcv_buff_idx == (*o_sm_len)))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcvd_data_len += rcvd_data_len;
            retries = 0;

            /*
            PRINT_ARR(uart_buff, apdu_le, 32, "RX");
            PRINTF("\r\n");
            */
        }
        else
        {
            usleep(10000);
            retries++;
        }
    }

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_dsa_verify(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if (apdu_uart_assign_key(i_uart_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_PK, i_pk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign dsa public key.");
        return IPQP_EC_FAIL;
    }

    return apdu_uart_dsa_verify_cmd(i_uart_conf, i_rtl_src, i_dsa_algo, i_pk, i_msg, i_msg_len, i_sm, i_sm_len, o_verified);
}

IPQP_ErrorCode apdu_uart_dsa_verify_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if ((i_uart_conf == NULL) || (i_pk == NULL) || (i_msg == NULL) || (i_sm == NULL) || (o_verified == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign key lengths according to algorithm
    switch (i_dsa_algo)
    {
    case APDU_CMD_INS_ALGO_DILITHIUM_2:
    case APDU_CMD_INS_ALGO_DILITHIUM_3:
    case APDU_CMD_INS_ALGO_DILITHIUM_5:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t uart_buff[UART_BUFFER_SIZE];
    memset(uart_buff, 0x00, UART_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = 2 + i_sm_len + i_msg_len; // sm_n_msg_len_val(2) + [sm + msg](sm_n_msg_len_val)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // expected data length
    int rsp_data_full_size = 2 + i_msg_len; // msg_len_val(2) + msg(msg_len_val)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_VERIFY;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &apdu_cmd, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    // send the apdu command header
    size_t cmd_pkt_size = 7;
    if (uart_write(i_uart_conf, uart_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_header");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_header\r\n");

    // send the apdu command data
    uint16_t sm_n_msg_len_val = i_sm_len + i_msg_len;

    // send apdu_data::sm_n_msg_len_val(2)
    cmd_pkt_size = 2;
    if (uart_write(i_uart_conf, (uint8_t *)&sm_n_msg_len_val, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::sm_n_msg_len_val(2)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::sm_n_msg_len_val(2)\r\n");

    // send apdu_data::sm(sm_len)
    cmd_pkt_size = i_sm_len;
    if (uart_write(i_uart_conf, (uint8_t *)i_sm, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::sm(sm_len)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::sm(sm_len)\r\n");

    // send apdu_data::msg(msg_len)
    cmd_pkt_size = i_msg_len;
    if (uart_write(i_uart_conf, (uint8_t *)i_msg, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_data::msg(msg_len)");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_data::msg(msg_len)\r\n");

    // send the apdu command footer
    cmd_pkt_size = 3;
    if (uart_write(i_uart_conf, uart_buff + 7, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_UART_IO, "uart_write()::apdu_footer");
        return IPQP_EC_UART_IO;
    }
    PRINTF("uart_write()::apdu_footer\r\n");

    uint8_t msg_len_data[2] = {0x00, 0x00};
    uint16_t msg_len_val = 0;
    uint8_t rcv_msg_buff[1] = {0x00};

    // fetching response data from the UART device
    uint8_t *rcv_buff = (uint8_t *)msg_len_data;
    int rcv_buff_idx = 0;
    int rcv_msg_buff_idx = 0;

    *o_verified = true;

    int total_rcvd_data_len = 0;
    int retries = 0;

    while ((total_rcvd_data_len < rsp_data_full_size) && (retries < 1000))
    {
        // reset tx/rx buffer
        memset(uart_buff, 0x00, UART_BUFFER_SIZE);

        ssize_t rcvd_data_len = uart_read(i_uart_conf, (uint8_t *)uart_buff, (size_t)UART_BUFFER_SIZE);
        if (rcvd_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcvd_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = uart_buff[i];

                    if ((rcv_buff == (uint8_t *)msg_len_data) && (rcv_buff_idx == 2))
                    {
                        msg_len_val = (size_t)(((uint16_t *)(msg_len_data))[0]);
                        rcv_buff = rcv_msg_buff;
                        rcv_buff_idx = 0;
                        rcv_msg_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)rcv_msg_buff) && (rcv_msg_buff_idx < msg_len_val))
                    {
                        if (uart_buff[i] != i_msg[rcv_msg_buff_idx])
                            *o_verified = false;

                        rcv_buff_idx = 0;
                        rcv_msg_buff_idx++;
                    }
                    else if ((rcv_buff == (uint8_t *)rcv_msg_buff) && (rcv_msg_buff_idx == msg_len_val))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcvd_data_len += rcvd_data_len;
            retries = 0;

            /*
            PRINT_ARR(uart_buff, apdu_le, 32, "RX");
            PRINTF("\r\n");
            */
        }
        else
        {
            usleep(10000);
            retries++;
        }
    }

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_uart_status_check(uart_conf_t *i_uart_conf, uint8_t *o_result)
{
    if ((i_uart_conf == NULL) || (o_result == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    apdu_t my_apdu;

    uint8_t uart_buff[10];
    memset(uart_buff, 0, 10);

    my_apdu.cla = APDU_CLA_DEV_INIT;
    my_apdu.ins = 0xAA;
    my_apdu.p1 = 0xBB;
    my_apdu.p2 = 0xCC;
    my_apdu.lc = 0;
    my_apdu.le = 2;
    my_apdu.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)uart_buff, &my_apdu, APDU_CMD_TPY_UART);

    // uart_clear_rcv_buffer(i_uart_conf);

    ssize_t snd_pkt_len = 10;
    if (uart_write(i_uart_conf, uart_buff, (size_t)snd_pkt_len) != snd_pkt_len)
        return IPQP_EC_UART_IO;

    size_t rcv_pkt_len = 2;
    if (uart_read_packet(i_uart_conf, uart_buff, rcv_pkt_len) != IPQP_EC_SUCCESS)
        return IPQP_EC_UART_IO;

    o_result[0] = uart_buff[0];
    o_result[1] = uart_buff[1];

    WORKAROUND_DELAY;

    return IPQP_EC_SUCCESS;
}
