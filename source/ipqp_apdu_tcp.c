#include "ipqp_apdu.h"

IPQP_ErrorCode apdu_tcp_kem_keypair(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_tcp_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
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

    uint8_t tcp_buff[TCP_BUFFER_SIZE];
    memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int rsp_data_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // send KEM keypair generation command to the TCP device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)tcp_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command header, from "cla" to "lc"
    size_t cmd_pkt_size = 7;
    if (tcp_write(i_tcp_conf, tcp_buff, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::header");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::header\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command footer, "le"
    cmd_pkt_size = 3;
    if (tcp_write(i_tcp_conf, (uint8_t *)&(tcp_buff[7]), cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::footer");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::footer\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // fetching response data from the TCP server
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;
    int round = 1;
    int retries = 0;
    ssize_t total_rcv_data_szie = 0;

    if (tcp_send_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_send_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_send_ack()\r\n");

    while ((total_rcv_data_szie < rsp_data_full_size) && (retries <= (i_tcp_conf->retries_on_failure)))
    {
        // reset tx/rx buffer
        memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

        // fetch data
        ssize_t rcv_data_len = tcp_read(i_tcp_conf, tcp_buff, TCP_BUFFER_SIZE);
        PRINTF("fetching data (idx = %d; len = " PRINT_SSIZE_FMT ")\r\n", round, rcv_data_len);

        if (rcv_data_len > 0)
        {
            // fill the key buffer
            for (int i = 0; i < rcv_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = tcp_buff[i];

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

            total_rcv_data_szie += rcv_data_len;
            round++;
            retries = 0;
        }
        else
        {
            retries++;
        }
    }

    if (retries > (i_tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_tcp_kem_encap(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if ((i_tcp_conf == NULL) || (i_pk == NULL) || (o_ss == NULL) || (o_ct == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign data lengths according to algorithm
    size_t ss_len = 0;
    size_t ct_len = 0;
    size_t pk_len = 0;
    switch (i_kem_algo)
    {
    case APDU_CMD_INS_ALGO_KYBER_512:
        ss_len = IPQP_KEM_kyber_512_length_shared_secret;
        ct_len = IPQP_KEM_kyber_512_length_ciphertext;
        pk_len = IPQP_KEM_kyber_512_length_public_key;
        break;
    case APDU_CMD_INS_ALGO_KYBER_768:
        ss_len = IPQP_KEM_kyber_768_length_shared_secret;
        ct_len = IPQP_KEM_kyber_768_length_ciphertext;
        pk_len = IPQP_KEM_kyber_768_length_public_key;
        break;
    case APDU_CMD_INS_ALGO_KYBER_1024:
        ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
        ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
        pk_len = IPQP_KEM_kyber_1024_length_public_key;
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

    // data size for apdu command
    int cmd_data_full_size = pk_len; // pk(pk_len)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // expected data length
    int rsp_data_full_size = 2 + 2 + ct_len + ss_len; // ct_len_val(2) + ss_len_val(2) + ct(ct_len_val) + ss(ss_len_val)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // reset tx/rx buffer
    uint8_t tcp_buff[TCP_BUFFER_SIZE];
    memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

    memset(o_ct, 0x00, ct_len);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_ENCAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)tcp_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command header, from "cla" to "lc"
    size_t cmd_pkt_size = 7;
    if (tcp_write(i_tcp_conf, tcp_buff, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::header");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::header\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, pk(pk_len)
    cmd_pkt_size = pk_len;
    if (tcp_write(i_tcp_conf, (uint8_t *)i_pk, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::pk(pk_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::pk(pk_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command footer, "le"
    cmd_pkt_size = 3;
    if (tcp_write(i_tcp_conf, (uint8_t *)&(tcp_buff[7]), cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::footer");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::footer\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    uint16_t ct_len_val = 0;
    uint16_t ss_len_val = 0;
    uint8_t ct_len_data[2] = {0x00, 0x00};
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the TCP server
    uint8_t *rcv_buff = (uint8_t *)ct_len_data;
    int rcv_buff_idx = 0;
    int round = 1;
    int retries = 0;
    ssize_t total_rcv_data_szie = 0;

    if (tcp_send_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_send_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_send_ack()\r\n");

    while ((total_rcv_data_szie < rsp_data_full_size) && (retries <= (i_tcp_conf->retries_on_failure)))
    {
        // reset tx/rx buffer
        memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

        // fetch data
        ssize_t rcv_data_len = tcp_read(i_tcp_conf, tcp_buff, TCP_BUFFER_SIZE);
        PRINTF("fetching data (idx = %d; len = " PRINT_SSIZE_FMT ")\r\n", round, rcv_data_len);

        // check if the response packet is valid
        if (rcv_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcv_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = tcp_buff[i];

                    if ((rcv_buff == (uint8_t *)ct_len_data) && (rcv_buff_idx == 2))
                    {
                        ct_len_val = ((uint16_t *)ct_len_data)[0];
                        rcv_buff = (uint8_t *)ss_len_data;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)ss_len_data) && (rcv_buff_idx == 2))
                    {
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

            total_rcv_data_szie += rcv_data_len;
            round++;
            retries = 0;
        }
        else
        {
            retries++;
        }
    }

    if (retries > (i_tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_tcp_kem_decap(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    if ((i_tcp_conf == NULL) || (i_sk == NULL) || (i_ct == NULL) || (o_ss == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign data lengths according to algorithm
    size_t ss_len = 0;
    size_t sk_len = 0;
    size_t ct_len = 0;
    switch (i_kem_algo)
    {
    case APDU_CMD_INS_ALGO_KYBER_512:
        ss_len = IPQP_KEM_kyber_512_length_shared_secret;
        sk_len = IPQP_KEM_kyber_512_length_secret_key;
        ct_len = IPQP_KEM_kyber_512_length_ciphertext;
        break;
    case APDU_CMD_INS_ALGO_KYBER_768:
        ss_len = IPQP_KEM_kyber_768_length_shared_secret;
        sk_len = IPQP_KEM_kyber_768_length_secret_key;
        ct_len = IPQP_KEM_kyber_768_length_ciphertext;
        break;
    case APDU_CMD_INS_ALGO_KYBER_1024:
        ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
        sk_len = IPQP_KEM_kyber_1024_length_secret_key;
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

    // data size for apdu command
    int cmd_data_full_size = ct_len + sk_len; // ct(ct_len) + sk(sk_len)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // expected data length
    int rsp_data_full_size = 2 + ss_len; // ss_len_val(2) + ss(ss_len_val)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // reset tx/rx buffer
    uint8_t tcp_buff[TCP_BUFFER_SIZE];
    memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

    memset(o_ss, 0x00, ss_len);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_DECAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)tcp_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command header, from "cla" to "lc"
    size_t cmd_pkt_size = 7;
    if (tcp_write(i_tcp_conf, tcp_buff, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::header");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::header\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, ct(ct_len)
    cmd_pkt_size = ct_len;
    if (tcp_write(i_tcp_conf, (uint8_t *)i_ct, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::ct(ct_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::ct(ct_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, sk(sk_len)
    cmd_pkt_size = sk_len;
    if (tcp_write(i_tcp_conf, (uint8_t *)i_sk, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::sk(sk_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::sk(sk_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command footer, "le"
    cmd_pkt_size = 3;
    if (tcp_write(i_tcp_conf, (uint8_t *)&(tcp_buff[7]), cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::footer");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::footer\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    uint16_t ss_len_val = 0;
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the TCP server
    uint8_t *rcv_buff = (uint8_t *)ss_len_data;
    int rcv_buff_idx = 0;
    int round = 1;
    int retries = 0;
    ssize_t total_rcv_data_szie = 0;

    if (tcp_send_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_send_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_send_ack()\r\n");

    while ((total_rcv_data_szie < rsp_data_full_size) && (retries <= (i_tcp_conf->retries_on_failure)))
    {
        // reset tx/rx buffer
        memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

        // fetch data
        ssize_t rcv_data_len = tcp_read(i_tcp_conf, tcp_buff, TCP_BUFFER_SIZE);
        PRINTF("fetching data (idx = %d; len = " PRINT_SSIZE_FMT ")\r\n", round, rcv_data_len);

        // check if the response packet is valid
        if (rcv_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcv_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = tcp_buff[i];

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

            total_rcv_data_szie += rcv_data_len;
            round++;
            retries = 0;
        }
        else
        {
            retries++;
        }
    }

    if (retries > (i_tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_tcp_dsa_keypair(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_tcp_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
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

    uint8_t tcp_buff[TCP_BUFFER_SIZE];
    memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int rsp_data_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // send DSA keypair generation command to the TCP server
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)tcp_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command header, from "cla" to "lc"
    size_t cmd_pkt_size = 7;
    if (tcp_write(i_tcp_conf, tcp_buff, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::header");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::header\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command footer, "le"
    cmd_pkt_size = 3;
    if (tcp_write(i_tcp_conf, (uint8_t *)&(tcp_buff[7]), cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::footer");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::footer\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // fetching response data from the TCP server
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;
    int round = 1;
    int retries = 0;
    ssize_t total_rcv_data_szie = 0;

    if (tcp_send_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_send_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_send_ack()\r\n");

    while ((total_rcv_data_szie < rsp_data_full_size) && (retries <= (i_tcp_conf->retries_on_failure)))
    {
        // reset tx/rx buffer
        memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

        // fetch data
        ssize_t rcv_data_len = tcp_read(i_tcp_conf, tcp_buff, TCP_BUFFER_SIZE);
        PRINTF("fetching data (idx = %d; len = " PRINT_SSIZE_FMT ")\r\n", round, rcv_data_len);

        if (rcv_data_len > 0)
        {
            // fill the key buffer
            for (int i = 0; i < rcv_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = tcp_buff[i];
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

            total_rcv_data_szie += rcv_data_len;
            round++;
            retries = 0;
        }
        else
        {
            retries++;
        }
    }

    if (retries > (i_tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_tcp_dsa_sign(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if ((i_tcp_conf == NULL) || (i_sk == NULL) || (i_msg == NULL) || (o_sm == NULL) || (o_sm_len == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign key lengths according to algorithm
    size_t sm_len = 0;
    size_t sk_len = 0;
    switch (i_dsa_algo)
    {
    case APDU_CMD_INS_ALGO_DILITHIUM_2:
        sm_len = IPQP_DSA_dilithium_2_length_signature;
        sk_len = IPQP_DSA_dilithium_2_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_DILITHIUM_3:
        sm_len = IPQP_DSA_dilithium_3_length_signature;
        sk_len = IPQP_DSA_dilithium_3_length_secret_key;
        break;
    case APDU_CMD_INS_ALGO_DILITHIUM_5:
        sm_len = IPQP_DSA_dilithium_5_length_signature;
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

    // data size for apdu command
    int cmd_data_full_size = 2 + i_msg_len + sk_len; // msg_len_val(2) + msg(msg_len_val) + sk(sk_len)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // expected data length
    int rsp_data_full_size = 2 + sm_len; // sm_len_val(2) + sm(sm_len_val)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // reset tx/rx buffer
    uint8_t tcp_buff[TCP_BUFFER_SIZE];
    memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_SIGN;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = cmd_data_full_size;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)tcp_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command header, from "cla" to "lc"
    size_t cmd_pkt_size = 7;
    if (tcp_write(i_tcp_conf, tcp_buff, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::header");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::header\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, msg_len_val(2)
    cmd_pkt_size = 2;
    if (tcp_write(i_tcp_conf, (uint8_t *)&i_msg_len, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::msg_len_val(2)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::msg_len_val(2)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, i_msg(i_msg_len)
    if (tcp_write(i_tcp_conf, (uint8_t *)i_msg, i_msg_len) != i_msg_len)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::i_msg(i_msg_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::i_msg(i_msg_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, i_sk(sk_len)
    if (tcp_write(i_tcp_conf, (uint8_t *)i_sk, sk_len) != sk_len)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::i_sk(sk_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::i_sk(sk_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command footer, "le"
    cmd_pkt_size = 3;
    if (tcp_write(i_tcp_conf, (uint8_t *)&(tcp_buff[7]), cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::footer");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::footer\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    *o_sm_len = 0;
    uint8_t sm_len_data[2] = {0x00, 0x00};

    // fetching response data from the TCP server
    uint8_t *rcv_buff = (uint8_t *)sm_len_data;
    int rcv_buff_idx = 0;
    int round = 1;
    int retries = 0;
    ssize_t total_rcv_data_szie = 0;

    if (tcp_send_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_send_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_send_ack()\r\n");

    while ((total_rcv_data_szie < rsp_data_full_size) && (retries <= (i_tcp_conf->retries_on_failure)))
    {
        // reset tx/rx buffer
        memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

        // fetch data
        ssize_t rcv_data_len = tcp_read(i_tcp_conf, tcp_buff, TCP_BUFFER_SIZE);
        PRINTF("fetching data (idx = %d; len = " PRINT_SSIZE_FMT ")\r\n", round, rcv_data_len);

        // check if the response packet is valid
        if (rcv_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcv_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = tcp_buff[i];
                    if ((rcv_buff == (uint8_t *)sm_len_data) && (rcv_buff_idx == 2))
                    {
                        *o_sm_len = (size_t)(((uint16_t *)(sm_len_data))[0]);
                        rcv_buff = (uint8_t *)o_sm;
                        rcv_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)o_sm) && (rcv_buff_idx == (*o_sm_len)))
                    {
                        rcv_buff = NULL;
                    }
                }
            }

            total_rcv_data_szie += rcv_data_len;
            round++;
            retries = 0;
        }
        else
        {
            retries++;
        }
    }

    if (retries > (i_tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_tcp_dsa_verify(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if ((i_tcp_conf == NULL) || (i_pk == NULL) || (i_msg == NULL) || (i_sm == NULL) || (o_verified == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    // assign key lengths according to algorithm
    size_t sm_len = 0;
    size_t pk_len = 0;
    switch (i_dsa_algo)
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

    uint8_t tcp_buff[TCP_BUFFER_SIZE];
    memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = 2 + i_msg_len + sm_len + pk_len; // msg_len_val(2) + msg(msg_len_val) + sm(sm_len_val) + pk(pk_len)
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
    apdu_set_buffer((uint8_t *)tcp_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command header, from "cla" to "lc"
    size_t cmd_pkt_size = 7;
    if (tcp_write(i_tcp_conf, tcp_buff, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::header");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::header\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, msg_len_val(2)
    cmd_pkt_size = 2;
    if (tcp_write(i_tcp_conf, (uint8_t *)&i_msg_len, cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::msg_len_val(2)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::msg_len_val(2)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, i_msg(i_msg_len)
    if (tcp_write(i_tcp_conf, (uint8_t *)i_msg, i_msg_len) != i_msg_len)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::i_msg(i_msg_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::i_msg(i_msg_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, i_sm(sm_len)
    if (tcp_write(i_tcp_conf, (uint8_t *)i_sm, sm_len) != sm_len)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::i_sm(sm_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::i_sm(sm_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command data, i_pk(pk_len)
    if (tcp_write(i_tcp_conf, (uint8_t *)i_pk, pk_len) != pk_len)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::data::i_pk(pk_len)");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::data::i_pk(pk_len)\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    // send the apdu command footer, "le"
    cmd_pkt_size = 3;
    if (tcp_write(i_tcp_conf, (uint8_t *)&(tcp_buff[7]), cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_write()::apdu::footer");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_write()::apdu::footer\r\n");

    if (tcp_receive_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_receive_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_receive_ack()\r\n");

    uint8_t msg_len_data[2] = {0x00, 0x00};
    uint16_t msg_len_val = 0;
    uint8_t rcv_msg_buff[1] = {0x00};
    *o_verified = true;

    // fetching response data from the TCP device
    uint8_t *rcv_buff = (uint8_t *)msg_len_data;
    int rcv_buff_idx = 0;
    int rcv_msg_buff_idx = 0;
    int round = 1;
    int retries = 0;
    ssize_t total_rcv_data_szie = 0;

    if (tcp_send_ack(i_tcp_conf) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_TCP_IO, "tcp_send_ack()");
        return IPQP_EC_TCP_IO;
    }
    PRINTF("tcp_send_ack()\r\n");

    while ((total_rcv_data_szie < rsp_data_full_size) && (retries <= (i_tcp_conf->retries_on_failure)))
    {
        // reset tx/rx buffer
        memset(tcp_buff, 0x00, TCP_BUFFER_SIZE);

        // fetch data
        ssize_t rcv_data_len = tcp_read(i_tcp_conf, tcp_buff, TCP_BUFFER_SIZE);
        PRINTF("fetching data (idx = %d; len = " PRINT_SSIZE_FMT ")\r\n", round, rcv_data_len);

        // check if the response packet is valid
        if (rcv_data_len > 0)
        {
            // fill the output buffer
            for (int i = 0; i < rcv_data_len; i++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = tcp_buff[i];
                    if ((rcv_buff == (uint8_t *)msg_len_data) && (rcv_buff_idx == 2))
                    {
                        msg_len_val = (size_t)(((uint16_t *)(msg_len_data))[0]);
                        rcv_buff = rcv_msg_buff;
                        rcv_buff_idx = 0;
                        rcv_msg_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)rcv_msg_buff) && (rcv_msg_buff_idx < msg_len_val))
                    {
                        if (tcp_buff[i] != i_msg[rcv_msg_buff_idx])
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

            total_rcv_data_szie += rcv_data_len;
            round++;
            retries = 0;
        }
        else
        {
            retries++;
        }
    }

    if (retries > (i_tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}
