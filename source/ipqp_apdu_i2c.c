#include "ipqp_apdu.h"

#include <linux/i2c-dev.h>

IPQP_ErrorCode apdu_i2c_kem_keypair(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_i2c_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
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
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int rsp_data_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // total packets number to receive response data
    int rcv_rsp_pkt_num = (((rsp_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (rsp_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", rcv_rsp_pkt_num);

    // send KEM keypair generation command to the I2C device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = 0;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
        return IPQP_EC_I2C_IO;
    }

    // fetching response data from the SPI device
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;
    bool to_check_i2c_status = true;
    for (int i = 0; i < rcv_rsp_pkt_num;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = (i == (rcv_rsp_pkt_num - 1)) ? (rcv_rsp_pkt_num % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        apdu_le += 5; // for packet validation checking header
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (rcv_rsp_pkt_num - 1 - i), apdu_le);

        // send data fetching command to the SPI device
        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_KEM_KEYPAIR;
        apdu_cmd.p2 = (rcv_rsp_pkt_num - i - 1);
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            // fill the key buffer
            for (int j = 0; j < apdu_le; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = i2c_buff[5 + j];

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

            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", (rcv_rsp_pkt_num - i - 1));
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_kem_encap(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if ((i_i2c_conf == NULL) || (i_pk == NULL) || (o_ss == NULL) || (o_ct == NULL))
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
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    ipqp_ec = apdu_i2c_assign_key(i_i2c_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_PK, i_pk);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "failed to assign key");
        return ipqp_ec;
    }

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    memset(o_ct, 0x00, ct_len);

    // expected data length
    int rsp_data_full_size = 2 + 2 + ct_len + ss_len; // ct_len(2) + ss_len(2) + ct(ct_len) + ss(ss_len)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // total packets number to receive response data
    int rcv_rsp_pkt_num = (((rsp_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (rsp_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", rcv_rsp_pkt_num);

    apdu_t apdu_cmd;
    // waiting for the I2C device to become ready
    ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
        return ipqp_ec;
    }

    // reset tx/rx buffer
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    // the apdu data length (lc) of current packet
    PRINTF("send command packet = %d; len = %d\r\n", 0, 0);

    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_ENCAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = 0;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
        return IPQP_EC_I2C_IO;
    }

    uint16_t ct_len_val = 0;
    uint16_t ss_len_val = 0;
    uint8_t ct_len_data[2] = {0x00, 0x00};
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)ct_len_data;
    int rcv_buff_idx = 0;
    bool to_check_i2c_status = true;
    for (int i = 0; i < rcv_rsp_pkt_num;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = (i == (rcv_rsp_pkt_num - 1)) ? (rcv_rsp_pkt_num % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        apdu_le += 5; // for packet validation checking header
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (rcv_rsp_pkt_num - 1 - i), apdu_le);

        // send data fetching command to the SPI device
        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_KEM_ENCAP;
        apdu_cmd.p2 = (rcv_rsp_pkt_num - i - 1);
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            // fill the output buffer
            for (int j = 0; j < apdu_le; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = i2c_buff[5 + j];

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

            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", (rcv_rsp_pkt_num - i - 1));
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    /*
    PRINTF("ct_len_data: %d\r\n", ct_len_val);
    PRINT_ARR(ct_len_data, 2, 32, "CT_LEN");
    PRINTF("ss_len_data: %d\r\n", ss_len_val);
    PRINT_ARR(ss_len_data, 2, 32, "SS_LEN");
    */

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_kem_decap(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    if ((i_i2c_conf == NULL) || (i_sk == NULL) || (i_ct == NULL) || (o_ss == NULL))
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
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    ipqp_ec = apdu_i2c_assign_key(i_i2c_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_SK, i_sk);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "failed to assign key");
        return ipqp_ec;
    }

    ipqp_ec = apdu_i2c_kem_assign_ciphertext(i_i2c_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_CT, i_ct);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "failed to assign ciphertext");
        return ipqp_ec;
    }

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    memset(o_ss, 0x00, ss_len);

    // expected data length
    int rsp_data_full_size = 2 + ss_len; // ct_len(2) + ss_len(2) + ct(ct_len) + ss(ss_len)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // total packets number to receive response data
    int rcv_rsp_pkt_num = (((rsp_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (rsp_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", rcv_rsp_pkt_num);

    // waiting for the I2C device to become ready
    ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
        return ipqp_ec;
    }

    // reset tx/rx buffer
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    // the apdu data length (lc) of current packet
    PRINTF("send command packet = %d; len = %d\r\n", 0, 0);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_DECAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = 0;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
        return IPQP_EC_I2C_IO;
    }

    /*
    PRINT_ARR(i2c_buff, cmd_pkt_size, 32, "TX");
    PRINTF("\r\n");
    */

    uint16_t ss_len_val = 0;
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)ss_len_data;
    int rcv_buff_idx = 0;
    bool to_check_i2c_status = true;
    for (int i = 0; i < rcv_rsp_pkt_num;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = (i == (rcv_rsp_pkt_num - 1)) ? (rcv_rsp_pkt_num % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        apdu_le += 5; // for packet validation checking header
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (rcv_rsp_pkt_num - 1 - i), apdu_le);

        // send data fetching command to the SPI device
        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_KEM_DECAP;
        apdu_cmd.p2 = (rcv_rsp_pkt_num - i - 1);
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            // fill the output buffer
            for (int j = 0; j < apdu_le; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = i2c_buff[5 + j];

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

            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", (rcv_rsp_pkt_num - i - 1));
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    /*
    PRINTF("ss_len_data: %d\r\n", ss_len_val);
    PRINT_ARR(ss_len_data, 2, 32, "SS_LEN");
    */

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_kem_assign_ciphertext(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t i_ct_type, uint8_t *i_ct)
{
    // parameters validation
    if ((i_i2c_conf == NULL) || (i_ct == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

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
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    uint8_t rsp_code = 0;
    switch (i_ct_type)
    {
    case APDU_CMD_P1_ASSIGN_KEM_CT:
        rsp_code = APDU_CMD_P1_RSP_ASSIGN_KEM_CT;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = ct_len; // ciphertext length
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int snd_cmd_pkt_num = (((cmd_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to send command data: %d\n", snd_cmd_pkt_num);

    apdu_t apdu_cmd;
    uint8_t *snd_buff = i_ct;
    int snd_buff_idx = 0;
    for (int i = 0; i < snd_cmd_pkt_num; i++)
    {
        // waiting for the I2C device to become ready
        ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
            return ipqp_ec;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_lc = (i == (snd_cmd_pkt_num - 1)) ? (cmd_data_full_size % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (snd_cmd_pkt_num - 1 - i), apdu_lc);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = i_ct_type;
        apdu_cmd.p2 = (snd_cmd_pkt_num - 1 - i);
        apdu_cmd.lc = apdu_lc;
        apdu_cmd.le = 0;

        // prepare the apdu data
        uint8_t apdu_pkt_data[I2C_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, I2C_PACKET_DATA_SIZE);
        for (int j = 0; j < apdu_lc; j++)
        {
            if (snd_buff != NULL)
            {
                apdu_pkt_data[j] = snd_buff[snd_buff_idx++];
                if ((snd_buff == (uint8_t *)i_ct) && (snd_buff_idx == ct_len))
                {
                    snd_buff = NULL;
                }
            }
        }
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        // send the apdu command
        size_t cmd_pkt_size = apdu_lc + 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        /*
        PRINT_ARR(i2c_buff, cmd_pkt_size, 32, "TX");
        PRINTF("\r\n");
        */
    }

    bool to_check_i2c_status = true;
    for (int i = 0; i < 1;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = 8; // 3 (packet data) + 5 (packet validation checking header)
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", 0, apdu_le);

        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = rsp_code;
        apdu_cmd.p2 = 0;
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = (uint8_t *)NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        if (received_valid_packet(i2c_buff))
        {
            if (!received_valid_packet(&(i2c_buff[4])))
                return IPQP_EC_FAIL;
            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet again.\r\n");
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_dsa_keypair(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_i2c_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
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
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int rsp_data_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // total packets number to receive response data
    int rcv_rsp_pkt_num = (((rsp_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (rsp_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", rcv_rsp_pkt_num);

    // send DSA keypair generation command to the SPI device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = rsp_data_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
    {
        IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
        return IPQP_EC_I2C_IO;
    }

    // fetching response data from the SPI device
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;
    bool to_check_i2c_status = true;
    for (int i = 0; i < rcv_rsp_pkt_num;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = (i == (rcv_rsp_pkt_num - 1)) ? (rcv_rsp_pkt_num % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        apdu_le += 5; // for packet validation checking header
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (rcv_rsp_pkt_num - 1 - i), apdu_le);

        // send data fetching command to the SPI device
        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_DSA_KEYPAIR;
        apdu_cmd.p2 = (rcv_rsp_pkt_num - i - 1);
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            // fill the key buffer
            for (int j = 0; j < apdu_le; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = i2c_buff[5 + j];

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

            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", (rcv_rsp_pkt_num - i - 1));
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_dsa_sign(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if ((i_i2c_conf == NULL) || (i_sk == NULL) || (i_msg == NULL) || (o_sm == NULL) || (o_sm_len == NULL))
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
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    ipqp_ec = apdu_i2c_assign_key(i_i2c_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_SK, i_sk);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "failed to assign key");
        return ipqp_ec;
    }

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = 2 + i_msg_len; // msg_len(2) + msg
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int snd_cmd_pkt_num = (((cmd_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to send command data: %d\n", snd_cmd_pkt_num);

    // expected data length
    int rsp_data_full_size = 2 + (sm_len + i_msg_len); // sm_n_msg_len_val(2) + [sm + msg](sm_n_msg_len_val)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // total packets number to receive response data
    int rcv_rsp_pkt_num = (((rsp_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (rsp_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", rcv_rsp_pkt_num);

    apdu_t apdu_cmd;
    uint8_t *snd_buff = (uint8_t *)&i_msg_len;
    int snd_buff_idx = 0;
    for (int i = 0; i < snd_cmd_pkt_num; i++)
    {
        // waiting for the I2C device to become ready
        ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
            return ipqp_ec;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_lc = (i == (snd_cmd_pkt_num - 1)) ? (cmd_data_full_size % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (snd_cmd_pkt_num - 1 - i), apdu_lc);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_DSA_SIGN;
        apdu_cmd.p2 = (snd_cmd_pkt_num - 1 - i);
        apdu_cmd.lc = apdu_lc;
        apdu_cmd.le = 0;

        // prepare the apdu data
        uint8_t apdu_pkt_data[I2C_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, I2C_PACKET_DATA_SIZE);
        for (int j = 0; j < apdu_lc; j++)
        {
            if (snd_buff != NULL)
            {
                apdu_pkt_data[j] = snd_buff[snd_buff_idx++];
                if ((snd_buff == (uint8_t *)&i_msg_len) && (snd_buff_idx == 2))
                {
                    snd_buff = i_msg;
                    snd_buff_idx = 0;
                }
                else if ((snd_buff == i_msg) && (snd_buff_idx == i_msg_len))
                {
                    snd_buff = NULL;
                }
            }
        }
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        // send the apdu command
        size_t cmd_pkt_size = apdu_lc + 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        /*
        PRINT_ARR(i2c_buff, cmd_pkt_size, 32, "TX");
        PRINTF("\r\n");
        */
    }

    *o_sm_len = 0;
    uint8_t sm_n_msg_len_data[2] = {0x00, 0x00};
    size_t sm_n_msg_len_val = 0;

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)sm_n_msg_len_data;
    int rcv_buff_idx = 0;
    bool to_check_i2c_status = true;
    for (int i = 0; i < rcv_rsp_pkt_num;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = (i == (rcv_rsp_pkt_num - 1)) ? (rcv_rsp_pkt_num % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        apdu_le += 5; // for packet validation checking header
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (rcv_rsp_pkt_num - 1 - i), apdu_le);

        // send data fetching command to the SPI device
        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_DSA_SIGN;
        apdu_cmd.p2 = (rcv_rsp_pkt_num - i - 1);
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            // fill the output buffer
            for (int j = 0; j < apdu_le; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = i2c_buff[5 + j];

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

            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", (rcv_rsp_pkt_num - i - 1));
            to_check_i2c_status = false;
        }

        /*
       PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
       PRINTF("\r\n");
       */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_dsa_verify(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if ((i_i2c_conf == NULL) || (i_pk == NULL) || (i_msg == NULL) || (i_sm == NULL) || (o_verified == NULL))
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
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    ipqp_ec = apdu_i2c_assign_key(i_i2c_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_PK, i_pk);
    if (ipqp_ec != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(ipqp_ec, "failed to assign key");
        return ipqp_ec;
    }

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = 2 + i_sm_len + i_msg_len; // sm_n_msg_len_val(2) + [sm + msg](sm_n_msg_len_val)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int snd_cmd_pkt_num = (((cmd_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to send command data: %d\n", snd_cmd_pkt_num);

    // expected data length
    int rsp_data_full_size = 2 + i_msg_len; // msg_len_val(2) + msg(msg_len_val)
    PRINTF("expected response size: %d\n", rsp_data_full_size);

    // total packets number to receive response data
    int rcv_rsp_pkt_num = (((rsp_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (rsp_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", rcv_rsp_pkt_num);

    apdu_t apdu_cmd;
    size_t sm_n_msg_len_val = i_sm_len + i_msg_len;
    uint8_t *snd_buff = (uint8_t *)&sm_n_msg_len_val;
    int snd_buff_idx = 0;
    for (int i = 0; i < snd_cmd_pkt_num; i++)
    {
        // waiting for the I2C device to become ready
        ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
            return ipqp_ec;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_lc = (i == (snd_cmd_pkt_num - 1)) ? (cmd_data_full_size % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (snd_cmd_pkt_num - 1 - i), apdu_lc);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_DSA_VERIFY;
        apdu_cmd.p2 = (snd_cmd_pkt_num - 1 - i);
        apdu_cmd.lc = apdu_lc;
        apdu_cmd.le = 0;

        // prepare the apdu data
        uint8_t apdu_pkt_data[I2C_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, I2C_PACKET_DATA_SIZE);
        for (int j = 0; j < apdu_lc; j++)
        {
            if (snd_buff != NULL)
            {
                apdu_pkt_data[j] = snd_buff[snd_buff_idx++];
                if ((snd_buff == (uint8_t *)&sm_n_msg_len_val) && (snd_buff_idx == 2))
                {
                    snd_buff = (uint8_t *)i_sm;
                    snd_buff_idx = 0;
                }
                else if ((snd_buff == (uint8_t *)i_sm) && (snd_buff_idx == i_sm_len))
                {
                    snd_buff = (uint8_t *)i_msg;
                    snd_buff_idx = 0;
                }
                else if ((snd_buff == (uint8_t *)i_msg) && (snd_buff_idx == i_msg_len))
                {
                    snd_buff = NULL;
                }
            }
        }
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        // send the apdu command
        size_t cmd_pkt_size = apdu_lc + 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        /*
        PRINT_ARR(i2c_buff, cmd_pkt_size, 32, "TX");
        PRINTF("\r\n");
        */
    }

    uint8_t msg_len_data[2] = {0x00, 0x00};
    uint16_t msg_len_val = 0;
    uint8_t rcv_msg_buff[1] = {0x00};

    // fetching response data from the I2C device
    uint8_t *rcv_buff = (uint8_t *)msg_len_data;
    int rcv_buff_idx = 0;
    int rcv_msg_buff_idx = 0;

    *o_verified = true;
    bool to_check_i2c_status = true;
    for (int i = 0; i < rcv_rsp_pkt_num;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = (i == (rcv_rsp_pkt_num - 1)) ? (rcv_rsp_pkt_num % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        apdu_le += 5; // for packet validation checking header
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (rcv_rsp_pkt_num - 1 - i), apdu_le);

        // send data fetching command to the I2C device
        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = APDU_CMD_P1_DSA_VERIFY; // ENCODE_ECHO;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_DSA_VERIFY;
        apdu_cmd.p2 = (rcv_rsp_pkt_num - i - 1);
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            // fill the output buffer
            for (int j = 0; j < apdu_le; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = i2c_buff[5 + j];

                    if ((rcv_buff == (uint8_t *)msg_len_data) && (rcv_buff_idx == 2))
                    {
                        msg_len_val = (size_t)(((uint16_t *)(msg_len_data))[0]);
                        rcv_buff = rcv_msg_buff;
                        rcv_buff_idx = 0;
                        rcv_msg_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)rcv_msg_buff) && (rcv_msg_buff_idx < msg_len_val))
                    {
                        if (i2c_buff[5 + j] != i_msg[rcv_msg_buff_idx])
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

            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", (rcv_rsp_pkt_num - i - 1));
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_assign_key(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_kem_algo, uint8_t i_key_type, uint8_t *i_key)
{
    // parameters validation
    if ((i_i2c_conf == NULL) || (i_key == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

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
        IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
        return IPQP_EC_ALGO_MISSING;
    }

    uint8_t rsp_code = 0;
    size_t key_len = 0;
    if (is_dsa_algo)
    {
        switch (i_key_type)
        {
        case APDU_CMD_P1_ASSIGN_DSA_PK:
            key_len = pk_len;
            rsp_code = APDU_CMD_P1_RSP_ASSIGN_DSA_PK;
            break;
        case APDU_CMD_P1_ASSIGN_DSA_SK:
            key_len = sk_len;
            rsp_code = APDU_CMD_P1_RSP_ASSIGN_DSA_SK;
            break;
        default:
            IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
            return IPQP_EC_ALGO_MISSING;
        }
    }
    else
    {
        switch (i_key_type)
        {
        case APDU_CMD_P1_ASSIGN_KEM_PK:
            key_len = pk_len;
            rsp_code = APDU_CMD_P1_RSP_ASSIGN_KEM_PK;
            break;
        case APDU_CMD_P1_ASSIGN_KEM_SK:
            key_len = sk_len;
            rsp_code = APDU_CMD_P1_RSP_ASSIGN_KEM_SK;
            break;
        default:
            IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
            return IPQP_EC_ALGO_MISSING;
        }
    }

    // RTL source validation
    uint8_t rsp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        rsp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        IPQP_EC_LOG(IPQP_EC_RTL_SRC_MISSING, NULL);
        return IPQP_EC_RTL_SRC_MISSING;
    }

    IPQP_ErrorCode ipqp_ec = IPQP_EC_FAIL;

    uint8_t i2c_buff[I2C_BUFFER_SIZE];
    memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = key_len; // key
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int snd_cmd_pkt_num = (((cmd_data_full_size % I2C_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / I2C_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", snd_cmd_pkt_num);

    apdu_t apdu_cmd;
    uint8_t *snd_buff = i_key;
    int snd_buff_idx = 0;
    for (int i = 0; i < snd_cmd_pkt_num; i++)
    {
        // waiting for the I2C device to become ready
        ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
            return ipqp_ec;
        }
        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_lc = (i == (snd_cmd_pkt_num - 1)) ? (cmd_data_full_size % I2C_PACKET_DATA_SIZE) : I2C_PACKET_DATA_SIZE;
        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = " PRINT_SIZE_FMT "\r\n", (snd_cmd_pkt_num - 1 - i), apdu_lc);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_dsa_kem_algo;
        apdu_cmd.p1 = i_key_type;
        apdu_cmd.p2 = (snd_cmd_pkt_num - 1 - i);
        apdu_cmd.lc = apdu_lc;
        apdu_cmd.le = 0;

        // prepare the apdu data
        uint8_t apdu_pkt_data[I2C_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, I2C_PACKET_DATA_SIZE);
        for (int j = 0; j < apdu_lc; j++)
        {
            if (snd_buff != NULL)
            {
                apdu_pkt_data[j] = snd_buff[snd_buff_idx++];
                if ((snd_buff == (uint8_t *)i_key) && (snd_buff_idx == key_len))
                {
                    snd_buff = NULL;
                }
            }
        }
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        // send the apdu command
        size_t cmd_pkt_size = apdu_lc + 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)cmd_pkt_size) != cmd_pkt_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        /*
        PRINT_ARR(i2c_buff, cmd_pkt_size, 32, "TX");
        PRINTF("\r\n");
        */
    }

    bool to_check_i2c_status = true;
    for (int i = 0; i < 1;)
    {
        if (to_check_i2c_status)
        {
            // waiting for the I2C device to become ready
            ipqp_ec = i2c_wait_for_ready(i_i2c_conf);
            if (ipqp_ec != IPQP_EC_SUCCESS)
            {
                IPQP_EC_LOG(ipqp_ec, "i2c_wait_for_ready()");
                return ipqp_ec;
            }
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        size_t apdu_le = 5 + 3; // 5 (packet validation checking header) + 3 (report if key assignment is successful)
        // the apdu data length (lc) of current packet
        PRINTF("send fetching data command packet = %d; len = " PRINT_SIZE_FMT "\r\n", 0, apdu_le);

        apdu_cmd.cla = rsp_rtl_src;
        apdu_cmd.ins = i_dsa_kem_algo;
        apdu_cmd.p1 = rsp_code;
        apdu_cmd.p2 = 0;
        apdu_cmd.lc = 0;
        apdu_cmd.le = apdu_le;

        apdu_cmd.data = (uint8_t *)NULL;
        apdu_set_buffer((uint8_t *)i2c_buff, &apdu_cmd, APDU_CMD_TPY_STD);

        /*
        PRINT_ARR(i2c_buff, rsp_cmd_size, 32, "TX");
        PRINTF("\r\n");
        */

        size_t rsp_cmd_size = 10;
        if (i2c_write(i_i2c_conf, i2c_buff, (size_t)rsp_cmd_size) != rsp_cmd_size)
        {
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "i2c_write()");
            return IPQP_EC_I2C_IO;
        }

        // reset tx/rx buffer
        memset(i2c_buff, 0x00, I2C_BUFFER_SIZE);

        ipqp_ec = i2c_read_packet(i_i2c_conf, i2c_buff, apdu_le);
        if (ipqp_ec != IPQP_EC_SUCCESS)
        {
            IPQP_EC_LOG(ipqp_ec, "i2c_read_packet()");
            return ipqp_ec;
        }

        // check if the response packet is valid
        if (received_valid_packet(i2c_buff))
        {
            if (!received_valid_packet(&(i2c_buff[4])))
                return IPQP_EC_FAIL;
            i++;
            to_check_i2c_status = true;
        }
        else
        {
            PRINTF("received invalid packet. fetch packet %d again.\r\n", 0);
            to_check_i2c_status = false;
        }

        /*
        PRINT_ARR(i2c_buff, apdu_le, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_i2c_status_check(i2c_conf_t *i_i2c_conf, uint8_t *o_result)
{
    if ((i_i2c_conf == NULL) || (o_result == NULL))
    {
        IPQP_EC_LOG(IPQP_EC_NULL_POINTER, NULL);
        return IPQP_EC_NULL_POINTER;
    }

    apdu_t my_apdu;

    uint8_t i2c_buff[10];
    memset(i2c_buff, 0, 10);

    my_apdu.cla = APDU_CLA_DEV_INIT;
    my_apdu.ins = 0xAA;
    my_apdu.p1 = 0xBB;
    my_apdu.p2 = 0xCC;
    my_apdu.lc = 0;
    my_apdu.le = 6;
    my_apdu.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)i2c_buff, &my_apdu, APDU_CMD_TPY_STD);

    ssize_t snd_pkt_len = 10;
    if (i2c_write(i_i2c_conf, i2c_buff, (size_t)snd_pkt_len) != snd_pkt_len)
        return IPQP_EC_I2C_IO;

    size_t rcv_pkt_len = 6;
    if (i2c_read_packet(i_i2c_conf, i2c_buff, rcv_pkt_len) != IPQP_EC_SUCCESS)
        return IPQP_EC_I2C_IO;

    o_result[0] = i2c_buff[4];
    o_result[1] = i2c_buff[5];

    return IPQP_EC_SUCCESS;
}
