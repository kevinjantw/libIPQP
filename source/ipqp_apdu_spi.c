#include "ipqp_apdu.h"

#include <linux/spi/spidev.h>

IPQP_ErrorCode apdu_spi_kem_assign_ciphertext(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t i_ct_type, uint8_t *i_ct)
{
    // parameters validation
    if ((i_spi_conf == NULL) || (i_ct == NULL))
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

    uint8_t rsp_code = 0;
    switch (i_ct_type)
    {
    case APDU_CMD_P1_ASSIGN_KEM_CT:
        rsp_code = APDU_CMD_P1_RSP_ASSIGN_KEM_CT;
        break;
    default:
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = ct_len; // ciphertext length
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int spi_snd_pkt_num = (((cmd_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_snd_pkt_num);

    apdu_t apdu_cmd;
    uint8_t *snd_buff = i_ct;
    int snd_buff_idx = 0;
    for (int i = 0; i < spi_snd_pkt_num; i++)
    {
        // waiting for the SPI device to become ready
        int ret = spi_wait_for_ready(i_spi_conf);
        if (ret < 0)
        {
            if (ret == IPQP_EC_SPI_IO)
                PRINTF("fail to check SPI device status\r\n");
            else if (ret == IPQP_EC_TIMEOUT)
                PRINTF("timeout error\r\n");
            return IPQP_EC_TIMEOUT;
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        int apdu_pkt_data_len = (i == (spi_snd_pkt_num - 1)) ? (cmd_data_full_size % SPI_PACKET_DATA_SIZE) : SPI_PACKET_DATA_SIZE;

        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = %d\r\n", (spi_snd_pkt_num - 1 - i), apdu_pkt_data_len);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = i_ct_type;
        apdu_cmd.p2 = (spi_snd_pkt_num - 1 - i);
        apdu_cmd.lc = apdu_pkt_data_len;
        apdu_cmd.le = 0; // not used

        // prepare the apdu data
        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        for (int j = 0; j < apdu_pkt_data_len; j++)
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
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        // send the apdu command
        size_t cmd_pkt_size = apdu_pkt_data_len + 10;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        /*
        PRINT_ARR(spi_tx_buff, cmd_pkt_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, cmd_pkt_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    bool to_check_spi_status = true;
    for (int i = 0; i < 1;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            int ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_kem_algo;
        apdu_cmd.p1 = rsp_code;
        apdu_cmd.p2 = 0;
        apdu_cmd.lc = 0;
        apdu_cmd.le = 3; // not used

        apdu_cmd.data = (uint8_t *)NULL;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        // send the apdu command
        size_t cmd_pkt_size = 10;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        if (received_valid_packet(spi_rx_buff))
        {
            if (!received_valid_packet(&(spi_rx_buff[4])))
                return IPQP_EC_FAIL;
            i++;
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet again.\r\n");
            to_check_spi_status = false;
        }

        /*
        PRINT_ARR(spi_tx_buff, cmd_pkt_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, cmd_pkt_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_assign_key(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_kem_algo, uint8_t i_key_type, uint8_t *i_key)
{
    // parameters validation
    if ((i_spi_conf == NULL) || (i_key == NULL))
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
            return IPQP_EC_ALGO_MISSING;
        }
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = key_len; // key
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int spi_snd_pkt_num = (((cmd_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_snd_pkt_num);

    apdu_t apdu_cmd;
    uint8_t *snd_buff = i_key;
    int snd_buff_idx = 0;
    for (int i = 0; i < spi_snd_pkt_num; i++)
    {
        // waiting for the SPI device to become ready
        int ret = spi_wait_for_ready(i_spi_conf);
        if (ret < 0)
        {
            if (ret == IPQP_EC_SPI_IO)
                PRINTF("fail to check SPI device status\r\n");
            else if (ret == IPQP_EC_TIMEOUT)
                PRINTF("timeout error\r\n");
            return IPQP_EC_TIMEOUT;
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        int apdu_pkt_data_len = (i == (spi_snd_pkt_num - 1)) ? (key_len % SPI_PACKET_DATA_SIZE) : SPI_PACKET_DATA_SIZE;

        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = %d\r\n", (spi_snd_pkt_num - 1 - i), apdu_pkt_data_len);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_dsa_kem_algo;
        apdu_cmd.p1 = i_key_type;
        apdu_cmd.p2 = (spi_snd_pkt_num - 1 - i);
        apdu_cmd.lc = apdu_pkt_data_len;
        apdu_cmd.le = 0; // not used

        // prepare the apdu data
        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        for (int j = 0; j < apdu_pkt_data_len; j++)
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
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        // send the apdu command
        size_t cmd_pkt_size = apdu_pkt_data_len + 10;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }
        
        /*
        PRINT_ARR(spi_tx_buff, cmd_pkt_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, cmd_pkt_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    bool to_check_spi_status = true;
    for (int i = 0; i < 1;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            int ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_dsa_kem_algo;
        apdu_cmd.p1 = rsp_code;
        apdu_cmd.p2 = 0;
        apdu_cmd.lc = 0;
        apdu_cmd.le = 3; // not used

        apdu_cmd.data = (uint8_t *)NULL;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        // send the apdu command
        size_t cmd_pkt_size = 10;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        if (received_valid_packet(spi_rx_buff))
        {
            if (!received_valid_packet(&(spi_rx_buff[4])))
                return IPQP_EC_FAIL;
            i++;
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet again.\r\n");
            to_check_spi_status = false;
        }

        /*
        PRINTF("================================================================\r\n");
        PRINT_ARR(spi_tx_buff, cmd_pkt_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, cmd_pkt_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_dsa_sign(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if (apdu_spi_assign_key(i_spi_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_SK, i_sk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign dsa secret key.");
        return IPQP_EC_FAIL;
    }

    return apdu_spi_dsa_sign_cmd(i_spi_conf, i_rtl_src, i_dsa_algo, i_sk, i_msg, i_msg_len, o_sm, o_sm_len);
}

IPQP_ErrorCode apdu_spi_dsa_sign_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if ((i_spi_conf == NULL) || (i_sk == NULL) || (i_msg == NULL) || (o_sm == NULL) || (o_sm_len == NULL))
        return IPQP_EC_NULL_POINTER;

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
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    if (apdu_spi_assign_key(i_spi_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_SK, i_sk) != IPQP_EC_SUCCESS)
    {
        PRINTF("failed to assign key\r\n");
        return IPQP_EC_FAIL;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = 2 + i_msg_len; // msg_len(2) + msg
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int spi_snd_pkt_num = (((cmd_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_snd_pkt_num);

    // expected data length
    int resp_data_full_size = 2 + (sm_len + i_msg_len); // sm_n_msg_len_val(2) + [sm + msg](sm_n_msg_len_val)
    PRINTF("expected response size: %d\n", resp_data_full_size);

    // total packets number to receive response data
    int spi_rcv_pkt_num = (((resp_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (resp_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_rcv_pkt_num);

    apdu_t apdu_cmd;
    uint8_t *snd_buff = (uint8_t *)&i_msg_len;
    int snd_buff_idx = 0;
    for (int i = 0; i < spi_snd_pkt_num; i++)
    {
        // waiting for the SPI device to become ready
        int ret = spi_wait_for_ready(i_spi_conf);
        if (ret < 0)
        {
            if (ret == IPQP_EC_SPI_IO)
                PRINTF("fail to check SPI device status\r\n");
            else if (ret == IPQP_EC_TIMEOUT)
                PRINTF("timeout error\r\n");
            return IPQP_EC_TIMEOUT;
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = %d\r\n", (spi_snd_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_DSA_SIGN;
        apdu_cmd.p2 = (spi_snd_pkt_num - 1 - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE;
        apdu_cmd.le = 0; // not used

        // prepare the apdu data
        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
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
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        // send the apdu command
        size_t cmd_pkt_size = SPI_PACKET_DATA_SIZE + 10;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        /*
        PRINT_ARR(spi_tx_buff, cmd_pkt_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, cmd_pkt_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    *o_sm_len = 0;
    uint8_t sm_n_msg_len_data[2] = {0x00, 0x00};
    size_t sm_n_msg_len_val = 0;

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)sm_n_msg_len_data;
    int rcv_buff_idx = 0;
    bool to_check_spi_status = true;
    for (int i = 0; i < spi_rcv_pkt_num;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            int ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        PRINTF("send fetching data command packet = %d; len = %d\r\n", (spi_rcv_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        // send data fetching command to the SPI device
        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_dsa_algo; // ENCODE_ECHO;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_DSA_SIGN;
        apdu_cmd.p2 = (spi_rcv_pkt_num - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE; // for clock generation for receiving response data
        apdu_cmd.le = 0;                    // not used

        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        size_t rsp_cmd_size = SPI_PACKET_DATA_SIZE + 5;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, rsp_cmd_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        // check if the response packet is valid
        if (received_valid_packet(spi_rx_buff))
        {
            // fill the output buffer
            for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = spi_rx_buff[5 + j];

                    if ((rcv_buff == (uint8_t *)sm_n_msg_len_data) && (rcv_buff_idx == 2))
                    {
                        // sm_n_msg_len_val = ((((uint16_t)sm_n_msg_len_data[1]) & 0xFF) << 8) | (((uint16_t)sm_n_msg_len_data[0]) & 0xFF);
                        sm_n_msg_len_val = (size_t)(((uint16_t *)(sm_n_msg_len_data))[0]);
                        *o_sm_len = (size_t)(sm_n_msg_len_val - i_msg_len);
                        /*
                        PRINTF("sm_n_msg_len_data = %02X %02X\r\n", sm_n_msg_len_data[0], sm_n_msg_len_data[1]);
                        PRINTF("sm_n_msg_len_val = %ld\r\n", *sm_n_msg_len_val);
                        PRINTF("*o_sm_len = %ld\r\n", *o_sm_len);
                        */
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
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet %d again.\r\n", (spi_rcv_pkt_num - 1 - i));
            to_check_spi_status = false;
        }

        /*
        PRINT_ARR(spi_tx_buff, rsp_cmd_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, rsp_cmd_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_dsa_verify(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if (apdu_spi_assign_key(i_spi_conf, i_rtl_src, i_dsa_algo, APDU_CMD_P1_ASSIGN_DSA_PK, i_pk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign dsa public key.");
        return IPQP_EC_FAIL;
    }

    return apdu_spi_dsa_verify_cmd(i_spi_conf, i_rtl_src, i_dsa_algo, i_pk, i_msg, i_msg_len, i_sm, i_sm_len, o_verified);
}

IPQP_ErrorCode apdu_spi_dsa_verify_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if ((i_spi_conf == NULL) || (i_pk == NULL) || (i_msg == NULL) || (i_sm == NULL) || (o_verified == NULL))
        return IPQP_EC_NULL_POINTER;

    /*
    PRINTF("i_msg_len = %ld\r\n", i_msg_len);
    PRINT_ARR(i_msg, i_msg_len, 32, "i_msg");
    */

    // assign key lengths according to algorithm
    switch (i_dsa_algo)
    {
    case APDU_CMD_INS_ALGO_DILITHIUM_2:
    case APDU_CMD_INS_ALGO_DILITHIUM_3:
    case APDU_CMD_INS_ALGO_DILITHIUM_5:
        break;
    default:
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    // data size for apdu command
    int cmd_data_full_size = 2 + i_sm_len + i_msg_len; // sm_n_msg_len_val(2) + [sm + msg](sm_n_msg_len_val)
    PRINTF("command data size: %d\n", cmd_data_full_size);

    // total packets number to send command
    int spi_snd_pkt_num = (((cmd_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (cmd_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_snd_pkt_num);

    // expected data length
    int resp_data_full_size = 2 + i_msg_len; // msg_len_val(2) + msg(msg_len_val)
    PRINTF("expected response size: %d\n", resp_data_full_size);

    // total packets number to receive response data
    int spi_rcv_pkt_num = (((resp_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (resp_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_rcv_pkt_num);

    apdu_t apdu_cmd;
    size_t sm_n_msg_len_val = i_sm_len + i_msg_len;
    uint8_t *snd_buff = (uint8_t *)&sm_n_msg_len_val;
    int snd_buff_idx = 0;
    for (int i = 0; i < spi_snd_pkt_num; i++)
    {
        // waiting for the SPI device to become ready
        int ret = spi_wait_for_ready(i_spi_conf);
        if (ret < 0)
        {
            if (ret == IPQP_EC_SPI_IO)
                PRINTF("fail to check SPI device status\r\n");
            else if (ret == IPQP_EC_TIMEOUT)
                PRINTF("timeout error\r\n");
            return IPQP_EC_TIMEOUT;
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        // the apdu data length (lc) of current packet
        PRINTF("send command packet = %d; len = %d\r\n", (spi_snd_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        apdu_cmd.cla = i_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_DSA_VERIFY;
        apdu_cmd.p2 = (spi_snd_pkt_num - 1 - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE;
        apdu_cmd.le = 0; // not used

        // prepare the apdu data
        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
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
                    /*
                    PRINTF("i_msg_len = %ld\r\n", i_msg_len);
                    PRINT_ARR(i_msg, i_msg_len, 32, "i_msg");
                    */
                    snd_buff = NULL;
                }
            }
        }
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        // send the apdu command
        size_t cmd_pkt_size = SPI_PACKET_DATA_SIZE + 10;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        /*
        PRINT_ARR(spi_tx_buff, SPI_PACKET_DATA_SIZE, 32, "TX");
        PRINT_ARR(spi_rx_buff, SPI_PACKET_DATA_SIZE, 32, "RX");
        PRINTF("\r\n");
        */
    }

    uint8_t msg_len_data[2] = {0x00, 0x00};
    uint16_t msg_len_val = 0;
    uint8_t rcv_msg_buff[1] = {0x00};

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)msg_len_data;
    int rcv_buff_idx = 0;
    int rcv_msg_buff_idx = 0;

    *o_verified = true;
    bool to_check_spi_status = true;
    for (int i = 0; i < spi_rcv_pkt_num;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            int ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        PRINTF("send fetching data command packet = %d; len = %d\r\n", (spi_snd_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        // send data fetching command to the SPI device
        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = APDU_CMD_P1_DSA_VERIFY; // ENCODE_ECHO;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_DSA_VERIFY;
        apdu_cmd.p2 = (spi_rcv_pkt_num - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE; // for clock generation for receiving response data
        apdu_cmd.le = 0;                    // not used

        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        size_t rsp_cmd_size = SPI_PACKET_DATA_SIZE + 5;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, rsp_cmd_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        // check if the response packet is valid
        if (received_valid_packet(spi_rx_buff))
        {
            // fill the output buffer
            for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = spi_rx_buff[5 + j];

                    if ((rcv_buff == (uint8_t *)msg_len_data) && (rcv_buff_idx == 2))
                    {
                        // uint16_t res_val = ((((uint16_t)msg_len_data[1]) & 0xFF) << 8) | (((uint16_t)msg_len_data[0]) & 0xFF);
                        msg_len_val = (size_t)(((uint16_t *)(msg_len_data))[0]);
                        rcv_buff = rcv_msg_buff;
                        rcv_buff_idx = 0;
                        rcv_msg_buff_idx = 0;
                    }
                    else if ((rcv_buff == (uint8_t *)rcv_msg_buff) && (rcv_msg_buff_idx < msg_len_val))
                    {
                        // printf(" ===== %02X %02X =====\r\n", spi_rx_buff[5 + j], i_msg[rcv_msg_buff_idx]);
                        if (spi_rx_buff[5 + j] != i_msg[rcv_msg_buff_idx])
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
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet %d again.\r\n", (spi_rcv_pkt_num - 1 - i));
            to_check_spi_status = false;
        }

        /*
        PRINT_ARR(spi_tx_buff, rsp_cmd_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, rsp_cmd_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    /*
     PRINT_ARR(res_data, 2, 32, "RES");
     */

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_dsa_keypair(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_spi_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
        return IPQP_EC_NULL_POINTER;

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
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int resp_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", resp_full_size);

    // total packets number to receive response data
    int spi_pkt_num = (((resp_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (resp_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_pkt_num);

    // send DSA keypair generation command to the SPI device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_dsa_algo;
    apdu_cmd.p1 = APDU_CMD_P1_DSA_KEYPAIR;
    apdu_cmd.p2 = 0;              // packet index
    apdu_cmd.lc = 0;              // first command doesn't response anything. clock generation is needless
    apdu_cmd.le = resp_full_size; // not used

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

    size_t snd_rcv_data_size = 10;
    if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, snd_rcv_data_size) < 0)
    {
        PRINTF("fail to send or receive SPI packet\r\n");
        return IPQP_EC_SPI_IO;
    }

    // fetching response data from the SPI device
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;
    bool to_check_spi_status = true;
    for (int i = 0; i < spi_pkt_num;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            int ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        PRINTF("send fetching data command packet = %d; len = %d\r\n", (spi_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        // send data fetching command to the SPI device
        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_dsa_algo;
        apdu_cmd.p1 = APDU_CMD_P1_DSA_KEYPAIR;
        apdu_cmd.p2 = (spi_pkt_num - 1 - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE; // for clock generation for receiving response data
        apdu_cmd.le = 0;                    // not used

        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        snd_rcv_data_size = SPI_PACKET_DATA_SIZE + 5;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, snd_rcv_data_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        // check if the response packet is valid
        if (received_valid_packet(spi_rx_buff))
        {
            // fill the key buffer
            for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = spi_rx_buff[5 + j];

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
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet %d again.\r\n", (spi_pkt_num - 1 - i));
            to_check_spi_status = false;
        }

        // PRINT_ARR(spi_rx_buff, snd_rcv_data_size, 32, "RX");
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_kem_decap(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    if (apdu_spi_assign_key(i_spi_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_SK, i_sk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign kem secert key.");
        return IPQP_EC_FAIL;
    }

    if (apdu_spi_kem_assign_ciphertext(i_spi_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_CT, i_ct) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign ciphertext.");
        return IPQP_EC_FAIL;
    }

    return apdu_spi_kem_decap_cmd(i_spi_conf, i_rtl_src, i_kem_algo, i_sk, i_ct, o_ss);
}

IPQP_ErrorCode apdu_spi_kem_decap_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    // this function does KEM key decapsulation using the SPI device.

    if ((i_spi_conf == NULL) || (i_sk == NULL) || (i_ct == NULL) || (o_ss == NULL))
        return IPQP_EC_NULL_POINTER;

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
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    memset(o_ss, 0x00, ss_len);

    // expected data length
    int resp_data_full_size = 2 + ss_len; // ct_len(2) + ss_len(2) + ct(ct_len) + ss(ss_len)
    PRINTF("expected response size: %d\n", resp_data_full_size);

    // total packets number to receive response data
    int spi_rcv_pkt_num = (((resp_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (resp_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_rcv_pkt_num);

    // waiting for the SPI device to become ready
    int ret = spi_wait_for_ready(i_spi_conf);
    if (ret < 0)
    {
        if (ret == IPQP_EC_SPI_IO)
            PRINTF("fail to check SPI device status\r\n");
        else if (ret == IPQP_EC_TIMEOUT)
            PRINTF("timeout error\r\n");
        return IPQP_EC_TIMEOUT;
    }

    // reset tx/rx buffer
    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    // the apdu data length (lc) of current packet
    PRINTF("send command packet = %d; len = %d\r\n", 0, 0);

    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_DECAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = 0; // not used

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
    {
        PRINTF("fail to send or receive SPI packet\r\n");
        return IPQP_EC_SPI_IO;
    }

    uint16_t ss_len_val = 0;
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)ss_len_data;
    int rcv_buff_idx = 0;
    bool to_check_spi_status = true;
    for (int i = 0; i < spi_rcv_pkt_num;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        PRINTF("send fetching data command packet = %d; len = %d\r\n", (spi_rcv_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        // send data fetching command to the SPI device
        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_kem_algo; // ENCODE_ECHO;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_KEM_DECAP;
        apdu_cmd.p2 = (spi_rcv_pkt_num - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE; // for clock generation for receiving response data
        apdu_cmd.le = 0;                    // not used

        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        size_t rsp_cmd_size = SPI_PACKET_DATA_SIZE + 5;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, rsp_cmd_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        // check if the response packet is valid
        if (received_valid_packet(spi_rx_buff))
        {
            // fill the output buffer
            for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = spi_rx_buff[5 + j];

                    if ((rcv_buff == (uint8_t *)ss_len_data) && (rcv_buff_idx == 2))
                    {
                        // ss_len_val = ((((uint16_t)ss_len_data[1]) & 0xFF) << 8) | (((uint16_t)ss_len_data[0]) & 0xFF);
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
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet %d again.\r\n", (spi_rcv_pkt_num - 1 - i));
            to_check_spi_status = false;
        }

        /*
        PRINT_ARR(spi_tx_buff, rsp_cmd_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, rsp_cmd_size, 32, "RX");
        PRINTF("\r\n");
        */
    }

    /*
     PRINTF("ss_len_data: %d\r\n", ss_len_val);
     PRINT_ARR(ss_len_data, 2, 32, "SS_LEN");
     */

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_kem_encap(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if (apdu_spi_assign_key(i_spi_conf, i_rtl_src, i_kem_algo, APDU_CMD_P1_ASSIGN_KEM_PK, i_pk) != IPQP_EC_SUCCESS)
    {
        IPQP_EC_LOG(IPQP_EC_FAIL, "failed to assign kem public key.");
        return IPQP_EC_FAIL;
    }

    return apdu_spi_kem_encap_cmd(i_spi_conf, i_rtl_src, i_kem_algo, i_pk, o_ss, o_ct);
}

IPQP_ErrorCode apdu_spi_kem_encap_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if ((i_spi_conf == NULL) || (i_pk == NULL) || (o_ss == NULL) || (o_ct == NULL))
        return IPQP_EC_NULL_POINTER;

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
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    memset(o_ct, 0x00, ct_len);

    // expected data length
    int resp_data_full_size = 2 + 2 + ct_len + ss_len; // ct_len(2) + ss_len(2) + ct(ct_len) + ss(ss_len)
    PRINTF("expected response size: %d\n", resp_data_full_size);

    // total packets number to receive response data
    int spi_rcv_pkt_num = (((resp_data_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (resp_data_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_rcv_pkt_num);

    apdu_t apdu_cmd;
    // waiting for the SPI device to become ready
    int ret = spi_wait_for_ready(i_spi_conf);
    if (ret < 0)
    {
        if (ret == IPQP_EC_SPI_IO)
            PRINTF("fail to check SPI device status\r\n");
        else if (ret == IPQP_EC_TIMEOUT)
            PRINTF("timeout error\r\n");
        return IPQP_EC_TIMEOUT;
    }

    // reset tx/rx buffer
    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    // the apdu data length (lc) of current packet
    PRINTF("send command packet = %d; len = %d\r\n", 0, 0);

    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_ENCAP;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0;
    apdu_cmd.le = 0; // not used

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

    // send the apdu command
    size_t cmd_pkt_size = 10;
    if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, cmd_pkt_size) < 0)
    {
        PRINTF("fail to send or receive SPI packet\r\n");
        return IPQP_EC_SPI_IO;
    }

    uint16_t ct_len_val = 0;
    uint16_t ss_len_val = 0;
    uint8_t ct_len_data[2] = {0x00, 0x00};
    uint8_t ss_len_data[2] = {0x00, 0x00};

    // fetching response data from the SPI device
    uint8_t *rcv_buff = (uint8_t *)ct_len_data;
    int rcv_buff_idx = 0;
    bool to_check_spi_status = true;
    for (int i = 0; i < spi_rcv_pkt_num;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        PRINTF("send fetching data command packet = %d; len = %d\r\n", (spi_rcv_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        // send data fetching command to the SPI device
        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_kem_algo; // ENCODE_ECHO;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_KEM_ENCAP;
        apdu_cmd.p2 = (spi_rcv_pkt_num - 1 - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE; // for clock generation for receiving response data
        apdu_cmd.le = 0;                    // not used

        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        size_t rsp_cmd_size = SPI_PACKET_DATA_SIZE + 5;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, rsp_cmd_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        // check if the response packet is valid
        if (received_valid_packet(spi_rx_buff))
        {
            // fill the output buffer
            for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = spi_rx_buff[5 + j];

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
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet %d again.\r\n", (spi_rcv_pkt_num - 1 - i));
            to_check_spi_status = false;
        }

        /*
        PRINT_ARR(spi_tx_buff, rsp_cmd_size, 32, "TX");
        PRINT_ARR(spi_rx_buff, rsp_cmd_size, 32, "RX");
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

IPQP_ErrorCode apdu_spi_kem_keypair(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    // parameters validation
    if ((i_spi_conf == NULL) || (o_pk == NULL) || (o_sk == NULL))
        return IPQP_EC_NULL_POINTER;

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
        return IPQP_EC_ALGO_MISSING;
    }

    // RTL source validation
    uint8_t resp_rtl_src = 0;
    switch (i_rtl_src)
    {
    case APDU_CLA_ITRI:
        resp_rtl_src = APDU_CLA_ITRI_RSP;
        break;
    default:
        return IPQP_EC_RTL_SRC_MISSING;
    }

    uint8_t spi_tx_buff[SPI_BUFFER_SIZE];
    uint8_t spi_rx_buff[SPI_BUFFER_SIZE];

    memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
    memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

    memset(o_pk, 0x00, pk_len);
    memset(o_sk, 0x00, sk_len);

    // expected data length
    int resp_full_size = pk_len + sk_len;
    PRINTF("expected response size: %d\n", resp_full_size);

    // total packets number to receive response data
    int spi_pkt_num = (((resp_full_size % SPI_PACKET_DATA_SIZE) == 0) ? 0 : 1) + (resp_full_size / SPI_PACKET_DATA_SIZE);
    PRINTF("number of packets to receive data: %d\n", spi_pkt_num);

    // send KEM keypair generation command to the SPI device
    apdu_t apdu_cmd;
    apdu_cmd.cla = i_rtl_src;
    apdu_cmd.ins = i_kem_algo;
    apdu_cmd.p1 = APDU_CMD_P1_KEM_KEYPAIR;
    apdu_cmd.p2 = 0;
    apdu_cmd.lc = 0; // first command doesn't response anything. clock generation is needless
    apdu_cmd.le = resp_full_size;

    apdu_cmd.data = (uint8_t *)NULL;
    apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

    size_t snd_rcv_data_size = 10;
    if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, snd_rcv_data_size) < 0)
    {
        PRINTF("fail to send or receive SPI packet\r\n");
        return IPQP_EC_SPI_IO;
    }

    // fetching response data from the SPI device
    uint8_t *rcv_buff = o_pk;
    int rcv_buff_idx = 0;
    bool to_check_spi_status = true;
    for (int i = 0; i < spi_pkt_num;)
    {
        if (to_check_spi_status)
        {
            // waiting for the SPI device to become ready
            int ret = spi_wait_for_ready(i_spi_conf);
            if (ret < 0)
            {
                if (ret == IPQP_EC_SPI_IO)
                    PRINTF("fail to check SPI device status\r\n");
                else if (ret == IPQP_EC_TIMEOUT)
                    PRINTF("timeout error\r\n");
                return IPQP_EC_TIMEOUT;
            }
        }

        // reset tx/rx buffer
        memset(spi_tx_buff, 0x00, SPI_BUFFER_SIZE);
        memset(spi_rx_buff, 0x00, SPI_BUFFER_SIZE);

        PRINTF("send fetching data command packet = %d; len = %d\r\n", (spi_pkt_num - 1 - i), SPI_PACKET_DATA_SIZE);

        // send data fetching command to the SPI device
        apdu_cmd.cla = resp_rtl_src;
        apdu_cmd.ins = i_kem_algo; // ENCODE_ECHO;
        apdu_cmd.p1 = APDU_CMD_P1_RSP_KEM_KEYPAIR;
        apdu_cmd.p2 = (spi_pkt_num - 1 - i);
        apdu_cmd.lc = SPI_PACKET_DATA_SIZE; // for clock generation for receiving response data
        apdu_cmd.le = 0;                    // not used

        uint8_t apdu_pkt_data[SPI_PACKET_DATA_SIZE];
        memset(apdu_pkt_data, 0x00, SPI_PACKET_DATA_SIZE);
        apdu_cmd.data = (uint8_t *)apdu_pkt_data;
        apdu_set_buffer((uint8_t *)spi_tx_buff, &apdu_cmd, APDU_CMD_TPY_SPI);

        snd_rcv_data_size = SPI_PACKET_DATA_SIZE + 5;
        if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, snd_rcv_data_size) < 0)
        {
            PRINTF("fail to send or receive SPI packet\r\n");
            return IPQP_EC_SPI_IO;
        }

        // check if the response packet is valid
        if (received_valid_packet(spi_rx_buff))
        {
            // fill the key buffer
            for (int j = 0; j < SPI_PACKET_DATA_SIZE; j++)
            {
                if (rcv_buff != NULL)
                {
                    rcv_buff[rcv_buff_idx++] = spi_rx_buff[5 + j];

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
            to_check_spi_status = true;
        }
        else
        {
            PRINTF("received invalid SPI packet. fetch packet %d again.\r\n", (spi_pkt_num - 1 - i));
            to_check_spi_status = false;
        }

        // PRINT_ARR(spi_rx_buff, snd_rcv_data_size, 32, "RX");
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode apdu_spi_status_check(spi_conf_t *i_spi_conf, uint8_t *o_result)
{
    if ((i_spi_conf == NULL) || (o_result == NULL))
        return IPQP_EC_NULL_POINTER;

    apdu_t my_apdu;

    uint8_t spi_tx_buff[6];
    uint8_t spi_rx_buff[6];

    memset(spi_tx_buff, 0, 6);
    memset(spi_rx_buff, 0, 6);

    my_apdu.cla = APDU_CLA_DEV_INIT;
    my_apdu.ins = 0xAA;
    my_apdu.p1 = 0xBB;
    my_apdu.p2 = 0xCC;
    my_apdu.lc = 0;
    my_apdu.le = 0;
    my_apdu.data = (uint8_t *)NULL;

    apdu_set_buffer((uint8_t *)spi_tx_buff, &my_apdu, APDU_CMD_TPY_SPI);

    // PRINT_ARR(spi_tx_buff, 6, 6, "TX");

    if (spi_data_snd_rcv(i_spi_conf, spi_tx_buff, spi_rx_buff, 6) < 0)
        return IPQP_EC_SPI_IO;

    // PRINT_ARR(spi_rx_buff, 6, 6, "RX");

    o_result[0] = spi_rx_buff[4];
    o_result[1] = spi_rx_buff[5];
    return IPQP_EC_SUCCESS;
}
