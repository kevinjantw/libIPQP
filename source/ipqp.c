#include "ipqp.h"
#include "ipqp_common.h"
#include "ipqp_apdu.h"
#include "ipqp_device.h"
#include <oqs/oqs.h>

/* Global variables */
static IPQP_Provider g_ipqp_provider = IPQP_PROV_LIBOQS;
static uint8_t g_apdu_rtl_src = APDU_CLA_ITRI;

static char g_spi_dev_name[256] = SPI_DEV_NAME;
static spi_conf_t g_spi_conf = {
    .fd = -1,
    .mode = SPI_MODE,
    .bits_per_word = SPI_BITS_PER_WORD,
    .speed = SPI_MAX_SPEED_HZ,
    .lsb = SPI_LSB_FIRST,
    .name = g_spi_dev_name};

static char g_uart_dev_name[256] = UART_DEV_NAME;
static uart_conf_t g_uart_conf = {
    .fd = -1,
    .name = g_uart_dev_name,
    .open_flags = UART_OPEN_FLAGS,
    .input_mode_flags = UART_INPUT_MODE_FLAGS,
    .output_mode_flags = UART_OUTPUT_MODE_FLAGS,
    .control_mode_flags = UART_CONTROL_MODE_FLAGS,
    .local_mode_flags = UART_LOCAL_MODE_FLAGS};

static char g_i2c_dev_name[256] = I2C_DEV_NAME;
static i2c_conf_t g_i2c_conf = {
    .fd = -1,
    .name = g_i2c_dev_name,
    .open_flags = I2C_OPEN_FLAGS,
    .ten_bits = I2C_TENBITS_ADDR,
    .slave_addr = I2C_SLAVE_ADDRESS};

static char g_tcp_server_ip[256] = TCP_DEV_IP;
static tcp_conf_t g_tcp_conf = {
    .fd = -1,
    .ip = g_tcp_server_ip,
    .port = TCP_DEV_PORT,
    .timeout_sec = TCP_TIMEOUT_SEC,
    .retries_on_failure = TCP_RETRIES_ON_FAILURE};

IPQP_ErrorCode IPQP_config(IPQP_Provider prov, ...)
{
    g_ipqp_provider = prov;

    switch (prov)
    {
    case IPQP_PROV_SPI_ITRI:
    {
        g_apdu_rtl_src = APDU_CLA_ITRI;

        va_list list;
        va_start(list, prov);

        spi_conf_t *i_spi_conf = va_arg(list, spi_conf_t *);
        snprintf(g_spi_dev_name, sizeof(g_spi_dev_name), "%s", i_spi_conf->name);
        g_spi_conf.fd = i_spi_conf->fd;
        g_spi_conf.mode = i_spi_conf->mode;
        g_spi_conf.bits_per_word = i_spi_conf->bits_per_word;
        g_spi_conf.speed = i_spi_conf->speed;
        g_spi_conf.lsb = i_spi_conf->lsb;
        g_spi_conf.name = g_spi_dev_name;

        va_end(list);
        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        g_apdu_rtl_src = APDU_CLA_ITRI;

        va_list list;
        va_start(list, prov);

        uart_conf_t *i_uart_conf = va_arg(list, uart_conf_t *);
        snprintf(g_uart_dev_name, sizeof(g_uart_dev_name), "%s", i_uart_conf->name);
        g_uart_conf.fd = i_uart_conf->fd;
        g_uart_conf.name = g_uart_dev_name;
        g_uart_conf.open_flags = i_uart_conf->open_flags;
        g_uart_conf.input_mode_flags = i_uart_conf->input_mode_flags;
        g_uart_conf.output_mode_flags = i_uart_conf->output_mode_flags;
        g_uart_conf.control_mode_flags = i_uart_conf->control_mode_flags;
        g_uart_conf.local_mode_flags = i_uart_conf->local_mode_flags;

        va_end(list);
        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        g_apdu_rtl_src = APDU_CLA_ITRI;
        va_list list;
        va_start(list, prov);

        i2c_conf_t *i_i2c_conf = va_arg(list, i2c_conf_t *);
        snprintf(g_i2c_dev_name, sizeof(g_i2c_dev_name), "%s", i_i2c_conf->name);
        g_i2c_conf.fd = i_i2c_conf->fd;
        g_i2c_conf.name = g_i2c_dev_name;
        g_i2c_conf.open_flags = i_i2c_conf->open_flags;
        g_i2c_conf.ten_bits = i_i2c_conf->ten_bits;
        g_i2c_conf.slave_addr = i_i2c_conf->slave_addr;

        va_end(list);
        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        g_apdu_rtl_src = APDU_CLA_ITRI;
        va_list list;
        va_start(list, prov);

        tcp_conf_t *i_tcp_conf = va_arg(list, tcp_conf_t *);
        snprintf(g_tcp_server_ip, sizeof(g_tcp_server_ip), "%s", i_tcp_conf->ip);
        g_tcp_conf.fd = i_tcp_conf->fd;
        g_tcp_conf.ip = g_tcp_server_ip;
        g_tcp_conf.port = i_tcp_conf->port;
        g_tcp_conf.timeout_sec = i_tcp_conf->timeout_sec;
        g_tcp_conf.retries_on_failure = i_tcp_conf->retries_on_failure;

        va_end(list);
        break;
    }
    default:
        break;
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode IPQP_kem_keypair(IPQP_Algorithm i_kem_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    if ((o_pk == NULL) || (o_sk == NULL))
        return IPQP_EC_NULL_POINTER;

    switch (g_ipqp_provider)
    {
    case IPQP_PROV_LIBOQS:
    {
        OQS_STATUS(*OQS_KEM_kyber_keypair)
        (uint8_t * public_key, uint8_t * secret_key);
        size_t pk_len = 0;
        size_t sk_len = 0;

        switch (i_kem_algo)
        {
        case IPQP_ALGO_KYBER_512:
            pk_len = OQS_KEM_kyber_512_length_public_key;
            sk_len = OQS_KEM_kyber_512_length_secret_key;
            OQS_KEM_kyber_keypair = &OQS_KEM_kyber_512_keypair;
            break;
        case IPQP_ALGO_KYBER_768:
            pk_len = OQS_KEM_kyber_768_length_public_key;
            sk_len = OQS_KEM_kyber_768_length_secret_key;
            OQS_KEM_kyber_keypair = &OQS_KEM_kyber_768_keypair;
            break;
        case IPQP_ALGO_KYBER_1024:
            pk_len = OQS_KEM_kyber_1024_length_public_key;
            sk_len = OQS_KEM_kyber_1024_length_secret_key;
            OQS_KEM_kyber_keypair = &OQS_KEM_kyber_1024_keypair;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }

        OQS_STATUS rc = OQS_KEM_kyber_keypair((uint8_t *)o_pk, (uint8_t *)o_sk);
        if (rc != OQS_SUCCESS)
        {
            PRINTF("ERROR: failed to gen-keypair! (%d)\r\n", rc);
            OQS_MEM_cleanse(o_pk, pk_len);
            OQS_MEM_cleanse(o_sk, sk_len);
            return IPQP_EC_FAIL;
        }
        break;
    }
    case IPQP_PROV_SPI_ITRI:
    {
        int res = spi_open(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_spi_kem_keypair(&g_spi_conf, g_apdu_rtl_src, i_kem_algo, o_pk, o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = spi_close(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        int res = uart_open(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_uart_kem_keypair(&g_uart_conf, g_apdu_rtl_src, i_kem_algo, o_pk, o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = uart_close(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        int res = i2c_open(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_i2c_kem_keypair(&g_i2c_conf, g_apdu_rtl_src, i_kem_algo, o_pk, o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = i2c_close(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        int res = tcp_open(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_tcp_kem_keypair(&g_tcp_conf, g_apdu_rtl_src, i_kem_algo, o_pk, o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = tcp_close(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    default:
        return IPQP_EC_PROV_NOT_CONFIGED;
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode IPQP_kem_encap(IPQP_Algorithm i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct)
{
    if ((i_pk == NULL) || (o_ss == NULL) || (o_ct == NULL))
        return IPQP_EC_NULL_POINTER;

    switch (g_ipqp_provider)
    {
    case IPQP_PROV_LIBOQS:
    {
        OQS_STATUS(*OQS_KEM_kyber_encaps)
        (uint8_t * ciphertext, uint8_t * shared_secret, const uint8_t *public_key);
        size_t ss_len = 0;
        size_t ct_len = 0;

        switch (i_kem_algo)
        {
        case IPQP_ALGO_KYBER_512:
            ss_len = IPQP_KEM_kyber_512_length_shared_secret;
            ct_len = IPQP_KEM_kyber_512_length_ciphertext;
            OQS_KEM_kyber_encaps = &OQS_KEM_kyber_512_encaps;
            break;
        case IPQP_ALGO_KYBER_768:
            ss_len = IPQP_KEM_kyber_768_length_shared_secret;
            ct_len = IPQP_KEM_kyber_768_length_ciphertext;
            OQS_KEM_kyber_encaps = &OQS_KEM_kyber_768_encaps;
            break;
        case IPQP_ALGO_KYBER_1024:
            ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
            ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
            OQS_KEM_kyber_encaps = &OQS_KEM_kyber_1024_encaps;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }

        OQS_STATUS rc = OQS_KEM_kyber_encaps((uint8_t *)o_ct, (uint8_t *)o_ss, (uint8_t *)i_pk);
        if (rc != OQS_SUCCESS)
        {
            printf("ERROR: failed to do key encaps! (%d)\r\n", rc);
            OQS_MEM_cleanse(o_ss, ss_len);
            OQS_MEM_cleanse(o_ct, ct_len);
            return IPQP_EC_FAIL;
        }
        break;
    }
    case IPQP_PROV_SPI_ITRI:
    {
        int res = spi_open(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_spi_kem_encap(&g_spi_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_pk, (uint8_t *)o_ss, (uint8_t *)o_ct);
        if (res == IPQP_EC_SUCCESS)
            return res;

        res = spi_close(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        int res = uart_open(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_uart_kem_encap(&g_uart_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_pk, (uint8_t *)o_ss, (uint8_t *)o_ct);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = uart_close(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        int res = i2c_open(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_i2c_kem_encap(&g_i2c_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_pk, (uint8_t *)o_ss, (uint8_t *)o_ct);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = i2c_close(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        int res = tcp_open(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_tcp_kem_encap(&g_tcp_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_pk, (uint8_t *)o_ss, (uint8_t *)o_ct);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = tcp_close(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    default:
        return IPQP_EC_PROV_NOT_CONFIGED;
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode IPQP_kem_decap(IPQP_Algorithm i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss)
{
    if ((i_sk == NULL) || (i_ct == NULL) || (o_ss == NULL))
        return IPQP_EC_NULL_POINTER;

    switch (g_ipqp_provider)
    {
    case IPQP_PROV_LIBOQS:
    {
        OQS_STATUS(*OQS_KEM_kyber_decaps)
        (uint8_t * shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
        size_t ss_len = 0;

        switch (i_kem_algo)
        {
        case IPQP_ALGO_KYBER_512:
            ss_len = IPQP_KEM_kyber_512_length_shared_secret;
            OQS_KEM_kyber_decaps = &OQS_KEM_kyber_512_decaps;
            break;
        case IPQP_ALGO_KYBER_768:
            ss_len = IPQP_KEM_kyber_768_length_shared_secret;
            OQS_KEM_kyber_decaps = &OQS_KEM_kyber_768_decaps;
            break;
        case IPQP_ALGO_KYBER_1024:
            ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
            OQS_KEM_kyber_decaps = &OQS_KEM_kyber_1024_decaps;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }

        OQS_STATUS rc = OQS_KEM_kyber_decaps((uint8_t *)o_ss, (uint8_t *)i_ct, (uint8_t *)i_sk);
        if (rc != OQS_SUCCESS)
        {
            printf("ERROR: failed to do key decaps! (%d)\r\n", rc);
            OQS_MEM_cleanse(o_ss, ss_len);
            return IPQP_EC_FAIL;
        }
        break;
    }
    case IPQP_PROV_SPI_ITRI:
    {
        int res = spi_open(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_spi_kem_decap(&g_spi_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_sk, (uint8_t *)i_ct, (uint8_t *)o_ss);
        if (res == IPQP_EC_SUCCESS)
            return res;

        res = spi_close(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        int res = uart_open(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_uart_kem_decap(&g_uart_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_sk, (uint8_t *)i_ct, (uint8_t *)o_ss);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = uart_close(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        int res = i2c_open(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_i2c_kem_decap(&g_i2c_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_sk, (uint8_t *)i_ct, (uint8_t *)o_ss);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = i2c_close(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        int res = tcp_open(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_tcp_kem_decap(&g_tcp_conf, g_apdu_rtl_src, i_kem_algo, (uint8_t *)i_sk, (uint8_t *)i_ct, (uint8_t *)o_ss);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = tcp_close(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    default:
        return IPQP_EC_PROV_NOT_CONFIGED;
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode IPQP_dsa_keypair(IPQP_Algorithm i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk)
{
    if ((o_pk == NULL) || (o_sk == NULL))
        return IPQP_EC_NULL_POINTER;

    switch (g_ipqp_provider)
    {
    case IPQP_PROV_LIBOQS:
    {
        OQS_STATUS(*OQS_SIG_dilithium_keypair)
        (uint8_t * public_key, uint8_t * secret_key);
        size_t pk_len = 0;
        size_t sk_len = 0;

        switch (i_dsa_algo)
        {
        case IPQP_ALGO_DILITHIUM_2:
            pk_len = OQS_SIG_dilithium_2_length_public_key;
            sk_len = OQS_SIG_dilithium_2_length_secret_key;
            OQS_SIG_dilithium_keypair = &OQS_SIG_dilithium_2_keypair;
            break;
        case IPQP_ALGO_DILITHIUM_3:
            pk_len = OQS_SIG_dilithium_3_length_public_key;
            sk_len = OQS_SIG_dilithium_3_length_secret_key;
            OQS_SIG_dilithium_keypair = &OQS_SIG_dilithium_3_keypair;
            break;
        case IPQP_ALGO_DILITHIUM_5:
            pk_len = OQS_SIG_dilithium_5_length_public_key;
            sk_len = OQS_SIG_dilithium_5_length_secret_key;
            OQS_SIG_dilithium_keypair = &OQS_SIG_dilithium_5_keypair;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }

        OQS_STATUS rc = OQS_SIG_dilithium_keypair((uint8_t *)o_pk, (uint8_t *)o_sk);
        if (rc != OQS_SUCCESS)
        {
            PRINTF("ERROR: failed to gen-keypair! (%d)\r\n", rc);
            OQS_MEM_cleanse(o_pk, pk_len);
            OQS_MEM_cleanse(o_sk, sk_len);
            return IPQP_EC_FAIL;
        }
        break;
    }
    case IPQP_PROV_SPI_ITRI:
    {
        int res = spi_open(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_spi_dsa_keypair(&g_spi_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)o_pk, (uint8_t *)o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = spi_close(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        int res = uart_open(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_uart_dsa_keypair(&g_uart_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)o_pk, (uint8_t *)o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = uart_close(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        int res = i2c_open(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_i2c_dsa_keypair(&g_i2c_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)o_pk, (uint8_t *)o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = i2c_close(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        int res = tcp_open(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_tcp_dsa_keypair(&g_tcp_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)o_pk, (uint8_t *)o_sk);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = tcp_close(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    default:
        return IPQP_EC_PROV_NOT_CONFIGED;
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode IPQP_dsa_sign(IPQP_Algorithm i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len)
{
    if ((i_sk == NULL) || (i_msg == NULL) || (o_sm == NULL) || (o_sm_len == NULL))
        return IPQP_EC_NULL_POINTER;

    switch (g_ipqp_provider)
    {
    case IPQP_PROV_LIBOQS:
    {
        OQS_STATUS(*OQS_SIG_dilithium_sign)
        (uint8_t * signature, size_t * signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

        switch (i_dsa_algo)
        {
        case IPQP_ALGO_DILITHIUM_2:
            OQS_SIG_dilithium_sign = &OQS_SIG_dilithium_2_sign;
            break;
        case IPQP_ALGO_DILITHIUM_3:
            OQS_SIG_dilithium_sign = &OQS_SIG_dilithium_3_sign;
            break;
        case IPQP_ALGO_DILITHIUM_5:
            OQS_SIG_dilithium_sign = &OQS_SIG_dilithium_5_sign;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }

        OQS_STATUS rc = OQS_SIG_dilithium_sign((uint8_t *)o_sm, (size_t *)o_sm_len, (uint8_t *)i_msg, (size_t)i_msg_len, (uint8_t *)i_sk);
        if (rc != OQS_SUCCESS)
        {
            PRINTF("ERROR: failed to sign! (%d)\r\n", rc);
            return IPQP_EC_FAIL;
        }

        break;
    }
    case IPQP_PROV_SPI_ITRI:
    {
        int res = spi_open(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_spi_dsa_sign(&g_spi_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_sk, (uint8_t *)i_msg, i_msg_len, (uint8_t *)o_sm, (size_t *)o_sm_len);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = spi_close(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        int res = uart_open(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_uart_dsa_sign(&g_uart_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_sk, (uint8_t *)i_msg, i_msg_len, (uint8_t *)o_sm, (size_t *)o_sm_len);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = uart_close(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        int res = i2c_open(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_i2c_dsa_sign(&g_i2c_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_sk, (uint8_t *)i_msg, i_msg_len, (uint8_t *)o_sm, (size_t *)o_sm_len);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = i2c_close(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        int res = tcp_open(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_tcp_dsa_sign(&g_tcp_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_sk, (uint8_t *)i_msg, i_msg_len, (uint8_t *)o_sm, (size_t *)o_sm_len);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = tcp_close(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    default:
        return IPQP_EC_PROV_NOT_CONFIGED;
    }

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode IPQP_dsa_verify(IPQP_Algorithm i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified)
{
    if ((i_pk == NULL) || (i_msg == NULL) || (o_verified == NULL))
        return IPQP_EC_NULL_POINTER;

    switch (g_ipqp_provider)
    {
    case IPQP_PROV_LIBOQS:
    {
        OQS_STATUS(*OQS_SIG_dilithium_verify)
        (const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

        switch (i_dsa_algo)
        {
        case IPQP_ALGO_DILITHIUM_2:
            OQS_SIG_dilithium_verify = &OQS_SIG_dilithium_2_verify;
            break;
        case IPQP_ALGO_DILITHIUM_3:
            OQS_SIG_dilithium_verify = &OQS_SIG_dilithium_3_verify;
            break;
        case IPQP_ALGO_DILITHIUM_5:
            OQS_SIG_dilithium_verify = &OQS_SIG_dilithium_5_verify;
            break;
        default:
            return IPQP_EC_ALGO_MISSING;
        }

        OQS_STATUS rc = OQS_SIG_dilithium_verify((uint8_t *)i_msg, (size_t)i_msg_len, (uint8_t *)i_sm, (size_t)i_sm_len, (uint8_t *)i_pk);
        if (rc != OQS_SUCCESS)
        {
            *o_verified = false;
        }
        else
        {
            *o_verified = true;
        }

        break;
    }
    case IPQP_PROV_SPI_ITRI:
    {
        int res = spi_open(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_spi_dsa_verify(&g_spi_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_pk, (uint8_t *)i_msg, (size_t)i_msg_len, (uint8_t *)i_sm, (size_t)i_sm_len, (bool *)o_verified);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = spi_close(&g_spi_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_UART_ITRI:
    {
        int res = uart_open(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_uart_dsa_verify(&g_uart_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_pk, (uint8_t *)i_msg, (size_t)i_msg_len, (uint8_t *)i_sm, (size_t)i_sm_len, (bool *)o_verified);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = uart_close(&g_uart_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_I2C_ITRI:
    {
        int res = i2c_open(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_i2c_dsa_verify(&g_i2c_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_pk, (uint8_t *)i_msg, (size_t)i_msg_len, (uint8_t *)i_sm, (size_t)i_sm_len, (bool *)o_verified);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = i2c_close(&g_i2c_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    case IPQP_PROV_TCP_ITRI:
    {
        int res = tcp_open(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = apdu_tcp_dsa_verify(&g_tcp_conf, g_apdu_rtl_src, i_dsa_algo, (uint8_t *)i_pk, (uint8_t *)i_msg, (size_t)i_msg_len, (uint8_t *)i_sm, (size_t)i_sm_len, (bool *)o_verified);
        if (res != IPQP_EC_SUCCESS)
            return res;

        res = tcp_close(&g_tcp_conf);
        if (res != IPQP_EC_SUCCESS)
            return res;

        break;
    }
    default:
        return IPQP_EC_PROV_NOT_CONFIGED;
    }

    return IPQP_EC_SUCCESS;
}
