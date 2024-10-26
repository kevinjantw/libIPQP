#ifndef __IPQP_APDU_H__
#define __IPQP_APDU_H__
#include "ipqp.h"

#include "ipqp_common.h"
#include "ipqp_device.h"

typedef enum apdu_command_class
{
    APDU_CLA_DEV_INIT = 0x91,
    APDU_CLA_DEV_INIT_RSP = 0x90,
    APDU_CLA_DEV_BUSY = 0x7F,
    APDU_CLA_PARA_BAD = 0x7E,

    APDU_CLA_ITRI = 0x80,
    APDU_CLA_ITRI_RSP = 0x81
} APDU_CMD_CLA;

typedef enum apdu_command_instruction
{
    APDU_CMD_INS_ALGO_KYBER_512 = IPQP_ALGO_KYBER_512,
    APDU_CMD_INS_ALGO_KYBER_768 = IPQP_ALGO_KYBER_768,
    APDU_CMD_INS_ALGO_KYBER_1024 = IPQP_ALGO_KYBER_1024,

    APDU_CMD_INS_ALGO_DILITHIUM_2 = IPQP_ALGO_DILITHIUM_2,
    APDU_CMD_INS_ALGO_DILITHIUM_3 = IPQP_ALGO_DILITHIUM_3,
    APDU_CMD_INS_ALGO_DILITHIUM_5 = IPQP_ALGO_DILITHIUM_5
} APDU_CMD_INS;

typedef enum apdu_command_parameter_1
{
    APDU_CMD_P1_KEM_KEYPAIR = 0x01, // generate KEM keypair
    APDU_CMD_P1_KEM_ENCAP = 0x02,   // key encapsulation
    APDU_CMD_P1_KEM_DECAP = 0x03,   // key decapsulation

    APDU_CMD_P1_ASSIGN_KEM_SK = 0x04, // assign secret key before key decapsulation
    APDU_CMD_P1_ASSIGN_KEM_PK = 0x05, // assign public key before key encapsulation
    APDU_CMD_P1_ASSIGN_KEM_CT = 0x06, // assign ciphertext before key decapsulation

    APDU_CMD_P1_DSA_KEYPAIR = 0x21, // generate DSA keypair
    APDU_CMD_P1_DSA_SIGN = 0x22,    // DSA signing
    APDU_CMD_P1_DSA_VERIFY = 0x23,  // DSA verifying

    APDU_CMD_P1_ASSIGN_DSA_PK = 0x26, // assign public key before verifying
    APDU_CMD_P1_ASSIGN_DSA_SK = 0x27, // assign secret key before signing

    APDU_CMD_P1_RSP_KEM_KEYPAIR = APDU_CMD_P1_KEM_KEYPAIR,
    APDU_CMD_P1_RSP_KEM_ENCAP = APDU_CMD_P1_KEM_ENCAP,
    APDU_CMD_P1_RSP_KEM_DECAP = APDU_CMD_P1_KEM_DECAP,

    APDU_CMD_P1_RSP_ASSIGN_KEM_PK = APDU_CMD_P1_ASSIGN_KEM_PK,
    APDU_CMD_P1_RSP_ASSIGN_KEM_SK = APDU_CMD_P1_ASSIGN_KEM_SK,
    APDU_CMD_P1_RSP_ASSIGN_KEM_CT = APDU_CMD_P1_ASSIGN_KEM_CT,

    APDU_CMD_P1_RSP_DSA_KEYPAIR = APDU_CMD_P1_DSA_KEYPAIR,
    APDU_CMD_P1_RSP_DSA_SIGN = APDU_CMD_P1_DSA_SIGN,
    APDU_CMD_P1_RSP_DSA_VERIFY = APDU_CMD_P1_DSA_VERIFY,

    APDU_CMD_P1_RSP_ASSIGN_DSA_PK = APDU_CMD_P1_ASSIGN_DSA_PK,
    APDU_CMD_P1_RSP_ASSIGN_DSA_SK = APDU_CMD_P1_ASSIGN_DSA_SK
} APDU_CMD_P1;

typedef enum apdu_command_type
{
    APDU_CMD_TPY_STD = 0,  // 3-byte lc/le in LSB
    APDU_CMD_TPY_UART = 1, // 3-byte lc/le in MSB & 1st byte must be zero
    APDU_CMD_TPY_SPI = 2   // 3-byte lc/le in MSB
} APDU_CMD_TYP;

typedef struct
{
    uint8_t cla;   // RTL source
    uint8_t ins;   // algorithm
    uint8_t p1;    // action
    uint8_t p2;    // apdu packet index
    uint32_t lc;   // length of the command parameter data
    uint8_t *data; // command data
    uint32_t le;   // length of the response data
} apdu_t;

/**
 * @brief This function sets the buffer for the APDU structure.
 *
 * @param temp_buf Pointer to the temporary buffer where the APDU data will be stored.
 * @param apdu Pointer to the APDU structure where the data will be assigned.
 *
 * @return void
 */
void apdu_set_buffer(uint8_t *temp_buf, apdu_t *apdu, APDU_CMD_TYP apdu_typ);

bool apdu_cla_valid(APDU_CMD_CLA cla);
bool apdu_ins_valid(APDU_CMD_INS ins);
bool apdu_p1_valid(APDU_CMD_P1 p1);

//----------------------------------------------------------------
/* SPI */

IPQP_ErrorCode apdu_spi_kem_keypair(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_spi_kem_encap(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode apdu_spi_kem_encap_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode apdu_spi_kem_decap(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);
IPQP_ErrorCode apdu_spi_kem_decap_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);

IPQP_ErrorCode apdu_spi_kem_assign_ciphertext(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t i_ct_type, uint8_t *i_ct);

IPQP_ErrorCode apdu_spi_dsa_keypair(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_spi_dsa_sign(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode apdu_spi_dsa_sign_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode apdu_spi_dsa_verify(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);
IPQP_ErrorCode apdu_spi_dsa_verify_cmd(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);

IPQP_ErrorCode apdu_spi_assign_key(spi_conf_t *i_spi_conf, uint8_t i_rtl_src, uint8_t i_dsa_kem_algo, uint8_t i_key_type, uint8_t *i_key);
IPQP_ErrorCode apdu_spi_status_check(spi_conf_t *i_spi_conf, uint8_t *o_result);

//----------------------------------------------------------------
/* UART */

IPQP_ErrorCode apdu_uart_kem_keypair(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_uart_kem_encap(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode apdu_uart_kem_encap_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode apdu_uart_kem_decap(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);
IPQP_ErrorCode apdu_uart_kem_decap_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);

IPQP_ErrorCode apdu_uart_kem_assign_ciphertext(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t i_ct_type, uint8_t *i_ct);

IPQP_ErrorCode apdu_uart_dsa_keypair(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_uart_dsa_sign(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode apdu_uart_dsa_sign_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode apdu_uart_dsa_verify(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);
IPQP_ErrorCode apdu_uart_dsa_verify_cmd(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);

IPQP_ErrorCode apdu_uart_assign_key(uart_conf_t *i_uart_conf, uint8_t i_rtl_src, uint8_t i_dsa_kem_algo, uint8_t i_key_type, uint8_t *i_key);

IPQP_ErrorCode apdu_uart_status_check(uart_conf_t *i_uart_conf, uint8_t *o_result);

//----------------------------------------------------------------
/* I2C */
IPQP_ErrorCode apdu_i2c_kem_keypair(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_i2c_kem_encap(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode apdu_i2c_kem_decap(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);

IPQP_ErrorCode apdu_i2c_kem_assign_ciphertext(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t i_ct_type, uint8_t *i_ct);

IPQP_ErrorCode apdu_i2c_dsa_keypair(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_i2c_dsa_sign(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode apdu_i2c_dsa_verify(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);

IPQP_ErrorCode apdu_i2c_assign_key(i2c_conf_t *i_i2c_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t i_key_type, uint8_t *i_key);
IPQP_ErrorCode apdu_i2c_status_check(i2c_conf_t *i_i2c_conf, uint8_t *o_result);

//----------------------------------------------------------------
/* TCP */
IPQP_ErrorCode apdu_tcp_kem_keypair(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_tcp_kem_encap(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode apdu_tcp_kem_decap(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);

IPQP_ErrorCode apdu_tcp_dsa_keypair(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode apdu_tcp_dsa_sign(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode apdu_tcp_dsa_verify(tcp_conf_t *i_tcp_conf, uint8_t i_rtl_src, uint8_t i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);

#endif /* __IPQP_APDU_H__ */
