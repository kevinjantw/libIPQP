#include "ipqp_apdu.h"

/**
 * @brief Set the APDU command buffer with the provided APDU command structure.
 *
 * This function constructs an APDU command buffer based on the provided APDU command structure.
 * The APDU command buffer follows the APDU command format, which includes the following fields:
 * - CLA (Command Class)
 * - INS (Instruction)
 * - P1 (Parameter 1)
 * - P2 (Parameter 2)
 * - LC (Length of the command data)
 * - DATA (Command data)
 * - LE (Expected length of the response data)
 *
 * @param temp_buf Pointer to the temporary buffer where the APDU command buffer will be stored.
 * @param apdu Pointer to the APDU command structure.
 */
void apdu_set_buffer(uint8_t *temp_buf, apdu_t *apdu, APDU_CMD_TYP apdu_typ)
{
    /*
        APDU Command format:
     |-----------------------------------------------------------|
     |       | CLA | INS | P1 | P2 | LC  |   DATA  |     LE      |
     |-----------------------------------------------------------|
     | size  |  1  |  1  |  1 |  1 |  3  |    N    |      3      |
     |-----------------------------------------------------------|
     | index |  0  |  1  |  2 |  3 | 4~6 | 7~(N+6) | (N+7)~(N+9) |
     |-----------------------------------------------------------|
    */

    temp_buf[0] = apdu->cla;
    temp_buf[1] = apdu->ins;
    temp_buf[2] = apdu->p1;
    temp_buf[3] = apdu->p2;

    switch (apdu_typ)
    {
    case APDU_CMD_TPY_UART:
        temp_buf[4] = 0x00;
        temp_buf[5] = ((uint8_t *)&(apdu->lc))[1];
        temp_buf[6] = ((uint8_t *)&(apdu->lc))[0];

        if (apdu->data != NULL)
        {
            memcpy(temp_buf + 7, apdu->data, apdu->lc);
            temp_buf[7 + apdu->lc] = 0x00;
            temp_buf[8 + apdu->lc] = ((uint8_t *)&(apdu->le))[1];
            temp_buf[9 + apdu->lc] = ((uint8_t *)&(apdu->le))[0];
        }
        else
        {
            temp_buf[7] = 0x00;
            temp_buf[8] = ((uint8_t *)&(apdu->le))[1];
            temp_buf[9] = ((uint8_t *)&(apdu->le))[0];
        }
        break;

    case APDU_CMD_TPY_SPI:
        temp_buf[4] = ((uint8_t *)&(apdu->lc))[2];
        temp_buf[5] = ((uint8_t *)&(apdu->lc))[1];
        temp_buf[6] = ((uint8_t *)&(apdu->lc))[0];

        if (apdu->data != NULL)
        {
            memcpy(temp_buf + 7, apdu->data, apdu->lc);
            temp_buf[7 + apdu->lc] = ((uint8_t *)&(apdu->le))[2];
            temp_buf[8 + apdu->lc] = ((uint8_t *)&(apdu->le))[1];
            temp_buf[9 + apdu->lc] = ((uint8_t *)&(apdu->le))[0];
        }
        else
        {
            temp_buf[7] = ((uint8_t *)&(apdu->le))[2];
            temp_buf[8] = ((uint8_t *)&(apdu->le))[1];
            temp_buf[9] = ((uint8_t *)&(apdu->le))[0];
        }
        break;
    case APDU_CMD_TPY_STD:
    default:
        temp_buf[4] = ((uint8_t *)&(apdu->lc))[0];
        temp_buf[5] = ((uint8_t *)&(apdu->lc))[1];
        temp_buf[6] = ((uint8_t *)&(apdu->lc))[2];

        if (apdu->data != NULL)
        {
            memcpy(temp_buf + 7, apdu->data, apdu->lc);
            temp_buf[7 + apdu->lc] = ((uint8_t *)&(apdu->le))[0];
            temp_buf[8 + apdu->lc] = ((uint8_t *)&(apdu->le))[1];
            temp_buf[9 + apdu->lc] = ((uint8_t *)&(apdu->le))[2];
        }
        else
        {
            temp_buf[7] = ((uint8_t *)&(apdu->le))[0];
            temp_buf[8] = ((uint8_t *)&(apdu->le))[1];
            temp_buf[9] = ((uint8_t *)&(apdu->le))[2];
        }
        break;
    }
}

uint32_t apdu_get_lc_le_from_array(uint8_t *lc_le_arr, APDU_CMD_TYP apdu_typ)
{
    uint32_t ret = 0;
    uint8_t *ret_ptr = (uint8_t *)&ret;
    switch (apdu_typ)
    {
    case APDU_CMD_TPY_UART:
        ret_ptr[0] = lc_le_arr[1];
        ret_ptr[1] = lc_le_arr[0];
        break;
    case APDU_CMD_TPY_SPI:
        ret_ptr[0] = lc_le_arr[2];
        ret_ptr[1] = lc_le_arr[1];
        ret_ptr[2] = lc_le_arr[0];
        break;
    case APDU_CMD_TPY_STD:
    default:
        ret_ptr[0] = lc_le_arr[0];
        ret_ptr[1] = lc_le_arr[1];
        ret_ptr[2] = lc_le_arr[2];
        break;
    }
    return ret;
}

bool apdu_cla_valid(APDU_CMD_CLA cla)
{
    switch (cla)
    {
    case APDU_CLA_DEV_INIT:
    case APDU_CLA_DEV_INIT_RSP:
    case APDU_CLA_DEV_BUSY:
    case APDU_CLA_PARA_BAD:
    case APDU_CLA_ITRI:
    case APDU_CLA_ITRI_RSP:
        return true;
    default:
        return false;
    }
    return false;
}
bool apdu_ins_valid(APDU_CMD_INS ins)
{
    switch (ins)
    {
    case APDU_CMD_INS_ALGO_KYBER_512:
    case APDU_CMD_INS_ALGO_KYBER_768:
    case APDU_CMD_INS_ALGO_KYBER_1024:
    case APDU_CMD_INS_ALGO_DILITHIUM_2:
    case APDU_CMD_INS_ALGO_DILITHIUM_3:
    case APDU_CMD_INS_ALGO_DILITHIUM_5:
        return true;
    default:
        return false;
    }
    return false;
}
bool apdu_p1_valid(APDU_CMD_P1 p1)
{
    switch (p1)
    {
    case APDU_CMD_P1_KEM_KEYPAIR:
    case APDU_CMD_P1_KEM_ENCAP:
    case APDU_CMD_P1_KEM_DECAP:

    case APDU_CMD_P1_ASSIGN_KEM_PK:
    case APDU_CMD_P1_ASSIGN_KEM_SK:
    case APDU_CMD_P1_ASSIGN_KEM_CT:

    case APDU_CMD_P1_DSA_KEYPAIR:
    case APDU_CMD_P1_DSA_SIGN:
    case APDU_CMD_P1_DSA_VERIFY:

    case APDU_CMD_P1_ASSIGN_DSA_PK:
    case APDU_CMD_P1_ASSIGN_DSA_SK:

#if false
    case APDU_CMD_P1_RSP_KEM_KEYPAIR:
    case APDU_CMD_P1_RSP_KEM_ENCAP:
    case APDU_CMD_P1_RSP_KEM_DECAP:

    case APDU_CMD_P1_RSP_ASSIGN_KEM_PK:
    case APDU_CMD_P1_RSP_ASSIGN_KEM_SK:
    case APDU_CMD_P1_RSP_ASSIGN_KEM_CT:

    case APDU_CMD_P1_RSP_DSA_KEYPAIR:
    case APDU_CMD_P1_RSP_DSA_SIGN:
    case APDU_CMD_P1_RSP_DSA_VERIFY:

    case APDU_CMD_P1_RSP_ASSIGN_DSA_PK:
    case APDU_CMD_P1_RSP_ASSIGN_DSA_SK:
#endif
        return true;
    default:
        return false;
    }
    return false;
}
