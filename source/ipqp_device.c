#include "ipqp_device.h"

bool received_valid_packet(uint8_t *rcv_buff)
{
    if (rcv_buff == NULL)
        return false;

    if ((rcv_buff[1] == 0xAA) && (rcv_buff[2] == 0xBB) && (rcv_buff[3] == 0xCC))
        return true;

    return false;
}
