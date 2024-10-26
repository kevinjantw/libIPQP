#include "ipqp_common.h"

void print_arr(uint8_t *arr, size_t arr_len, size_t byte_per_line, const char *arr_name)
{
    if (arr_name != NULL)
        printf("%s:\r\n", arr_name);

    for (int i = 0; i < arr_len; i++)
    {
        printf(" %02X", arr[i]);
        if (i % byte_per_line == (byte_per_line - 1))
            printf("\r\n");
    }

    if (arr_len % byte_per_line != 0)
        printf("\r\n");

    printf("\r\n");
}

void ipqp_error_code_log(IPQP_ErrorCode ec, char *log)
{
    switch (ec)
    {
    case IPQP_EC_SUCCESS:
        if (log == NULL)
            PRINTF("[IPQP_EC_SUCCESS]: Success\r\n");
        else
            PRINTF("[IPQP_EC_SUCCESS]: %s\r\n", log);
        break;
    case IPQP_EC_FAIL:
        if (log == NULL)
            PRINTF("[IPQP_EC_FAIL]: Fail.\r\n");
        else
            PRINTF("[IPQP_EC_FAIL]: %s\r\n", log);
        break;
    case IPQP_EC_TIMEOUT:
        if (log == NULL)
            PRINTF("[IPQP_EC_TIMEOUT]: Timeout.\r\n");
        else
            PRINTF("[IPQP_EC_TIMEOUT]: %s\r\n", log);
        break;
    case IPQP_EC_NULL_POINTER:
        if (log == NULL)
            PRINTF("[IPQP_EC_NULL_POINTER]: Null pointer exception.\r\n");
        else
            PRINTF("[IPQP_EC_NULL_POINTER]: %s\r\n", log);
        break;
    case IPQP_EC_RTL_SRC_MISSING:
        if (log == NULL)
            PRINTF("[IPQP_EC_RTL_SRC_MISSING]: Provider not found.\r\n");
        else
            PRINTF("[IPQP_EC_RTL_SRC_MISSING]: %s\r\n", log);
        break;
    case IPQP_EC_ALGO_MISSING:
        if (log == NULL)
            PRINTF("[IPQP_EC_ALGO_MISSING]: Algorithm not found.\r\n");
        else
            PRINTF("[IPQP_EC_ALGO_MISSING]: %s\r\n", log);
        break;
    case IPQP_EC_PROV_NOT_CONFIGED:
        if (log == NULL)
            PRINTF("[IPQP_EC_PROV_NOT_CONFIGED]: Provider not configured.\r\n");
        else
            PRINTF("[IPQP_EC_PROV_NOT_CONFIGED]: %s\r\n", log);
        break;
    case IPQP_EC_SPI_IO:
        if (log == NULL)
            PRINTF("[IPQP_EC_SPI_IO]: SPI I/O error.\r\n");
        else
            PRINTF("[IPQP_EC_SPI_IO]: %s\r\n", log);
        break;
    case IPQP_EC_UART_IO:
        if (log == NULL)
            PRINTF("[IPQP_EC_UART_IO]: UART I/O error.\r\n");
        else
            PRINTF("[IPQP_EC_UART_IO]: %s\r\n", log);
        break;
    default:
        break;
    }
}
