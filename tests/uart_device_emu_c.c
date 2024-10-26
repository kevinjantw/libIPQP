#include "ipqp_common.h"
#include "test_common.h"
#include "kat.h"

int main(int argc, char *argv[])
{
    printf("===== [START] =====\r\n");

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

    uint8_t rcv_data[UART_BUFFER_SIZE];
    uint8_t snd_data[UART_BUFFER_SIZE];
    uint8_t pkt_data[UART_BUFFER_SIZE];

    memset((uint8_t *)rcv_data, 0x00, UART_BUFFER_SIZE);
    memset((uint8_t *)snd_data, 0x00, UART_BUFFER_SIZE);
    memset((uint8_t *)pkt_data, 0x00, UART_BUFFER_SIZE);

    bool stop_loop = false;
    while (!stop_loop)
    {
        printf("----------\r\n");

#if false
        uart_clear_rcv_buffer(&uart_conf);
        printf("input:\r\n");
        if (fgets((char *)snd_data, UART_BUFFER_SIZE, stdin) == NULL)
            continue;
        printf("\r\n");

        ssize_t wrt_res = -1;
        int snd_size = strlen((char *)snd_data);
        if (snd_data[0] == '`')
        {
            stop_loop = true;
        }
        else if (snd_data[0] == '1')
        {
            for (int i = 0; i < 256; i++)
                snd_data[i] = i % 256;
            snd_size = 256;

            printf("send(%2d):\r\n", snd_size);
            print_arr((uint8_t *)snd_data, snd_size, 32, NULL);
            wrt_res = uart_write(&uart_conf, snd_data, snd_size);
        }
        else if (snd_data[0] == '2')
        {
            for (int i = 0; i < UART_BUFFER_SIZE; i++)
                snd_data[i] = i % 256;
            snd_size = UART_BUFFER_SIZE;

            printf("send(%2d):\r\n", snd_size);
            print_arr((uint8_t *)snd_data, snd_size, 32, NULL);
            wrt_res = uart_write(&uart_conf, snd_data, snd_size);
        }
        else if (snd_data[0] == '3')
        {
            
            printf("send(%2d):\r\n", snd_size);
            print_arr((uint8_t *)snd_data, snd_size, 32, NULL);
            wrt_res = uart_write(&uart_conf, snd_data, snd_size);
        }
        else
        {
            printf("send(%2d): %s\r\n", snd_size, snd_data);
            print_arr((uint8_t *)snd_data, snd_size, 32, NULL);
            wrt_res = uart_write(&uart_conf, snd_data, snd_size);
        }
        printf("wrt_res = " PRINT_SSIZE_FMT "\r\n", wrt_res);
#endif

#if false
        int pkt_len = 0;
        int pkt_idx = 0;
        int retries = 100;
        while ((pkt_len < snd_size) && (retries-- > 0))
        {
            int n = 100;
            int rcv_data_len = -1;
            while ((n-- > 0) && rcv_data_len < 0)
            {
                rcv_data_len = uart_read(&uart_conf, rcv_data, 1024);
                usleep(5000);
            }

            if (rcv_data_len > 0)
            {
                memcpy(pkt_data + pkt_len, rcv_data, rcv_data_len);
                pkt_len += rcv_data_len;
                // retries = -1;
                printf("%d:: read(%2d):\r\n", ++pkt_idx, rcv_data_len);
                print_arr((uint8_t *)rcv_data, rcv_data_len, 32, NULL);
            }
        }

        printf("packet data(%d):\r\n", pkt_len);
        print_arr((uint8_t *)pkt_data, pkt_len, 32, NULL);
#else
        // size_t pkt_len = snd_size;
        size_t pkt_len = 255;
        if (uart_read_packet(&uart_conf, pkt_data, pkt_len) != IPQP_EC_SUCCESS)
        {
            printf("failed to read packet.\r\n");
            FAIL_n_EXIT;
        }

        printf("packet data(" PRINT_SIZE_FMT "):\r\n", pkt_len);
        print_arr((uint8_t *)pkt_data, pkt_len, 32, NULL);
#endif

        printf("\r\n");
    }

    if (uart_close(&uart_conf) < 0)
    {
        PRINTF("[ERROR]:: fail to close uart iface %s\r\n", uart_conf.name);
        FAIL_n_EXIT;
    }

    printf("===== [E N D] =====\r\n");
    PASS_n_EXIT;
}
