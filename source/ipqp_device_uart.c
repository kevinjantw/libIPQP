#include "ipqp_common.h"
#include "ipqp_device.h"
#include "ipqp_apdu.h"
#include "ipqp.h"

int uart_open(uart_conf_t *uart_conf)
{
    struct termios tty_cfg;
    memset(&tty_cfg, 0, sizeof(tty_cfg));

    uart_conf->fd = open(uart_conf->name, uart_conf->open_flags);
    if (uart_conf->fd < 0)
    {
        PRINTF("[ERROR] %s: failed to open UART %s\r\n", __func__, uart_conf->name);
        return -1;
    }

    tty_cfg.c_iflag |= uart_conf->input_mode_flags;
    tty_cfg.c_oflag |= uart_conf->output_mode_flags;
    tty_cfg.c_cflag |= uart_conf->control_mode_flags;
    tty_cfg.c_lflag |= uart_conf->local_mode_flags;

    if (((uart_conf->local_mode_flags) & ICANON) == 0)
    {
        tty_cfg.c_cc[VTIME] = 0;
        tty_cfg.c_cc[VMIN] = 1;
    }

    tcflush(uart_conf->fd, TCIFLUSH);

    if (tcsetattr(uart_conf->fd, TCSANOW, &tty_cfg) != 0)
    {
        printf("[ERROR] %s: failed to set attributes\r\n", __func__);
        return -1;
    }

    return 0;
}

int uart_close(uart_conf_t *uart_conf)
{
    return close(uart_conf->fd);
}

ssize_t uart_read(uart_conf_t *uart_conf, uint8_t *buff, size_t max_buff_len)
{
    return read(uart_conf->fd, buff, max_buff_len);
}

IPQP_ErrorCode uart_read_packet(uart_conf_t *uart_conf, uint8_t *pkt_buff, size_t pkt_len)
{
    int rcv_data_idx = 0;
    int max_round_to_read = 100000;
    int total_rcvd_pkt_len = 0;
    int retries = 0;
    while ((total_rcvd_pkt_len < pkt_len) && (retries < max_round_to_read))
    {
        int rcvd_data_len = uart_read(uart_conf, pkt_buff + total_rcvd_pkt_len, pkt_len - total_rcvd_pkt_len);
        if (rcvd_data_len > 0)
        {
            PRINTF("%d:: read(%2d):\r\n", rcv_data_idx++, rcvd_data_len);
            // PRINT_ARR((uint8_t *)pkt_buff + total_rcvd_pkt_len, rcvd_data_len, 32, NULL);

            total_rcvd_pkt_len += rcvd_data_len;
            retries = 0;
        }
        else
        {
            usleep(5000);
            retries++;
        }
    }

    if (retries >= max_round_to_read)
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

ssize_t uart_write(uart_conf_t *uart_conf, uint8_t *buff, size_t len_to_write)
{
    size_t written_len = 0;
    int n = 0;
    int max_retries = 100;
    int retries = 0;
    while ((written_len < len_to_write) && (retries < max_retries))
    {
        size_t len_to_write_l = ((len_to_write - written_len) > UART_PACKET_DATA_SIZE) ? UART_PACKET_DATA_SIZE : (len_to_write - written_len);
        ssize_t written_len_l = write(uart_conf->fd, buff + written_len, len_to_write_l);
        // tcdrain(uart_conf->fd);           // Wait until transmission ends
        // tcflush(uart_conf->fd, TCOFLUSH); // Clear write buffer

        if (written_len_l > 0)
        {
            PRINTF("%d:: " PRINT_SSIZE_FMT "\r\n", n, written_len_l);
            written_len += written_len_l;
            n++;
            retries = 0;
        }
        else
        {
            // PRINTF("Failed to write (%d)\r\n", retries);
            retries++;
        }
    }

    if (retries >= max_retries)
        return -1;

    return written_len;
}

IPQP_ErrorCode uart_wait_for_ready(uart_conf_t *uart_conf)
{
    if (uart_conf == NULL)
        return IPQP_EC_NULL_POINTER;

    int max_retries = 500;
    uint8_t status[2] = {0x00, 0x00};
    bool to_stop = false;
    do
    {
        status[0] = 0x00;
        status[1] = 0x00;
        if (apdu_uart_status_check(uart_conf, status) < 0)
            return IPQP_EC_UART_IO; // failed to check status

        if ((status[0] == 0x90) && (status[1] == 0x00))
            to_stop = true;
        else
            usleep(100000);

        if (max_retries <= 0)
            return IPQP_EC_TIMEOUT;
        max_retries--;
    } while (!to_stop);
    return IPQP_EC_SUCCESS;
}

void uart_clear_rcv_buffer(uart_conf_t *uart_conf)
{
    bool to_stop_loop = false;
    while (!to_stop_loop)
    {
        uint8_t rcv_data[128];
        int n = 100;
        int read_data_len = -1;
        while ((n-- > 0) && read_data_len < 0)
        {
            read_data_len = uart_read(uart_conf, rcv_data, 128);
            usleep(5000);
        }

        if (read_data_len <= 0)
            to_stop_loop = true;
    }
}
